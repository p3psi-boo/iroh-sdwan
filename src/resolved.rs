//! Runtime integration with systemd-resolved's per-link split-DNS API.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Context, Result, ensure};
use tracing::{info, warn};
use zbus::Connection;

use crate::{
    config::{Config, DnsConfig},
    dns::reverse_routing_domains,
};

#[zbus::proxy(
    interface = "org.freedesktop.resolve1.Manager",
    default_service = "org.freedesktop.resolve1",
    default_path = "/org/freedesktop/resolve1"
)]
trait ResolveManager {
    #[zbus(name = "SetLinkDNSEx")]
    fn set_link_dns_ex(
        &self,
        ifindex: i32,
        servers: Vec<(i32, Vec<u8>, u16, String)>,
    ) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDomains")]
    fn set_link_domains(&self, ifindex: i32, domains: Vec<(String, bool)>) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDefaultRoute")]
    fn set_link_default_route(&self, ifindex: i32, enabled: bool) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDNSSEC")]
    fn set_link_dnssec(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    #[zbus(name = "SetLinkDNSOverTLS")]
    fn set_link_dns_over_tls(&self, ifindex: i32, mode: &str) -> zbus::Result<()>;

    #[zbus(name = "RevertLink")]
    fn revert_link(&self, ifindex: i32) -> zbus::Result<()>;
}

pub struct ResolvedRegistration {
    ifindex: i32,
    interface: String,
}

impl ResolvedRegistration {
    pub async fn install(config: &Config, server: SocketAddr) -> Result<Self> {
        ensure!(
            config.dns.enabled,
            "resolved registration requires dns.enabled"
        );
        ensure!(
            config.dns.accept_dns,
            "resolved registration requires dns.accept_dns"
        );
        let ifindex = interface_index(&config.node_interface).await?;
        let connection = Connection::system()
            .await
            .context("failed connecting to the system D-Bus")?;
        let proxy = ResolveManagerProxy::new(&connection)
            .await
            .context("systemd-resolved is unavailable on the system D-Bus")?;
        let registration = Self {
            ifindex,
            interface: config.node_interface.clone(),
        };
        if let Err(error) = install_with_proxy(&proxy, config, ifindex, server).await {
            if let Err(revert_error) = proxy.revert_link(ifindex).await {
                warn!(%revert_error, ifindex, "failed reverting partial systemd-resolved state");
            }
            return Err(error);
        }
        info!(
            interface = %config.node_interface,
            %ifindex,
            %server,
            domain = %config.dns.domain.as_deref().unwrap_or_default(),
            "installed systemd-resolved split DNS"
        );
        Ok(registration)
    }

    pub async fn revert(self) -> Result<()> {
        let connection = Connection::system()
            .await
            .context("failed reconnecting to the system D-Bus for DNS cleanup")?;
        let proxy = ResolveManagerProxy::new(&connection).await?;
        proxy.revert_link(self.ifindex).await.with_context(|| {
            format!(
                "failed reverting systemd-resolved state for {}",
                self.interface
            )
        })?;
        info!(interface = %self.interface, ifindex = self.ifindex, "reverted systemd-resolved split DNS");
        Ok(())
    }
}

async fn install_with_proxy(
    proxy: &ResolveManagerProxy<'_>,
    config: &Config,
    ifindex: i32,
    server: SocketAddr,
) -> Result<()> {
    proxy
        .set_link_dns_ex(ifindex, vec![dns_server_tuple(server)])
        .await
        .context("failed setting per-link DNS server")?;
    let domains = link_domains(&config.dns)?;
    proxy
        .set_link_domains(ifindex, domains)
        .await
        .context("failed setting per-link DNS domains")?;
    proxy
        .set_link_default_route(ifindex, false)
        .await
        .context("failed disabling the DNS default route")?;
    proxy
        .set_link_dnssec(ifindex, "no")
        .await
        .context("failed disabling DNSSEC for the private zone")?;
    proxy
        .set_link_dns_over_tls(ifindex, "no")
        .await
        .context("failed disabling DNS-over-TLS for the local authority")?;
    Ok(())
}

fn link_domains(dns: &DnsConfig) -> Result<Vec<(String, bool)>> {
    let domain = dns
        .domain
        .as_deref()
        .context("validated DNS configuration has no domain")?
        .trim_end_matches('.')
        .to_owned();
    let mut domains = vec![(domain, !dns.short_names)];
    for prefix in &dns.reverse_prefixes {
        domains.extend(
            reverse_routing_domains(*prefix)
                .into_iter()
                .map(|domain| (domain, true)),
        );
    }
    domains.sort();
    domains.dedup();
    Ok(domains)
}

fn dns_server_tuple(server: SocketAddr) -> (i32, Vec<u8>, u16, String) {
    let (family, address) = match server.ip() {
        IpAddr::V4(address) => (libc_family_v4(), address.octets().to_vec()),
        IpAddr::V6(address) => (libc_family_v6(), address.octets().to_vec()),
    };
    (family, address, server.port(), String::new())
}

const fn libc_family_v4() -> i32 {
    2 // Linux AF_INET
}

const fn libc_family_v6() -> i32 {
    10 // Linux AF_INET6
}

async fn interface_index(interface: &str) -> Result<i32> {
    let path = format!("/sys/class/net/{interface}/ifindex");
    let raw = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed reading interface index from {path}"))?;
    let value = raw
        .trim()
        .parse::<i32>()
        .with_context(|| format!("invalid interface index in {path}"))?;
    ensure!(value > 0, "interface {interface} has an invalid index");
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;

    #[test]
    fn dns_server_tuple_matches_resolve1_signature() {
        assert_eq!(
            dns_server_tuple("100.64.0.1:1053".parse().unwrap()),
            (2, vec![100, 64, 0, 1], 1053, String::new())
        );
        let tuple = dns_server_tuple("[fd42::1]:1053".parse().unwrap());
        assert_eq!(tuple.0, 10);
        assert_eq!(tuple.1.len(), 16);
        assert_eq!(tuple.2, 1053);
    }

    #[test]
    fn link_domains_include_search_and_aligned_reverse_routes() {
        let dns = DnsConfig {
            enabled: true,
            domain: Some("mesh.example".to_owned()),
            reverse_prefixes: vec![
                "100.64.0.0/10".parse::<IpNet>().unwrap(),
                "fd42:1234::/48".parse::<IpNet>().unwrap(),
            ],
            ..DnsConfig::default()
        };

        let domains = link_domains(&dns).unwrap();
        assert!(domains.contains(&("mesh.example".to_owned(), false)));
        assert!(domains.contains(&("64.100.in-addr.arpa".to_owned(), true)));
        assert!(domains.contains(&("127.100.in-addr.arpa".to_owned(), true)));
        assert!(domains.contains(&("0.0.0.0.4.3.2.1.2.4.d.f.ip6.arpa".to_owned(), true)));
    }

    #[test]
    fn link_domains_mark_forward_zone_route_only_without_short_names() {
        let dns = DnsConfig {
            enabled: true,
            domain: Some("mesh.example.".to_owned()),
            short_names: false,
            ..DnsConfig::default()
        };

        assert_eq!(
            link_domains(&dns).unwrap(),
            vec![("mesh.example".to_owned(), true)]
        );
    }
}
