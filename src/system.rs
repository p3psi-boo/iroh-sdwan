use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    process::Stdio,
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use tokio::process::Command;
use tracing::{debug, info};

use crate::config::Config;

// Private route-protocol marker used only for FlowRouter-owned kernel routes.
// 100 avoids the named assignments commonly used by dynamic routing stacks,
// OSPF, and other routing daemons.
const FLOW_ROUTER_ROUTE_PROTOCOL: &str = "100";

/// Configure the already-created FlowRouter TUN. Device creation stays in the
/// data-plane lifecycle so exactly one file descriptor owns packet I/O.
pub async fn prepare_node_interface(config: &Config) -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("iroh-sdwan runtime is supported only on Linux");
    }

    run_ip(&["link", "set", "dev", &config.node_interface, "up"]).await?;
    for family in ["-4", "-6"] {
        run_ip_allow_failure(&[
            family,
            "address",
            "flush",
            "dev",
            &config.node_interface,
            "scope",
            "global",
        ])
        .await?;
    }
    for address in &config.node_addresses {
        replace_address(&config.node_interface, *address).await?;
    }
    Ok(())
}

pub async fn cleanup_node_interface(config: &Config) -> Result<()> {
    run_ip_allow_failure(&["link", "del", "dev", &config.node_interface]).await?;
    info!(interface = %config.node_interface, "cleaned FlowRouter TUN interface");
    Ok(())
}

pub async fn prepare_routing(config: &Config) -> Result<()> {
    let priority = config.routing.rule_priority.to_string();
    let underlay_priority = config.routing.rule_priority.saturating_sub(1).to_string();
    for address in config.static_underlay_addresses() {
        let (family, prefix) = host_prefix(address);
        run_ip_allow_failure(&[
            family,
            "rule",
            "del",
            "priority",
            &underlay_priority,
            "to",
            &prefix,
            "lookup",
            "main",
        ])
        .await?;
        run_ip(&[
            family,
            "rule",
            "add",
            "priority",
            &underlay_priority,
            "to",
            &prefix,
            "lookup",
            "main",
            "protocol",
            "static",
        ])
        .await?;
    }

    if config.routing.isolate_overlay {
        let table = config.routing.table.to_string();
        for family in ["-4", "-6"] {
            run_ip_allow_failure(&[
                family, "rule", "del", "priority", &priority, "lookup", &table,
            ])
            .await?;
            run_ip(&[
                family, "rule", "add", "priority", &priority, "lookup", &table, "protocol",
                "static",
            ])
            .await?;
        }
    }

    sync_overlay_routes(config, config.all_remote_prefixes()).await?;
    info!(
        table = routing_table(config),
        priority = config.routing.rule_priority,
        interface = %config.node_interface,
        "prepared FlowRouter routes"
    );
    Ok(())
}

/// Reconcile the destination inventory accepted by the single TUN. New routes
/// are installed before stale routes are removed, avoiding a table-wide gap
/// when signed Presence inventory changes.
pub async fn sync_overlay_routes(
    config: &Config,
    prefixes: impl IntoIterator<Item = IpNet>,
) -> Result<()> {
    let table = routing_table(config).to_string();
    let (ipv4_source, ipv6_source) = preferred_sources(&config.node_addresses);
    let desired = prefixes.into_iter().collect::<HashSet<_>>();
    let installed = installed_overlay_routes(&table).await?;
    let mut ordered = desired.iter().copied().collect::<Vec<_>>();
    ordered.sort();
    for prefix in ordered {
        let (family, source) = if prefix.addr().is_ipv4() {
            ("-4", ipv4_source.as_deref())
        } else {
            ("-6", ipv6_source.as_deref())
        };
        let mut args = vec![
            family.to_owned(),
            "route".into(),
            "replace".into(),
            "table".into(),
            table.clone(),
            prefix.to_string(),
            "dev".into(),
            config.node_interface.clone(),
            "proto".into(),
            FLOW_ROUTER_ROUTE_PROTOCOL.into(),
        ];
        if let Some(source) = source {
            args.extend(["src".into(), source.into()]);
        }
        let references = args.iter().map(String::as_str).collect::<Vec<_>>();
        run_ip(&references).await?;
    }
    let mut stale = installed.difference(&desired).copied().collect::<Vec<_>>();
    stale.sort();
    for prefix in stale {
        let family = if prefix.addr().is_ipv4() { "-4" } else { "-6" };
        run_ip(&[
            family,
            "route",
            "del",
            "table",
            &table,
            &prefix.to_string(),
            "proto",
            FLOW_ROUTER_ROUTE_PROTOCOL,
        ])
        .await?;
    }
    Ok(())
}

async fn installed_overlay_routes(table: &str) -> Result<HashSet<IpNet>> {
    let mut installed = HashSet::new();
    for family in ["-4", "-6"] {
        let output = Command::new("ip")
            .args([
                family,
                "-j",
                "route",
                "show",
                "table",
                table,
                "proto",
                FLOW_ROUTER_ROUTE_PROTOCOL,
            ])
            .output()
            .await
            .context("failed to inspect FlowRouter routes")?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            if error.contains("FIB table does not exist") {
                continue;
            }
            bail!("failed to inspect FlowRouter routes: {}", error.trim());
        }
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed to parse FlowRouter route inventory")?;
        for destination in routes
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|route| route.get("dst").and_then(serde_json::Value::as_str))
        {
            if let Some(prefix) = parse_route_destination(family, destination) {
                installed.insert(prefix);
            }
        }
    }
    Ok(installed)
}

fn parse_route_destination(family: &str, destination: &str) -> Option<IpNet> {
    if destination == "default" {
        return if family == "-4" {
            "0.0.0.0/0".parse().ok()
        } else {
            "::/0".parse().ok()
        };
    }
    destination.parse::<IpNet>().ok().or_else(|| {
        destination
            .parse::<IpAddr>()
            .ok()
            .and_then(|address| IpNet::new(address, if address.is_ipv4() { 32 } else { 128 }).ok())
    })
}

pub async fn cleanup_routing(config: &Config) -> Result<()> {
    let table = routing_table(config).to_string();
    let priority = config.routing.rule_priority.to_string();
    let underlay_priority = config.routing.rule_priority.saturating_sub(1).to_string();
    for address in config.static_underlay_addresses() {
        let (family, prefix) = host_prefix(address);
        run_ip_allow_failure(&[
            family,
            "rule",
            "del",
            "priority",
            &underlay_priority,
            "to",
            &prefix,
            "lookup",
            "main",
        ])
        .await?;
    }
    for family in ["-4", "-6"] {
        if config.routing.isolate_overlay {
            run_ip_allow_failure(&[
                family, "rule", "del", "priority", &priority, "lookup", &table,
            ])
            .await?;
        }
        run_ip_allow_failure(&[
            family,
            "route",
            "flush",
            "table",
            &table,
            "proto",
            FLOW_ROUTER_ROUTE_PROTOCOL,
        ])
        .await?;
    }
    info!(
        table = routing_table(config),
        priority = config.routing.rule_priority,
        "cleaned FlowRouter routes"
    );
    Ok(())
}

pub fn routing_table(config: &Config) -> u32 {
    if config.routing.isolate_overlay {
        config.routing.table
    } else {
        254
    }
}

fn host_prefix(address: SocketAddr) -> (&'static str, String) {
    if address.is_ipv4() {
        ("-4", format!("{}/32", address.ip()))
    } else {
        ("-6", format!("{}/128", address.ip()))
    }
}

fn preferred_sources(addresses: &[IpNet]) -> (Option<String>, Option<String>) {
    let mut ipv4 = None;
    let mut ipv6 = None;
    for address in addresses.iter().map(IpNet::addr) {
        let source = if address.is_ipv4() {
            &mut ipv4
        } else {
            &mut ipv6
        };
        source.get_or_insert_with(|| address.to_string());
        if ipv4.is_some() && ipv6.is_some() {
            break;
        }
    }
    (ipv4, ipv6)
}

async fn replace_address(interface: &str, address: IpNet) -> Result<()> {
    run_ip(&["address", "replace", &address.to_string(), "dev", interface]).await
}

async fn run_ip(args: &[&str]) -> Result<()> {
    debug!(command = %format!("ip {}", args.join(" ")), "executing network configuration");
    let output = Command::new("ip")
        .args(args)
        .output()
        .await
        .context("failed to execute iproute2")?;
    if !output.status.success() {
        bail!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

async fn run_ip_allow_failure(args: &[&str]) -> Result<()> {
    debug!(command = %format!("ip {}", args.join(" ")), "executing idempotent network cleanup");
    Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .context("failed to execute iproute2")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flow_router_route_destinations() {
        assert_eq!(
            parse_route_destination("-4", "10.0.0.7/32"),
            Some("10.0.0.7/32".parse().unwrap())
        );
        assert_eq!(
            parse_route_destination("-6", "default"),
            Some("::/0".parse().unwrap())
        );
    }
}
