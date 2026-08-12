use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::{
    config::{Config, RouteOriginConfig},
    deployment, identity,
};

const ROUTE_FILE_VERSION: u8 = 1;

/// CLI-managed static route registry. It intentionally lives outside the
/// sealed daemon configuration so route changes do not rewrite config.toml.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRegistry {
    #[serde(default = "route_file_version")]
    pub version: u8,
    #[serde(default, rename = "route")]
    pub routes: Vec<RouteOriginConfig>,
}

impl Default for RouteRegistry {
    fn default() -> Self {
        Self {
            version: ROUTE_FILE_VERSION,
            routes: Vec::new(),
        }
    }
}

impl RouteRegistry {
    pub async fn load(path: &Path) -> Result<Self> {
        match tokio::fs::read_to_string(path).await {
            Ok(raw) => Self::parse(&raw)
                .with_context(|| format!("failed to parse route registry {}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to read route registry {}", path.display())),
        }
    }

    pub async fn import(path: &Path) -> Result<Self> {
        let raw = if path == Path::new("-") {
            let mut raw = String::new();
            std::io::stdin()
                .read_to_string(&mut raw)
                .context("failed to read route import from standard input")?;
            raw
        } else {
            tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("failed to read route import {}", path.display()))?
        };
        let source = if path == Path::new("-") {
            "standard input".into()
        } else {
            path.display().to_string()
        };
        Self::parse(&raw).or_else(|toml_error| {
            Self::parse_lines(&raw).with_context(|| {
                format!(
                    "failed to parse {source} as routes TOML ({toml_error}) or line-oriented routes"
                )
            })
        })
    }

    pub fn parse(raw: &str) -> Result<Self> {
        let mut registry: Self = toml::from_str(raw)?;
        registry.normalize()?;
        Ok(registry)
    }

    /// Parse one owner and one or more prefixes per line:
    /// `<endpoint-id> <prefix> [prefix ...]`. Blank lines and `#` comments are
    /// ignored, making small route inventories convenient to generate.
    pub fn parse_lines(raw: &str) -> Result<Self> {
        let mut routes = Vec::new();
        for (index, original) in raw.lines().enumerate() {
            let line = original.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let endpoint_id = fields
                .next()
                .context("missing endpoint ID")?
                .parse::<EndpointId>()
                .with_context(|| format!("line {} has an invalid endpoint ID", index + 1))?;
            let prefixes = fields
                .map(|value| {
                    value
                        .parse::<IpNet>()
                        .with_context(|| format!("line {} has invalid prefix {value}", index + 1))
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                !prefixes.is_empty(),
                "line {} requires at least one prefix",
                index + 1
            );
            routes.push(RouteOriginConfig {
                endpoint_id,
                prefixes,
            });
        }
        let mut registry = Self {
            version: ROUTE_FILE_VERSION,
            routes,
        };
        registry.normalize()?;
        Ok(registry)
    }

    pub fn merge(&mut self, imported: Self) -> Result<()> {
        self.routes.extend(imported.routes);
        self.normalize()
    }

    pub fn remove(&mut self, selector: &str) -> Result<usize> {
        if let Ok(prefix) = selector.parse::<IpNet>() {
            let before = self.prefix_count();
            for route in &mut self.routes {
                route.prefixes.retain(|candidate| *candidate != prefix);
            }
            self.routes.retain(|route| !route.prefixes.is_empty());
            return Ok(before - self.prefix_count());
        }
        if let Ok(endpoint_id) = EndpointId::from_str(selector) {
            let before = self.prefix_count();
            self.routes.retain(|route| route.endpoint_id != endpoint_id);
            return Ok(before - self.prefix_count());
        }
        bail!("route selector must be a prefix or endpoint ID: {selector}")
    }

    pub fn prefix_count(&self) -> usize {
        self.routes.iter().map(|route| route.prefixes.len()).sum()
    }

    pub fn flattened(&self) -> Vec<(IpNet, EndpointId)> {
        let mut entries = self
            .routes
            .iter()
            .flat_map(|route| {
                route
                    .prefixes
                    .iter()
                    .copied()
                    .map(|prefix| (prefix, route.endpoint_id))
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| {
            left.0
                .to_string()
                .cmp(&right.0.to_string())
                .then_with(|| left.1.to_string().cmp(&right.1.to_string()))
        });
        entries
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let encoded = toml::to_string_pretty(self)?;
        // The state directory is private; the registry itself is intentionally
        // readable by the unprivileged daemon after a root CLI atomically
        // replaces it.
        deployment::atomic_write(path, encoded.as_bytes(), 0o644)
    }

    pub fn normalize(&mut self) -> Result<()> {
        ensure!(
            self.version == ROUTE_FILE_VERSION,
            "unsupported route registry version {}; expected {ROUTE_FILE_VERSION}",
            self.version
        );
        let mut owners: BTreeMap<String, (EndpointId, Vec<IpNet>)> = BTreeMap::new();
        for route in self.routes.drain(..) {
            ensure!(
                !route.prefixes.is_empty(),
                "route owner {} requires at least one prefix",
                route.endpoint_id
            );
            owners
                .entry(route.endpoint_id.to_string())
                .or_insert_with(|| (route.endpoint_id, Vec::new()))
                .1
                .extend(route.prefixes);
        }

        self.routes = owners
            .into_values()
            .map(|(endpoint_id, mut prefixes)| {
                let mut seen = HashSet::new();
                prefixes.retain(|prefix| seen.insert(*prefix));
                prefixes.sort_by_key(ToString::to_string);
                RouteOriginConfig {
                    endpoint_id,
                    prefixes,
                }
            })
            .collect();
        Ok(())
    }
}

/// Keep mutable routes with the node identity under the state directory. This
/// works for ordinary packages and immutable Nix-store main configurations
/// without adding another main-configuration setting.
pub fn registry_path(identity_file: &Path) -> PathBuf {
    identity_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("routes.toml")
}

pub async fn validate_for_config(config_path: &Path, registry: &RouteRegistry) -> Result<()> {
    let config = Config::load_with_route_origins(config_path, registry.routes.clone()).await?;
    let secret_key = identity::load(&config.identity_file)?;
    config.validate_local_id(secret_key.public())
}

fn route_file_version() -> u8 {
    ROUTE_FILE_VERSION
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn id(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    #[test]
    fn line_import_groups_owners_and_deduplicates_prefixes() {
        let first = id(1);
        let second = id(2);
        let registry = RouteRegistry::parse_lines(&format!(
            "# generated\n{first} 10.0.0.0/24 10.0.1.0/24\n{first} 10.0.0.0/24\n{second} 10.0.2.0/24\n"
        ))
        .unwrap();
        assert_eq!(registry.routes.len(), 2);
        assert_eq!(registry.prefix_count(), 3);
    }

    #[test]
    fn selector_removes_a_prefix_or_an_owner() {
        let first = id(3);
        let second = id(4);
        let mut registry = RouteRegistry::parse_lines(&format!(
            "{first} 10.1.0.0/24 10.1.1.0/24\n{second} 10.2.0.0/24\n"
        ))
        .unwrap();
        assert_eq!(registry.remove("10.1.0.0/24").unwrap(), 1);
        assert_eq!(registry.remove(&second.to_string()).unwrap(), 1);
        assert_eq!(registry.prefix_count(), 1);
    }

    #[test]
    fn canonical_toml_round_trips() {
        let registry = RouteRegistry::parse_lines(&format!("{} 10.3.0.0/16\n", id(5))).unwrap();
        let encoded = toml::to_string_pretty(&registry).unwrap();
        assert_eq!(RouteRegistry::parse(&encoded).unwrap().prefix_count(), 1);
        assert!(encoded.contains("[[route]]"));
    }
}
