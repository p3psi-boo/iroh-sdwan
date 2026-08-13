//! Durable desired state owned by external control-plane extensions.

use std::{
    collections::{BTreeMap, HashSet},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use ironet_extension_sdk::{
    ApplyRoutesRequest, CONTROL_API_VERSION, DeleteRoutesRequest, DesiredRoute, DesiredRouteSpec,
    RouteApply, RouteMutationResult,
};
use serde::{Deserialize, Serialize};

use crate::{config::RouteOriginConfig, deployment, routes::RouteRegistry};

const STATE_FILE_VERSION: u8 = 1;
pub const MAX_ROUTE_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_IDEMPOTENCY_RECORDS: usize = 1_024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionState {
    #[serde(default = "state_file_version")]
    version: u8,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    routes: BTreeMap<String, DesiredRoute>,
    #[serde(default)]
    idempotency: BTreeMap<String, IdempotencyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdempotencyRecord {
    fingerprint: String,
    result: RouteMutationResult,
}

#[derive(Debug, Clone)]
pub struct Mutation {
    pub state: ExtensionState,
    pub result: RouteMutationResult,
    pub persist: bool,
    pub reload: bool,
}

impl ExtensionState {
    pub async fn load(path: &Path) -> Result<Self> {
        match tokio::fs::read_to_string(path).await {
            Ok(raw) => {
                let state: Self = toml::from_str(&raw).with_context(|| {
                    format!("failed to parse extension state {}", path.display())
                })?;
                ensure!(
                    state.version == STATE_FILE_VERSION,
                    "unsupported extension-state version {}",
                    state.version
                );
                Ok(state)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to read extension state {}", path.display())),
        }
    }

    pub fn new() -> Self {
        Self {
            version: STATE_FILE_VERSION,
            ..Self::default()
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let encoded = toml::to_string_pretty(self)?;
        deployment::atomic_write(path, encoded.as_bytes(), 0o600)
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn list(&self, now_unix: u64) -> Vec<DesiredRoute> {
        self.routes
            .values()
            .filter(|route| !expired(route, now_unix))
            .cloned()
            .collect()
    }

    pub fn route_origins(&self, now_unix: u64) -> Result<Vec<RouteOriginConfig>> {
        let mut owners: BTreeMap<String, (EndpointId, Vec<IpNet>)> = BTreeMap::new();
        for route in self.list(now_unix) {
            let endpoint_id = route
                .spec
                .endpoint_id
                .parse::<EndpointId>()
                .with_context(|| format!("route {} has an invalid endpoint ID", route.name))?;
            let entry = owners
                .entry(endpoint_id.to_string())
                .or_insert_with(|| (endpoint_id, Vec::new()));
            for prefix in route.spec.prefixes {
                entry.1.push(prefix.parse::<IpNet>().with_context(|| {
                    format!("route {} has invalid prefix {prefix}", route.name)
                })?);
            }
        }
        let mut registry = RouteRegistry {
            version: 1,
            routes: owners
                .into_values()
                .map(|(endpoint_id, prefixes)| RouteOriginConfig {
                    endpoint_id,
                    prefixes,
                })
                .collect(),
        };
        registry.normalize()?;
        Ok(registry.routes)
    }

    pub fn apply(&self, request: &ApplyRoutesRequest, now_unix: u64) -> Result<Mutation> {
        ensure!(
            !request.routes.is_empty(),
            "apply_routes requires at least one route"
        );
        validate_key(&request.idempotency_key, "idempotency_key")?;
        let fingerprint = fingerprint(request)?;
        if let Some(cached) = self.idempotency.get(&request.idempotency_key) {
            ensure!(
                cached.fingerprint == fingerprint,
                "idempotency_key was already used with different parameters"
            );
            return Ok(Mutation {
                state: self.clone(),
                result: cached.result.clone(),
                persist: false,
                reload: false,
            });
        }

        let mut candidate = self.clone();
        let expired_count = candidate.prune_expired(now_unix);
        let mut changed = 0;
        let mut unchanged = 0;
        let mut request_keys = HashSet::new();
        for route in &request.routes {
            validate_apply(route)?;
            let key = route_key(&route.owner, &route.name);
            ensure!(
                request_keys.insert(key.clone()),
                "duplicate route {key} in request"
            );
            let desired = desired(route, now_unix)?;
            match candidate.routes.get(&key) {
                Some(existing) if route.revision == existing.revision => {
                    ensure!(
                        existing.api_version == desired.api_version
                            && existing.name == desired.name
                            && existing.owner == desired.owner
                            && existing.spec == desired.spec,
                        "route {key} revision {} was reused with different state",
                        route.revision
                    );
                    unchanged += 1;
                }
                Some(existing) => {
                    ensure!(
                        route.revision > existing.revision,
                        "route {key} revision {} is not newer than {}",
                        route.revision,
                        existing.revision
                    );
                    candidate.routes.insert(key, desired);
                    changed += 1;
                }
                None => {
                    candidate.routes.insert(key, desired);
                    changed += 1;
                }
            }
        }
        candidate.finish_mutation(
            request.dry_run,
            changed + expired_count,
            unchanged,
            &request.idempotency_key,
            fingerprint,
            now_unix,
        )
    }

    pub fn delete(&self, request: &DeleteRoutesRequest, now_unix: u64) -> Result<Mutation> {
        validate_name(&request.owner, "owner")?;
        validate_key(&request.idempotency_key, "idempotency_key")?;
        ensure!(
            !request.names.is_empty(),
            "delete_routes requires at least one name"
        );
        let fingerprint = fingerprint(request)?;
        if let Some(cached) = self.idempotency.get(&request.idempotency_key) {
            ensure!(
                cached.fingerprint == fingerprint,
                "idempotency_key was already used with different parameters"
            );
            return Ok(Mutation {
                state: self.clone(),
                result: cached.result.clone(),
                persist: false,
                reload: false,
            });
        }

        let mut candidate = self.clone();
        let expired_count = candidate.prune_expired(now_unix);
        let mut changed = 0;
        let mut unchanged = 0;
        let mut names = HashSet::new();
        for name in &request.names {
            validate_name(name, "route name")?;
            ensure!(names.insert(name), "duplicate route name {name} in request");
            let key = route_key(&request.owner, name);
            match candidate.routes.get(&key) {
                Some(existing) => {
                    if let Some(revision) = request.expected_revision {
                        ensure!(
                            revision == existing.revision,
                            "route {key} revision changed from {revision} to {}",
                            existing.revision
                        );
                    }
                    candidate.routes.remove(&key);
                    changed += 1;
                }
                None => unchanged += 1,
            }
        }
        candidate.finish_mutation(
            request.dry_run,
            changed + expired_count,
            unchanged,
            &request.idempotency_key,
            fingerprint,
            now_unix,
        )
    }

    fn finish_mutation(
        mut self,
        dry_run: bool,
        changed: usize,
        unchanged: usize,
        idempotency_key: &str,
        fingerprint: String,
        now_unix: u64,
    ) -> Result<Mutation> {
        let next_generation = self.generation.saturating_add(u64::from(changed > 0));
        let result = RouteMutationResult {
            generation: next_generation,
            changed,
            unchanged,
            dry_run,
            routes: self.list(now_unix),
        };
        if !dry_run {
            self.generation = next_generation;
            self.idempotency.insert(
                idempotency_key.into(),
                IdempotencyRecord {
                    fingerprint,
                    result: result.clone(),
                },
            );
            while self.idempotency.len() > MAX_IDEMPOTENCY_RECORDS {
                if let Some(oldest) = self.idempotency.keys().next().cloned() {
                    self.idempotency.remove(&oldest);
                }
            }
        }
        Ok(Mutation {
            state: self,
            result,
            persist: !dry_run,
            reload: !dry_run && changed > 0,
        })
    }

    fn prune_expired(&mut self, now_unix: u64) -> usize {
        let before = self.routes.len();
        self.routes.retain(|_, route| !expired(route, now_unix));
        before - self.routes.len()
    }

    pub fn expire(&self, now_unix: u64) -> Option<(Self, Vec<DesiredRoute>)> {
        let mut candidate = self.clone();
        let expired = candidate
            .routes
            .values()
            .filter(|route| expired(route, now_unix))
            .cloned()
            .collect::<Vec<_>>();
        if expired.is_empty() {
            return None;
        }
        candidate.prune_expired(now_unix);
        candidate.generation = candidate.generation.saturating_add(1);
        Some((candidate, expired))
    }

    /// Timestamp of the next active lease expiry, if any. The daemon uses this
    /// instead of polling so extension leases add no steady-state wakeups.
    pub fn next_expiry(&self, now_unix: u64) -> Option<u64> {
        self.routes
            .values()
            .filter_map(|route| route.expires_unix)
            .filter(|expires| *expires > now_unix)
            .min()
    }
}

pub fn state_path(identity_file: &Path) -> PathBuf {
    identity_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("extensions.toml")
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_apply(route: &RouteApply) -> Result<()> {
    ensure!(
        route.api_version == CONTROL_API_VERSION,
        "route {} uses unsupported API version {}",
        route.name,
        route.api_version
    );
    validate_name(&route.name, "route name")?;
    validate_name(&route.owner, "owner")?;
    ensure!(
        route.revision > 0,
        "route revision must be greater than zero"
    );
    ensure!(
        !route.spec.prefixes.is_empty(),
        "route {} requires at least one prefix",
        route.name
    );
    ensure!(
        route
            .ttl_seconds
            .is_none_or(|ttl| ttl > 0 && ttl <= MAX_ROUTE_TTL_SECONDS),
        "route TTL must be between 1 and {MAX_ROUTE_TTL_SECONDS} seconds"
    );
    route
        .spec
        .endpoint_id
        .parse::<EndpointId>()
        .context("invalid route endpoint_id")?;
    let mut prefixes = HashSet::new();
    for prefix in &route.spec.prefixes {
        let parsed = prefix
            .parse::<IpNet>()
            .with_context(|| format!("invalid route prefix {prefix}"))?;
        ensure!(prefixes.insert(parsed), "duplicate route prefix {prefix}");
    }
    Ok(())
}

fn validate_name(value: &str, field: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= 128,
        "{field} must contain 1-128 characters"
    );
    ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'/' | b'_' | b'-')),
        "{field} contains unsupported characters"
    );
    Ok(())
}

fn validate_key(value: &str, field: &str) -> Result<()> {
    validate_name(value, field)
}

fn desired(route: &RouteApply, now_unix: u64) -> Result<DesiredRoute> {
    let mut prefixes = route
        .spec
        .prefixes
        .iter()
        .map(|prefix| prefix.parse::<IpNet>().map(|value| value.to_string()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    prefixes.sort();
    Ok(DesiredRoute {
        api_version: CONTROL_API_VERSION,
        name: route.name.clone(),
        owner: route.owner.clone(),
        revision: route.revision,
        expires_unix: route.ttl_seconds.map(|ttl| now_unix.saturating_add(ttl)),
        spec: DesiredRouteSpec {
            endpoint_id: route.spec.endpoint_id.parse::<EndpointId>()?.to_string(),
            prefixes,
        },
    })
}

fn expired(route: &DesiredRoute, now_unix: u64) -> bool {
    route
        .expires_unix
        .is_some_and(|expires| expires <= now_unix)
}

fn route_key(owner: &str, name: &str) -> String {
    format!("{owner}/{name}")
}

fn fingerprint<T: Serialize>(value: &T) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

fn state_file_version() -> u8 {
    STATE_FILE_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;

    fn route(revision: u64) -> RouteApply {
        RouteApply {
            api_version: CONTROL_API_VERSION,
            name: "office".into(),
            owner: "example.com/ipam".into(),
            revision,
            ttl_seconds: Some(300),
            spec: DesiredRouteSpec {
                endpoint_id: SecretKey::from_bytes(&[4; 32]).public().to_string(),
                prefixes: vec!["10.30.0.0/16".into()],
            },
        }
    }

    #[test]
    fn apply_is_revisioned_and_idempotent() {
        let request = ApplyRoutesRequest {
            routes: vec![route(1)],
            dry_run: false,
            idempotency_key: "apply-1".into(),
        };
        let first = ExtensionState::new().apply(&request, 100).unwrap();
        assert_eq!(first.result.changed, 1);
        assert_eq!(first.result.generation, 1);
        let replay = first.state.apply(&request, 101).unwrap();
        assert_eq!(replay.result, first.result);
        let stale = ApplyRoutesRequest {
            routes: vec![route(1)],
            dry_run: false,
            idempotency_key: "apply-stale".into(),
        };
        assert!(first.state.apply(&stale, 101).unwrap().result.unchanged == 1);
    }

    #[test]
    fn expired_routes_are_not_resolved() {
        let request = ApplyRoutesRequest {
            routes: vec![route(1)],
            dry_run: false,
            idempotency_key: "ttl".into(),
        };
        let mutation = ExtensionState::new().apply(&request, 100).unwrap();
        assert_eq!(mutation.state.route_origins(399).unwrap().len(), 1);
        assert!(mutation.state.route_origins(400).unwrap().is_empty());
    }

    #[test]
    fn dry_run_does_not_advance_generation() {
        let request = ApplyRoutesRequest {
            routes: vec![route(1)],
            dry_run: true,
            idempotency_key: "preview".into(),
        };
        let mutation = ExtensionState::new().apply(&request, 100).unwrap();
        assert_eq!(mutation.result.changed, 1);
        assert_eq!(mutation.state.generation(), 0);
    }
}
