//! Versioned, per-peer learner memory.

use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::{
    learner::{ArmMemoryV2, LearnerMemoryV2},
    tuning::Bbr3PresetV2,
};

pub const MEMORY_SCHEMA_VERSION_V2: u32 = 1;
pub const BUILTIN_POLICY_ID_V2: &str = "bandit-vivace@1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MemoryFileV2 {
    pub schema_version: u32,
    pub policy_id: String,
    pub peer: String,
    pub updated_unix_secs: u64,
    pub learner: LearnerMemoryV2,
}

impl MemoryFileV2 {
    pub fn new(peer: String, policy_id: String, learner: LearnerMemoryV2) -> Self {
        Self {
            schema_version: MEMORY_SCHEMA_VERSION_V2,
            policy_id,
            peer,
            updated_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            learner,
        }
    }

    fn validate(&self, expected_peer: &str) -> Result<()> {
        ensure!(
            self.schema_version == MEMORY_SCHEMA_VERSION_V2,
            "unsupported autotune memory schema {}",
            self.schema_version
        );
        ensure!(self.peer == expected_peer, "autotune memory peer mismatch");
        ensure!(
            !self.policy_id.trim().is_empty(),
            "autotune memory policy id is empty"
        );
        ensure!(
            self.learner
                .contexts
                .iter()
                .flat_map(|context| context.arms.iter())
                .all(|arm| arm.mean.is_finite()),
            "autotune memory contains a non-finite reward"
        );
        ensure!(
            self.learner.contexts.iter().all(|context| {
                (-100..=150).contains(&context.fine.up_gain_delta_milli)
                    && (-50..=50).contains(&context.fine.headroom_delta_milli)
                    && (-300..=300).contains(&context.fine.cwnd_gain_delta_milli)
                    && (-1..=1).contains(&context.fine.direction)
            }),
            "autotune memory contains invalid fine parameters"
        );
        Ok(())
    }
}

pub fn state_dir(identity_file: &Path) -> PathBuf {
    identity_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("autotune")
}

pub fn peer_path(directory: &Path, peer: &str) -> PathBuf {
    directory.join(format!("{peer}.json"))
}

pub fn load(directory: &Path, peer: &str, policy_id: &str) -> Result<Option<MemoryFileV2>> {
    let path = peer_path(directory, peer);
    let contents = match std::fs::read(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let mut memory: MemoryFileV2 = serde_json::from_slice(&contents)
        .with_context(|| format!("decoding {}", path.display()))?;
    memory.validate(peer)?;
    if memory.policy_id != policy_id {
        let same_algorithm = memory.policy_id.split('@').next() == policy_id.split('@').next();
        memory.policy_id = policy_id.to_owned();
        if !same_algorithm {
            for context in &mut memory.learner.contexts {
                context.arms = [ArmMemoryV2 {
                    observations: 0,
                    mean: 0.0,
                }; 7];
                context.active = Bbr3PresetV2::SharedConservative;
            }
        }
    }
    Ok(Some(memory))
}

pub fn save(directory: &Path, memory: &MemoryFileV2) -> Result<()> {
    memory.validate(&memory.peer)?;
    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let mut contents = serde_json::to_vec_pretty(memory)?;
    contents.push(b'\n');
    crate::deployment::atomic_write(&peer_path(directory, &memory.peer), &contents, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_round_trips_and_rejects_peer_or_policy_substitution() {
        let directory = std::env::temp_dir().join(format!(
            "ironet-autotune-memory-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let peer = "0123456789abcdef";
        let memory = MemoryFileV2::new(
            peer.to_owned(),
            BUILTIN_POLICY_ID_V2.to_owned(),
            LearnerMemoryV2::default(),
        );
        save(&directory, &memory).unwrap();
        assert_eq!(
            load(&directory, peer, BUILTIN_POLICY_ID_V2).unwrap(),
            Some(memory)
        );
        assert!(
            load(&directory, "other-peer", BUILTIN_POLICY_ID_V2)
                .unwrap()
                .is_none()
        );

        let path = peer_path(&directory, peer);
        let mut tampered: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        tampered["policy_id"] = "unknown@9".into();
        std::fs::write(&path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        let migrated = load(&directory, peer, BUILTIN_POLICY_ID_V2)
            .unwrap()
            .unwrap();
        assert_eq!(migrated.policy_id, BUILTIN_POLICY_ID_V2);
        std::fs::remove_dir_all(directory).unwrap();
    }
}
