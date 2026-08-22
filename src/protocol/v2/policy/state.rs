//! Per-peer policy state persistence (plan section 8.1).
//!
//! The policy backend returns an opaque `next_state` blob on every tick; the
//! host keeps it in memory and writes it to disk only at bounded moments
//! (fixed interval, module switch, peer disconnect, daemon exit). Files are
//! keyed by `(policy_id, state_schema, peer)` and never by module digest, so
//! a rebuild of the same policy keeps its learning history:
//!
//! ```text
//! <autotune_state_dir>/autotune-wasm/<policy_id>/<state_schema>/<peer>.state
//! ```
//!
//! File layout (all integers little endian):
//!
//! ```text
//! magic            8 bytes  "IRNPSTV1"
//! version          u32      1
//! policy_id        u16 len + UTF-8
//! state_schema     u32
//! module_digest    u16 len + UTF-8   (audit only; "native" or a hex digest)
//! payload_len      u32
//! blake3           32 bytes  BLAKE3(all preceding header bytes || payload)
//! payload          payload_len bytes
//! ```
//!
//! A file whose header, length or digest does not verify is quarantined by
//! renaming it to `<name>.corrupt` and treated as absent, so the backend
//! restarts from an empty state (plan section 8.2).

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};

/// Directory below the autotune state directory that holds policy state.
pub const POLICY_STATE_DIRECTORY: &str = "autotune-wasm";
/// File extension of a state file.
pub const POLICY_STATE_EXTENSION: &str = "state";
/// Suffix appended to a quarantined (unreadable) state file.
pub const POLICY_STATE_CORRUPT_SUFFIX: &str = ".corrupt";
/// Header magic.
pub const POLICY_STATE_MAGIC: &[u8; 8] = b"IRNPSTV1";
/// Header version.
pub const POLICY_STATE_FILE_VERSION: u32 = 1;
/// Module digest recorded for the host-native backend.
pub const NATIVE_MODULE_DIGEST: &str = "native";

const HEADER_FIXED_BYTES: usize = 8 + 4 + 2 + 4 + 2 + 4 + 32;

/// Why a state file was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateFileError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u32),
    PolicyIdMismatch,
    StateSchemaMismatch { expected: u32, found: u32 },
    LengthMismatch { declared: u32, found: usize },
    DigestMismatch,
    PayloadTooLarge { bytes: usize, cap: usize },
    Malformed,
}

impl fmt::Display for StateFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("state file is truncated"),
            Self::BadMagic => f.write_str("state file magic mismatch"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported state file version {version}")
            }
            Self::PolicyIdMismatch => f.write_str("state file policy id mismatch"),
            Self::StateSchemaMismatch { expected, found } => {
                write!(
                    f,
                    "state schema mismatch: expected {expected}, found {found}"
                )
            }
            Self::LengthMismatch { declared, found } => {
                write!(
                    f,
                    "payload length mismatch: declared {declared}, found {found}"
                )
            }
            Self::DigestMismatch => f.write_str("state file digest mismatch"),
            Self::PayloadTooLarge { bytes, cap } => {
                write!(f, "state payload {bytes} bytes exceeds cap {cap}")
            }
            Self::Malformed => f.write_str("state file is malformed"),
        }
    }
}

impl std::error::Error for StateFileError {}

/// Decoded state file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStateFileV1 {
    pub policy_id: String,
    pub state_schema: u32,
    pub module_digest: String,
    pub payload: Vec<u8>,
}

/// Encode a state file (header + payload).
pub fn encode_state_file(
    policy_id: &str,
    state_schema: u32,
    module_digest: &str,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let policy_id_len = u16::try_from(policy_id.len()).context("policy id too long")?;
    let digest_len = u16::try_from(module_digest.len()).context("module digest too long")?;
    let payload_len = u32::try_from(payload.len()).context("state payload too long")?;
    let mut out = Vec::with_capacity(
        HEADER_FIXED_BYTES + policy_id.len() + module_digest.len() + payload.len(),
    );
    out.extend_from_slice(POLICY_STATE_MAGIC);
    out.extend_from_slice(&POLICY_STATE_FILE_VERSION.to_le_bytes());
    out.extend_from_slice(&policy_id_len.to_le_bytes());
    out.extend_from_slice(policy_id.as_bytes());
    out.extend_from_slice(&state_schema.to_le_bytes());
    out.extend_from_slice(&digest_len.to_le_bytes());
    out.extend_from_slice(module_digest.as_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(&out);
    hasher.update(payload);
    out.extend_from_slice(hasher.finalize().as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decode and verify a state file for the expected key; `payload_cap` bounds
/// the accepted payload size.
pub fn decode_state_file(
    bytes: &[u8],
    expected_policy_id: &str,
    expected_state_schema: u32,
    payload_cap: usize,
) -> Result<PolicyStateFileV1, StateFileError> {
    let mut cursor = Cursor { bytes, offset: 0 };
    let magic = cursor.take(8)?;
    if magic != POLICY_STATE_MAGIC {
        return Err(StateFileError::BadMagic);
    }
    let version = cursor.u32()?;
    if version != POLICY_STATE_FILE_VERSION {
        return Err(StateFileError::UnsupportedVersion(version));
    }
    let policy_id_len = usize::from(cursor.u16()?);
    let policy_id = std::str::from_utf8(cursor.take(policy_id_len)?)
        .map_err(|_| StateFileError::Malformed)?
        .to_owned();
    let state_schema = cursor.u32()?;
    let digest_len = usize::from(cursor.u16()?);
    let module_digest = std::str::from_utf8(cursor.take(digest_len)?)
        .map_err(|_| StateFileError::Malformed)?
        .to_owned();
    let payload_len = cursor.u32()?;
    let header_end = cursor.offset;
    let digest: [u8; 32] = cursor
        .take(32)?
        .try_into()
        .map_err(|_| StateFileError::Malformed)?;
    let payload = &bytes[cursor.offset..];
    if payload.len() != payload_len as usize {
        return Err(StateFileError::LengthMismatch {
            declared: payload_len,
            found: payload.len(),
        });
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(&bytes[..header_end]);
    hasher.update(payload);
    if hasher.finalize().as_bytes() != &digest {
        return Err(StateFileError::DigestMismatch);
    }
    if policy_id != expected_policy_id {
        return Err(StateFileError::PolicyIdMismatch);
    }
    if state_schema != expected_state_schema {
        return Err(StateFileError::StateSchemaMismatch {
            expected: expected_state_schema,
            found: state_schema,
        });
    }
    if payload.len() > payload_cap {
        return Err(StateFileError::PayloadTooLarge {
            bytes: payload.len(),
            cap: payload_cap,
        });
    }
    Ok(PolicyStateFileV1 {
        policy_id,
        state_schema,
        module_digest,
        payload: payload.to_vec(),
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], StateFileError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(StateFileError::Truncated)?;
        if end > self.bytes.len() {
            return Err(StateFileError::Truncated);
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn u16(&mut self) -> Result<u16, StateFileError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| StateFileError::Malformed)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, StateFileError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| StateFileError::Malformed)?;
        Ok(u32::from_le_bytes(bytes))
    }
}

/// Map an identifier onto a single safe path component. Policy ids come from
/// external artifacts, so anything outside `[A-Za-z0-9._@+-]` is replaced
/// and the result can never be empty, `.` or `..`.
pub fn path_component(value: &str) -> String {
    let mut out: String = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '@' | '+' | '-')
            {
                character
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() || out == "." || out == ".." {
        out = format!("_{}", blake3::hash(value.as_bytes()).to_hex());
    }
    out
}

/// On-disk store for policy state keyed by `(policy_id, state_schema,
/// peer)`.
#[derive(Debug, Clone)]
pub struct PolicyStateStoreV1 {
    root: PathBuf,
    flush_interval: Duration,
    payload_cap: usize,
}

impl PolicyStateStoreV1 {
    /// `autotune_state_dir` is the existing per-identity autotune directory;
    /// state lives in its `autotune-wasm` child.
    pub fn new(autotune_state_dir: &Path, flush_interval: Duration, payload_cap: usize) -> Self {
        Self {
            root: autotune_state_dir.join(POLICY_STATE_DIRECTORY),
            flush_interval: flush_interval.max(Duration::from_secs(1)),
            payload_cap,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Minimum interval between periodic flushes of one peer's state.
    pub fn flush_interval(&self) -> Duration {
        self.flush_interval
    }

    /// Largest payload accepted on load.
    pub fn payload_cap(&self) -> usize {
        self.payload_cap
    }

    pub fn path(&self, policy_id: &str, state_schema: u32, peer: &str) -> PathBuf {
        self.root
            .join(path_component(policy_id))
            .join(state_schema.to_string())
            .join(format!("{}.{POLICY_STATE_EXTENSION}", path_component(peer)))
    }

    /// Load the state for the key. A missing file yields `None`; an
    /// unreadable or unverifiable file is renamed to `.corrupt` (best
    /// effort), logged, and also yields `None`.
    pub fn load(&self, policy_id: &str, state_schema: u32, peer: &str) -> Option<Vec<u8>> {
        let path = self.path(policy_id, state_schema, peer);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "unreadable V2 policy state file");
                return None;
            }
        };
        match decode_state_file(&bytes, policy_id, state_schema, self.payload_cap) {
            Ok(file) => Some(file.payload),
            Err(error) => {
                let quarantined = quarantine_path(&path);
                let renamed = std::fs::rename(&path, &quarantined);
                tracing::warn!(
                    path = %path.display(),
                    quarantined = %quarantined.display(),
                    renamed = renamed.is_ok(),
                    %error,
                    "quarantined invalid V2 policy state file; restarting from an empty state"
                );
                None
            }
        }
    }

    /// Atomically write the state for the key (`0600`).
    pub fn save(
        &self,
        policy_id: &str,
        state_schema: u32,
        peer: &str,
        module_digest: &str,
        payload: &[u8],
    ) -> Result<()> {
        ensure!(
            payload.len() <= self.payload_cap,
            "policy state payload {} bytes exceeds cap {}",
            payload.len(),
            self.payload_cap
        );
        let path = self.path(policy_id, state_schema, peer);
        let contents = encode_state_file(policy_id, state_schema, module_digest, payload)?;
        crate::deployment::atomic_write(&path, &contents, 0o600)
            .with_context(|| format!("writing policy state {}", path.display()))
    }
}

fn quarantine_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(POLICY_STATE_CORRUPT_SUFFIX);
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ironet-policy-state-{name}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn state_file_round_trips_and_is_keyed_by_policy_and_schema() {
        let encoded = encode_state_file("bandit-vivace@1", 1, "native", b"payload").unwrap();
        let decoded = decode_state_file(&encoded, "bandit-vivace@1", 1, 1024).unwrap();
        assert_eq!(decoded.policy_id, "bandit-vivace@1");
        assert_eq!(decoded.state_schema, 1);
        assert_eq!(decoded.module_digest, "native");
        assert_eq!(decoded.payload, b"payload");
        assert_eq!(
            decode_state_file(&encoded, "other@1", 1, 1024),
            Err(StateFileError::PolicyIdMismatch)
        );
        assert_eq!(
            decode_state_file(&encoded, "bandit-vivace@1", 2, 1024),
            Err(StateFileError::StateSchemaMismatch {
                expected: 2,
                found: 1
            })
        );
        assert_eq!(
            decode_state_file(&encoded, "bandit-vivace@1", 1, 3),
            Err(StateFileError::PayloadTooLarge { bytes: 7, cap: 3 })
        );
        // Empty payload is a valid (cold) state.
        let empty = encode_state_file("p@1", 1, "abc", b"").unwrap();
        assert!(
            decode_state_file(&empty, "p@1", 1, 0)
                .unwrap()
                .payload
                .is_empty()
        );
    }

    #[test]
    fn every_header_corruption_is_detected() {
        let encoded = encode_state_file("bandit-vivace@1", 1, "digest", b"payload").unwrap();
        for index in 0..encoded.len() {
            let mut tampered = encoded.clone();
            tampered[index] ^= 0x01;
            assert!(
                decode_state_file(&tampered, "bandit-vivace@1", 1, 1024).is_err(),
                "flip at byte {index} went unnoticed"
            );
        }
        for cut in 0..encoded.len() {
            assert!(
                decode_state_file(&encoded[..cut], "bandit-vivace@1", 1, 1024).is_err(),
                "truncation at {cut} went unnoticed"
            );
        }
        let mut appended = encoded.clone();
        appended.push(0);
        assert_eq!(
            decode_state_file(&appended, "bandit-vivace@1", 1, 1024),
            Err(StateFileError::LengthMismatch {
                declared: 7,
                found: 8
            })
        );
        assert_eq!(
            decode_state_file(b"XXXXXXXX", "bandit-vivace@1", 1, 1024),
            Err(StateFileError::BadMagic)
        );
    }

    #[test]
    fn store_saves_loads_and_quarantines_corrupt_files() {
        let directory = scratch("store");
        let store = PolicyStateStoreV1::new(&directory, Duration::from_secs(60), 1024);
        assert_eq!(
            store.path("bandit-vivace@1", 1, "peer"),
            directory
                .join("autotune-wasm")
                .join("bandit-vivace@1")
                .join("1")
                .join("peer.state")
        );
        assert_eq!(store.load("bandit-vivace@1", 1, "peer"), None);
        store
            .save("bandit-vivace@1", 1, "peer", "native", b"state-bytes")
            .unwrap();
        assert_eq!(
            store.load("bandit-vivace@1", 1, "peer").as_deref(),
            Some(&b"state-bytes"[..])
        );
        // Same policy id, different schema: independent key.
        assert_eq!(store.load("bandit-vivace@1", 2, "peer"), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(store.path("bandit-vivace@1", 1, "peer"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        // Overwrite keeps the newest payload.
        store
            .save("bandit-vivace@1", 1, "peer", "native", b"newer")
            .unwrap();
        assert_eq!(
            store.load("bandit-vivace@1", 1, "peer").as_deref(),
            Some(&b"newer"[..])
        );
        // Corrupt the file: load quarantines it and reports absence.
        let path = store.path("bandit-vivace@1", 1, "peer");
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(store.load("bandit-vivace@1", 1, "peer"), None);
        assert!(!path.exists());
        assert!(quarantine_path(&path).exists());
        // Oversized payloads are refused on save.
        assert!(
            store
                .save("bandit-vivace@1", 1, "peer", "native", &[0; 2048])
                .is_err()
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn path_components_are_sanitized() {
        assert_eq!(path_component("bandit-vivace@1"), "bandit-vivace@1");
        assert_eq!(path_component("../evil/id"), ".._evil_id");
        assert!(path_component("").starts_with('_'));
        assert!(path_component("..").starts_with('_'));
        assert_eq!(path_component("a b"), "a_b");
    }
}
