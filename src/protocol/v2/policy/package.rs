//! Single-file WASM policy package format.
//!
//! A policy is a plain WebAssembly component whose top-level custom sections
//! carry an `ironet.manifest.v1` description and, optionally, an
//! `ironet.signature.v1` detached signature. This module parses the outer
//! component container byte-for-byte (no WASM runtime involved), recomputes
//! the BLAKE3 digest over the exact prefix, and verifies the signature
//! against the sealed trust store.
//!
//! Rules (see the design document, section 4.2):
//!
//! - only top-level sections count; nested core modules or sub-components
//!   are opaque payloads and are never descended into;
//! - exactly one manifest section;
//! - at most one signature section, and it must be the last section;
//! - `digest = BLAKE3(file[0 .. signature_section_offset])`, or
//!   `BLAKE3(whole file)` when unsigned (digest-pin mode).

use std::fmt;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::signature::{
    PolicyPublicKey, PolicySigningKey, TrustStoreV1, encode_digest, encode_signature, parse_digest,
    parse_signature,
};
use crate::config::AutotuneWasmConfig;

/// Custom section carrying the JSON-encoded [`PolicyManifestV1`].
pub const MANIFEST_SECTION_NAME: &str = "ironet.manifest.v1";
/// Custom section carrying the JSON-encoded [`PolicySignatureV1`].
pub const SIGNATURE_SECTION_NAME: &str = "ironet.signature.v1";
/// WIT world every V1 policy must target.
pub const POLICY_ABI_WORLD_V1: &str = "ironet:policy/policy@1.0.0";
/// `format_version` of [`PolicyManifestV1`].
pub const MANIFEST_FORMAT_VERSION_V1: u16 = 1;
/// `signature_format` of [`PolicySignatureV1`].
pub const SIGNATURE_FORMAT_V1: u16 = 1;
/// Total payload bytes of all top-level custom sections.
pub const MAXIMUM_CUSTOM_SECTION_BYTES: usize = 256 * 1024;
/// Upper bound for every manifest/signature string field, in bytes.
pub const MAXIMUM_MANIFEST_STRING_BYTES: usize = 128;
/// Upper bound for every manifest list field.
pub const MAXIMUM_MANIFEST_LIST_ITEMS: usize = 64;
/// Upper bound for `maximum_state_bytes` (matches `autotune.wasm`).
pub const MAXIMUM_MANIFEST_STATE_BYTES: u32 = 1024 * 1024;
/// Smallest meaningful guest memory request (one WASM page).
pub const MINIMUM_REQUESTED_MEMORY_BYTES: u32 = 64 * 1024;

/// `\0asm` followed by the component-model version/layer (`0x0d 0x00 0x01 0x00`).
pub const COMPONENT_HEADER: [u8; 8] = [0x00, b'a', b's', b'm', 0x0d, 0x00, 0x01, 0x00];
const CUSTOM_SECTION_ID: u8 = 0;
const DIGEST_LEN: usize = 32;

/// Parse limits; normally derived from `[autotune.wasm]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageLimits {
    pub maximum_module_bytes: u64,
    pub maximum_custom_section_bytes: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self::from_config(&AutotuneWasmConfig::default())
    }
}

impl PackageLimits {
    pub fn from_config(config: &AutotuneWasmConfig) -> Self {
        Self {
            maximum_module_bytes: config.maximum_module_bytes,
            maximum_custom_section_bytes: MAXIMUM_CUSTOM_SECTION_BYTES,
        }
    }
}

/// Every error the package layer produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyPackageError {
    /// Structural or encoding problem in the file.
    Malformed(String),
    /// Trust store requires a signature and the file carries none.
    MissingSignature,
    /// `signer_id` is not in the trust store.
    UnknownSigner { signer_id: String },
    /// Signature does not verify under the signer's public key.
    BadSignature { signer_id: String },
    /// Signature section digest differs from the recomputed prefix digest.
    DigestMismatch { expected: String, actual: String },
    /// `policy_version` is below the signer's rollback floor.
    VersionRollback {
        signer_id: String,
        policy_version: u64,
        minimum_policy_version: u64,
    },
    /// Signer entry has passed its `expires_at`.
    SignerExpired {
        signer_id: String,
        expires_at: DateTime<Utc>,
    },
    /// Unsigned package in digest-pin mode whose digest is not pinned.
    DigestNotPinned { digest: String },
}

impl fmt::Display for PolicyPackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(f, "malformed policy package: {reason}"),
            Self::MissingSignature => {
                f.write_str("policy package is unsigned but autotune.wasm.require_signature = true")
            }
            Self::UnknownSigner { signer_id } => {
                write!(f, "policy signer {signer_id:?} is not in the trust store")
            }
            Self::BadSignature { signer_id } => {
                write!(f, "policy signature by {signer_id:?} does not verify")
            }
            Self::DigestMismatch { expected, actual } => write!(
                f,
                "policy signature digest {expected} does not match file digest {actual}"
            ),
            Self::VersionRollback {
                signer_id,
                policy_version,
                minimum_policy_version,
            } => write!(
                f,
                "policy_version {policy_version} is below signer {signer_id:?} minimum_policy_version {minimum_policy_version}"
            ),
            Self::SignerExpired {
                signer_id,
                expires_at,
            } => write!(
                f,
                "policy signer {signer_id:?} expired at {}",
                expires_at.to_rfc3339()
            ),
            Self::DigestNotPinned { digest } => write!(
                f,
                "unsigned policy digest {digest} is not in autotune.wasm.digest_pins"
            ),
        }
    }
}

impl std::error::Error for PolicyPackageError {}

fn malformed(reason: impl Into<String>) -> PolicyPackageError {
    PolicyPackageError::Malformed(reason.into())
}

/// One top-level section of the component.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionEntry {
    pub id: u8,
    /// Custom section name (`id == 0`), `None` otherwise.
    pub name: Option<String>,
    /// Byte offset of the section id within the file.
    pub offset: usize,
    /// Total section length including id, size and (for custom) the name.
    pub len: usize,
    /// Byte offset of the content (custom: after the name).
    pub payload_offset: usize,
    pub payload_len: usize,
}

impl SectionEntry {
    pub fn kind(&self) -> &'static str {
        section_kind(self.id)
    }

    fn end(&self) -> usize {
        self.offset + self.len
    }
}

/// Component-model top-level section ids (for display only).
pub fn section_kind(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "core-module",
        2 => "core-instance",
        3 => "core-type",
        4 => "component",
        5 => "instance",
        6 => "alias",
        7 => "type",
        8 => "canon",
        9 => "start",
        10 => "import",
        11 => "export",
        12 => "value",
        _ => "unknown",
    }
}

/// Structural view of a component: header plus flat section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentLayout {
    pub sections: Vec<SectionEntry>,
    pub file_len: usize,
}

impl ComponentLayout {
    /// Walks the top-level section table without interpreting payloads.
    pub fn parse(bytes: &[u8], limits: PackageLimits) -> Result<Self, PolicyPackageError> {
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limits.maximum_module_bytes {
            return Err(malformed(format!(
                "file is {} bytes, above maximum_module_bytes {}",
                bytes.len(),
                limits.maximum_module_bytes
            )));
        }
        if bytes.len() < COMPONENT_HEADER.len() {
            return Err(malformed("file shorter than the component header"));
        }
        if bytes[..4] != COMPONENT_HEADER[..4] {
            return Err(malformed("missing \\0asm magic"));
        }
        if bytes[4..8] != COMPONENT_HEADER[4..8] {
            return Err(malformed(format!(
                "not a component (version/layer {:02x?}, expected {:02x?})",
                &bytes[4..8],
                &COMPONENT_HEADER[4..8]
            )));
        }

        let mut sections = Vec::new();
        let mut position = COMPONENT_HEADER.len();
        let mut custom_total = 0usize;
        while position < bytes.len() {
            let offset = position;
            let id = bytes[position];
            position += 1;
            let size = read_leb128_u32(bytes, &mut position)
                .map_err(|reason| malformed(format!("section at {offset}: {reason}")))?;
            let size = usize::try_from(size).map_err(|_| malformed("section size overflow"))?;
            let payload_start = position;
            let payload_end = payload_start
                .checked_add(size)
                .ok_or_else(|| malformed("section size overflow"))?;
            if payload_end > bytes.len() {
                return Err(malformed(format!(
                    "section at {offset} claims {size} bytes but only {} remain",
                    bytes.len() - payload_start
                )));
            }
            let entry = if id == CUSTOM_SECTION_ID {
                let mut cursor = payload_start;
                let name_len = read_leb128_u32(&bytes[..payload_end], &mut cursor)
                    .map_err(|reason| malformed(format!("custom section at {offset}: {reason}")))?;
                let name_len = usize::try_from(name_len)
                    .map_err(|_| malformed("custom section name length overflow"))?;
                let name_end = cursor
                    .checked_add(name_len)
                    .filter(|end| *end <= payload_end)
                    .ok_or_else(|| {
                        malformed(format!(
                            "custom section at {offset}: name length {name_len} exceeds section"
                        ))
                    })?;
                let name = std::str::from_utf8(&bytes[cursor..name_end])
                    .map_err(|_| {
                        malformed(format!("custom section at {offset}: name is not UTF-8"))
                    })?
                    .to_owned();
                custom_total = custom_total.saturating_add(size);
                if custom_total > limits.maximum_custom_section_bytes {
                    return Err(malformed(format!(
                        "custom sections total more than {} bytes",
                        limits.maximum_custom_section_bytes
                    )));
                }
                SectionEntry {
                    id,
                    name: Some(name),
                    offset,
                    len: payload_end - offset,
                    payload_offset: name_end,
                    payload_len: payload_end - name_end,
                }
            } else {
                SectionEntry {
                    id,
                    name: None,
                    offset,
                    len: payload_end - offset,
                    payload_offset: payload_start,
                    payload_len: size,
                }
            };
            sections.push(entry);
            position = payload_end;
        }
        Ok(Self {
            sections,
            file_len: bytes.len(),
        })
    }

    fn custom_sections<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a SectionEntry> {
        self.sections
            .iter()
            .filter(move |section| section.name.as_deref() == Some(name))
    }
}

fn read_leb128_u32(bytes: &[u8], position: &mut usize) -> Result<u32, String> {
    let mut result = 0u32;
    for index in 0..5u32 {
        let Some(&byte) = bytes.get(*position) else {
            return Err("truncated LEB128".to_owned());
        };
        *position += 1;
        if index == 4 && byte & 0xf0 != 0 {
            return Err("LEB128 u32 longer than 5 bytes or above u32::MAX".to_owned());
        }
        result |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err("LEB128 u32 longer than 5 bytes".to_owned())
}

fn write_leb128_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Encodes one custom section (`id 0`, size, name, content).
pub fn encode_custom_section(name: &str, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(name.len() + content.len() + 5);
    write_leb128_u32(
        &mut body,
        u32::try_from(name.len()).expect("section name fits u32"),
    );
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(content);
    let mut section = Vec::with_capacity(body.len() + 6);
    section.push(CUSTOM_SECTION_ID);
    write_leb128_u32(
        &mut section,
        u32::try_from(body.len()).expect("custom section fits u32"),
    );
    section.extend_from_slice(&body);
    section
}

/// `ironet.manifest.v1`: what the policy is and what it asks for.
///
/// The manifest is a capability request, not a grant; the host intersects it
/// with its own and the node's configured capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyManifestV1 {
    pub format_version: u16,
    pub policy_id: String,
    pub policy_version: u64,
    pub abi_world: String,
    #[serde(default)]
    pub extensions_supported: Vec<u16>,
    pub state_schema: u32,
    #[serde(default)]
    pub state_schema_accepts: Vec<u32>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub minimum_host_version: String,
    pub maximum_state_bytes: u32,
    pub requested_memory_bytes: u32,
    pub requested_fuel: u64,
    #[serde(default)]
    pub built_at: String,
    #[serde(default)]
    pub source_revision: String,
}

fn check_string(field: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() <= MAXIMUM_MANIFEST_STRING_BYTES,
        "{field} is {} bytes, above {MAXIMUM_MANIFEST_STRING_BYTES}",
        value.len()
    );
    ensure!(
        !value.chars().any(char::is_control),
        "{field} contains control characters"
    );
    Ok(())
}

fn check_list<T>(field: &str, value: &[T]) -> Result<()> {
    ensure!(
        value.len() <= MAXIMUM_MANIFEST_LIST_ITEMS,
        "{field} has {} items, above {MAXIMUM_MANIFEST_LIST_ITEMS}",
        value.len()
    );
    Ok(())
}

fn check_unique<T: Ord + fmt::Debug + Clone>(field: &str, value: &[T]) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for item in value {
        ensure!(seen.insert(item.clone()), "{field} repeats {item:?}");
    }
    Ok(())
}

impl PolicyManifestV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format_version == MANIFEST_FORMAT_VERSION_V1,
            "manifest format_version {} is not {MANIFEST_FORMAT_VERSION_V1}",
            self.format_version
        );
        check_string("policy_id", &self.policy_id)?;
        ensure!(
            !self.policy_id.trim().is_empty(),
            "policy_id cannot be empty"
        );
        check_string("abi_world", &self.abi_world)?;
        ensure!(
            self.abi_world == POLICY_ABI_WORLD_V1,
            "abi_world {:?} is not {POLICY_ABI_WORLD_V1:?}",
            self.abi_world
        );
        check_list("extensions_supported", &self.extensions_supported)?;
        check_unique("extensions_supported", &self.extensions_supported)?;
        check_list("state_schema_accepts", &self.state_schema_accepts)?;
        check_unique("state_schema_accepts", &self.state_schema_accepts)?;
        check_list("capabilities", &self.capabilities)?;
        check_unique("capabilities", &self.capabilities)?;
        for capability in &self.capabilities {
            check_string("capabilities", capability)?;
            ensure!(
                !capability.is_empty()
                    && capability.bytes().all(|byte| byte.is_ascii_alphanumeric()
                        || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')),
                "capability {capability:?} must be a non-empty [A-Za-z0-9-_.:/] identifier"
            );
        }
        check_string("minimum_host_version", &self.minimum_host_version)?;
        ensure!(
            !self.minimum_host_version.trim().is_empty(),
            "minimum_host_version cannot be empty"
        );
        ensure!(
            (1..=MAXIMUM_MANIFEST_STATE_BYTES).contains(&self.maximum_state_bytes),
            "maximum_state_bytes {} must be between 1 and {MAXIMUM_MANIFEST_STATE_BYTES}",
            self.maximum_state_bytes
        );
        ensure!(
            self.requested_memory_bytes >= MINIMUM_REQUESTED_MEMORY_BYTES,
            "requested_memory_bytes {} must be at least {MINIMUM_REQUESTED_MEMORY_BYTES}",
            self.requested_memory_bytes
        );
        ensure!(self.requested_fuel > 0, "requested_fuel must be non-zero");
        check_string("built_at", &self.built_at)?;
        check_string("source_revision", &self.source_revision)?;
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes).context("manifest JSON")?;
        manifest.validate()?;
        Ok(manifest)
    }
}

/// `ironet.signature.v1`: detached signature over the file prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignatureV1 {
    pub signature_format: u16,
    pub signer_id: String,
    /// `blake3:<64 hex>` of the file prefix before this section.
    pub digest: String,
    /// `ed25519:<128 hex>` over `"ironet-policy-v1\0" || digest`.
    pub signature: String,
}

impl PolicySignatureV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.signature_format == SIGNATURE_FORMAT_V1,
            "signature_format {} is not {SIGNATURE_FORMAT_V1}",
            self.signature_format
        );
        check_string("signer_id", &self.signer_id)?;
        ensure!(
            !self.signer_id.trim().is_empty(),
            "signer_id cannot be empty"
        );
        parse_digest(&self.digest)?;
        parse_signature(&self.signature)?;
        Ok(())
    }

    pub fn digest_bytes(&self) -> Result<[u8; DIGEST_LEN]> {
        parse_digest(&self.digest)
    }

    pub fn signature_bytes(&self) -> Result<[u8; 64]> {
        parse_signature(&self.signature)
    }
}

/// Parsed, structurally valid (but not yet trusted) policy package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyPackage {
    pub manifest: PolicyManifestV1,
    pub signature: Option<PolicySignatureV1>,
    /// BLAKE3 of `file[..body_len]`.
    pub digest: [u8; DIGEST_LEN],
    pub sections: Vec<SectionEntry>,
    /// Length of the signed prefix: the signature section offset, or the
    /// whole file when unsigned.
    pub body_len: usize,
    pub file_len: usize,
}

impl PolicyPackage {
    /// Parses and structurally validates a component file.
    pub fn parse(bytes: &[u8], limits: PackageLimits) -> Result<Self, PolicyPackageError> {
        let layout = ComponentLayout::parse(bytes, limits)?;

        let manifests: Vec<&SectionEntry> = layout.custom_sections(MANIFEST_SECTION_NAME).collect();
        let manifest_section = match manifests.as_slice() {
            [] => {
                return Err(malformed(format!(
                    "missing {MANIFEST_SECTION_NAME} section"
                )));
            }
            [single] => *single,
            _ => {
                return Err(malformed(format!(
                    "{} {MANIFEST_SECTION_NAME} sections, expected exactly one",
                    manifests.len()
                )));
            }
        };
        let manifest = PolicyManifestV1::from_json(section_payload(bytes, manifest_section))
            .map_err(|error| malformed(format!("{MANIFEST_SECTION_NAME}: {error:#}")))?;

        let signatures: Vec<&SectionEntry> =
            layout.custom_sections(SIGNATURE_SECTION_NAME).collect();
        let signature_section = match signatures.as_slice() {
            [] => None,
            [single] => Some(*single),
            _ => {
                return Err(malformed(format!(
                    "{} {SIGNATURE_SECTION_NAME} sections, expected at most one",
                    signatures.len()
                )));
            }
        };
        if let Some(section) = signature_section {
            let last = layout.sections.last().expect("non-empty section table");
            if section.offset != last.offset || section.end() != bytes.len() {
                return Err(malformed(format!(
                    "{SIGNATURE_SECTION_NAME} must be the last top-level section"
                )));
            }
        }
        let signature = signature_section
            .map(|section| -> Result<PolicySignatureV1> {
                let signature: PolicySignatureV1 =
                    serde_json::from_slice(section_payload(bytes, section))
                        .context("signature JSON")?;
                signature.validate()?;
                Ok(signature)
            })
            .transpose()
            .map_err(|error| malformed(format!("{SIGNATURE_SECTION_NAME}: {error:#}")))?;

        let body_len = signature_section.map_or(bytes.len(), |section| section.offset);
        let digest = blake3::hash(&bytes[..body_len]).into();
        Ok(Self {
            manifest,
            signature,
            digest,
            sections: layout.sections,
            body_len,
            file_len: layout.file_len,
        })
    }

    /// `blake3:<hex>` of the signed prefix.
    pub fn digest_string(&self) -> String {
        encode_digest(&self.digest)
    }

    /// Verifies the package against the sealed trust store.
    ///
    /// `now` is supplied by the caller so that this layer never reads the
    /// wall clock.
    pub fn verify(
        &self,
        trust: &TrustStoreV1,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPolicy, PolicyPackageError> {
        verify(self, trust, now)
    }
}

fn section_payload<'a>(bytes: &'a [u8], section: &SectionEntry) -> &'a [u8] {
    &bytes[section.payload_offset..section.payload_offset + section.payload_len]
}

/// How a package came to be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustBasis {
    /// Valid signature from a trust store signer.
    Signer,
    /// Unsigned, digest listed in `digest_pins`.
    DigestPin,
}

/// Result of a successful [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPolicy {
    pub manifest: PolicyManifestV1,
    pub digest: [u8; DIGEST_LEN],
    pub signer_id: Option<String>,
    pub trust: TrustBasis,
}

impl VerifiedPolicy {
    pub fn digest_string(&self) -> String {
        encode_digest(&self.digest)
    }
}

/// Verification rules:
///
/// - `require_signature`: a signature section must exist, its `signer_id`
///   must be in the trust store, the signature must verify, the signer must
///   not be expired and `policy_version` must reach the signer's floor;
/// - otherwise an unsigned package is accepted only when its digest is
///   pinned; a signed package is still fully verified as above.
pub fn verify(
    package: &PolicyPackage,
    trust: &TrustStoreV1,
    now: DateTime<Utc>,
) -> Result<VerifiedPolicy, PolicyPackageError> {
    let Some(signature) = &package.signature else {
        if trust.require_signature {
            return Err(PolicyPackageError::MissingSignature);
        }
        if !trust.is_pinned(&package.digest) {
            return Err(PolicyPackageError::DigestNotPinned {
                digest: package.digest_string(),
            });
        }
        return Ok(VerifiedPolicy {
            manifest: package.manifest.clone(),
            digest: package.digest,
            signer_id: None,
            trust: TrustBasis::DigestPin,
        });
    };

    let claimed_digest = signature
        .digest_bytes()
        .map_err(|error| malformed(format!("signature digest: {error:#}")))?;
    if claimed_digest != package.digest {
        return Err(PolicyPackageError::DigestMismatch {
            expected: signature.digest.clone(),
            actual: package.digest_string(),
        });
    }
    let signer_id = signature.signer_id.trim().to_owned();
    let Some(signer) = trust.signer(&signer_id) else {
        return Err(PolicyPackageError::UnknownSigner { signer_id });
    };
    let signature_bytes = signature
        .signature_bytes()
        .map_err(|error| malformed(format!("signature: {error:#}")))?;
    if !signer
        .public_key
        .verify_digest(&package.digest, &signature_bytes)
    {
        return Err(PolicyPackageError::BadSignature { signer_id });
    }
    if let Some(expires_at) = signer.expires_at
        && now >= expires_at
    {
        return Err(PolicyPackageError::SignerExpired {
            signer_id,
            expires_at,
        });
    }
    if package.manifest.policy_version < signer.minimum_policy_version {
        return Err(PolicyPackageError::VersionRollback {
            signer_id,
            policy_version: package.manifest.policy_version,
            minimum_policy_version: signer.minimum_policy_version,
        });
    }
    Ok(VerifiedPolicy {
        manifest: package.manifest.clone(),
        digest: package.digest,
        signer_id: Some(signer_id),
        trust: TrustBasis::Signer,
    })
}

/// Rebuilds the component keeping every section except the named custom
/// sections, then appends `tail`.
fn rebuild_without(
    bytes: &[u8],
    layout: &ComponentLayout,
    dropped: &[&str],
    tail: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() + tail.iter().map(Vec::len).sum::<usize>());
    out.extend_from_slice(&COMPONENT_HEADER);
    for section in &layout.sections {
        let drop = section
            .name
            .as_deref()
            .is_some_and(|name| dropped.contains(&name));
        if !drop {
            out.extend_from_slice(&bytes[section.offset..section.end()]);
        }
    }
    for section in tail {
        out.extend_from_slice(section);
    }
    out
}

/// Attaches (or replaces) the manifest section. Any existing signature is
/// removed because it would no longer cover the file.
pub fn attach_manifest(
    component: &[u8],
    manifest: &PolicyManifestV1,
    limits: PackageLimits,
) -> Result<Vec<u8>> {
    let layout = ComponentLayout::parse(component, limits)?;
    let manifest_section = encode_custom_section(MANIFEST_SECTION_NAME, &manifest.to_json()?);
    let out = rebuild_without(
        component,
        &layout,
        &[MANIFEST_SECTION_NAME, SIGNATURE_SECTION_NAME],
        &[manifest_section],
    );
    PolicyPackage::parse(&out, limits).context("attached manifest does not parse back")?;
    Ok(out)
}

/// Signs a package: strips any existing signature section, digests the
/// remaining bytes and appends a fresh `ironet.signature.v1` as the last
/// section. Re-signing therefore replaces the previous signature.
pub fn sign(
    unsigned: &[u8],
    signing_key: &PolicySigningKey,
    signer_id: &str,
    limits: PackageLimits,
) -> Result<Vec<u8>> {
    let signer_id = signer_id.trim();
    ensure!(!signer_id.is_empty(), "signer_id cannot be empty");
    ensure!(
        signer_id.len() <= MAXIMUM_MANIFEST_STRING_BYTES,
        "signer_id longer than {MAXIMUM_MANIFEST_STRING_BYTES} bytes"
    );
    let layout = ComponentLayout::parse(unsigned, limits)?;
    let body = rebuild_without(unsigned, &layout, &[SIGNATURE_SECTION_NAME], &[]);
    // The body must already be a complete, valid package apart from the
    // signature (exactly one manifest etc.).
    let unsigned_package = PolicyPackage::parse(&body, limits)?;
    debug_assert!(unsigned_package.signature.is_none());
    let digest = unsigned_package.digest;
    let signature = PolicySignatureV1 {
        signature_format: SIGNATURE_FORMAT_V1,
        signer_id: signer_id.to_owned(),
        digest: encode_digest(&digest),
        signature: encode_signature(&signing_key.sign_digest(&digest)),
    };
    let mut out = body;
    out.extend_from_slice(&encode_custom_section(
        SIGNATURE_SECTION_NAME,
        &serde_json::to_vec(&signature)?,
    ));
    let signed =
        PolicyPackage::parse(&out, limits).context("signed package does not parse back")?;
    ensure!(
        signed.digest == digest,
        "internal error: signed prefix digest changed"
    );
    Ok(out)
}

/// Convenience for callers that only know the public key text.
pub fn signer_public_key(text: &str) -> Result<PolicyPublicKey> {
    PolicyPublicKey::parse(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::AutotuneSignerConfig, protocol::v2::policy::signature::TrustedSigner};

    /// The committed builtin component must match its BLAKE3 sidecar and
    /// still parse as a valid V1 package. Rebuild with
    /// `nix develop -c scripts/build-policy-guest.sh` when the guest changes.
    #[test]
    fn committed_builtin_wasm_matches_its_digest_sidecar() {
        let bytes = include_bytes!("../../../../crates/ironet-policy-builtin/builtin.wasm");
        let sidecar = include_str!("../../../../crates/ironet-policy-builtin/builtin.wasm.blake3");
        let digest = blake3::hash(bytes);
        assert_eq!(
            sidecar.trim(),
            format!("blake3:{}", hex::encode(digest.as_bytes())),
            "crates/ironet-policy-builtin/builtin.wasm drifted from its digest sidecar; \
             rebuild with `nix develop -c scripts/build-policy-guest.sh`"
        );
        let package = PolicyPackage::parse(bytes, PackageLimits::default())
            .unwrap_or_else(|error| panic!("committed builtin.wasm must parse: {error}"));
        assert_eq!(package.manifest.format_version, MANIFEST_FORMAT_VERSION_V1);
        assert_eq!(package.manifest.abi_world, POLICY_ABI_WORLD_V1);
    }

    fn now() -> DateTime<Utc> {
        "2026-08-21T00:00:00Z".parse().unwrap()
    }

    fn manifest() -> PolicyManifestV1 {
        PolicyManifestV1 {
            format_version: 1,
            policy_id: "bandit-vivace".into(),
            policy_version: 3,
            abi_world: POLICY_ABI_WORLD_V1.into(),
            extensions_supported: vec![1, 2],
            state_schema: 1,
            state_schema_accepts: vec![1],
            capabilities: vec!["bbr.preset".into(), "fec.geometry".into()],
            minimum_host_version: "0.1.0".into(),
            maximum_state_bytes: 4096,
            requested_memory_bytes: 1 << 20,
            requested_fuel: 1_000_000,
            built_at: "2026-08-21T00:00:00Z".into(),
            source_revision: "deadbeef".into(),
        }
    }

    /// Minimal component: header + one empty custom section (`""`).
    fn bare_component() -> Vec<u8> {
        let mut bytes = COMPONENT_HEADER.to_vec();
        bytes.extend_from_slice(&encode_custom_section("", b""));
        bytes
    }

    fn with_manifest() -> Vec<u8> {
        attach_manifest(&bare_component(), &manifest(), PackageLimits::default()).unwrap()
    }

    fn key() -> PolicySigningKey {
        PolicySigningKey::from_bytes(&[42u8; 32])
    }

    fn store_for(key: &PolicySigningKey, signer_id: &str, minimum: u64) -> TrustStoreV1 {
        TrustStoreV1::with_signers([TrustedSigner {
            signer_id: signer_id.into(),
            public_key: key.public(),
            minimum_policy_version: minimum,
            expires_at: None,
        }])
        .unwrap()
    }

    fn signed() -> Vec<u8> {
        sign(&with_manifest(), &key(), "ops", PackageLimits::default()).unwrap()
    }

    fn parse(bytes: &[u8]) -> Result<PolicyPackage, PolicyPackageError> {
        PolicyPackage::parse(bytes, PackageLimits::default())
    }

    fn is_malformed(result: Result<PolicyPackage, PolicyPackageError>, needle: &str) -> bool {
        match result {
            Err(PolicyPackageError::Malformed(reason)) => {
                assert!(reason.contains(needle), "{reason:?} lacks {needle:?}");
                true
            }
            other => panic!("expected Malformed({needle}), got {other:?}"),
        }
    }

    #[test]
    fn leb128_round_trips_and_rejects_overlong() {
        for value in [0u32, 1, 127, 128, 300, 16_383, 16_384, u32::MAX] {
            let mut out = Vec::new();
            write_leb128_u32(&mut out, value);
            let mut position = 0;
            assert_eq!(read_leb128_u32(&out, &mut position).unwrap(), value);
            assert_eq!(position, out.len());
        }
        let mut position = 0;
        assert!(read_leb128_u32(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], &mut position).is_err());
        position = 0;
        assert!(read_leb128_u32(&[0x80, 0x80, 0x80, 0x80, 0x10], &mut position).is_err());
        position = 0;
        assert!(read_leb128_u32(&[0x80], &mut position).is_err());
    }

    #[test]
    fn parses_manifest_and_unsigned_digest() {
        let bytes = with_manifest();
        let package = parse(&bytes).unwrap();
        assert_eq!(package.manifest, manifest());
        assert!(package.signature.is_none());
        assert_eq!(package.body_len, bytes.len());
        assert_eq!(package.digest, <[u8; 32]>::from(blake3::hash(&bytes)));
        assert_eq!(package.sections.len(), 2);
        assert_eq!(
            package.sections[1].name.as_deref(),
            Some(MANIFEST_SECTION_NAME)
        );
        assert_eq!(package.sections[0].kind(), "custom");
    }

    #[test]
    fn attach_manifest_replaces_existing_and_strips_signature() {
        let signed = signed();
        let mut updated = manifest();
        updated.policy_version = 9;
        let out = attach_manifest(&signed, &updated, PackageLimits::default()).unwrap();
        let package = parse(&out).unwrap();
        assert_eq!(package.manifest.policy_version, 9);
        assert!(package.signature.is_none());
        assert_eq!(
            package
                .sections
                .iter()
                .filter(|section| section.name.as_deref() == Some(MANIFEST_SECTION_NAME))
                .count(),
            1
        );
    }

    #[test]
    fn manifest_missing_duplicate_oversized_and_out_of_range() {
        assert!(is_malformed(
            parse(&bare_component()),
            "missing ironet.manifest.v1"
        ));

        let mut duplicate = with_manifest();
        duplicate.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            &manifest().to_json().unwrap(),
        ));
        assert!(is_malformed(
            parse(&duplicate),
            "2 ironet.manifest.v1 sections"
        ));

        let mut oversized = manifest();
        oversized.policy_id = "x".repeat(129);
        assert!(oversized.validate().is_err());
        let mut bytes = bare_component();
        bytes.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            &serde_json::to_vec(&oversized).unwrap(),
        ));
        assert!(is_malformed(parse(&bytes), "policy_id is 129 bytes"));

        let mut too_many = manifest();
        too_many.capabilities = (0..65).map(|index| format!("cap{index}")).collect();
        assert!(too_many.validate().is_err());
        let mut wrong_world = manifest();
        wrong_world.abi_world = "ironet:policy/policy@2.0.0".into();
        assert!(wrong_world.validate().is_err());
        let mut wrong_format = manifest();
        wrong_format.format_version = 2;
        assert!(wrong_format.validate().is_err());
        let mut zero_state = manifest();
        zero_state.maximum_state_bytes = 0;
        assert!(zero_state.validate().is_err());
        let mut huge_state = manifest();
        huge_state.maximum_state_bytes = MAXIMUM_MANIFEST_STATE_BYTES + 1;
        assert!(huge_state.validate().is_err());
        let mut small_memory = manifest();
        small_memory.requested_memory_bytes = 1;
        assert!(small_memory.validate().is_err());
        let mut no_fuel = manifest();
        no_fuel.requested_fuel = 0;
        assert!(no_fuel.validate().is_err());
        let mut duplicate_capability = manifest();
        duplicate_capability.capabilities = vec!["a".into(), "a".into()];
        assert!(duplicate_capability.validate().is_err());
        let mut bad_capability = manifest();
        bad_capability.capabilities = vec!["bad cap".into()];
        assert!(bad_capability.validate().is_err());
        let mut control = manifest();
        control.source_revision = "a\nb".into();
        assert!(control.validate().is_err());

        // Unknown fields and non-JSON payloads are rejected too.
        let mut bytes = bare_component();
        bytes.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            br#"{"format_version":1,"extra":true}"#,
        ));
        assert!(is_malformed(parse(&bytes), "ironet.manifest.v1"));
        let mut bytes = bare_component();
        bytes.extend_from_slice(&encode_custom_section(MANIFEST_SECTION_NAME, b"\xff\xfe"));
        assert!(is_malformed(parse(&bytes), "ironet.manifest.v1"));
    }

    #[test]
    fn signature_missing_duplicate_and_misplaced() {
        let store = store_for(&key(), "ops", 0);
        let unsigned = parse(&with_manifest()).unwrap();
        assert_eq!(
            unsigned.verify(&store, now()),
            Err(PolicyPackageError::MissingSignature)
        );

        let signed = signed();
        let signature_section = {
            let package = parse(&signed).unwrap();
            let last = package.sections.last().unwrap();
            signed[last.offset..last.offset + last.len].to_vec()
        };
        let mut duplicate = signed.clone();
        duplicate.extend_from_slice(&signature_section);
        assert!(is_malformed(
            parse(&duplicate),
            "2 ironet.signature.v1 sections"
        ));

        // Signature followed by another (innocent) section: not last.
        let mut trailing = signed.clone();
        trailing.extend_from_slice(&encode_custom_section("ironet.note", b"hi"));
        assert!(is_malformed(
            parse(&trailing),
            "must be the last top-level section"
        ));

        // Signature before the manifest.
        let mut reordered = bare_component();
        reordered.extend_from_slice(&signature_section);
        reordered.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            &manifest().to_json().unwrap(),
        ));
        assert!(is_malformed(
            parse(&reordered),
            "must be the last top-level section"
        ));
    }

    #[test]
    fn signature_verification_failures_are_classified() {
        let signing = key();
        let signed = signed();
        let package = parse(&signed).unwrap();
        assert_eq!(
            package.body_len,
            signed.len() - package.sections.last().unwrap().len
        );

        // Happy path.
        let verified = package
            .verify(&store_for(&signing, "ops", 3), now())
            .unwrap();
        assert_eq!(verified.trust, TrustBasis::Signer);
        assert_eq!(verified.signer_id.as_deref(), Some("ops"));
        assert_eq!(verified.manifest.policy_version, 3);

        // Unknown signer.
        assert!(matches!(
            package.verify(&store_for(&signing, "someone-else", 0), now()),
            Err(PolicyPackageError::UnknownSigner { signer_id }) if signer_id == "ops"
        ));

        // Wrong key under the right id.
        let other = PolicySigningKey::from_bytes(&[9u8; 32]);
        assert!(matches!(
            package.verify(&store_for(&other, "ops", 0), now()),
            Err(PolicyPackageError::BadSignature { .. })
        ));

        // Rollback.
        assert!(matches!(
            package.verify(&store_for(&signing, "ops", 4), now()),
            Err(PolicyPackageError::VersionRollback {
                policy_version: 3,
                minimum_policy_version: 4,
                ..
            })
        ));

        // Expired signer (boundary inclusive).
        let expired = TrustStoreV1::with_signers([TrustedSigner {
            signer_id: "ops".into(),
            public_key: signing.public(),
            minimum_policy_version: 0,
            expires_at: Some(now()),
        }])
        .unwrap();
        assert!(matches!(
            package.verify(&expired, now()),
            Err(PolicyPackageError::SignerExpired { .. })
        ));
        let still_valid = TrustStoreV1::with_signers([TrustedSigner {
            signer_id: "ops".into(),
            public_key: signing.public(),
            minimum_policy_version: 0,
            expires_at: Some(now() + chrono::Duration::seconds(1)),
        }])
        .unwrap();
        assert!(package.verify(&still_valid, now()).is_ok());

        // Flip one byte inside the signed body: digest mismatch.
        let mut tampered_body = signed.clone();
        let manifest_section = package
            .sections
            .iter()
            .find(|section| section.name.as_deref() == Some(MANIFEST_SECTION_NAME))
            .unwrap();
        let position = manifest_section.payload_offset + manifest_section.payload_len - 3;
        // Keep the JSON valid: change the last digit of "deadbeef".
        assert_eq!(tampered_body[position], b'f');
        tampered_body[position] = b'e';
        let tampered = parse(&tampered_body).unwrap();
        assert!(matches!(
            tampered.verify(&store_for(&signing, "ops", 0), now()),
            Err(PolicyPackageError::DigestMismatch { .. })
        ));

        // Flip one hex digit of the signature itself.
        let mut tampered_signature = package.signature.clone().unwrap();
        let mut chars: Vec<char> = tampered_signature.signature.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '0' { '1' } else { '0' };
        tampered_signature.signature = chars.into_iter().collect();
        let mut forged = signed[..package.body_len].to_vec();
        forged.extend_from_slice(&encode_custom_section(
            SIGNATURE_SECTION_NAME,
            &serde_json::to_vec(&tampered_signature).unwrap(),
        ));
        let forged = parse(&forged).unwrap();
        assert!(matches!(
            forged.verify(&store_for(&signing, "ops", 0), now()),
            Err(PolicyPackageError::BadSignature { .. })
        ));

        // Malformed signature payloads.
        let mut bad_json = signed[..package.body_len].to_vec();
        bad_json.extend_from_slice(&encode_custom_section(
            SIGNATURE_SECTION_NAME,
            br#"{"signature_format":2,"signer_id":"ops","digest":"blake3:00","signature":"ed25519:00"}"#,
        ));
        assert!(is_malformed(parse(&bad_json), "ironet.signature.v1"));
    }

    #[test]
    fn manifest_required_fields_and_boundary_values() {
        // Empty / blank required strings are rejected.
        let mut empty_id = manifest();
        empty_id.policy_id = "".into();
        assert!(empty_id.validate().is_err());
        let mut blank_id = manifest();
        blank_id.policy_id = "   ".into();
        assert!(blank_id.validate().is_err());
        let mut empty_host = manifest();
        empty_host.minimum_host_version = "".into();
        assert!(empty_host.validate().is_err());
        let mut blank_host = manifest();
        blank_host.minimum_host_version = "  ".into();
        assert!(blank_host.validate().is_err());

        // A manifest missing a required (no-default) field fails to parse.
        let json = br#"{"policy_id":"p","policy_version":1,"abi_world":"ironet:policy/policy@1.0.0","state_schema":1,"minimum_host_version":"0.1.0","maximum_state_bytes":4096,"requested_memory_bytes":1048576,"requested_fuel":1000}"#;
        let mut bytes = bare_component();
        bytes.extend_from_slice(&encode_custom_section(MANIFEST_SECTION_NAME, json));
        assert!(is_malformed(parse(&bytes), "ironet.manifest.v1"));

        // In-range boundary values are accepted.
        let mut low_state = manifest();
        low_state.maximum_state_bytes = 1;
        assert!(low_state.validate().is_ok());
        let mut max_state = manifest();
        max_state.maximum_state_bytes = MAXIMUM_MANIFEST_STATE_BYTES;
        assert!(max_state.validate().is_ok());
        let mut min_mem = manifest();
        min_mem.requested_memory_bytes = MINIMUM_REQUESTED_MEMORY_BYTES;
        assert!(min_mem.validate().is_ok());
        let mut below_mem = manifest();
        below_mem.requested_memory_bytes = MINIMUM_REQUESTED_MEMORY_BYTES - 1;
        assert!(below_mem.validate().is_err());
        let mut fuel1 = manifest();
        fuel1.requested_fuel = 1;
        assert!(fuel1.validate().is_ok());
    }

    #[test]
    fn non_custom_sections_are_opaque_and_signature_still_must_be_last() {
        // A non-custom (e.g. core-module) section is treated as opaque
        // payload and does not break package parsing.
        let mut bytes = bare_component();
        bytes.push(1); // core-module section id
        write_leb128_u32(&mut bytes, 4);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        bytes.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            &manifest().to_json().unwrap(),
        ));
        let package = parse(&bytes).unwrap();
        assert!(package.signature.is_none());
        assert!(
            package
                .sections
                .iter()
                .any(|section| section.kind() == "core-module")
        );

        // Moving the signature before that opaque section makes it not-last.
        let mut signed = signed();
        signed.extend_from_slice(&[1u8, 4, 0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(is_malformed(
            parse(&signed),
            "must be the last top-level section"
        ));
    }

    #[test]
    fn component_truncation_garbage_and_limits() {
        let signed = signed();
        for cut in [0, 3, 7, 8, 9, 12, signed.len() - 1] {
            assert!(
                matches!(parse(&signed[..cut]), Err(PolicyPackageError::Malformed(_))),
                "cut {cut}"
            );
        }

        // Appended garbage that is not a valid section.
        let mut garbage = signed.clone();
        garbage.extend_from_slice(&[0x00, 0x7f]);
        assert!(is_malformed(parse(&garbage), "claims 127 bytes"));

        // Wrong magic / core module instead of component.
        let mut core = signed.clone();
        core[4..8].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert!(is_malformed(parse(&core), "not a component"));
        let mut magic = signed.clone();
        magic[0] = b'x';
        assert!(is_malformed(parse(&magic), "magic"));

        // Section size above remaining bytes.
        let mut oversize = COMPONENT_HEADER.to_vec();
        oversize.extend_from_slice(&[0x00, 0xff, 0xff, 0x03, 0x00]);
        assert!(is_malformed(parse(&oversize), "only"));

        // LEB128 longer than five bytes.
        let mut overlong = COMPONENT_HEADER.to_vec();
        overlong.extend_from_slice(&[0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
        assert!(is_malformed(parse(&overlong), "LEB128"));

        // Custom section name longer than its payload.
        let mut bad_name = COMPONENT_HEADER.to_vec();
        bad_name.extend_from_slice(&[0x00, 0x02, 0x05, b'a']);
        assert!(is_malformed(parse(&bad_name), "name length"));

        // Invalid UTF-8 name.
        let mut bad_utf8 = COMPONENT_HEADER.to_vec();
        bad_utf8.extend_from_slice(&[0x00, 0x03, 0x02, 0xff, 0xfe]);
        assert!(is_malformed(parse(&bad_utf8), "not UTF-8"));

        // Custom sections above the 256 KiB budget.
        let mut heavy = with_manifest();
        heavy.extend_from_slice(&encode_custom_section("pad", &vec![0u8; 200 * 1024]));
        heavy.extend_from_slice(&encode_custom_section("pad", &vec![0u8; 60 * 1024]));
        assert!(is_malformed(parse(&heavy), "custom sections total"));

        // Non-custom sections do not count against the custom budget.
        let mut heavy_module = with_manifest();
        heavy_module.push(1);
        write_leb128_u32(&mut heavy_module, 300 * 1024);
        heavy_module.extend(std::iter::repeat_n(0u8, 300 * 1024));
        let package = parse(&heavy_module).unwrap();
        assert_eq!(package.sections.last().unwrap().kind(), "core-module");

        // File above maximum_module_bytes.
        let limits = PackageLimits {
            maximum_module_bytes: 64,
            maximum_custom_section_bytes: MAXIMUM_CUSTOM_SECTION_BYTES,
        };
        assert!(matches!(
            PolicyPackage::parse(&signed, limits),
            Err(PolicyPackageError::Malformed(reason)) if reason.contains("maximum_module_bytes")
        ));
    }

    #[test]
    fn digest_pin_mode() {
        let bytes = with_manifest();
        let package = parse(&bytes).unwrap();
        let pinned = TrustStoreV1::with_digest_pins([package.digest]);
        let verified = package.verify(&pinned, now()).unwrap();
        assert_eq!(verified.trust, TrustBasis::DigestPin);
        assert_eq!(verified.signer_id, None);
        assert_eq!(verified.digest_string(), encode_digest(&package.digest));

        let unpinned = TrustStoreV1::with_digest_pins([[0u8; 32]]);
        assert!(matches!(
            package.verify(&unpinned, now()),
            Err(PolicyPackageError::DigestNotPinned { .. })
        ));

        // Pins do not rescue a signed file whose signer is unknown.
        let signed = parse(&signed()).unwrap();
        let pinned_signed = TrustStoreV1::with_digest_pins([signed.digest]);
        assert!(matches!(
            signed.verify(&pinned_signed, now()),
            Err(PolicyPackageError::UnknownSigner { .. })
        ));

        // From config: pins + require_signature = false.
        let config = AutotuneWasmConfig {
            require_signature: false,
            digest_pins: vec![package.digest_string()],
            ..AutotuneWasmConfig::default()
        };
        let store = TrustStoreV1::from_config(&config).unwrap();
        assert!(package.verify(&store, now()).is_ok());
    }

    #[test]
    fn sign_is_idempotent_and_replaces_previous_signature() {
        let signing = key();
        let first = sign(&with_manifest(), &signing, "ops", PackageLimits::default()).unwrap();
        let second = sign(&first, &signing, "ops", PackageLimits::default()).unwrap();
        assert_eq!(first, second);

        let other = PolicySigningKey::from_bytes(&[1u8; 32]);
        let resigned = sign(&first, &other, "ops-2027", PackageLimits::default()).unwrap();
        let package = parse(&resigned).unwrap();
        assert_eq!(package.signature.as_ref().unwrap().signer_id, "ops-2027");
        assert_eq!(
            package
                .sections
                .iter()
                .filter(|section| section.name.as_deref() == Some(SIGNATURE_SECTION_NAME))
                .count(),
            1
        );
        assert_eq!(package.digest, parse(&first).unwrap().digest);
        assert!(
            package
                .verify(&store_for(&other, "ops-2027", 0), now())
                .is_ok()
        );
        assert!(
            package
                .verify(&store_for(&signing, "ops", 0), now())
                .is_err()
        );

        assert!(sign(&bare_component(), &signing, "ops", PackageLimits::default()).is_err());
        assert!(sign(&with_manifest(), &signing, "  ", PackageLimits::default()).is_err());
    }

    #[test]
    fn keygen_sign_verify_end_to_end_through_files_and_config() {
        let directory = tempfile::tempdir().unwrap();
        let key_path = directory.path().join("signer.key");
        let generated = PolicySigningKey::generate().unwrap();
        generated.write_file(&key_path).unwrap();
        let loaded = PolicySigningKey::read_file(&key_path).unwrap();
        let signer_id = loaded.public().default_signer_id();

        let signed = sign(
            &with_manifest(),
            &loaded,
            &signer_id,
            PackageLimits::default(),
        )
        .unwrap();
        let config = AutotuneWasmConfig {
            require_signature: true,
            signers: vec![AutotuneSignerConfig {
                signer_id: signer_id.clone(),
                public_key: loaded.public().encode(),
                minimum_policy_version: 3,
                expires_at: Some("2030-01-01T00:00:00Z".into()),
            }],
            ..AutotuneWasmConfig::default()
        };
        let store = TrustStoreV1::from_config(&config).unwrap();
        let package = PolicyPackage::parse(&signed, PackageLimits::from_config(&config)).unwrap();
        let verified = package.verify(&store, now()).unwrap();
        assert_eq!(verified.signer_id.as_deref(), Some(signer_id.as_str()));
        assert_eq!(verified.trust, TrustBasis::Signer);

        let json = serde_json::to_string_pretty(&package.manifest).unwrap();
        let decoded: PolicyManifestV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, manifest());
    }

    /// Wraps `payload` as one top-level section with the given id.
    fn raw_section(id: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        write_leb128_u32(&mut out, u32::try_from(payload.len()).unwrap());
        out.extend_from_slice(payload);
        out
    }

    fn manifest_package(json: &[u8]) -> Vec<u8> {
        let mut bytes = bare_component();
        bytes.extend_from_slice(&encode_custom_section(MANIFEST_SECTION_NAME, json));
        bytes
    }

    #[test]
    fn nested_manifest_and_signature_sections_are_never_honored() {
        let manifest_section =
            encode_custom_section(MANIFEST_SECTION_NAME, &manifest().to_json().unwrap());
        let signed = signed();
        let signature_section = {
            let package = parse(&signed).unwrap();
            let last = package.sections.last().unwrap();
            signed[last.offset..last.offset + last.len].to_vec()
        };

        // A core module (id 1) whose payload is a custom manifest section:
        // the top level has no manifest, so the package is rejected.
        let mut nested_module = bare_component();
        nested_module.extend_from_slice(&raw_section(1, &manifest_section));
        assert!(is_malformed(
            parse(&nested_module),
            "missing ironet.manifest.v1"
        ));

        // A nested component (id 4) carrying a complete signed package.
        let mut nested_component = bare_component();
        nested_component.extend_from_slice(&raw_section(4, &signed));
        assert!(is_malformed(
            parse(&nested_component),
            "missing ironet.manifest.v1"
        ));

        // Top-level manifest plus a nested signature: the file is unsigned.
        let mut nested_signature = with_manifest();
        nested_signature.extend_from_slice(&raw_section(1, &signature_section));
        let package = parse(&nested_signature).unwrap();
        assert!(package.signature.is_none());
        assert_eq!(package.body_len, nested_signature.len());
        assert_eq!(
            package.verify(&store_for(&key(), "ops", 0), now()),
            Err(PolicyPackageError::MissingSignature)
        );

        // Nested sections are not found even when a top-level one is present
        // (so a nested duplicate is not a duplicate).
        let mut nested_duplicate = with_manifest();
        nested_duplicate.extend_from_slice(&raw_section(4, &manifest_section));
        let package = parse(&nested_duplicate).unwrap();
        assert_eq!(
            package
                .sections
                .iter()
                .filter(|section| section.name.as_deref() == Some(MANIFEST_SECTION_NAME))
                .count(),
            1
        );
    }

    #[test]
    fn manifest_json_shape_type_and_numeric_range_errors() {
        let valid = serde_json::to_value(manifest()).unwrap();
        let mutate = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
            let mut object = valid.as_object().cloned().unwrap();
            edit(&mut object);
            serde_json::to_vec(&serde_json::Value::Object(object)).unwrap()
        };
        let json = |value: &str| serde_json::Value::String(value.to_owned());

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty object", b"{}".to_vec()),
            ("array", b"[]".to_vec()),
            ("null", b"null".to_vec()),
            ("string", br#""manifest""#.to_vec()),
            ("empty payload", Vec::new()),
            (
                "truncated json",
                serde_json::to_vec(&valid).unwrap()[..40].to_vec(),
            ),
            (
                "trailing garbage",
                [serde_json::to_vec(&valid).unwrap(), b"x".to_vec()].concat(),
            ),
            (
                "two objects",
                [
                    serde_json::to_vec(&valid).unwrap(),
                    serde_json::to_vec(&valid).unwrap(),
                ]
                .concat(),
            ),
            ("duplicate key", {
                let text = serde_json::to_string(&valid).unwrap();
                format!(r#"{{"policy_version":1,{}"#, &text[1..]).into_bytes()
            }),
            (
                "policy_version as string",
                mutate(&|m| {
                    m.insert("policy_version".into(), json("3"));
                }),
            ),
            (
                "policy_version negative",
                mutate(&|m| {
                    m.insert("policy_version".into(), serde_json::json!(-1));
                }),
            ),
            (
                "policy_version above u64",
                mutate(&|m| {
                    m.insert(
                        "policy_version".into(),
                        serde_json::from_str("18446744073709551616").unwrap(),
                    );
                }),
            ),
            (
                "policy_version float",
                mutate(&|m| {
                    m.insert("policy_version".into(), serde_json::json!(3.5));
                }),
            ),
            (
                "format_version above u16",
                mutate(&|m| {
                    m.insert("format_version".into(), serde_json::json!(65536));
                }),
            ),
            (
                "maximum_state_bytes above u32",
                mutate(&|m| {
                    m.insert(
                        "maximum_state_bytes".into(),
                        serde_json::json!(4294967296u64),
                    );
                }),
            ),
            (
                "requested_memory_bytes above u32",
                mutate(&|m| {
                    m.insert(
                        "requested_memory_bytes".into(),
                        serde_json::json!(4294967296u64),
                    );
                }),
            ),
            (
                "requested_fuel negative",
                mutate(&|m| {
                    m.insert("requested_fuel".into(), serde_json::json!(-1));
                }),
            ),
            (
                "extensions_supported above u16",
                mutate(&|m| {
                    m.insert("extensions_supported".into(), serde_json::json!([70000]));
                }),
            ),
            (
                "extensions_supported not a list",
                mutate(&|m| {
                    m.insert("extensions_supported".into(), serde_json::json!(1));
                }),
            ),
            (
                "capabilities not strings",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::json!([1, 2]));
                }),
            ),
            (
                "capabilities null",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::Value::Null);
                }),
            ),
            (
                "policy_id null",
                mutate(&|m| {
                    m.insert("policy_id".into(), serde_json::Value::Null);
                }),
            ),
            (
                "policy_id missing",
                mutate(&|m| {
                    m.remove("policy_id");
                }),
            ),
            (
                "abi_world missing",
                mutate(&|m| {
                    m.remove("abi_world");
                }),
            ),
            (
                "state_schema missing",
                mutate(&|m| {
                    m.remove("state_schema");
                }),
            ),
            (
                "requested_fuel missing",
                mutate(&|m| {
                    m.remove("requested_fuel");
                }),
            ),
            (
                "policy_id with NUL",
                mutate(&|m| {
                    m.insert("policy_id".into(), json("bandit\u{0}vivace"));
                }),
            ),
            (
                "policy_id with DEL",
                mutate(&|m| {
                    m.insert("policy_id".into(), json("bandit\u{7f}"));
                }),
            ),
            (
                "policy_id with escape",
                mutate(&|m| {
                    m.insert("policy_id".into(), json("\u{1b}[31mred"));
                }),
            ),
            (
                "policy_id 129 bytes of multibyte text",
                mutate(&|m| {
                    m.insert("policy_id".into(), json(&"策".repeat(43)));
                }),
            ),
            (
                "capability empty",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::json!([""]));
                }),
            ),
            (
                "capability with space",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::json!(["bbr preset"]));
                }),
            ),
            (
                "capability unicode",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::json!(["bbr.préset"]));
                }),
            ),
            (
                "capability 129 bytes",
                mutate(&|m| {
                    m.insert("capabilities".into(), serde_json::json!(["c".repeat(129)]));
                }),
            ),
            (
                "65 extensions",
                mutate(&|m| {
                    m.insert(
                        "extensions_supported".into(),
                        serde_json::json!((0..65u16).collect::<Vec<_>>()),
                    );
                }),
            ),
            (
                "duplicate extensions",
                mutate(&|m| {
                    m.insert("extensions_supported".into(), serde_json::json!([1, 1]));
                }),
            ),
            (
                "65 state_schema_accepts",
                mutate(&|m| {
                    m.insert(
                        "state_schema_accepts".into(),
                        serde_json::json!((0..65u32).collect::<Vec<_>>()),
                    );
                }),
            ),
            (
                "duplicate state_schema_accepts",
                mutate(&|m| {
                    m.insert("state_schema_accepts".into(), serde_json::json!([1, 1]));
                }),
            ),
            (
                "built_at 129 bytes",
                mutate(&|m| {
                    m.insert("built_at".into(), json(&"2".repeat(129)));
                }),
            ),
            (
                "built_at control",
                mutate(&|m| {
                    m.insert("built_at".into(), json("2026\t"));
                }),
            ),
            (
                "minimum_host_version 129 bytes",
                mutate(&|m| {
                    m.insert("minimum_host_version".into(), json(&"9".repeat(129)));
                }),
            ),
            (
                "abi_world major 2",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("ironet:policy/policy@2.0.0"));
                }),
            ),
            (
                "abi_world major 0",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("ironet:policy/policy@0.1.0"));
                }),
            ),
            (
                "abi_world minor bump",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("ironet:policy/policy@1.1.0"));
                }),
            ),
            (
                "abi_world unversioned",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("ironet:policy/policy"));
                }),
            ),
            (
                "abi_world other world",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("ironet:policy/other@1.0.0"));
                }),
            ),
            (
                "abi_world padded",
                mutate(&|m| {
                    m.insert("abi_world".into(), json(" ironet:policy/policy@1.0.0"));
                }),
            ),
            (
                "abi_world case",
                mutate(&|m| {
                    m.insert("abi_world".into(), json("Ironet:Policy/Policy@1.0.0"));
                }),
            ),
            (
                "format_version 0",
                mutate(&|m| {
                    m.insert("format_version".into(), serde_json::json!(0));
                }),
            ),
            (
                "unknown field",
                mutate(&|m| {
                    m.insert("signer_id".into(), json("ops"));
                }),
            ),
            (
                "deeply nested array",
                [
                    "[".repeat(100_000).into_bytes(),
                    "]".repeat(100_000).into_bytes(),
                ]
                .concat(),
            ),
            (
                "deeply nested field",
                mutate(&|m| {
                    // Well above serde_json's recursion limit (128).
                    let mut nested = serde_json::json!(1);
                    for _ in 0..1_000 {
                        nested = serde_json::json!({ "x": nested });
                    }
                    m.insert("capabilities".into(), nested);
                }),
            ),
        ];
        for (label, json) in cases {
            match parse(&manifest_package(&json)) {
                Err(PolicyPackageError::Malformed(reason)) => assert!(
                    reason.contains(MANIFEST_SECTION_NAME),
                    "{label}: {reason:?}"
                ),
                other => panic!("{label}: expected Malformed, got {other:?}"),
            }
        }

        // Boundary values that must be accepted.
        let accepted: Vec<(&str, Vec<u8>)> = vec![
            (
                "128-byte policy_id",
                mutate(&|m| {
                    m.insert("policy_id".into(), json(&"x".repeat(128)));
                }),
            ),
            (
                "128-byte multibyte policy_id",
                mutate(&|m| {
                    m.insert("policy_id".into(), json(&format!("{}ab", "策".repeat(42))));
                }),
            ),
            (
                "64 capabilities",
                mutate(&|m| {
                    m.insert(
                        "capabilities".into(),
                        serde_json::json!((0..64).map(|i| format!("cap-{i}")).collect::<Vec<_>>()),
                    );
                }),
            ),
            (
                "all identifier characters",
                mutate(&|m| {
                    m.insert(
                        "capabilities".into(),
                        serde_json::json!(["Az09-_.:/", "bbr.preset"]),
                    );
                }),
            ),
            (
                "optional lists absent",
                mutate(&|m| {
                    m.remove("extensions_supported");
                    m.remove("state_schema_accepts");
                    m.remove("capabilities");
                    m.remove("built_at");
                    m.remove("source_revision");
                }),
            ),
            (
                "u64::MAX policy_version and fuel",
                mutate(&|m| {
                    m.insert("policy_version".into(), serde_json::json!(u64::MAX));
                    m.insert("requested_fuel".into(), serde_json::json!(u64::MAX));
                }),
            ),
            (
                "u32::MAX requested_memory_bytes",
                mutate(&|m| {
                    m.insert("requested_memory_bytes".into(), serde_json::json!(u32::MAX));
                }),
            ),
            (
                "whitespace-padded json under the section budget",
                [serde_json::to_vec(&valid).unwrap(), vec![b' '; 200 * 1024]].concat(),
            ),
        ];
        for (label, json) in accepted {
            let package = parse(&manifest_package(&json)).unwrap_or_else(|error| {
                panic!("{label}: {error}");
            });
            assert!(package.manifest.validate().is_ok(), "{label}");
        }
        // Whitespace padding beyond the custom-section budget is structural.
        let padded = [
            serde_json::to_vec(&valid).unwrap(),
            vec![b' '; MAXIMUM_CUSTOM_SECTION_BYTES],
        ]
        .concat();
        assert!(is_malformed(
            parse(&manifest_package(&padded)),
            "custom sections total"
        ));
    }

    #[test]
    fn signature_section_payload_malformations() {
        let signed = signed();
        let package = parse(&signed).unwrap();
        let good = package.signature.clone().unwrap();
        let body = signed[..package.body_len].to_vec();
        let with_signature = |payload: &[u8]| {
            let mut out = body.clone();
            out.extend_from_slice(&encode_custom_section(SIGNATURE_SECTION_NAME, payload));
            out
        };
        let mutate = |edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>)| {
            let mut object = serde_json::to_value(&good)
                .unwrap()
                .as_object()
                .cloned()
                .unwrap();
            edit(&mut object);
            serde_json::to_vec(&serde_json::Value::Object(object)).unwrap()
        };
        let json = |value: &str| serde_json::Value::String(value.to_owned());
        let hex64 = "0".repeat(64);
        let hex128 = "0".repeat(128);

        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("empty object", b"{}".to_vec()),
            ("array", b"[]".to_vec()),
            ("not json", b"\xff\xfe".to_vec()),
            (
                "trailing garbage",
                [serde_json::to_vec(&good).unwrap(), b"}".to_vec()].concat(),
            ),
            (
                "unknown field",
                mutate(&|m| {
                    m.insert("public_key".into(), json("ed25519:00"));
                }),
            ),
            (
                "missing signature",
                mutate(&|m| {
                    m.remove("signature");
                }),
            ),
            (
                "missing digest",
                mutate(&|m| {
                    m.remove("digest");
                }),
            ),
            (
                "missing signer_id",
                mutate(&|m| {
                    m.remove("signer_id");
                }),
            ),
            (
                "missing signature_format",
                mutate(&|m| {
                    m.remove("signature_format");
                }),
            ),
            (
                "signature_format 0",
                mutate(&|m| {
                    m.insert("signature_format".into(), serde_json::json!(0));
                }),
            ),
            (
                "signature_format 2",
                mutate(&|m| {
                    m.insert("signature_format".into(), serde_json::json!(2));
                }),
            ),
            (
                "signature_format string",
                mutate(&|m| {
                    m.insert("signature_format".into(), json("1"));
                }),
            ),
            (
                "signer_id empty",
                mutate(&|m| {
                    m.insert("signer_id".into(), json(""));
                }),
            ),
            (
                "signer_id blank",
                mutate(&|m| {
                    m.insert("signer_id".into(), json("  \t"));
                }),
            ),
            (
                "signer_id 129 bytes",
                mutate(&|m| {
                    m.insert("signer_id".into(), json(&"s".repeat(129)));
                }),
            ),
            (
                "signer_id control",
                mutate(&|m| {
                    m.insert("signer_id".into(), json("ops\n"));
                }),
            ),
            (
                "signer_id number",
                mutate(&|m| {
                    m.insert("signer_id".into(), serde_json::json!(7));
                }),
            ),
            (
                "digest wrong prefix",
                mutate(&|m| {
                    m.insert("digest".into(), json(&format!("sha256:{hex64}")));
                }),
            ),
            (
                "digest no prefix",
                mutate(&|m| {
                    m.insert("digest".into(), json(&hex64));
                }),
            ),
            (
                "digest short",
                mutate(&|m| {
                    m.insert("digest".into(), json(&format!("blake3:{}", &hex64[..62])));
                }),
            ),
            (
                "digest long",
                mutate(&|m| {
                    m.insert("digest".into(), json(&format!("blake3:{hex64}00")));
                }),
            ),
            (
                "digest non-hex",
                mutate(&|m| {
                    m.insert("digest".into(), json(&format!("blake3:{}zz", &hex64[..62])));
                }),
            ),
            (
                "digest empty",
                mutate(&|m| {
                    m.insert("digest".into(), json(""));
                }),
            ),
            (
                "digest null",
                mutate(&|m| {
                    m.insert("digest".into(), serde_json::Value::Null);
                }),
            ),
            (
                "signature wrong prefix",
                mutate(&|m| {
                    m.insert("signature".into(), json(&format!("rsa:{hex128}")));
                }),
            ),
            (
                "signature no prefix",
                mutate(&|m| {
                    m.insert("signature".into(), json(&hex128));
                }),
            ),
            (
                "signature short",
                mutate(&|m| {
                    m.insert(
                        "signature".into(),
                        json(&format!("ed25519:{}", &hex128[..126])),
                    );
                }),
            ),
            (
                "signature long",
                mutate(&|m| {
                    m.insert("signature".into(), json(&format!("ed25519:{hex128}00")));
                }),
            ),
            (
                "signature non-hex",
                mutate(&|m| {
                    m.insert(
                        "signature".into(),
                        json(&format!("ed25519:{}zz", &hex128[..126])),
                    );
                }),
            ),
            (
                "signature padded",
                mutate(&|m| {
                    m.insert("signature".into(), json(&format!(" {}", good.signature)));
                }),
            ),
            (
                "signature is a digest",
                mutate(&|m| {
                    m.insert("signature".into(), json(&good.digest));
                }),
            ),
            (
                "signature empty",
                mutate(&|m| {
                    m.insert("signature".into(), json(""));
                }),
            ),
            (
                "signature array",
                mutate(&|m| {
                    m.insert("signature".into(), serde_json::json!(vec![0u8; 64]));
                }),
            ),
        ];
        for (label, payload) in cases {
            match parse(&with_signature(&payload)) {
                Err(PolicyPackageError::Malformed(reason)) => assert!(
                    reason.contains(SIGNATURE_SECTION_NAME),
                    "{label}: {reason:?}"
                ),
                other => panic!("{label}: expected Malformed, got {other:?}"),
            }
        }

        // A re-encoding of the same signature must still parse and verify:
        // JSON key order and whitespace are not part of the signed prefix.
        let reordered = format!(
            r#"{{ "signature" : {:?} , "digest" : {:?} , "signer_id" : "ops" , "signature_format" : 1 }}"#,
            good.signature, good.digest
        );
        let package = parse(&with_signature(reordered.as_bytes())).unwrap();
        assert_eq!(package.signature.as_ref(), Some(&good));
        assert!(package.verify(&store_for(&key(), "ops", 0), now()).is_ok());
        // Upper-case hex in the signature section is the same signature.
        let upper = mutate(&|m| {
            m.insert(
                "digest".into(),
                json(&format!(
                    "blake3:{}",
                    good.digest["blake3:".len()..].to_ascii_uppercase()
                )),
            );
            m.insert(
                "signature".into(),
                json(&format!(
                    "ed25519:{}",
                    good.signature["ed25519:".len()..].to_ascii_uppercase()
                )),
            );
        });
        let package = parse(&with_signature(&upper)).unwrap();
        assert!(package.verify(&store_for(&key(), "ops", 0), now()).is_ok());
        // Whitespace around signer_id is trimmed for lookup.
        let padded_id = mutate(&|m| {
            m.insert("signer_id".into(), json("  ops "));
        });
        let package = parse(&with_signature(&padded_id)).unwrap();
        let verified = package.verify(&store_for(&key(), "ops", 0), now()).unwrap();
        assert_eq!(verified.signer_id.as_deref(), Some("ops"));
    }

    #[test]
    fn transplanted_forged_and_replayed_signatures_are_rejected() {
        let signing = key();
        let store = store_for(&signing, "ops", 0);
        let signed_a = signed();
        let package_a = parse(&signed_a).unwrap();
        let signature_a = package_a.signature.clone().unwrap();
        let section_a = {
            let last = package_a.sections.last().unwrap();
            signed_a[last.offset..last.offset + last.len].to_vec()
        };

        // Package B: same signer, different manifest.
        let mut manifest_b = manifest();
        manifest_b.policy_version = 9;
        let unsigned_b =
            attach_manifest(&bare_component(), &manifest_b, PackageLimits::default()).unwrap();
        let package_b = parse(&unsigned_b).unwrap();
        assert_ne!(package_a.digest, package_b.digest);

        // 1. Transplant A's signature section onto B: the claimed digest is
        //    A's, so it is a digest mismatch before any key is consulted.
        let mut transplanted = unsigned_b.clone();
        transplanted.extend_from_slice(&section_a);
        let package = parse(&transplanted).unwrap();
        assert!(matches!(
            package.verify(&store, now()),
            Err(PolicyPackageError::DigestMismatch { expected, actual })
                if expected == signature_a.digest && actual == package_b.digest_string()
        ));
        // Unknown-signer stores must not short-circuit into accepting either.
        assert!(
            package
                .verify(&store_for(&signing, "nobody", 0), now())
                .is_err()
        );

        // 2. Forge: keep A's signature bytes but rewrite the digest to B's.
        let forged = PolicySignatureV1 {
            digest: package_b.digest_string(),
            ..signature_a.clone()
        };
        let mut forged_file = unsigned_b.clone();
        forged_file.extend_from_slice(&encode_custom_section(
            SIGNATURE_SECTION_NAME,
            &serde_json::to_vec(&forged).unwrap(),
        ));
        let package = parse(&forged_file).unwrap();
        assert!(matches!(
            package.verify(&store, now()),
            Err(PolicyPackageError::BadSignature { signer_id }) if signer_id == "ops"
        ));

        // 3. Right key, right digest, wrong domain: signed as a raw message.
        let raw = ed25519_dalek::SigningKey::from_bytes(&signing.to_bytes());
        let undomained = PolicySignatureV1 {
            signature: encode_signature(
                &ed25519_dalek::Signer::sign(&raw, &package_b.digest).to_bytes(),
            ),
            digest: package_b.digest_string(),
            ..signature_a.clone()
        };
        let mut undomained_file = unsigned_b.clone();
        undomained_file.extend_from_slice(&encode_custom_section(
            SIGNATURE_SECTION_NAME,
            &serde_json::to_vec(&undomained).unwrap(),
        ));
        let package = parse(&undomained_file).unwrap();
        assert!(matches!(
            package.verify(&store, now()),
            Err(PolicyPackageError::BadSignature { .. })
        ));

        // 4. Attacker's own key, claiming the trusted signer id.
        let attacker = PolicySigningKey::from_bytes(&[0xa7u8; 32]);
        let impostor = sign(&unsigned_b, &attacker, "ops", PackageLimits::default()).unwrap();
        let package = parse(&impostor).unwrap();
        assert!(matches!(
            package.verify(&store, now()),
            Err(PolicyPackageError::BadSignature { .. })
        ));
        // ... and a zero signature.
        let zero = PolicySignatureV1 {
            signature: encode_signature(&[0u8; 64]),
            digest: package_b.digest_string(),
            ..signature_a.clone()
        };
        let mut zero_file = unsigned_b.clone();
        zero_file.extend_from_slice(&encode_custom_section(
            SIGNATURE_SECTION_NAME,
            &serde_json::to_vec(&zero).unwrap(),
        ));
        assert!(matches!(
            parse(&zero_file).unwrap().verify(&store, now()),
            Err(PolicyPackageError::BadSignature { .. })
        ));

        // 5. Replay a correctly signed old version under a raised floor.
        let floor = store_for(&signing, "ops", 4);
        assert!(matches!(
            package_a.verify(&floor, now()),
            Err(PolicyPackageError::VersionRollback {
                policy_version: 3,
                ..
            })
        ));
        let signed_b = sign(&unsigned_b, &signing, "ops", PackageLimits::default()).unwrap();
        assert!(parse(&signed_b).unwrap().verify(&floor, now()).is_ok());

        // 6. Byte flips anywhere in the signed prefix that keep the file
        //    structurally valid are digest mismatches: flip every byte of the
        //    leading empty custom section's name length... which would break
        //    structure, so instead flip bytes inside the core-module payload.
        let mut with_module = with_manifest();
        with_module.extend_from_slice(&raw_section(1, &[0x11, 0x22, 0x33, 0x44]));
        let signed_module = sign(&with_module, &signing, "ops", PackageLimits::default()).unwrap();
        let module_package = parse(&signed_module).unwrap();
        assert!(module_package.verify(&store, now()).is_ok());
        let module_section = module_package
            .sections
            .iter()
            .find(|section| section.id == 1)
            .unwrap();
        for offset in module_section.payload_offset
            ..module_section.payload_offset + module_section.payload_len
        {
            for bit in 0..8 {
                let mut flipped = signed_module.clone();
                flipped[offset] ^= 1 << bit;
                let package = parse(&flipped).unwrap();
                assert!(
                    matches!(
                        package.verify(&store, now()),
                        Err(PolicyPackageError::DigestMismatch { .. })
                    ),
                    "offset {offset} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn no_truncation_or_extension_of_a_signed_file_verifies() {
        let signing = key();
        let store = store_for(&signing, "ops", 0);
        let signed = signed();
        let package = parse(&signed).unwrap();
        let mut accepted_unsigned = 0;
        for cut in 0..signed.len() {
            match parse(&signed[..cut]) {
                Err(PolicyPackageError::Malformed(_)) => {}
                Ok(truncated) => {
                    // Only cutting exactly at the signature boundary yields a
                    // parseable (unsigned) package; it must not verify.
                    assert_eq!(cut, package.body_len, "cut {cut} parsed");
                    assert!(truncated.signature.is_none());
                    assert_eq!(truncated.digest, package.digest);
                    assert_eq!(
                        truncated.verify(&store, now()),
                        Err(PolicyPackageError::MissingSignature)
                    );
                    accepted_unsigned += 1;
                }
                Err(other) => panic!("cut {cut}: unexpected {other:?}"),
            }
        }
        assert_eq!(accepted_unsigned, 1);
        // Truncating an unsigned package never parses.
        let unsigned = with_manifest();
        for cut in 0..unsigned.len() {
            assert!(
                matches!(
                    parse(&unsigned[..cut]),
                    Err(PolicyPackageError::Malformed(_))
                ),
                "unsigned cut {cut}"
            );
        }

        // Every way of extending the signed file is rejected at parse.
        let extensions: Vec<(&str, Vec<u8>)> = vec![
            ("single zero byte", vec![0x00]),
            ("single 0xff", vec![0xff]),
            ("empty custom section with empty size", vec![0x00, 0x00]),
            (
                "unnamed empty custom section",
                encode_custom_section("", b""),
            ),
            (
                "named custom section",
                encode_custom_section("ironet.note", b"hi"),
            ),
            ("core module", raw_section(1, &[0xde, 0xad])),
            ("unknown id", raw_section(0xff, &[])),
            (
                "another manifest",
                encode_custom_section(MANIFEST_SECTION_NAME, &manifest().to_json().unwrap()),
            ),
            ("random bytes", b"GARBAGE GARBAGE".to_vec()),
            ("copy of the header", COMPONENT_HEADER.to_vec()),
            ("copy of the whole file", signed.clone()),
        ];
        for (label, extra) in extensions {
            let mut extended = signed.clone();
            extended.extend_from_slice(&extra);
            assert!(
                matches!(parse(&extended), Err(PolicyPackageError::Malformed(_))),
                "{label}"
            );
        }

        // Extending an unsigned file with a well-formed section still parses
        // but changes the digest, so a pin on the original no longer matches.
        let pinned = TrustStoreV1::with_digest_pins([parse(&unsigned).unwrap().digest]);
        let mut extended = unsigned.clone();
        extended.extend_from_slice(&encode_custom_section("ironet.note", b"hi"));
        let package = parse(&extended).unwrap();
        assert!(matches!(
            package.verify(&pinned, now()),
            Err(PolicyPackageError::DigestNotPinned { .. })
        ));
        // Garbage after an unsigned file is still structural.
        let mut garbage = unsigned.clone();
        garbage.extend_from_slice(&[0x01]);
        assert!(is_malformed(parse(&garbage), "truncated LEB128"));
    }

    #[test]
    fn section_table_edge_cases() {
        // Header only: structurally fine, but no manifest.
        assert!(is_malformed(
            parse(&COMPONENT_HEADER),
            "missing ironet.manifest.v1"
        ));
        // Header + manifest only (no other section) parses.
        let mut minimal = COMPONENT_HEADER.to_vec();
        minimal.extend_from_slice(&encode_custom_section(
            MANIFEST_SECTION_NAME,
            &manifest().to_json().unwrap(),
        ));
        let package = parse(&minimal).unwrap();
        assert_eq!(package.sections.len(), 1);
        assert_eq!(package.body_len, minimal.len());

        // Zero-length non-custom sections and unknown ids are opaque.
        let mut odd = with_manifest();
        odd.extend_from_slice(&raw_section(1, &[]));
        odd.extend_from_slice(&raw_section(12, &[0x01]));
        odd.extend_from_slice(&raw_section(13, &[0x01]));
        odd.extend_from_slice(&raw_section(0xff, &[]));
        let package = parse(&odd).unwrap();
        let kinds: Vec<&str> = package.sections.iter().map(SectionEntry::kind).collect();
        assert_eq!(
            kinds,
            [
                "custom",
                "custom",
                "core-module",
                "value",
                "unknown",
                "unknown"
            ]
        );
        // Signing such a file keeps it verifiable and the signature last.
        let signed = sign(&odd, &key(), "ops", PackageLimits::default()).unwrap();
        let package = parse(&signed).unwrap();
        assert_eq!(
            package.sections.last().unwrap().name.as_deref(),
            Some(SIGNATURE_SECTION_NAME)
        );
        assert!(package.verify(&store_for(&key(), "ops", 0), now()).is_ok());

        // Per-section encoding faults.
        let faults: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "custom section with empty payload",
                vec![0x00, 0x00],
                "truncated LEB128",
            ),
            (
                "custom name length truncated",
                vec![0x00, 0x01, 0x80],
                "truncated LEB128",
            ),
            (
                "custom name length overlong",
                vec![0x00, 0x06, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00],
                "LEB128",
            ),
            (
                "custom name longer than payload",
                vec![0x00, 0x02, 0x05, b'a'],
                "name length",
            ),
            (
                "custom name spans into next section",
                vec![0x00, 0x02, 0x03, b'a', 0x00, 0x00],
                "name length",
            ),
            (
                "custom name invalid utf-8",
                vec![0x00, 0x03, 0x02, 0xff, 0xfe],
                "not UTF-8",
            ),
            (
                "custom name overlong utf-8",
                vec![0x00, 0x03, 0x02, 0xc0, 0x80],
                "not UTF-8",
            ),
            (
                "section size u32::MAX",
                vec![0x00, 0xff, 0xff, 0xff, 0xff, 0x0f],
                "claims 4294967295 bytes",
            ),
            (
                "section size 5-byte high bits",
                vec![0x00, 0xff, 0xff, 0xff, 0xff, 0x7f],
                "LEB128",
            ),
            (
                "section size truncated",
                vec![0x01, 0x80],
                "truncated LEB128",
            ),
            ("section id only", vec![0x07], "truncated LEB128"),
            (
                "non-custom oversize",
                vec![0x01, 0x10, 0x00],
                "only 1 remain",
            ),
        ];
        for (label, tail, needle) in faults {
            let mut bytes = with_manifest();
            bytes.extend_from_slice(&tail);
            match parse(&bytes) {
                Err(PolicyPackageError::Malformed(reason)) => {
                    assert!(
                        reason.contains(needle),
                        "{label}: {reason:?} lacks {needle:?}"
                    );
                }
                other => panic!("{label}: expected Malformed, got {other:?}"),
            }
        }

        // Non-minimal (but at most 5-byte) LEB128 sizes are legal WASM and
        // the digest still covers the exact bytes, so both encodings differ.
        let minimal_manifest =
            encode_custom_section(MANIFEST_SECTION_NAME, &manifest().to_json().unwrap());
        let mut body = Vec::new();
        write_leb128_u32(
            &mut body,
            u32::try_from(MANIFEST_SECTION_NAME.len()).unwrap(),
        );
        body.extend_from_slice(MANIFEST_SECTION_NAME.as_bytes());
        body.extend_from_slice(&manifest().to_json().unwrap());
        let size = u32::try_from(body.len()).unwrap();
        assert!(size < 128 * 128, "fixture stays within two-byte LEB");
        let mut padded_manifest = vec![
            0x00,
            (size & 0x7f) as u8 | 0x80,
            ((size >> 7) & 0x7f) as u8 | 0x80,
            0x00,
        ];
        padded_manifest.extend_from_slice(&body);
        assert_eq!(padded_manifest.len(), minimal_manifest.len() + 1);
        let mut a = bare_component();
        a.extend_from_slice(&minimal_manifest);
        let mut b = bare_component();
        b.extend_from_slice(&padded_manifest);
        let package_a = parse(&a).unwrap();
        let package_b = parse(&b).unwrap();
        assert_eq!(package_a.manifest, package_b.manifest);
        assert_ne!(package_a.digest, package_b.digest);

        // Custom section budget: exactly at the limit passes, one byte over
        // fails, and the budget is the sum over all custom sections.
        let base = with_manifest();
        let used: usize = parse(&base)
            .unwrap()
            .sections
            .iter()
            .filter(|section| section.id == 0)
            .map(|section| {
                let name_len = section.name.as_deref().unwrap().len();
                leb_len(name_len) + name_len + section.payload_len
            })
            .sum();
        let pad_section =
            |content_len: usize| encode_custom_section("pad", &vec![0u8; content_len]);
        // The budget counts each section's size field: name length LEB,
        // name and content.
        let room = MAXIMUM_CUSTOM_SECTION_BYTES - used - leb_len("pad".len()) - "pad".len();
        let mut exact = base.clone();
        exact.extend_from_slice(&pad_section(room));
        assert!(parse(&exact).is_ok());
        let mut over = base.clone();
        over.extend_from_slice(&pad_section(room + 1));
        assert!(is_malformed(parse(&over), "custom sections total"));
        let mut split = base.clone();
        split.extend_from_slice(&pad_section(room / 2));
        split.extend_from_slice(&pad_section(
            room - room / 2 - "pad".len() - leb_len("pad".len()) + 1,
        ));
        assert!(is_malformed(parse(&split), "custom sections total"));

        // The file limit is checked before anything else, including magic.
        let tiny = PackageLimits {
            maximum_module_bytes: 7,
            maximum_custom_section_bytes: MAXIMUM_CUSTOM_SECTION_BYTES,
        };
        assert!(matches!(
            PolicyPackage::parse(&COMPONENT_HEADER, tiny),
            Err(PolicyPackageError::Malformed(reason)) if reason.contains("maximum_module_bytes")
        ));
        assert!(matches!(
            PolicyPackage::parse(b"", tiny),
            Err(PolicyPackageError::Malformed(reason)) if reason.contains("shorter than")
        ));
    }

    /// Encoded length of `value` as LEB128 u32.
    fn leb_len(value: usize) -> usize {
        let mut out = Vec::new();
        write_leb128_u32(&mut out, u32::try_from(value).unwrap());
        out.len()
    }
}
