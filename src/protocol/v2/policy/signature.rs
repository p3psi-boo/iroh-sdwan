//! Ed25519 signing keys, text encodings and the sealed trust store for
//! single-file WASM policy packages.
//!
//! This module is byte-level only: it never touches the WASM runtime. The
//! signature covers a BLAKE3 digest with a fixed domain separator:
//!
//! ```text
//! signature = Ed25519Sign("ironet-policy-v1\0" || digest)
//! ```

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ring::rand::SecureRandom;

use crate::config::{AutotuneSignerConfig, AutotuneWasmConfig};

/// Domain separator prepended to the digest before signing.
pub const SIGNATURE_DOMAIN_V1: &[u8] = b"ironet-policy-v1\0";
/// Text prefix of public keys and signatures.
pub const PUBLIC_KEY_PREFIX: &str = "ed25519:";
/// Text prefix of secret keys stored on disk.
pub const SECRET_KEY_PREFIX: &str = "ed25519-secret:";
/// Text prefix of signatures in the signature section.
pub const SIGNATURE_PREFIX: &str = "ed25519:";
/// Text prefix of BLAKE3 digests (signature section and `digest_pins`).
pub const DIGEST_PREFIX: &str = "blake3:";

const KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const DIGEST_LEN: usize = 32;
/// 32 bytes in RFC 4648 base32 without padding.
const KEY_BASE32_LEN: usize = 52;
/// Hex length of the default signer id (first 8 bytes of BLAKE3(public key)).
const DEFAULT_SIGNER_ID_BYTES: usize = 8;

/// Ed25519 signing key used by `ironet policy keygen` / `sign`.
#[derive(Clone)]
pub struct PolicySigningKey(SigningKey);

impl std::fmt::Debug for PolicySigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PolicySigningKey")
            .field(&self.public().encode())
            .finish()
    }
}

impl PolicySigningKey {
    /// Generates a fresh key from the system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; KEY_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| anyhow::anyhow!("system random generator unavailable"))?;
        Ok(Self::from_bytes(&seed))
    }

    pub fn from_bytes(seed: &[u8; KEY_LEN]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    pub fn public(&self) -> PolicyPublicKey {
        PolicyPublicKey(self.0.verifying_key())
    }

    /// Signs a BLAKE3 digest with the `ironet-policy-v1` domain separator.
    pub fn sign_digest(&self, digest: &[u8; DIGEST_LEN]) -> [u8; SIGNATURE_LEN] {
        self.0.sign(&signing_message(digest)).to_bytes()
    }

    /// `ed25519-secret:<64 hex>`.
    pub fn encode(&self) -> String {
        format!("{SECRET_KEY_PREFIX}{}", hex::encode(self.to_bytes()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let Some(encoded) = text.strip_prefix(SECRET_KEY_PREFIX) else {
            bail!("signing key must start with {SECRET_KEY_PREFIX:?}");
        };
        let seed: [u8; KEY_LEN] = decode_hex_array(encoded)
            .with_context(|| format!("signing key must be {SECRET_KEY_PREFIX}<64 hex chars>"))?;
        Ok(Self::from_bytes(&seed))
    }

    /// Writes the key as a single `ed25519-secret:<hex>` line with mode 0600.
    pub fn write_file(&self, path: &Path) -> Result<()> {
        let contents = format!("{}\n", self.encode());
        crate::deployment::atomic_write(path, contents.as_bytes(), 0o600)
            .with_context(|| format!("failed writing signing key {}", path.display()))
    }

    pub fn read_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed reading signing key {}", path.display()))?;
        Self::parse(&contents).with_context(|| format!("invalid signing key {}", path.display()))
    }
}

/// Ed25519 public key of a policy signer.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyPublicKey(VerifyingKey);

impl std::fmt::Debug for PolicyPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PolicyPublicKey")
            .field(&self.encode())
            .finish()
    }
}

impl std::fmt::Display for PolicyPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl PolicyPublicKey {
    pub fn from_bytes(bytes: &[u8; KEY_LEN]) -> Result<Self> {
        let key = VerifyingKey::from_bytes(bytes).context("invalid ed25519 public key")?;
        Ok(Self(key))
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0.to_bytes()
    }

    /// `ed25519:<64 hex>`.
    pub fn encode(&self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", hex::encode(self.to_bytes()))
    }

    /// Accepts `ed25519:<64 hex>` and `ed25519:<52 base32>` (optional `====`
    /// padding, either letter case).
    pub fn parse(text: &str) -> Result<Self> {
        let text = text.trim();
        let Some(encoded) = text.strip_prefix(PUBLIC_KEY_PREFIX) else {
            bail!("public key must start with {PUBLIC_KEY_PREFIX:?}, got {text:?}");
        };
        let bytes: [u8; KEY_LEN] = if encoded.len() == KEY_LEN * 2 {
            decode_hex_array(encoded).context("public key hex must be 64 characters")?
        } else {
            decode_base32_key(encoded).with_context(|| {
                format!(
                    "public key must be {PUBLIC_KEY_PREFIX}<64 hex chars> or {PUBLIC_KEY_PREFIX}<52 base32 chars>, got {text:?}"
                )
            })?
        };
        Self::from_bytes(&bytes)
    }

    /// Default `signer_id`: first 8 bytes of BLAKE3(public key) in hex.
    pub fn default_signer_id(&self) -> String {
        hex::encode(&blake3::hash(&self.to_bytes()).as_bytes()[..DEFAULT_SIGNER_ID_BYTES])
    }

    /// Verifies a domain-separated digest signature (strict, non-malleable).
    pub fn verify_digest(
        &self,
        digest: &[u8; DIGEST_LEN],
        signature: &[u8; SIGNATURE_LEN],
    ) -> bool {
        let signature = Signature::from_bytes(signature);
        self.0
            .verify_strict(&signing_message(digest), &signature)
            .is_ok()
    }
}

fn signing_message(digest: &[u8; DIGEST_LEN]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN_V1.len() + DIGEST_LEN);
    message.extend_from_slice(SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(digest);
    message
}

/// `ed25519:<128 hex>`.
pub fn encode_signature(signature: &[u8; SIGNATURE_LEN]) -> String {
    format!("{SIGNATURE_PREFIX}{}", hex::encode(signature))
}

pub fn parse_signature(text: &str) -> Result<[u8; SIGNATURE_LEN]> {
    let Some(encoded) = text.strip_prefix(SIGNATURE_PREFIX) else {
        bail!("signature must start with {SIGNATURE_PREFIX:?}");
    };
    decode_hex_array(encoded).context("signature must be ed25519:<128 hex chars>")
}

/// `blake3:<64 hex>`.
pub fn encode_digest(digest: &[u8; DIGEST_LEN]) -> String {
    format!("{DIGEST_PREFIX}{}", hex::encode(digest))
}

pub fn parse_digest(text: &str) -> Result<[u8; DIGEST_LEN]> {
    let Some(encoded) = text.trim().strip_prefix(DIGEST_PREFIX) else {
        bail!("digest must start with {DIGEST_PREFIX:?}, got {text:?}");
    };
    decode_hex_array(encoded).context("digest must be blake3:<64 hex chars>")
}

fn decode_hex_array<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    ensure!(
        encoded.len() == N * 2,
        "expected {} hex characters, got {}",
        N * 2,
        encoded.len()
    );
    let mut out = [0u8; N];
    hex::decode_to_slice(encoded, &mut out).context("invalid hex")?;
    Ok(out)
}

/// RFC 4648 base32 (no padding or `====`) of exactly 32 bytes.
fn decode_base32_key(encoded: &str) -> Result<[u8; KEY_LEN]> {
    let unpadded = encoded.strip_suffix("====").unwrap_or(encoded);
    ensure!(
        unpadded.len() == KEY_BASE32_LEN,
        "base32 key must be {KEY_BASE32_LEN} characters"
    );
    let mut out = [0u8; KEY_LEN];
    let mut buffer: u64 = 0;
    let mut bits = 0u32;
    let mut index = 0usize;
    for byte in unpadded.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => bail!("invalid base32 character {:?}", char::from(byte)),
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if index < KEY_LEN {
                out[index] = ((buffer >> bits) & 0xff) as u8;
                index += 1;
            }
        }
    }
    ensure!(index == KEY_LEN, "base32 key decodes to {index} bytes");
    // 52 characters carry 260 bits; the trailing 4 bits must be zero so that
    // each key has exactly one canonical encoding.
    ensure!(
        buffer & ((1u64 << bits) - 1) == 0,
        "base32 key has non-zero trailing bits"
    );
    Ok(out)
}

/// One trusted signer from sealed configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSigner {
    pub signer_id: String,
    pub public_key: PolicyPublicKey,
    /// Rollback floor for `policy_version`.
    pub minimum_policy_version: u64,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Host trust store derived from `[autotune.wasm]`.
///
/// Built from sealed configuration only; a module's self-reported key never
/// counts as trust.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustStoreV1 {
    pub require_signature: bool,
    signers: BTreeMap<String, TrustedSigner>,
    digest_pins: BTreeSet<[u8; DIGEST_LEN]>,
}

impl TrustStoreV1 {
    pub fn from_config(config: &AutotuneWasmConfig) -> Result<Self> {
        let mut store = Self {
            require_signature: config.require_signature,
            ..Self::default()
        };
        for signer in &config.signers {
            store.add_signer(TrustedSigner::from_config(signer)?)?;
        }
        for pin in &config.digest_pins {
            store.add_digest_pin(parse_digest(pin).context("autotune.wasm.digest_pins")?);
        }
        Ok(store)
    }

    /// Signature-only store with an explicit signer list.
    pub fn with_signers(signers: impl IntoIterator<Item = TrustedSigner>) -> Result<Self> {
        let mut store = Self {
            require_signature: true,
            ..Self::default()
        };
        for signer in signers {
            store.add_signer(signer)?;
        }
        Ok(store)
    }

    /// Development store: unsigned packages are accepted when their digest
    /// is pinned; signed packages are still fully verified against `signers`.
    pub fn with_digest_pins(pins: impl IntoIterator<Item = [u8; DIGEST_LEN]>) -> Self {
        let mut store = Self {
            require_signature: false,
            ..Self::default()
        };
        for pin in pins {
            store.add_digest_pin(pin);
        }
        store
    }

    pub fn add_signer(&mut self, signer: TrustedSigner) -> Result<()> {
        let signer_id = signer.signer_id.trim().to_owned();
        ensure!(!signer_id.is_empty(), "signer_id cannot be empty");
        ensure!(
            !self.signers.contains_key(&signer_id),
            "duplicate signer_id {signer_id:?}"
        );
        self.signers.insert(signer_id, signer);
        Ok(())
    }

    pub fn add_digest_pin(&mut self, digest: [u8; DIGEST_LEN]) {
        self.digest_pins.insert(digest);
    }

    pub fn signer(&self, signer_id: &str) -> Option<&TrustedSigner> {
        self.signers.get(signer_id.trim())
    }

    pub fn signers(&self) -> impl Iterator<Item = &TrustedSigner> {
        self.signers.values()
    }

    pub fn is_pinned(&self, digest: &[u8; DIGEST_LEN]) -> bool {
        self.digest_pins.contains(digest)
    }

    pub fn digest_pins(&self) -> impl Iterator<Item = &[u8; DIGEST_LEN]> {
        self.digest_pins.iter()
    }
}

impl TrustedSigner {
    pub fn from_config(config: &AutotuneSignerConfig) -> Result<Self> {
        let signer_id = config.signer_id.trim().to_owned();
        ensure!(
            !signer_id.is_empty(),
            "autotune.wasm.signers: signer_id cannot be empty"
        );
        let public_key = PolicyPublicKey::parse(&config.public_key)
            .with_context(|| format!("autotune.wasm.signers[{signer_id}].public_key"))?;
        let expires_at = config
            .expires_at
            .as_deref()
            .map(|value| {
                DateTime::parse_from_rfc3339(value.trim())
                    .map(|timestamp| timestamp.with_timezone(&Utc))
                    .with_context(|| {
                        format!(
                            "autotune.wasm.signers[{signer_id}].expires_at must be RFC 3339, got {value:?}"
                        )
                    })
            })
            .transpose()?;
        Ok(Self {
            signer_id,
            public_key,
            minimum_policy_version: config.minimum_policy_version,
            expires_at,
        })
    }

    /// Signer with the key's default id, no rollback floor and no expiry.
    pub fn new(public_key: PolicyPublicKey) -> Self {
        Self {
            signer_id: public_key.default_signer_id(),
            public_key,
            minimum_policy_version: 0,
            expires_at: None,
        }
    }

    pub fn with_signer_id(mut self, signer_id: impl Into<String>) -> Self {
        self.signer_id = signer_id.into();
        self
    }

    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> PolicySigningKey {
        PolicySigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn key_text_round_trips_in_hex_and_base32() {
        let key = fixed_key();
        let parsed = PolicySigningKey::parse(&format!("  {}\n", key.encode())).unwrap();
        assert_eq!(parsed.to_bytes(), key.to_bytes());

        let public = key.public();
        assert_eq!(PolicyPublicKey::parse(&public.encode()).unwrap(), public);

        // Hand-encode to base32 and make sure the decoder agrees.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bytes = public.to_bytes();
        let mut buffer = 0u64;
        let mut bits = 0u32;
        let mut base32 = String::new();
        for byte in bytes {
            buffer = (buffer << 8) | u64::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                base32.push(char::from(alphabet[((buffer >> bits) & 0x1f) as usize]));
            }
        }
        base32.push(char::from(
            alphabet[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
        assert_eq!(base32.len(), 52);
        let upper = format!("ed25519:{base32}");
        assert_eq!(PolicyPublicKey::parse(&upper).unwrap(), public);
        let padded = format!("ed25519:{base32}====");
        assert_eq!(PolicyPublicKey::parse(&padded).unwrap(), public);
        let lower = format!("ed25519:{}", base32.to_ascii_lowercase());
        assert_eq!(PolicyPublicKey::parse(&lower).unwrap(), public);

        assert!(PolicyPublicKey::parse("ed25519:zz").is_err());
        assert!(PolicyPublicKey::parse("rsa:00").is_err());
        assert!(PolicySigningKey::parse("ed25519:0000").is_err());
        assert_eq!(public.default_signer_id().len(), 16);
    }

    #[test]
    fn domain_separated_signature_verifies_only_for_same_digest() {
        let key = fixed_key();
        let digest = blake3::hash(b"policy").into();
        let signature = key.sign_digest(&digest);
        assert!(key.public().verify_digest(&digest, &signature));
        let other: [u8; 32] = blake3::hash(b"other").into();
        assert!(!key.public().verify_digest(&other, &signature));
        let mut flipped = signature;
        flipped[3] ^= 0x01;
        assert!(!key.public().verify_digest(&digest, &flipped));
        let encoded = encode_signature(&signature);
        assert_eq!(parse_signature(&encoded).unwrap(), signature);
        let encoded_digest = encode_digest(&digest);
        assert_eq!(parse_digest(&encoded_digest).unwrap(), digest);
    }

    #[test]
    fn trust_store_from_config_parses_signers_and_pins() {
        let key = fixed_key();
        let config = AutotuneWasmConfig {
            require_signature: true,
            signers: vec![AutotuneSignerConfig {
                signer_id: "ops-2026".into(),
                public_key: key.public().encode(),
                minimum_policy_version: 3,
                expires_at: Some("2027-01-01T00:00:00Z".into()),
            }],
            digest_pins: vec![encode_digest(&[1u8; 32])],
            ..AutotuneWasmConfig::default()
        };
        let store = TrustStoreV1::from_config(&config).unwrap();
        assert!(store.require_signature);
        let signer = store.signer("ops-2026").unwrap();
        assert_eq!(signer.minimum_policy_version, 3);
        assert_eq!(signer.public_key, key.public());
        assert!(signer.is_expired_at("2027-01-01T00:00:00Z".parse().unwrap()));
        assert!(!signer.is_expired_at("2026-12-31T23:59:59Z".parse().unwrap()));
        assert!(store.is_pinned(&[1u8; 32]));
        assert!(!store.is_pinned(&[2u8; 32]));

        let bad_expiry = AutotuneWasmConfig {
            signers: vec![AutotuneSignerConfig {
                signer_id: "x".into(),
                public_key: key.public().encode(),
                minimum_policy_version: 0,
                expires_at: Some("tomorrow".into()),
            }],
            ..AutotuneWasmConfig::default()
        };
        assert!(TrustStoreV1::from_config(&bad_expiry).is_err());
        let bad_pin = AutotuneWasmConfig {
            digest_pins: vec!["sha256:00".into()],
            ..AutotuneWasmConfig::default()
        };
        assert!(TrustStoreV1::from_config(&bad_pin).is_err());
    }

    #[test]
    fn key_file_round_trip_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("signer.key");
        let key = PolicySigningKey::generate().unwrap();
        key.write_file(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let loaded = PolicySigningKey::read_file(&path).unwrap();
        assert_eq!(loaded.to_bytes(), key.to_bytes());
    }

    #[test]
    fn digest_and_signature_text_reject_malformed_encodings() {
        let digest = [0x5au8; 32];
        let encoded = encode_digest(&digest);
        assert_eq!(parse_digest(&encoded).unwrap(), digest);
        // Surrounding whitespace is tolerated, upper-case hex decodes to the
        // same bytes (the canonical form written by `encode_digest` is lower).
        assert_eq!(parse_digest(&format!(" {encoded}\n")).unwrap(), digest);
        assert_eq!(
            parse_digest(&format!("blake3:{}", "5A".repeat(32))).unwrap(),
            digest
        );
        for bad in [
            "",
            "blake3:",
            "blake3",
            "sha256:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "blake3:zz5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "blake3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
            "BLAKE3:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        ] {
            assert!(parse_digest(bad).is_err(), "digest {bad:?} accepted");
        }

        let signature = [0xa5u8; 64];
        let encoded = encode_signature(&signature);
        assert_eq!(parse_signature(&encoded).unwrap(), signature);
        let hex128 = "a5".repeat(64);
        for bad in [
            String::new(),
            "ed25519:".to_owned(),
            hex128.clone(),
            format!("rsa:{hex128}"),
            format!("ED25519:{hex128}"),
            format!("ed25519:{}", &hex128[..126]),
            format!("ed25519:{hex128}a5"),
            format!("ed25519:{}zz", &hex128[..126]),
            format!("ed25519:{hex128}\n"),
            format!(" ed25519:{hex128}"),
        ] {
            assert!(parse_signature(&bad).is_err(), "signature {bad:?} accepted");
        }
        // Upper-case hex decodes to the same bytes, as for digests.
        assert_eq!(
            parse_signature(&format!("ed25519:{}", "A5".repeat(64))).unwrap(),
            signature
        );
    }

    #[test]
    fn public_key_parse_rejects_bad_length_alphabet_trailing_bits_and_points() {
        let public = fixed_key().public();
        let hex64 = hex::encode(public.to_bytes());
        // Upper-case hex is the same key; everything else is rejected.
        assert_eq!(
            PolicyPublicKey::parse(&format!("ed25519:{}", hex64.to_ascii_uppercase())).unwrap(),
            public
        );
        for bad in [
            String::new(),
            "ed25519:".to_owned(),
            hex64.clone(),
            format!("ed25519:{}", &hex64[..62]),
            format!("ed25519:{hex64}00"),
            format!("ed25519:{}zz", &hex64[..62]),
            format!("ed25519-secret:{hex64}"),
        ] {
            assert!(
                PolicyPublicKey::parse(&bad).is_err(),
                "key {bad:?} accepted"
            );
        }

        // Canonical base32 of the key; then perturb it.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut buffer = 0u64;
        let mut bits = 0u32;
        let mut base32 = String::new();
        for byte in public.to_bytes() {
            buffer = (buffer << 8) | u64::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                base32.push(char::from(alphabet[((buffer >> bits) & 0x1f) as usize]));
            }
        }
        base32.push(char::from(
            alphabet[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
        assert_eq!(
            PolicyPublicKey::parse(&format!("ed25519:{base32}")).unwrap(),
            public
        );
        // The last symbol carries one key bit plus 4 padding bits that must
        // be zero: any other padding would be a second encoding of the key.
        let last = base32.pop().unwrap();
        let last_value = alphabet
            .iter()
            .position(|c| char::from(*c) == last)
            .unwrap();
        assert_eq!(last_value & 0x0f, 0, "canonical encoding has zero padding");
        for (value, symbol) in alphabet.iter().enumerate() {
            let mut candidate = base32.clone();
            candidate.push(char::from(*symbol));
            let parsed = PolicyPublicKey::parse(&format!("ed25519:{candidate}"));
            if value == last_value {
                assert_eq!(parsed.unwrap(), public);
            } else if value & 0x0f != 0 {
                assert!(
                    parsed.is_err(),
                    "non-canonical trailing char {value} accepted"
                );
            } else if let Ok(other) = parsed {
                // Different top bit: a different key, never ours.
                assert_ne!(other, public);
            }
        }
        base32.push(last);
        for bad in [
            format!("ed25519:{}", &base32[..51]),
            format!("ed25519:{base32}A"),
            format!("ed25519:{base32}="),
            format!("ed25519:{base32}====="),
            format!("ed25519:{base32}======"),
            format!("ed25519:{}====", &base32[..51]),
            format!("ed25519:{}0", &base32[..51]),
            format!("ed25519:{}1", &base32[..51]),
            format!("ed25519:{}8", &base32[..51]),
            format!("ed25519:{}-", &base32[..51]),
            // 64 characters but not hex: must not be mistaken for hex.
            format!("ed25519:{}{}", base32, "x".repeat(12)),
        ] {
            assert!(
                PolicyPublicKey::parse(&bad).is_err(),
                "key {bad:?} accepted"
            );
        }

        // 32 well-formed bytes that are not a curve point.
        assert!(PolicyPublicKey::from_bytes(&[2u8; 32]).is_err());
        assert!(PolicyPublicKey::parse(&format!("ed25519:{}", "02".repeat(32))).is_err());

        // Secret keys only accept their own prefix and hex.
        let secret = fixed_key();
        for bad in [
            secret.public().encode(),
            format!("ed25519-secret:{}", &hex::encode(secret.to_bytes())[..62]),
            format!("ed25519-secret:{}00", hex::encode(secret.to_bytes())),
            format!("ed25519-secret:{base32}"),
            "ed25519-secret:".to_owned(),
        ] {
            assert!(
                PolicySigningKey::parse(&bad).is_err(),
                "secret {bad:?} accepted"
            );
        }
    }

    #[test]
    fn signature_rejects_other_domains_keys_and_non_canonical_scalars() {
        let key = fixed_key();
        let public = key.public();
        let digest: [u8; 32] = blake3::hash(b"policy").into();
        let signature = key.sign_digest(&digest);
        assert!(public.verify_digest(&digest, &signature));

        // Same key, same digest, but signed without the domain separator or
        // under a different one: never accepted.
        let raw_key = SigningKey::from_bytes(&key.to_bytes());
        let undomained = raw_key.sign(&digest).to_bytes();
        assert!(!public.verify_digest(&digest, &undomained));
        let mut other_domain = b"ironet-policy-v2\0".to_vec();
        other_domain.extend_from_slice(&digest);
        assert!(!public.verify_digest(&digest, &raw_key.sign(&other_domain).to_bytes()));
        let mut unterminated = b"ironet-policy-v1".to_vec();
        unterminated.extend_from_slice(&digest);
        assert!(!public.verify_digest(&digest, &raw_key.sign(&unterminated).to_bytes()));

        // Another key's signature over the same message.
        let other = PolicySigningKey::from_bytes(&[8u8; 32]);
        assert!(!public.verify_digest(&digest, &other.sign_digest(&digest)));
        assert!(!other.public().verify_digest(&digest, &signature));

        // Degenerate encodings.
        assert!(!public.verify_digest(&digest, &[0u8; 64]));
        assert!(!public.verify_digest(&digest, &[0xffu8; 64]));
        let mut swapped = [0u8; 64];
        swapped[..32].copy_from_slice(&signature[32..]);
        swapped[32..].copy_from_slice(&signature[..32]);
        assert!(!public.verify_digest(&digest, &swapped));

        // Malleability: s + L is the same scalar mod L; strict verification
        // must reject the non-canonical encoding so that exactly one
        // signature string verifies.
        const GROUP_ORDER_LE: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut malleable = signature;
        let mut carry = 0u16;
        for index in 0..32 {
            let sum = u16::from(signature[32 + index]) + u16::from(GROUP_ORDER_LE[index]) + carry;
            malleable[32 + index] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "s + L must fit in 256 bits");
        assert_ne!(malleable, signature);
        assert!(!public.verify_digest(&digest, &malleable));

        // Every single-bit flip anywhere in the signature is rejected.
        for bit in 0..64 * 8 {
            let mut flipped = signature;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(!public.verify_digest(&digest, &flipped), "bit {bit}");
        }
        // And every single-bit flip of the digest.
        for bit in 0..32 * 8 {
            let mut flipped = digest;
            flipped[bit / 8] ^= 1 << (bit % 8);
            assert!(
                !public.verify_digest(&flipped, &signature),
                "digest bit {bit}"
            );
        }
    }

    #[test]
    fn trust_store_rejects_duplicate_blank_and_invalid_signers() {
        let key = fixed_key();
        let signer = |id: &str| TrustedSigner {
            signer_id: id.into(),
            public_key: key.public(),
            minimum_policy_version: 0,
            expires_at: None,
        };
        // Ids are compared after trimming, so " ops" and "ops" collide.
        assert!(TrustStoreV1::with_signers([signer("ops"), signer(" ops ")]).is_err());
        assert!(TrustStoreV1::with_signers([signer("")]).is_err());
        assert!(TrustStoreV1::with_signers([signer("  \t")]).is_err());
        let store = TrustStoreV1::with_signers([signer(" ops ")]).unwrap();
        assert!(store.require_signature);
        assert!(store.signer("ops").is_some());
        assert!(store.signer("  ops").is_some());
        assert!(store.signer("ops2").is_none());
        assert!(store.signer("").is_none());
        assert_eq!(store.signers().count(), 1);
        assert_eq!(store.digest_pins().count(), 0);

        // Different ids for the same key are allowed (rotation overlap).
        let both = TrustStoreV1::with_signers([signer("ops-2026"), signer("ops-2027")]).unwrap();
        assert_eq!(both.signers().count(), 2);

        // Config path: duplicates, blank ids and bad keys are all errors.
        let config_signer = |id: &str, public_key: String| AutotuneSignerConfig {
            signer_id: id.into(),
            public_key,
            minimum_policy_version: 0,
            expires_at: None,
        };
        let duplicate = AutotuneWasmConfig {
            signers: vec![
                config_signer("ops", key.public().encode()),
                config_signer(
                    "ops",
                    PolicySigningKey::from_bytes(&[9u8; 32]).public().encode(),
                ),
            ],
            ..AutotuneWasmConfig::default()
        };
        assert!(TrustStoreV1::from_config(&duplicate).is_err());
        let blank = AutotuneWasmConfig {
            signers: vec![config_signer("   ", key.public().encode())],
            ..AutotuneWasmConfig::default()
        };
        assert!(TrustStoreV1::from_config(&blank).is_err());
        for bad_key in [
            String::new(),
            "ed25519:".to_owned(),
            format!("ed25519:{}", "02".repeat(32)),
            key.encode(),
        ] {
            let config = AutotuneWasmConfig {
                signers: vec![config_signer("ops", bad_key.clone())],
                ..AutotuneWasmConfig::default()
            };
            assert!(
                TrustStoreV1::from_config(&config).is_err(),
                "public_key {bad_key:?} accepted"
            );
        }
        // Duplicate pins collapse; pins never imply trust in a signer.
        let pins = TrustStoreV1::with_digest_pins([[3u8; 32], [3u8; 32]]);
        assert!(!pins.require_signature);
        assert_eq!(pins.digest_pins().count(), 1);
        assert!(pins.signer("ops").is_none());
    }
}
