//! TLS configuration for iroh.
//!
//! Currently there is one mechanism available:
//! - Raw Public Keys, using the TLS extension described in [RFC 7250]
//!
//! [RFC 7250]: https://datatracker.ietf.org/doc/html/rfc7250

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
};

use iroh_base::{PublicKey, SecretKey};
use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use tracing::warn;

use self::resolver::ResolveRawPublicKeyCert;
use crate::endpoint::TlsSessionPartition;

pub(crate) mod misc;
mod resolver;
mod verifier;

/// Identity-neutral SNI used by generic iroh callers that do not select an
/// application cover profile. Ironet always overrides this through
/// `ConnectOptions`, but the fallback must never encode the authenticated
/// EndpointId into the public ClientHello.
pub(crate) const DEFAULT_VISIBLE_SERVER_NAME: &str = "media.example";

#[allow(deprecated)] // Re-export of backwards-compatibility item
pub use iroh_relay::tls::CaRootsConfig;
pub use iroh_relay::tls::CaTlsConfig;
#[cfg(with_crypto_provider)]
pub use iroh_relay::tls::default_provider;

/// Maximum amount of TLS tickets we will cache (by default) for 0-RTT connection
/// establishment.
///
/// 8 tickets per remote endpoint, 32 different endpoints would max out the required storage:
/// ~200 bytes per session + certificates (which are ~387 bytes)
/// So 8 * 32 * (200 + 387) = 150.272 bytes, assuming pointers to certificates
/// are never aliased pointers (they're Arc'ed).
/// I think 150KB is an acceptable default upper limit for such a cache.
pub(crate) const DEFAULT_MAX_TLS_TICKETS: usize = 8 * 32;
// rustls rounds this value into eight-ticket server-name buckets. Its bounded
// cache deliberately evicts when the allocation becomes full so the *next*
// insertion cannot allocate; one nominal bucket therefore retains zero
// entries. Reserve two nominal buckets for one effective server-name entry.
const TLS_TICKETS_PER_PARTITION: usize = 16;

#[derive(Debug, Clone)]
struct PeerClientState {
    verifier: Arc<verifier::ServerCertificateVerifier>,
    session_store: Arc<dyn rustls::client::ClientSessionStore>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PeerClientKey {
    peer: PublicKey,
    network_id: String,
    cover_profile: u32,
    quic_version: u32,
}

#[derive(Debug, Default)]
struct PeerClientCache {
    entries: HashMap<PeerClientKey, PeerClientState>,
    order: VecDeque<PeerClientKey>,
}

impl PeerClientCache {
    fn get_or_insert(&mut self, key: PeerClientKey, maximum_peers: usize) -> PeerClientState {
        if let Some(state) = self.entries.get(&key).cloned() {
            self.order.retain(|candidate| candidate != &key);
            self.order.push_back(key);
            return state;
        }
        while self.entries.len() >= maximum_peers {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        let state = PeerClientState {
            verifier: Arc::new(verifier::ServerCertificateVerifier::for_peer(key.peer)),
            session_store: Arc::new(rustls::client::ClientSessionMemoryCache::new(
                TLS_TICKETS_PER_PARTITION,
            )),
        };
        self.entries.insert(key.clone(), state.clone());
        self.order.push_back(key);
        state
    }
}

/// Configuration for TLS.
///
/// The main point of this struct is to keep state that should be kept the same
/// over multiple TLS sessions the same.
/// E.g. the per-peer server verifier and client verifier Arc pointers are checked
/// to be the same between different TLS session calls with 0-RTT data in rustls.
/// This makes sure that's the case without sharing tickets across peer identities.
#[derive(Debug)]
pub(crate) struct TlsConfig {
    pub(crate) secret_key: SecretKey,
    cert_resolver: Arc<ResolveRawPublicKeyCert>,
    client_verifier: Arc<verifier::ClientCertificateVerifier>,
    peer_clients: Mutex<PeerClientCache>,
    maximum_peer_clients: usize,
    early_data: bool,
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
}

impl TlsConfig {
    pub(crate) fn new(
        secret_key: SecretKey,
        max_tls_tickets: usize,
        early_data: bool,
        crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Self {
        Self {
            cert_resolver: Arc::new(ResolveRawPublicKeyCert::new(&secret_key)),
            client_verifier: Arc::new(verifier::ClientCertificateVerifier),
            peer_clients: Mutex::new(PeerClientCache::default()),
            maximum_peer_clients: max_tls_tickets.div_ceil(TLS_TICKETS_PER_PARTITION).max(1),
            early_data,
            crypto_provider,
            secret_key,
        }
    }

    pub(crate) fn make_client_config_for_peer(
        &self,
        peer: PublicKey,
        partition: Option<&TlsSessionPartition>,
        keylog: bool,
    ) -> Result<QuicClientConfig, TlsConfigError> {
        let key = PeerClientKey {
            peer,
            network_id: partition
                .map(|partition| partition.network_id.clone())
                .unwrap_or_default(),
            cover_profile: partition.map_or(0, |partition| partition.cover_profile),
            quic_version: partition.map_or(0, |partition| partition.quic_version),
        };
        let state = self
            .peer_clients
            .lock()
            .expect("peer TLS cache lock poisoned")
            .get_or_insert(key, self.maximum_peer_clients);
        self.make_client_config_inner(state.verifier, state.session_store, keylog)
    }

    fn make_client_config_inner(
        &self,
        verifier: Arc<verifier::ServerCertificateVerifier>,
        session_store: Arc<dyn rustls::client::ClientSessionStore>,
        keylog: bool,
    ) -> Result<QuicClientConfig, TlsConfigError> {
        let mut crypto = rustls::ClientConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(self.cert_resolver.clone());

        crypto.resumption = rustls::client::Resumption::store(session_store);
        crypto.enable_early_data = self.early_data;

        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let quic = QuicClientConfig::try_from(crypto)?;
        Ok(quic)
    }

    /// Create a TLS server configuration.
    ///
    /// If *keylog* is `true` this will enable logging of the pre-master key to the file in the
    /// `SSLKEYLOGFILE` environment variable.  This can be used to inspect the traffic for
    /// debugging purposes.
    pub(crate) fn make_server_config(
        &self,
        keylog: bool,
    ) -> Result<QuicServerConfig, TlsConfigError> {
        let mut crypto = rustls::ServerConfig::builder_with_provider(self.crypto_provider.clone())
            .with_protocol_versions(verifier::PROTOCOL_VERSIONS)?
            .with_client_cert_verifier(self.client_verifier.clone())
            .with_cert_resolver(self.cert_resolver.clone());
        if keylog {
            warn!("enabling SSLKEYLOGFILE for TLS pre-master keys");
            crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        // must be u32::MAX or 0 (the default). Any other value panics with QUIC
        // This is specified in RFC 9001: https://www.rfc-editor.org/rfc/rfc9001#section-4.6.1
        crypto.max_early_data_size = if self.early_data { u32::MAX } else { 0 };
        let quic = QuicServerConfig::try_from(crypto)?;
        Ok(quic)
    }
}

#[allow(missing_docs)]
#[n0_error::stack_error(derive, add_meta, from_sources)]
#[non_exhaustive]
pub enum TlsConfigError {
    #[error(
        "The configured crypto provider is missing support for TLS13_AES_128_GCM_SHA256, which is required for QUIC initial packets."
    )]
    CryptoProviderNoInitialCipherSuite {
        #[error(std_err)]
        source: noq::crypto::rustls::NoInitialCipherSuite,
    },
    #[error("The configured crypto provider is incompatible with iroh and QUIC encryption")]
    CryptoProviderIncompatible {
        #[error(std_err)]
        source: rustls::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(peer_byte: u8, network: &str, cover_profile: u32) -> PeerClientKey {
        PeerClientKey {
            peer: SecretKey::from_bytes(&[peer_byte; 32]).public(),
            network_id: network.into(),
            cover_profile,
            quic_version: 1,
        }
    }

    #[test]
    fn tickets_are_partitioned_by_peer_network_profile_and_version() {
        let mut cache = PeerClientCache::default();
        let base = key(1, "network-a", 7);
        let same = cache.get_or_insert(base.clone(), 16);
        let repeated = cache.get_or_insert(base.clone(), 16);
        assert!(Arc::ptr_eq(&same.session_store, &repeated.session_store));

        for distinct in [
            key(2, "network-a", 7),
            key(1, "network-b", 7),
            key(1, "network-a", 8),
            PeerClientKey {
                quic_version: 2,
                ..base.clone()
            },
        ] {
            let state = cache.get_or_insert(distinct, 16);
            assert!(!Arc::ptr_eq(&same.session_store, &state.session_store));
            assert!(!Arc::ptr_eq(&same.verifier, &state.verifier));
        }
    }

    #[test]
    fn ticket_partition_cache_is_bounded() {
        let mut cache = PeerClientCache::default();
        cache.get_or_insert(key(1, "a", 1), 2);
        cache.get_or_insert(key(2, "a", 1), 2);
        cache.get_or_insert(key(3, "a", 1), 2);
        assert_eq!(cache.entries.len(), 2);
        assert_eq!(cache.order.len(), 2);
    }
}
