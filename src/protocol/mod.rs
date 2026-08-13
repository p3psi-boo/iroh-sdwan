//! Iroh SD-WAN protocol generation 4.
//!
//! QUIC/TLS authenticates endpoint identities. A mandatory session exchange
//! then authenticates network membership, negotiates independently versioned
//! features and (when configured) proves possession of a pairwise link key.
//! Every application datagram uses [`envelope::Envelope`].

pub mod envelope;
pub mod feature;
pub mod node_record;
pub mod routing;
pub mod session;

pub const MAJOR: u16 = 4;
pub const MIN_MINOR: u16 = 1;
pub const MAX_MINOR: u16 = 1;
