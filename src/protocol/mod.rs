//! Ironet protocol generation V1.
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

pub const MAJOR: u16 = 1;
pub const MIN_MINOR: u16 = 0;
pub const MAX_MINOR: u16 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_protocol_is_v1_0() {
        assert_eq!((MAJOR, MIN_MINOR, MAX_MINOR), (1, 0, 0));
        assert_eq!(crate::PROTOCOL_NAME, "ironet/ip/1");
        assert_eq!(envelope::MAGIC, b"IRN1");
    }
}
