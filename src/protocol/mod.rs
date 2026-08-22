//! Ironet Protocol V2 is the sole application protocol.
//!
//! QUIC v1 is the standardized transport version and is not an Ironet
//! application-protocol generation. There is no legacy decoder, negotiation,
//! downgrade selector, or fallback path in this module.

pub mod v2;
