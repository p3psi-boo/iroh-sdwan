pub mod address;
pub mod capacity;
pub mod capacity_probe;
pub mod config;
pub mod control;
pub mod daemon;
pub mod delivery;
pub mod deployment;
pub mod derp;
pub mod display;
pub mod fec;
pub mod flow_router;
pub mod identity;
pub mod link_metrics;
pub mod logging;
pub mod mesh;
pub mod observability;
pub mod packet;
pub mod path_selection;
pub mod protocol;
pub mod routes;
pub mod runtime;
pub mod system;
pub mod trace;
pub mod transport;
pub mod tui;
pub mod tunnel;
pub mod wire;

/// Clean-slate wire generation. V3 nodes intentionally negotiate a different
/// ALPN and can therefore never accidentally exchange v4 frames.
pub const PROTOCOL_NAME: &str = "iroh-sdwan/ip/4";
