# Ironet iroh V2 patch

- Upstream crate: `iroh 1.0.3`
- crates.io checksum: `460de6bc52163b41b1646931f2897e5ab986f0966ade444467fec25024751a72`
- Integration: vendored path dependency at `crates/iroh-v2`; it is excluded from the
  root workspace so its upstream examples and development dependencies do not alter
  Ironet's build graph.

## Intentional API/behavior changes

- `ConnectOptions::with_visible_server_name` changes only ClientHello SNI.
- Generic callers that omit it use the identity-neutral `media.example`; the
  EndpointId-to-`.iroh.invalid` encoder and every client call site were removed.
- Raw-public-key verification captures the expected `EndpointId` from `EndpointAddr`;
  SNI is never decoded into peer identity.
- `TlsSessionPartition` keys resumption state by authenticated peer, network ID,
  cover-profile generation, and QUIC version.
- The per-partition session cache is bounded and keeps verifier/session-store `Arc`
  identity stable for rustls 0-RTT compatibility.

Keep this directory at the recorded upstream version until the patch is rebased and
the SNI, wrong-peer, and ticket-partition tests pass against the new source.
