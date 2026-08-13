# Iroh SD-WAN Protocol v4

v4 is a clean protocol generation. Its ALPN is derived from
`iroh-sdwan/ip/4`, so a v3 process cannot be mistaken for a compatible peer.

## Layers

1. **Transport** — QUIC/TLS authenticates the Iroh `EndpointId`.
2. **Session** — the client sends `Hello`, the server sends `HelloAck`, and the
   client commits the exact transcript with `Ready` on one reliable stream.
3. **Features** — each feature has a stable numeric ID and an independent
   version range. Required features fail closed; optional unknown features are
   omitted from the negotiated profile.
4. **Data** — every application datagram starts with the common `ISW4`
   envelope and a stable message type. Envelope header length reserves bounded
   extension space; unknown message types are dropped before body parsing.
5. **Directory and routing** — `NodeRecord`, `RouteOrigin` and `RoutePath` are
   separate models. Their numeric attribute maps preserve extension bytes
   without teaching the core router their semantics.

## Session authentication

The handshake proves the shared network membership key in addition to the TLS
endpoint identity. The proof covers identities and fresh nonces. A pairwise
private link adds a second proof derived from its `auth_key` and `link id`.
The selected datagram/control limits are the minimum offered by both sides.

## Attachment-independent transit

`attachment = "none"` skips TUN allocation, Linux route programming and cleanup.
Packets still enter over QUIC, pass source/destination policy, decrement their
IP hop limit, use the normal userspace FlowRouter, and leave through another
peer. Transit-only nodes own no overlay prefixes and require
`routing.transit_enabled = true`.

## Pairwise private links

`[[links]]` separates a node identity from a transport path:

- `remote_addresses` and `local_bind` are local pairwise state and never enter
  NodeRecord/Presence gossip.
- `active`, `passive` and `auto` define connection ownership.
- private links are exclusive and have no discovery, relay, DERP, observed
  candidate or public-address fallback.
- the selected QUIC path must be the configured remote locator, an IP path, and
  inside both local and remote positive prefix allowlists. Migration outside
  the contract closes the connection.
- the v4 session must also prove the 32-byte pairwise secret.

## Stability rules

- The v4 major ALPN is changed only for incompatible framing or security model
  changes.
- New behavior is introduced as an optional feature or a new envelope message
  type. Existing message semantics are not silently changed.
- Limits are negotiated, not inferred from a build version.
- Reserved fields must be zero; bounded extension fields are opaque to peers
  that do not negotiate their feature.
- Before a future v5, captured v4 fixtures and mixed-minor negotiation tests
  remain release gates.
