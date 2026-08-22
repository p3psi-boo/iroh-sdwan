# Ironet noq V2 patch

- Upstream crate: `noq 1.1.1`
- crates.io checksum: `09e4bb6601fa543c110d8957813267d5a8d775a0f8fbaccf1f615d06ba9b10da`
- Integration: `[patch.crates-io]` points at `crates/noq-v2`; the package is
  excluded from the root workspace so upstream examples and development
  dependencies do not change Ironet's build graph.

## Intentional API/behavior changes

- `Connection::send_datagram_batch_wait` admits the currently-unblocked prefix
  of a bounded `Vec<Bytes>` while holding the QUIC connection-state lock once.
- Backpressure resumes from the first uncommitted DATAGRAM. Protocol errors can
  be returned after an earlier prefix was committed, matching the V2 runtime's
  fail-closed session behavior without retry duplication.
- The ordinary one-DATAGRAM APIs and their behavior are unchanged.

Keep this directory at the recorded upstream version until the patch is rebased
and the real-QUIC V2 PacketTrain test plus dual-end profile validation pass.
