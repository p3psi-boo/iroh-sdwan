use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use tun_rs::{
    VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6, VIRTIO_NET_HDR_GSO_UDP_L4,
    VIRTIO_NET_HDR_LEN, VirtioNetHdr,
};

const MAGIC: &[u8; 4] = b"GSV2";
const VERSION: u8 = 1;
pub const METADATA_LEN: usize = 16;
const GSO_ECN: u8 = 0x80;
const KNOWN_VIRTIO_FLAGS: u8 = 0x07;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GsoObservationV2 {
    pub input_bytes: u64,
    pub preserved_bytes: u64,
    pub fallback_splits: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsoMetadataV2 {
    pub flags: u8,
    pub gso_type: u8,
    pub header_len: u16,
    pub segment_size: u16,
    pub checksum_start: u16,
    pub checksum_offset: u16,
}

impl GsoMetadataV2 {
    pub fn from_virtio(header: VirtioNetHdr, packet: &[u8]) -> Result<Option<Self>> {
        ensure!(
            header.flags & !KNOWN_VIRTIO_FLAGS == 0,
            "unknown virtio-net flags"
        );
        if header.gso_type & !GSO_ECN == VIRTIO_NET_HDR_GSO_NONE {
            ensure!(header.gso_size == 0, "non-GSO V2 input has a segment size");
            if header.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM == 0 {
                ensure!(
                    header.hdr_len == 0 && header.csum_start == 0 && header.csum_offset == 0,
                    "plain V2 input has unexpected virtio metadata"
                );
                return Ok(None);
            }
        }
        let metadata = Self {
            flags: header.flags,
            gso_type: header.gso_type,
            header_len: header.hdr_len,
            segment_size: header.gso_size,
            checksum_start: header.csum_start,
            checksum_offset: header.csum_offset,
        };
        metadata.validate(packet)?;
        Ok(Some(metadata))
    }

    pub fn decode(bytes: Bytes, packet: &[u8]) -> Result<Self> {
        Self::decode_with_layout(bytes, packet.len(), packet)
    }

    fn decode_with_layout(bytes: Bytes, packet_len: usize, packet_prefix: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == METADATA_LEN,
            "invalid V2 GSO metadata length"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 GSO metadata magic");
        ensure!(bytes[4] == VERSION, "unsupported V2 GSO metadata version");
        ensure!(bytes[7] == 0, "unsupported V2 GSO metadata flags");
        let metadata = Self {
            flags: bytes[5],
            gso_type: bytes[6],
            header_len: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            segment_size: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
            checksum_start: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
            checksum_offset: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
        };
        metadata.validate_layout(packet_len, packet_prefix)?;
        Ok(metadata)
    }

    pub fn encode(self, packet: &[u8]) -> Result<Bytes> {
        self.validate(packet)?;
        let mut output = BytesMut::with_capacity(METADATA_LEN);
        output.extend_from_slice(MAGIC);
        output.put_u8(VERSION);
        output.put_u8(self.flags);
        output.put_u8(self.gso_type);
        output.put_u8(0);
        output.put_u16(self.header_len);
        output.put_u16(self.segment_size);
        output.put_u16(self.checksum_start);
        output.put_u16(self.checksum_offset);
        Ok(output.freeze())
    }

    pub fn to_virtio(self, packet: &[u8]) -> Result<VirtioNetHdr> {
        self.validate(packet)?;
        Ok(VirtioNetHdr {
            flags: self.flags,
            gso_type: self.gso_type,
            hdr_len: self.header_len,
            gso_size: self.segment_size,
            csum_start: self.checksum_start,
            csum_offset: self.checksum_offset,
        })
    }

    pub fn attach(self, packet: &[u8]) -> Result<BytesMut> {
        let header = self.to_virtio(packet)?;
        let mut output = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + packet.len());
        header.encode(&mut output[..VIRTIO_NET_HDR_LEN])?;
        output[VIRTIO_NET_HDR_LEN..].copy_from_slice(packet);
        Ok(output)
    }

    fn validate(self, packet: &[u8]) -> Result<()> {
        self.validate_layout(packet.len(), packet)
    }

    fn validate_layout(self, packet_len: usize, packet_prefix: &[u8]) -> Result<()> {
        ensure!(
            self.flags & !KNOWN_VIRTIO_FLAGS == 0,
            "unknown virtio-net flags"
        );
        let base_type = self.gso_type & !GSO_ECN;
        ensure!(
            matches!(
                base_type,
                VIRTIO_NET_HDR_GSO_NONE
                    | VIRTIO_NET_HDR_GSO_TCPV4
                    | VIRTIO_NET_HDR_GSO_TCPV6
                    | VIRTIO_NET_HDR_GSO_UDP_L4
            ),
            "unsupported V2 GSO type"
        );
        if base_type == VIRTIO_NET_HDR_GSO_NONE {
            ensure!(
                self.segment_size == 0,
                "non-GSO V2 metadata has a segment size"
            );
        } else {
            ensure!(self.segment_size > 0, "V2 GSO segment size is zero");
            ensure!(
                usize::from(self.header_len) < packet_len,
                "V2 GSO header exceeds packet"
            );
            ensure!(
                packet_len - usize::from(self.header_len) > usize::from(self.segment_size),
                "V2 GSO packet has no segmentation work"
            );
        }
        let checksum_end = usize::from(self.checksum_start)
            .checked_add(usize::from(self.checksum_offset))
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| anyhow::anyhow!("V2 GSO checksum offset overflow"))?;
        ensure!(
            checksum_end <= packet_len,
            "V2 GSO checksum field exceeds packet"
        );
        if self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 && base_type != VIRTIO_NET_HDR_GSO_NONE {
            ensure!(
                usize::from(self.checksum_start) < usize::from(self.header_len),
                "V2 GSO checksum starts after transport header"
            );
        }
        if base_type == VIRTIO_NET_HDR_GSO_NONE {
            ensure!(
                self.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0,
                "non-GSO V2 metadata carries no checksum work"
            );
            ensure!(
                usize::from(self.checksum_start) < packet_len,
                "V2 checksum start exceeds packet"
            );
            Ok(())
        } else {
            validate_ip_transport(
                base_type,
                packet_len,
                packet_prefix,
                usize::from(self.header_len),
            )
        }
    }
}

fn validate_ip_transport(
    gso_type: u8,
    packet_len: usize,
    packet_prefix: &[u8],
    header_len: usize,
) -> Result<()> {
    ensure!(!packet_prefix.is_empty(), "empty V2 GSO packet prefix");
    let version = packet_prefix[0] >> 4;
    match gso_type {
        VIRTIO_NET_HDR_GSO_TCPV4 => {
            ensure!(
                version == 4 && packet_len >= 20 && packet_prefix.len() > 9,
                "TCPv4 GSO has invalid IPv4 packet"
            );
            let ip_header = usize::from(packet_prefix[0] & 0x0f) * 4;
            ensure!(
                ip_header >= 20 && packet_len >= ip_header + 20,
                "invalid IPv4/TCP GSO header"
            );
            ensure!(packet_prefix[9] == 6, "TCPv4 GSO packet is not TCP");
            ensure!(
                header_len >= ip_header + 20,
                "TCPv4 GSO hdr_len is too small"
            );
        }
        VIRTIO_NET_HDR_GSO_TCPV6 => {
            ensure!(
                version == 6 && packet_len >= 60 && packet_prefix.len() > 6,
                "TCPv6 GSO has invalid IPv6 packet"
            );
            ensure!(
                packet_prefix[6] == 6,
                "TCPv6 GSO extension headers are not normalized"
            );
            ensure!(header_len >= 60, "TCPv6 GSO hdr_len is too small");
        }
        VIRTIO_NET_HDR_GSO_UDP_L4 => match version {
            4 => {
                ensure!(
                    packet_len >= 28 && packet_prefix.len() > 9 && packet_prefix[9] == 17,
                    "UDP GSO has invalid IPv4 packet"
                );
                let ip_header = usize::from(packet_prefix[0] & 0x0f) * 4;
                ensure!(
                    header_len >= ip_header + 8,
                    "UDPv4 GSO hdr_len is too small"
                );
            }
            6 => {
                ensure!(
                    packet_len >= 48 && packet_prefix.len() > 6 && packet_prefix[6] == 17,
                    "UDP GSO has invalid IPv6 packet"
                );
                ensure!(header_len >= 48, "UDPv6 GSO hdr_len is too small");
            }
            _ => anyhow::bail!("UDP GSO has an invalid IP version"),
        },
        _ => unreachable!(),
    }
    ensure!(header_len <= packet_len, "V2 GSO hdr_len exceeds packet");
    Ok(())
}

pub fn decode_virtio_record(raw: Bytes) -> Result<(Option<GsoMetadataV2>, Bytes)> {
    ensure!(
        raw.len() > VIRTIO_NET_HDR_LEN,
        "truncated virtio-net V2 record"
    );
    let header = VirtioNetHdr::decode(&raw[..VIRTIO_NET_HDR_LEN])?;
    let packet = raw.slice(VIRTIO_NET_HDR_LEN..);
    let metadata = GsoMetadataV2::from_virtio(header, &packet)?;
    Ok((metadata, packet))
}

pub fn encode_train_record(raw: Bytes) -> Result<(Bytes, Bytes)> {
    let (metadata, packet, _) = encode_train_record_observed(raw)?;
    Ok((metadata, packet))
}

pub fn encode_train_record_observed(raw: Bytes) -> Result<(Bytes, Bytes, GsoObservationV2)> {
    let (metadata, packet) = decode_virtio_record(raw)?;
    let is_gso =
        metadata.is_some_and(|metadata| metadata.gso_type & !GSO_ECN != VIRTIO_NET_HDR_GSO_NONE);
    let metadata =
        metadata.map_or_else(|| Ok(Bytes::new()), |metadata| metadata.encode(&packet))?;
    let observed_bytes = if is_gso {
        u64::try_from(packet.len()).unwrap_or(u64::MAX)
    } else {
        0
    };
    Ok((
        metadata,
        packet,
        GsoObservationV2 {
            input_bytes: observed_bytes,
            // V2 carries validated virtio metadata end-to-end, so a GSO
            // super-packet stays intact rather than being split in userspace.
            preserved_bytes: observed_bytes,
            fallback_splits: 0,
        },
    ))
}

pub fn restore_tun_record(metadata: Bytes, packet: Bytes) -> Result<BytesMut> {
    if metadata.is_empty() {
        let mut output = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + packet.len());
        VirtioNetHdr::default().encode(&mut output[..VIRTIO_NET_HDR_LEN])?;
        output[VIRTIO_NET_HDR_LEN..].copy_from_slice(&packet);
        return Ok(output);
    }
    GsoMetadataV2::decode(metadata, &packet)?.attach(&packet)
}

/// Restore a possibly fragmented record directly into its final TUN buffer.
/// This performs one payload copy instead of first coalescing the IP packet
/// and then copying it again while attaching the virtio-net header.
pub fn restore_tun_record_fragments(
    metadata: Bytes,
    total_len: usize,
    fragments: &[Bytes],
) -> Result<BytesMut> {
    ensure!(total_len > 0, "empty fragmented V2 TUN record");
    ensure!(!fragments.is_empty(), "V2 TUN record has no fragments");
    let mut output = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + total_len);
    let mut cursor = VIRTIO_NET_HDR_LEN;
    for fragment in fragments {
        let end = cursor
            .checked_add(fragment.len())
            .ok_or_else(|| anyhow::anyhow!("V2 TUN fragment length overflow"))?;
        ensure!(end <= output.len(), "V2 TUN fragments exceed record length");
        output[cursor..end].copy_from_slice(fragment);
        cursor = end;
    }
    ensure!(
        cursor == output.len(),
        "V2 TUN fragments do not fill record"
    );
    let packet = &output[VIRTIO_NET_HDR_LEN..];
    let header = if metadata.is_empty() {
        VirtioNetHdr::default()
    } else {
        GsoMetadataV2::decode(metadata, packet)?.to_virtio(packet)?
    };
    header.encode(&mut output[..VIRTIO_NET_HDR_LEN])?;
    Ok(output)
}

/// Encode only the virtio-net header for a fragmented record. The caller can
/// gather-write this header followed by the immutable fragment slices, so the
/// complete GSO super-packet never needs a userspace coalescing buffer.
pub fn virtio_header_for_record_fragments(
    metadata: Bytes,
    total_len: usize,
    fragments: &[Bytes],
) -> Result<[u8; VIRTIO_NET_HDR_LEN]> {
    ensure!(total_len > 0, "empty fragmented V2 TUN record");
    ensure!(!fragments.is_empty(), "V2 TUN record has no fragments");
    let observed_len = fragments.iter().try_fold(0_usize, |total, fragment| {
        total
            .checked_add(fragment.len())
            .ok_or_else(|| anyhow::anyhow!("V2 TUN fragment length overflow"))
    })?;
    ensure!(observed_len == total_len, "V2 TUN fragment length mismatch");

    let mut prefix = [0_u8; 10];
    let mut prefix_len = 0_usize;
    for fragment in fragments {
        let take = fragment.len().min(prefix.len() - prefix_len);
        prefix[prefix_len..prefix_len + take].copy_from_slice(&fragment[..take]);
        prefix_len += take;
        if prefix_len == prefix.len() {
            break;
        }
    }
    let header = if metadata.is_empty() {
        VirtioNetHdr::default()
    } else {
        let decoded =
            GsoMetadataV2::decode_with_layout(metadata, total_len, &prefix[..prefix_len])?;
        VirtioNetHdr {
            flags: decoded.flags,
            gso_type: decoded.gso_type,
            hdr_len: decoded.header_len,
            gso_size: decoded.segment_size,
            csum_start: decoded.checksum_start,
            csum_offset: decoded.checksum_offset,
        }
    };
    let mut encoded = [0_u8; VIRTIO_NET_HDR_LEN];
    header.encode(&mut encoded)?;
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcpv4_super_packet() -> Bytes {
        let mut packet = vec![0_u8; 40 + 3 * 1200];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[20 + 12] = 5 << 4;
        Bytes::from(packet)
    }

    fn metadata() -> GsoMetadataV2 {
        GsoMetadataV2 {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            header_len: 40,
            segment_size: 1200,
            checksum_start: 20,
            checksum_offset: 16,
        }
    }

    #[test]
    fn gso_metadata_round_trips_and_restores_virtio_header() {
        let packet = tcpv4_super_packet();
        let encoded = metadata().encode(&packet).unwrap();
        assert_eq!(GsoMetadataV2::decode(encoded, &packet).unwrap(), metadata());
        let attached = metadata().attach(&packet).unwrap();
        let (decoded, restored) = decode_virtio_record(attached.freeze()).unwrap();
        assert_eq!(decoded, Some(metadata()));
        assert_eq!(restored, packet);
    }

    #[test]
    fn gso_observation_counts_preserved_super_packet_without_fallback_split() {
        let packet = tcpv4_super_packet();
        let raw = metadata().attach(&packet).unwrap().freeze();
        let (encoded, restored, observation) = encode_train_record_observed(raw).unwrap();
        assert!(!encoded.is_empty());
        assert_eq!(restored, packet);
        assert_eq!(observation.input_bytes, packet.len() as u64);
        assert_eq!(observation.preserved_bytes, packet.len() as u64);
        assert_eq!(observation.fallback_splits, 0);
    }

    #[test]
    fn non_gso_virtio_header_has_no_record_metadata() {
        let packet = tcpv4_super_packet();
        let mut raw = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + packet.len());
        VirtioNetHdr::default()
            .encode(&mut raw[..VIRTIO_NET_HDR_LEN])
            .unwrap();
        raw[VIRTIO_NET_HDR_LEN..].copy_from_slice(&packet);
        let (metadata, restored) = decode_virtio_record(raw.freeze()).unwrap();
        assert_eq!(metadata, None);
        assert_eq!(restored, packet);

        let mut raw = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + packet.len());
        raw[VIRTIO_NET_HDR_LEN..].copy_from_slice(&packet);
        let (metadata, payload) = encode_train_record(raw.freeze()).unwrap();
        assert!(metadata.is_empty());
        let restored = restore_tun_record(metadata, payload).unwrap();
        assert_eq!(&restored[VIRTIO_NET_HDR_LEN..], packet.as_ref());
    }

    #[test]
    fn checksum_only_virtio_metadata_is_preserved() {
        let packet = tcpv4_super_packet().slice(..1400);
        let header = VirtioNetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 16,
        };
        let metadata = GsoMetadataV2::from_virtio(header, &packet)
            .unwrap()
            .expect("checksum metadata is retained");
        let encoded = metadata.encode(&packet).unwrap();
        assert_eq!(GsoMetadataV2::decode(encoded, &packet).unwrap(), metadata);
        let restored = metadata.attach(&packet).unwrap();
        let decoded = VirtioNetHdr::decode(&restored[..VIRTIO_NET_HDR_LEN]).unwrap();
        assert_eq!(decoded.flags, header.flags);
        assert_eq!(decoded.gso_type, header.gso_type);
        assert_eq!(decoded.hdr_len, header.hdr_len);
        assert_eq!(decoded.gso_size, header.gso_size);
        assert_eq!(decoded.csum_start, header.csum_start);
        assert_eq!(decoded.csum_offset, header.csum_offset);

        let (_, _, observation) = encode_train_record_observed(restored.freeze()).unwrap();
        assert_eq!(observation, GsoObservationV2::default());
    }

    #[test]
    fn fragmented_record_is_restored_directly_into_final_tun_buffer() {
        let packet = tcpv4_super_packet();
        let encoded = metadata().encode(&packet).unwrap();
        let fragments = [packet.slice(..1_337), packet.slice(1_337..)];
        let restored = restore_tun_record_fragments(encoded, packet.len(), &fragments).unwrap();
        let header = VirtioNetHdr::decode(&restored[..VIRTIO_NET_HDR_LEN]).unwrap();
        assert_eq!(header.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(&restored[VIRTIO_NET_HDR_LEN..], packet.as_ref());
    }

    #[test]
    fn fragmented_record_header_supports_gather_write_without_payload_copy() {
        let packet = tcpv4_super_packet();
        let encoded = metadata().encode(&packet).unwrap();
        let fragments = [
            packet.slice(..7),
            packet.slice(7..1_337),
            packet.slice(1_337..),
        ];
        let header = virtio_header_for_record_fragments(encoded, packet.len(), &fragments).unwrap();
        let decoded = VirtioNetHdr::decode(&header).unwrap();
        assert_eq!(decoded.gso_type, VIRTIO_NET_HDR_GSO_TCPV4);
        assert_eq!(decoded.gso_size, metadata().segment_size);
    }

    #[test]
    fn invalid_type_checksum_and_protocol_are_rejected() {
        let packet = tcpv4_super_packet();
        let mut invalid = metadata();
        invalid.gso_type = 3;
        assert!(invalid.encode(&packet).is_err());
        invalid = metadata();
        invalid.checksum_start = u16::MAX;
        assert!(invalid.encode(&packet).is_err());
        let mut udp = packet.to_vec();
        udp[9] = 17;
        assert!(metadata().encode(&udp).is_err());
    }
}
