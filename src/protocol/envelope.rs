use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

pub const MAGIC: &[u8; 4] = b"IRN1";
pub const HEADER_LEN: usize = 12;
pub const MAX_HEADER_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    IpFragment = 1,
    IpBatch = 2,
    RepairRequest = 3,
    CapacityProbe = 4,
    Delivery = 5,
    Heartbeat = 6,
    ConnectionRefresh = 7,
    AddressCandidates = 8,
    FecShard = 9,
}

impl MessageType {
    pub fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::IpFragment,
            2 => Self::IpBatch,
            3 => Self::RepairRequest,
            4 => Self::CapacityProbe,
            5 => Self::Delivery,
            6 => Self::Heartbeat,
            7 => Self::ConnectionRefresh,
            8 => Self::AddressCandidates,
            9 => Self::FecShard,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub kind: MessageType,
    pub flags: u16,
    pub extension: Bytes,
    pub payload: Bytes,
}

impl Envelope {
    pub fn new(kind: MessageType, payload: impl Into<Bytes>) -> Self {
        Self {
            kind,
            flags: 0,
            extension: Bytes::new(),
            payload: payload.into(),
        }
    }

    pub fn encode(&self) -> Result<Bytes> {
        encode_parts(self.kind, self.flags, &self.extension, &self.payload)
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(bytes.len() >= HEADER_LEN, "truncated v1 envelope");
        ensure!(&bytes[..4] == MAGIC, "invalid v1 envelope magic");
        let raw_kind = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let kind = MessageType::from_wire(raw_kind)
            .ok_or_else(|| anyhow::anyhow!("unknown v1 message type {raw_kind}"))?;
        let flags = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let header_len = usize::from(u16::from_be_bytes(bytes[8..10].try_into().unwrap()));
        ensure!(
            bytes[10..12] == [0, 0],
            "unsupported v1 envelope reserved bits"
        );
        ensure!(
            (HEADER_LEN..=MAX_HEADER_LEN).contains(&header_len) && header_len <= bytes.len(),
            "invalid v1 envelope header length"
        );
        Ok(Self {
            kind,
            flags,
            extension: bytes.slice(HEADER_LEN..header_len),
            payload: bytes.slice(header_len..),
        })
    }
}

/// Write a V1 envelope in one allocation. Callers that already have a
/// contiguous payload must use this instead of building a payload `Vec`
/// and copying it into a second envelope buffer.
pub fn encode_parts(
    kind: MessageType,
    flags: u16,
    extension: &[u8],
    payload: &[u8],
) -> Result<Bytes> {
    let header_len = HEADER_LEN + extension.len();
    ensure!(
        header_len <= MAX_HEADER_LEN,
        "v1 envelope extension is too large"
    );
    ensure!(
        header_len <= u16::MAX as usize,
        "v1 envelope header is too large"
    );
    let mut out = BytesMut::with_capacity(header_len + payload.len());
    write_header(&mut out, kind, flags, header_len as u16);
    out.extend_from_slice(extension);
    out.extend_from_slice(payload);
    Ok(out.freeze())
}

pub fn write_header(out: &mut BytesMut, kind: MessageType, flags: u16, header_len: u16) {
    out.extend_from_slice(MAGIC);
    out.put_u16(kind as u16);
    out.put_u16(flags);
    out.put_u16(header_len);
    out.put_u16(0);
}

/// Patch a header into bytes that already contain the payload at
/// `payload_start`. Used by the single-datagram in-place path.
pub fn write_header_at(dest: &mut [u8], kind: MessageType, flags: u16) -> Result<()> {
    ensure!(
        dest.len() >= HEADER_LEN,
        "envelope header destination is too small"
    );
    dest[..4].copy_from_slice(MAGIC);
    dest[4..6].copy_from_slice(&(kind as u16).to_be_bytes());
    dest[6..8].copy_from_slice(&flags.to_be_bytes());
    dest[8..10].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
    dest[10..12].copy_from_slice(&0_u16.to_be_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_preserves_extensions_for_feature_codecs() {
        let envelope = Envelope {
            kind: MessageType::Heartbeat,
            flags: 7,
            extension: Bytes::from_static(b"future"),
            payload: Bytes::from_static(b"payload"),
        };
        assert_eq!(
            Envelope::decode(envelope.encode().unwrap()).unwrap(),
            envelope
        );
    }

    #[test]
    fn encode_parts_matches_struct_encode() {
        let payload = Bytes::from_static(b"payload");
        let envelope = Envelope::new(MessageType::IpFragment, payload.clone());
        assert_eq!(
            encode_parts(MessageType::IpFragment, 0, &[], &payload).unwrap(),
            envelope.encode().unwrap()
        );
    }

    #[test]
    fn unknown_messages_are_rejected_without_parsing_payload() {
        let mut bytes = Envelope::new(MessageType::Heartbeat, Bytes::new())
            .encode()
            .unwrap()
            .to_vec();
        bytes[4..6].copy_from_slice(&999_u16.to_be_bytes());
        assert!(Envelope::decode(Bytes::from(bytes)).is_err());
    }
}
