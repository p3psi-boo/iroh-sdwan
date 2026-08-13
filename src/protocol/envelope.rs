use anyhow::{Result, ensure};
use bytes::Bytes;

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
        let header_len = HEADER_LEN + self.extension.len();
        ensure!(
            header_len <= MAX_HEADER_LEN,
            "v1 envelope extension is too large"
        );
        ensure!(
            header_len <= u16::MAX as usize,
            "v1 envelope header is too large"
        );
        let mut out = Vec::with_capacity(header_len + self.payload.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.kind as u16).to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(header_len as u16).to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&self.extension);
        out.extend_from_slice(&self.payload);
        Ok(Bytes::from(out))
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
    fn unknown_messages_are_rejected_without_parsing_payload() {
        let mut bytes = Envelope::new(MessageType::Heartbeat, Bytes::new())
            .encode()
            .unwrap()
            .to_vec();
        bytes[4..6].copy_from_slice(&999_u16.to_be_bytes());
        assert!(Envelope::decode(Bytes::from(bytes)).is_err());
    }
}
