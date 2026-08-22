use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

use super::tuning::CoverTrafficProfileV2;

pub const COVER_MAGIC: &[u8; 4] = b"PCV2";
pub const COVER_HEADER_LEN: usize = 20;
pub const SMALL_FEEDBACK_BYTES: usize = 128;
pub const MEDIUM_CONTROL_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverPaddingV2 {
    pub profile: CoverTrafficProfileV2,
    pub session_epoch: u32,
    pub sequence: u64,
}

impl CoverPaddingV2 {
    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(COVER_MAGIC)
    }

    pub fn encode(self, target_bytes: usize, maximum_datagram_size: usize) -> Result<Bytes> {
        ensure!(
            self.session_epoch != 0,
            "V2 cover session epoch zero is reserved"
        );
        ensure!(
            (COVER_HEADER_LEN..=maximum_datagram_size).contains(&target_bytes),
            "V2 cover padding size is outside the path limit"
        );
        let mut output = BytesMut::zeroed(target_bytes);
        {
            let mut header = &mut output[..COVER_HEADER_LEN];
            header.put_slice(COVER_MAGIC);
            header.put_u8(1);
            header.put_u8(profile_to_wire(self.profile));
            header.put_u16(0);
            header.put_u32(self.session_epoch);
            header.put_u64(self.sequence);
        }
        Ok(output.freeze())
    }

    pub fn decode(bytes: &[u8], expected_session_epoch: u32) -> Result<Self> {
        ensure!(
            bytes.len() >= COVER_HEADER_LEN,
            "truncated V2 cover padding"
        );
        ensure!(&bytes[..4] == COVER_MAGIC, "invalid V2 cover padding magic");
        ensure!(bytes[4] == 1, "unsupported V2 cover padding version");
        ensure!(bytes[6..8] == [0, 0], "unsupported V2 cover padding flags");
        let session_epoch = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        ensure!(
            session_epoch == expected_session_epoch,
            "V2 cover padding belongs to another session epoch"
        );
        Ok(Self {
            profile: profile_from_wire(bytes[5])?,
            session_epoch,
            sequence: u64::from_be_bytes(bytes[12..20].try_into().unwrap()),
        })
    }

    pub fn target_size(self, maximum_datagram_size: usize) -> usize {
        let small = SMALL_FEEDBACK_BYTES.min(maximum_datagram_size);
        let medium = MEDIUM_CONTROL_BYTES.min(maximum_datagram_size);
        match self.profile {
            CoverTrafficProfileV2::Idle => COVER_HEADER_LEN,
            CoverTrafficProfileV2::LiveBroadcast => {
                if self.sequence.is_multiple_of(8) {
                    small
                } else {
                    maximum_datagram_size
                }
            }
            CoverTrafficProfileV2::InteractiveVideo => {
                if self.sequence.is_multiple_of(3) {
                    medium
                } else {
                    maximum_datagram_size
                }
            }
            CoverTrafficProfileV2::GenericH3Bulk => {
                if self.sequence.is_multiple_of(4) {
                    medium
                } else {
                    maximum_datagram_size
                }
            }
        }
        .max(COVER_HEADER_LEN)
    }
}

fn profile_to_wire(profile: CoverTrafficProfileV2) -> u8 {
    match profile {
        CoverTrafficProfileV2::Idle => 0,
        CoverTrafficProfileV2::LiveBroadcast => 1,
        CoverTrafficProfileV2::InteractiveVideo => 2,
        CoverTrafficProfileV2::GenericH3Bulk => 3,
    }
}

fn profile_from_wire(value: u8) -> Result<CoverTrafficProfileV2> {
    Ok(match value {
        0 => CoverTrafficProfileV2::Idle,
        1 => CoverTrafficProfileV2::LiveBroadcast,
        2 => CoverTrafficProfileV2::InteractiveVideo,
        3 => CoverTrafficProfileV2::GenericH3Bulk,
        _ => anyhow::bail!("unknown V2 cover traffic profile {value}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cover_padding_has_three_bounded_size_buckets_and_strict_epoch() {
        let padding = CoverPaddingV2 {
            profile: CoverTrafficProfileV2::LiveBroadcast,
            session_epoch: 7,
            sequence: 8,
        };
        let small = padding.target_size(1_382);
        assert_eq!(small, SMALL_FEEDBACK_BYTES);
        let encoded = padding.encode(small, 1_382).unwrap();
        assert_eq!(CoverPaddingV2::decode(&encoded, 7).unwrap(), padding);
        assert!(CoverPaddingV2::decode(&encoded, 8).is_err());

        let mut full = padding;
        full.sequence = 9;
        assert_eq!(full.target_size(1_382), 1_382);

        let mut interactive = padding;
        interactive.profile = CoverTrafficProfileV2::InteractiveVideo;
        interactive.sequence = 3;
        assert_eq!(interactive.target_size(1_382), MEDIUM_CONTROL_BYTES);
    }

    #[test]
    fn cover_decoder_rejects_unknown_version_profile_and_flags() {
        let padding = CoverPaddingV2 {
            profile: CoverTrafficProfileV2::GenericH3Bulk,
            session_epoch: 7,
            sequence: 1,
        };
        let encoded = padding.encode(128, 1_382).unwrap();
        for (offset, value) in [(4, 2), (5, 9), (6, 1)] {
            let mut malformed = encoded.to_vec();
            malformed[offset] = value;
            assert!(CoverPaddingV2::decode(&malformed, 7).is_err());
        }
    }
}
