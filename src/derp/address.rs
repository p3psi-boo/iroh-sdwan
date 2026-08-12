use std::{fmt, str::FromStr};

use anyhow::{Context, Result, ensure};
use iroh_base::CustomAddr;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use url::Url;

pub const DERP_TRANSPORT_ID: u64 = u64::from_be_bytes(*b"ISWDERP1");
const ADDRESS_VERSION: u8 = 1;
const ADDRESS_LEN: usize = 1 + 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerpPublicKey([u8; 32]);

impl DerpPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for DerpPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for DerpPublicKey {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        let bytes = hex::decode(value).context("DERP public key must be hexadecimal")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("DERP public key must contain exactly 32 bytes"))?;
        Ok(Self(bytes))
    }
}

impl Serialize for DerpPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for DerpPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionId(pub u64);

impl fmt::Display for RegionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerpServer {
    pub region_id: RegionId,
    pub url: Url,
    pub display: String,
}

impl DerpServer {
    pub fn parse(value: &str) -> Result<Self> {
        let mut url = Url::parse(value).context("invalid DERP server URL")?;
        ensure!(
            matches!(url.scheme(), "http" | "https"),
            "DERP server URL scheme must be http or https"
        );
        ensure!(url.host_str().is_some(), "DERP server URL requires a host");
        ensure!(
            url.username().is_empty(),
            "DERP server URL cannot contain credentials"
        );
        ensure!(
            url.password().is_none(),
            "DERP server URL cannot contain credentials"
        );
        ensure!(
            url.query().is_none(),
            "DERP server URL cannot contain a query"
        );
        ensure!(
            url.fragment().is_none(),
            "DERP server URL cannot contain a fragment"
        );
        ensure!(
            matches!(url.path(), "" | "/" | "/derp" | "/derp/"),
            "DERP server URL path must be /derp or empty"
        );
        url.set_path("/derp");
        let canonical = url.to_string();
        let digest = blake3::derive_key("iroh-sdwan DERP region URL v1", canonical.as_bytes());
        let region_id = RegionId(u64::from_be_bytes(
            digest[..8].try_into().expect("fixed size"),
        ));
        let display = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().expect("validated host")),
            None => url.host_str().expect("validated host").to_owned(),
        };
        Ok(Self {
            region_id,
            url,
            display,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerpAddr {
    pub region_id: RegionId,
    pub public_key: DerpPublicKey,
}

impl DerpAddr {
    pub fn to_custom(self) -> CustomAddr {
        let mut data = [0_u8; ADDRESS_LEN];
        data[0] = ADDRESS_VERSION;
        data[1..9].copy_from_slice(&self.region_id.0.to_be_bytes());
        data[9..].copy_from_slice(self.public_key.as_bytes());
        CustomAddr::from_parts(DERP_TRANSPORT_ID, &data)
    }

    pub fn from_custom(value: &CustomAddr) -> Result<Self> {
        ensure!(
            value.id() == DERP_TRANSPORT_ID,
            "unexpected custom transport id"
        );
        ensure!(
            value.data().len() == ADDRESS_LEN,
            "invalid DERP custom address length"
        );
        ensure!(
            value.data()[0] == ADDRESS_VERSION,
            "unsupported DERP custom address version"
        );
        let region_id = RegionId(u64::from_be_bytes(
            value.data()[1..9].try_into().expect("validated length"),
        ));
        let public_key =
            DerpPublicKey::from_bytes(value.data()[9..].try_into().expect("validated length"));
        Ok(Self {
            region_id,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_urls_produce_stable_regions() {
        let bare = DerpServer::parse("https://Relay.Example.COM").unwrap();
        let explicit = DerpServer::parse("https://relay.example.com/derp").unwrap();
        assert_eq!(bare.url, explicit.url);
        assert_eq!(bare.region_id, explicit.region_id);
        assert_eq!(bare.display, "relay.example.com");
    }

    #[test]
    fn custom_address_round_trip() {
        let address = DerpAddr {
            region_id: RegionId(42),
            public_key: DerpPublicKey::from_bytes([7; 32]),
        };
        assert_eq!(
            DerpAddr::from_custom(&address.to_custom()).unwrap(),
            address
        );
    }

    #[test]
    fn public_key_serde_is_hex() {
        #[derive(Debug, Serialize, Deserialize)]
        struct Wrapper {
            key: DerpPublicKey,
        }
        let key = DerpPublicKey::from_bytes([0xab; 32]);
        let encoded = toml::to_string(&Wrapper { key }).unwrap();
        let decoded: Wrapper = toml::from_str(&encoded).unwrap();
        assert_eq!(decoded.key, key);
    }
}
