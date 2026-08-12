use crate::PROTOCOL_NAME;

pub fn network_alpn(network_id: &str) -> Vec<u8> {
    network_alpn_with_context(network_id, b"iroh-sdwan-network-alpn-v3\0", "")
}

/// Separate ALPN for short-lived reachability/RTT probes. Keeping probes off
/// the data-plane ALPN prevents an exploratory handshake from replacing an
/// established overlay connection for the same endpoint.
pub fn network_probe_alpn(network_id: &str) -> Vec<u8> {
    network_alpn_with_context(network_id, b"iroh-sdwan-mesh-probe-alpn-v2\0", "/probe")
}

fn network_alpn_with_context(network_id: &str, context: &[u8], suffix: &str) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(context);
    hasher.update(network_id.as_bytes());
    format!("{PROTOCOL_NAME}{suffix}/{}", hasher.finalize().to_hex()).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_id_separates_alpn_domains() {
        assert_ne!(network_alpn("one"), network_alpn("two"));
        assert_ne!(network_probe_alpn("one"), network_probe_alpn("two"));
        assert_ne!(network_alpn("one"), network_probe_alpn("one"));
    }
}
