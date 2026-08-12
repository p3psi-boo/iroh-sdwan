use std::sync::Arc;

use anyhow::{Context, Result};
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// The single L3 device owned by FlowRouter. All local overlay traffic enters
/// here; next-hop selection happens in userspace rather than in the kernel.
pub struct OverlayTunnel {
    pub name: String,
    pub device: Arc<AsyncDevice>,
}

impl OverlayTunnel {
    pub fn create(name: String, mtu: u16) -> Result<Self> {
        let device = DeviceBuilder::new()
            .name(name.clone())
            .layer(Layer::L3)
            .mtu(mtu)
            .build_async()
            .with_context(|| format!("failed to create FlowRouter TUN interface {name}"))?;
        Ok(Self {
            name,
            device: Arc::new(device),
        })
    }
}
