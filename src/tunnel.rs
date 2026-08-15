use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::BytesMut;
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, Layer, VIRTIO_NET_HDR_LEN};

use crate::buffer::{DataplaneBuf, OVERLAY_HEADER_HEADROOM, PacketSlotPool};

const MAX_TUN_QUEUES: usize = 8;

pub fn data_plane_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, MAX_TUN_QUEUES)
}

/// The single L3 device owned by FlowRouter. All local overlay traffic enters
/// here; next-hop selection happens in userspace rather than in the kernel.
pub struct OverlayTunnel {
    pub name: String,
    pub devices: Vec<Arc<AsyncDevice>>,
    pub mtu: u16,
}

impl OverlayTunnel {
    pub fn create(name: String, mtu: u16) -> Result<Self> {
        let queue_count = data_plane_parallelism();
        let device = DeviceBuilder::new()
            .name(name.clone())
            .layer(Layer::L3)
            .mtu(mtu)
            .offload(true)
            .multi_queue(queue_count > 1)
            .build_async()
            .with_context(|| format!("failed to create FlowRouter TUN interface {name}"))?;
        let mut devices = Vec::with_capacity(queue_count);
        devices.push(Arc::new(device));
        for queue in 1..queue_count {
            let device = devices[0]
                .try_clone()
                .with_context(|| format!("failed attaching TUN queue {queue} to {name}"))?;
            devices.push(Arc::new(device));
        }
        Ok(Self { name, devices, mtu })
    }

    pub fn queue_count(&self) -> usize {
        self.devices.len()
    }

    pub fn device(&self, shard: usize) -> &Arc<AsyncDevice> {
        &self.devices[shard % self.devices.len()]
    }

    pub fn writer(&self) -> OverlayTunnelWriter {
        OverlayTunnelWriter {
            queues: self
                .devices
                .iter()
                .cloned()
                .map(OverlayTunnelQueueWriter::new)
                .collect(),
        }
    }

    pub fn queue_writer(&self, shard: usize) -> OverlayTunnelQueueWriter {
        OverlayTunnelQueueWriter::new(self.devices[shard % self.devices.len()].clone())
    }
}

/// Single-owner TUN writer covering every queue. Prefer a per-queue writer
/// when inbound work is already sharded.
pub struct OverlayTunnelWriter {
    queues: Vec<OverlayTunnelQueueWriter>,
}

impl OverlayTunnelWriter {
    pub async fn send(&mut self, shard: usize, packet: &[u8]) -> std::io::Result<usize> {
        let index = shard % self.queues.len();
        self.queues[index].send_slice(packet).await
    }

    pub async fn send_batch(&mut self, shard: usize, packets: &[&[u8]]) -> std::io::Result<usize> {
        let index = shard % self.queues.len();
        self.queues[index].send_slices(packets).await
    }
}

/// GRO state is local to one TUN queue / inbound shard.
pub struct OverlayTunnelQueueWriter {
    device: Arc<AsyncDevice>,
    gro_table: GROTable,
}

impl OverlayTunnelQueueWriter {
    fn new(device: Arc<AsyncDevice>) -> Self {
        Self {
            device,
            gro_table: GROTable::default(),
        }
    }

    pub async fn send_slice(&mut self, packet: &[u8]) -> std::io::Result<usize> {
        self.send_slices(&[packet]).await
    }

    pub async fn send_slices(&mut self, packets: &[&[u8]]) -> std::io::Result<usize> {
        let mut buffers = packets.iter().map(|packet| attach_virtio_copy(packet)).collect::<Vec<_>>();
        self.device
            .send_multiple(&mut self.gro_table, &mut buffers, VIRTIO_NET_HDR_LEN)
            .await
    }

    pub async fn send_owned(&mut self, packets: &mut [BytesMut]) -> std::io::Result<usize> {
        self.device
            .send_multiple(&mut self.gro_table, packets, VIRTIO_NET_HDR_LEN)
            .await
    }
}

pub fn tun_read_pool() -> PacketSlotPool {
    PacketSlotPool::new(tun_rs::IDEAL_BATCH_SIZE, OVERLAY_HEADER_HEADROOM)
}

/// Place a virtio-net header in unused prefix bytes when the packet is unique.
pub fn attach_virtio(packet: DataplaneBuf) -> BytesMut {
    const HDR: usize = VIRTIO_NET_HDR_LEN;
    if packet.can_prepend(HDR)
        && let Ok(sealed) = packet.clone().try_prepend(&[0_u8; HDR])
        && let Ok(mut unique) = sealed.try_into_mut()
    {
        unique[..HDR].fill(0);
        return unique;
    }
    attach_virtio_copy(packet.as_slice())
}

pub fn attach_virtio_copy(packet: &[u8]) -> BytesMut {
    let mut buffer = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + packet.len());
    buffer[VIRTIO_NET_HDR_LEN..].copy_from_slice(packet);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn attach_virtio_uses_unique_prefix() {
        let mut raw = BytesMut::zeroed(VIRTIO_NET_HDR_LEN + 4);
        raw[VIRTIO_NET_HDR_LEN..].copy_from_slice(b"abcd");
        let packet = DataplaneBuf::from_pooled(raw.freeze(), VIRTIO_NET_HDR_LEN);
        let prepared = attach_virtio(packet);
        assert_eq!(&prepared[..VIRTIO_NET_HDR_LEN], &[0; VIRTIO_NET_HDR_LEN]);
        assert_eq!(&prepared[VIRTIO_NET_HDR_LEN..], b"abcd");
    }

    #[test]
    fn tun_read_pool_is_not_all_jumbo() {
        let pool = tun_read_pool();
        assert!(pool.large_slot_count() < pool.slot_count());
        assert_eq!(pool.headroom(), OVERLAY_HEADER_HEADROOM);
    }
}
