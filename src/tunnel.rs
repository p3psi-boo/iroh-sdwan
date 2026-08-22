use std::{io::IoSlice, sync::Arc};

use anyhow::{Context, Result};
use bytes::BytesMut;
use tun_rs::{AsyncDevice, DeviceBuilder, GROTable, Layer, VIRTIO_NET_HDR_LEN};

const MAX_TUN_QUEUES: usize = 8;
// A virtio-net TUN record can carry a ~64 KiB GSO aggregate. The Linux
// default of hundreds of packets therefore permits tens of MiB to accumulate
// behind a backpressured userspace reader, hiding overload from inner TCP and
// delaying even newly generated control traffic by seconds. fq_codel remains
// the queueing discipline; this is only its device-ring ceiling.
const TUN_TX_QUEUE_RECORDS: u32 = 128;

pub fn data_plane_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .clamp(1, MAX_TUN_QUEUES)
}

/// The single L3 device owned by V2 dataplane. All local overlay traffic enters
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
            .tx_queue_len(TUN_TX_QUEUE_RECORDS)
            .offload(true)
            .multi_queue(queue_count > 1)
            .build_async()
            .with_context(|| format!("failed to create V2 dataplane TUN interface {name}"))?;
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
}

/// Single-owner TUN writer covering every queue. Prefer a per-queue writer
/// when inbound work is already sharded.
pub struct OverlayTunnelWriter {
    queues: Vec<OverlayTunnelQueueWriter>,
}

impl OverlayTunnelWriter {
    pub async fn send_owned(
        &mut self,
        shard: usize,
        packets: &mut [BytesMut],
    ) -> std::io::Result<usize> {
        let index = shard % self.queues.len();
        self.queues[index].send_owned(packets).await
    }

    /// Gather-write one already validated raw virtio-net record. This keeps a
    /// fragmented GSO packet in its QUIC-owned `Bytes` slices all the way to
    /// the TUN syscall instead of coalescing it in userspace.
    pub async fn send_raw_vectored(
        &mut self,
        shard: usize,
        virtio_header: &[u8; VIRTIO_NET_HDR_LEN],
        fragments: &[bytes::Bytes],
    ) -> std::io::Result<usize> {
        let index = shard % self.queues.len();
        let mut slices = Vec::with_capacity(fragments.len() + 1);
        slices.push(IoSlice::new(virtio_header));
        slices.extend(fragments.iter().map(|fragment| IoSlice::new(fragment)));
        self.queues[index].device.send_vectored(&slices).await
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

    pub async fn send_owned(&mut self, packets: &mut [BytesMut]) -> std::io::Result<usize> {
        self.device
            .send_multiple(&mut self.gro_table, packets, VIRTIO_NET_HDR_LEN)
            .await
    }
}
