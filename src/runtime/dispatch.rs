//! Sharded ingress/route dispatch with flow-stable ownership.

use std::sync::Arc;

use anyhow::{Context, Result};
use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::mpsc;

use super::{FLOW_DISPATCH_QUEUE, InboundPacket, RouteRequest};
use crate::packet::PacketInfo;

#[derive(Clone)]
pub(super) struct InboundDispatcher {
    senders: Arc<Vec<mpsc::Sender<InboundPacket>>>,
}

impl InboundDispatcher {
    pub(super) fn new(senders: Vec<mpsc::Sender<InboundPacket>>) -> Self {
        assert!(
            !senders.is_empty(),
            "at least one inbound shard is required"
        );
        Self {
            senders: Arc::new(senders),
        }
    }

    pub(super) fn shard_count(&self) -> usize {
        self.senders.len()
    }

    fn shard_for(&self, packet: PacketInfo) -> usize {
        flow_shard(packet, self.senders.len())
    }

    /// Reserve and publish a receive burst per flow-owner shard. Publishing a
    /// whole reservation coalesces Tokio receiver notifications while keeping
    /// unrelated flow shards independent under backpressure.
    pub(super) async fn send_batch_with_scratch(
        &self,
        packets: &mut Vec<InboundPacket>,
        by_shard: &mut [Vec<InboundPacket>],
    ) -> Result<()> {
        if packets.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(by_shard.len(), self.senders.len());
        for bucket in by_shard.iter_mut() {
            bucket.clear();
        }
        for packet in packets.drain(..) {
            by_shard[self.shard_for(packet.packet_info)].push(packet);
        }
        let mut sends = FuturesUnordered::new();
        for (index, (sender, shard)) in self.senders.iter().zip(by_shard.iter_mut()).enumerate() {
            if shard.is_empty() {
                continue;
            }
            let sender = sender.clone();
            let mut shard = std::mem::take(shard);
            sends.push(async move {
                while !shard.is_empty() {
                    let count = shard.len().min(FLOW_DISPATCH_QUEUE);
                    let permits = sender
                        .reserve_many(count)
                        .await
                        .context("inbound shard queue closed")?;
                    for (permit, packet) in permits.zip(shard.drain(..count)) {
                        permit.send(packet);
                    }
                }
                Ok::<_, anyhow::Error>((index, shard))
            });
        }
        while let Some(result) = sends.next().await {
            let (index, empty) = result?;
            by_shard[index] = empty;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(super) struct RouteDispatcher {
    senders: Arc<Vec<mpsc::Sender<RouteRequest>>>,
}

impl RouteDispatcher {
    pub(super) fn new(senders: Vec<mpsc::Sender<RouteRequest>>) -> Self {
        assert!(
            !senders.is_empty(),
            "at least one FlowRouter shard is required"
        );
        Self {
            senders: Arc::new(senders),
        }
    }

    pub(super) fn shard_count(&self) -> usize {
        self.senders.len()
    }

    fn shard_for(&self, packet: PacketInfo) -> usize {
        flow_shard(packet, self.senders.len())
    }

    /// Sends every shard independently. One saturated owner therefore cannot
    /// head-of-line block unrelated flow owners in the same TUN batch.
    pub(super) async fn send_batch_with_scratch(
        &self,
        requests: &mut Vec<RouteRequest>,
        by_shard: &mut [Vec<RouteRequest>],
    ) -> Result<()> {
        if requests.is_empty() {
            return Ok(());
        }
        debug_assert_eq!(by_shard.len(), self.senders.len());
        for bucket in by_shard.iter_mut() {
            bucket.clear();
        }
        for request in requests.drain(..) {
            by_shard[self.shard_for(request.packet_info)].push(request);
        }
        let mut sends = FuturesUnordered::new();
        for (index, (sender, shard)) in self.senders.iter().zip(by_shard.iter_mut()).enumerate() {
            if shard.is_empty() {
                continue;
            }
            let sender = sender.clone();
            let mut shard = std::mem::take(shard);
            sends.push(async move {
                while !shard.is_empty() {
                    let count = shard.len().min(FLOW_DISPATCH_QUEUE);
                    let permits = sender
                        .reserve_many(count)
                        .await
                        .context("FlowRouter request queue closed")?;
                    for (permit, request) in permits.zip(shard.drain(..count)) {
                        permit.send(request);
                    }
                }
                Ok::<_, anyhow::Error>((index, shard))
            });
        }
        while let Some(result) = sends.next().await {
            let (index, empty) = result?;
            by_shard[index] = empty;
        }
        Ok(())
    }
}

pub(super) fn flow_shard(packet: PacketInfo, shards: usize) -> usize {
    debug_assert!(shards > 0);
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut mix_u64 = |value: u64| {
        hash ^= value;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    let mut mix_bytes = |bytes: &[u8]| {
        let mut chunks = bytes.chunks_exact(8);
        for chunk in chunks.by_ref() {
            mix_u64(u64::from_be_bytes(chunk.try_into().unwrap()));
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut tail = [0_u8; 8];
            tail[..rest.len()].copy_from_slice(rest);
            mix_u64(u64::from_be_bytes(tail));
        }
    };
    match packet.source {
        std::net::IpAddr::V4(address) => mix_bytes(&address.octets()),
        std::net::IpAddr::V6(address) => mix_bytes(&address.octets()),
    }
    match packet.destination {
        std::net::IpAddr::V4(address) => mix_bytes(&address.octets()),
        std::net::IpAddr::V6(address) => mix_bytes(&address.octets()),
    }
    mix_bytes(&[packet.protocol]);
    mix_bytes(&packet.source_port.unwrap_or_default().to_be_bytes());
    mix_bytes(&packet.destination_port.unwrap_or_default().to_be_bytes());
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    if shards.is_power_of_two() {
        (hash as usize) & (shards - 1)
    } else {
        (hash as usize) % shards
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::Duration,
    };

    use super::*;
    use crate::buffer::DataplaneBuf;

    fn packet_for_shard(shard: usize) -> PacketInfo {
        (1..=u16::MAX)
            .map(|port| PacketInfo {
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                protocol: 17,
                source_port: Some(port),
                destination_port: Some(443),
                length: 1,
            })
            .find(|packet| flow_shard(*packet, 2) == shard)
            .unwrap()
    }

    fn request(packet_info: PacketInfo) -> RouteRequest {
        RouteRequest {
            packet: DataplaneBuf::from_static(b"x"),
            packet_info,
            previous_peer: None,
            delivery_tag: None,
        }
    }

    #[tokio::test]
    async fn saturated_shard_does_not_block_an_independent_owner() {
        let (tx0, mut rx0) = mpsc::channel(1);
        let (tx1, mut rx1) = mpsc::channel(1);
        let shard0 = packet_for_shard(0);
        let shard1 = packet_for_shard(1);
        tx0.try_send(request(shard0)).unwrap();
        let dispatcher = RouteDispatcher::new(vec![tx0, tx1]);
        let mut requests = vec![request(shard0), request(shard1)];
        let mut scratch = vec![Vec::new(), Vec::new()];

        let dispatch = tokio::spawn(async move {
            dispatcher
                .send_batch_with_scratch(&mut requests, &mut scratch)
                .await
        });
        let independent = tokio::time::timeout(Duration::from_millis(100), rx1.recv())
            .await
            .expect("independent shard was head-of-line blocked")
            .unwrap();
        assert_eq!(flow_shard(independent.packet_info, 2), 1);
        assert!(!dispatch.is_finished());

        rx0.recv().await.unwrap();
        dispatch.await.unwrap().unwrap();
        assert_eq!(flow_shard(rx0.recv().await.unwrap().packet_info, 2), 0);
    }
}
