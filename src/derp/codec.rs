use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_PACKET_SIZE: usize = 64 << 10;
pub const MAX_FRAME_SIZE: usize = 1 << 20;
pub const MAGIC: &[u8; 8] = b"DERP\xF0\x9F\x94\x91";

pub const FRAME_SERVER_KEY: u8 = 0x01;
pub const FRAME_CLIENT_INFO: u8 = 0x02;
pub const FRAME_SERVER_INFO: u8 = 0x03;
pub const FRAME_SEND_PACKET: u8 = 0x04;
pub const FRAME_RECV_PACKET: u8 = 0x05;
pub const FRAME_KEEP_ALIVE: u8 = 0x06;
pub const FRAME_NOTE_PREFERRED: u8 = 0x07;
pub const FRAME_PEER_GONE: u8 = 0x08;
pub const FRAME_PING: u8 = 0x12;
pub const FRAME_PONG: u8 = 0x13;
pub const FRAME_HEALTH: u8 = 0x14;
pub const FRAME_RESTARTING: u8 = 0x15;

#[derive(Debug)]
pub struct Frame {
    pub frame_type: u8,
    pub payload: Bytes,
}

pub async fn read_frame<R>(reader: &mut R) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let frame_type = reader.read_u8().await?;
    let len = reader.read_u32().await? as usize;
    ensure!(
        len <= MAX_FRAME_SIZE,
        "DERP frame type 0x{frame_type:02x} length {len} exceeds maximum size {MAX_FRAME_SIZE}"
    );
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Frame {
        frame_type,
        payload: payload.into(),
    })
}

pub async fn write_frame<W>(writer: &mut W, frame_type: u8, payload: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_SIZE {
        bail!("DERP frame exceeds maximum size");
    }
    writer.write_u8(frame_type).await?;
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut left, mut right) = tokio::io::duplex(1024);
        let write = tokio::spawn(async move {
            write_frame(&mut left, FRAME_PING, b"12345678")
                .await
                .unwrap();
        });
        let frame = read_frame(&mut right).await.unwrap();
        write.await.unwrap();
        assert_eq!(frame.frame_type, FRAME_PING);
        assert_eq!(&frame.payload[..], b"12345678");
    }
}
