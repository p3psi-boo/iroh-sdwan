//! Stable, lightweight control-plane contract for Ironet extensions.
//!
//! This crate deliberately does not expose Ironet's routing, transport, or
//! runtime implementation types. Extensions communicate with the daemon over
//! the versioned Unix-socket API and survive internal refactors.

use std::{
    io,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixStream, unix::OwnedReadHalf},
};

pub const CONTROL_API_VERSION: u16 = 1;
pub const DEFAULT_CONTROL_SOCKET: &str = "/run/ironet/control.sock";
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub api_version: u16,
    pub minimum_api_version: u16,
    pub daemon_version: String,
    pub capabilities: Vec<Capability>,
    pub limits: ApiLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    pub name: String,
    pub version: u16,
    pub streaming: bool,
    pub mutable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiLimits {
    pub maximum_request_bytes: usize,
    pub maximum_response_bytes: usize,
    pub event_history: usize,
    pub maximum_route_ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredRouteSpec {
    pub endpoint_id: String,
    pub prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredRoute {
    pub api_version: u16,
    pub name: String,
    pub owner: String,
    pub revision: u64,
    pub expires_unix: Option<u64>,
    pub spec: DesiredRouteSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteApply {
    pub api_version: u16,
    pub name: String,
    pub owner: String,
    pub revision: u64,
    pub ttl_seconds: Option<u64>,
    pub spec: DesiredRouteSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyRoutesRequest {
    pub routes: Vec<RouteApply>,
    #[serde(default)]
    pub dry_run: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeleteRoutesRequest {
    pub owner: String,
    pub names: Vec<String>,
    pub expected_revision: Option<u64>,
    #[serde(default)]
    pub dry_run: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteMutationResult {
    pub generation: u64,
    pub changed: usize,
    pub unchanged: usize,
    pub dry_run: bool,
    pub routes: Vec<DesiredRoute>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionEvent {
    pub cursor: u64,
    pub emitted_unix_millis: u64,
    pub kind: String,
    pub resource: Option<String>,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventWatchAck {
    pub current_cursor: u64,
    pub oldest_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Rpc(RpcError),
    Protocol(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Rpc(error) => write!(formatter, "daemon {}: {}", error.code, error.message),
            Self::Protocol(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Client {
    socket: PathBuf,
}

impl Client {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    pub fn system() -> Self {
        Self::new(DEFAULT_CONTROL_SOCKET)
    }

    pub async fn capabilities(&self) -> Result<CapabilitySet> {
        self.request("get_capabilities", json!({})).await
    }

    /// Return a forward-compatible JSON snapshot. Extensions should deserialize
    /// only the fields they consume instead of binding to daemon internals.
    pub async fn snapshot(&self) -> Result<Value> {
        self.request("get_snapshot", json!({})).await
    }

    pub async fn routes(&self) -> Result<Vec<DesiredRoute>> {
        self.request("list_routes", json!({})).await
    }

    pub async fn apply_routes(&self, request: ApplyRoutesRequest) -> Result<RouteMutationResult> {
        self.request("apply_routes", serde_json::to_value(request)?)
            .await
    }

    pub async fn delete_routes(&self, request: DeleteRoutesRequest) -> Result<RouteMutationResult> {
        self.request("delete_routes", serde_json::to_value(request)?)
            .await
    }

    pub async fn watch_events(&self, after_cursor: Option<u64>) -> Result<EventStream> {
        let id = next_request_id();
        let mut request = json!({
            "version": CONTROL_API_VERSION,
            "id": id,
            "method": "watch_events",
        });
        request["after_cursor"] = serde_json::to_value(after_cursor)?;
        let mut reader = send(&self.socket, &request).await?;
        let frame = read_frame(&mut reader).await?;
        let ack = decode_result::<EventWatchAck>(frame, id)?;
        Ok(EventStream { id, ack, reader })
    }

    async fn request<T: DeserializeOwned>(&self, method: &str, parameters: Value) -> Result<T> {
        let id = next_request_id();
        let mut request = parameters;
        let object = request.as_object_mut().ok_or_else(|| {
            Error::Protocol("control request parameters must be an object".into())
        })?;
        object.insert("version".into(), json!(CONTROL_API_VERSION));
        object.insert("id".into(), json!(id));
        object.insert("method".into(), json!(method));
        let mut reader = send(&self.socket, &request).await?;
        decode_result(read_frame(&mut reader).await?, id)
    }
}

pub struct EventStream {
    id: u64,
    ack: EventWatchAck,
    reader: BufReader<OwnedReadHalf>,
}

impl EventStream {
    pub fn acknowledgement(&self) -> &EventWatchAck {
        &self.ack
    }

    pub async fn next(&mut self) -> Result<ExtensionEvent> {
        let frame = read_frame(&mut self.reader).await?;
        validate_frame(&frame, self.id)?;
        match frame.get("event").and_then(Value::as_str) {
            Some("extension_event") => Ok(serde_json::from_value(
                frame.get("extension_event").cloned().ok_or_else(|| {
                    Error::Protocol("extension event frame has no payload".into())
                })?,
            )?),
            Some("error") => Err(Error::Rpc(serde_json::from_value(
                frame
                    .get("error")
                    .cloned()
                    .ok_or_else(|| Error::Protocol("error frame has no error".into()))?,
            )?)),
            event => Err(Error::Protocol(format!(
                "unexpected event-stream frame {event:?}"
            ))),
        }
    }
}

async fn send(path: &Path, request: &Value) -> Result<BufReader<OwnedReadHalf>> {
    let stream = UnixStream::connect(path).await?;
    let (reader, mut writer) = stream.into_split();
    let mut encoded = serde_json::to_vec(request)?;
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol("control request is too large".into()));
    }
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.shutdown().await?;
    Ok(BufReader::new(reader))
}

async fn read_frame(reader: &mut BufReader<OwnedReadHalf>) -> Result<Value> {
    let mut encoded = Vec::new();
    let read = reader.read_until(b'\n', &mut encoded).await?;
    if read == 0 {
        return Err(Error::Protocol(
            "daemon closed the control connection without a frame".into(),
        ));
    }
    if encoded.len() > MAX_FRAME_BYTES {
        return Err(Error::Protocol("control response is too large".into()));
    }
    Ok(serde_json::from_slice(&encoded)?)
}

fn decode_result<T: DeserializeOwned>(frame: Value, id: u64) -> Result<T> {
    validate_frame(&frame, id)?;
    match frame.get("event").and_then(Value::as_str) {
        Some("result") => Ok(serde_json::from_value(
            frame
                .get("result")
                .cloned()
                .ok_or_else(|| Error::Protocol("result frame has no result".into()))?,
        )?),
        Some("error") => Err(Error::Rpc(serde_json::from_value(
            frame
                .get("error")
                .cloned()
                .ok_or_else(|| Error::Protocol("error frame has no error".into()))?,
        )?)),
        event => Err(Error::Protocol(format!(
            "unexpected control response {event:?}"
        ))),
    }
}

fn validate_frame(frame: &Value, id: u64) -> Result<()> {
    if frame.get("version").and_then(Value::as_u64) != Some(u64::from(CONTROL_API_VERSION)) {
        return Err(Error::Protocol(
            "daemon returned an unsupported control API version".into(),
        ));
    }
    if frame.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(Error::Protocol("daemon response ID mismatch".into()));
    }
    Ok(())
}

fn next_request_id() -> u64 {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    sequence ^ (u64::from(std::process::id()) << 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_requests_are_forward_compatible_json_contracts() {
        let request = ApplyRoutesRequest {
            routes: vec![RouteApply {
                api_version: CONTROL_API_VERSION,
                name: "office".into(),
                owner: "example.com/ipam".into(),
                revision: 7,
                ttl_seconds: Some(300),
                spec: DesiredRouteSpec {
                    endpoint_id: "endpoint".into(),
                    prefixes: vec!["10.30.0.0/16".into()],
                },
            }],
            dry_run: true,
            idempotency_key: "request-7".into(),
        };
        let value = serde_json::to_value(request).unwrap();
        assert_eq!(value["routes"][0]["owner"], "example.com/ipam");
        assert_eq!(value["routes"][0]["revision"], 7);
    }
}
