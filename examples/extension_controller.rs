//! Minimal external controller using only the stable extension SDK.

use std::{env, time::Duration};

use ironet_extension_sdk::{
    ApplyRoutesRequest, CONTROL_API_VERSION, Client, DesiredRouteSpec, RouteApply,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var("IRONET_CONTROL_SOCKET")
        .unwrap_or_else(|_| ironet_extension_sdk::DEFAULT_CONTROL_SOCKET.into());
    let endpoint_id = env::var("IRONET_ROUTE_ENDPOINT")?;
    let client = Client::new(socket);

    let capabilities = client.capabilities().await?;
    println!("daemon capabilities: {capabilities:#?}");

    let result = client
        .apply_routes(ApplyRoutesRequest {
            routes: vec![RouteApply {
                api_version: CONTROL_API_VERSION,
                name: "example-office".into(),
                owner: "example.com/demo-controller".into(),
                revision: 1,
                ttl_seconds: Some(Duration::from_secs(300).as_secs()),
                spec: DesiredRouteSpec {
                    endpoint_id,
                    prefixes: vec!["10.30.0.0/16".into()],
                },
            }],
            dry_run: false,
            idempotency_key: "example-office-revision-1".into(),
        })
        .await?;
    println!("apply result: {result:#?}");

    let snapshot = client.snapshot().await?;
    let cursor = snapshot["event_cursor"].as_u64();
    let mut events = client.watch_events(cursor).await?;
    loop {
        println!("event: {:#?}", events.next().await?);
    }
}
