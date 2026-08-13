use tracing_subscriber::EnvFilter;

pub fn init(quiet: bool) {
    let default_filter = if quiet { "warn" } else { "info" };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    if std::env::var("IRONET_LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt()
            .json()
            .with_writer(std::io::stderr)
            .with_current_span(false)
            .with_span_list(false)
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .init();
    }
}
