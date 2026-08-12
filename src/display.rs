//! Formatting helpers for values shown to people in the CLI.
//!
//! The status API and the JSON/JSONL CLI formats intentionally keep their
//! base units so that scripts have a stable, unambiguous contract.  Human
//! output goes through this module instead.

use std::time::Duration;

use chrono::{Local, TimeZone};

/// Format a byte count using SI prefixes, matching the existing CLI and
/// network-oriented counters.
pub fn bytes(value: u64) -> String {
    scaled(value as f64, 1000.0, &["B", "KB", "MB", "GB", "TB", "PB"])
}

/// Format a byte rate using binary byte prefixes.
pub fn bytes_per_second(value: u64) -> String {
    format!("{}/s", bytes(value))
}

/// Format a bit rate using SI prefixes, the convention used by link speeds.
pub fn bits_per_second(value: u64) -> String {
    scaled(
        value as f64,
        1000.0,
        &["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s", "Pbit/s"],
    )
}

/// Format a duration compactly, promoting through ns, µs, ms, s, min, h, and d.
pub fn duration(value: Duration) -> String {
    let nanos = value.as_nanos();
    if nanos == 0 {
        return "0s".into();
    }
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return scaled_duration(nanos as f64, 1_000.0, &["ns", "µs"]);
    }
    if nanos < 1_000_000_000 {
        return scaled_duration(nanos as f64 / 1_000_000.0, 1_000.0, &["ms"]);
    }

    let seconds = value.as_secs();
    if seconds < 60 {
        return scaled_duration(value.as_secs_f64(), 1_000.0, &["s"]);
    }

    let minutes = seconds / 60;
    let seconds = seconds % 60;
    if minutes < 60 {
        return format!("{minutes}m{seconds:02}s");
    }

    let hours = minutes / 60;
    let minutes = minutes % 60;
    if hours < 24 {
        return format!("{hours}h{minutes:02}m");
    }

    let days = hours / 24;
    let hours = hours % 24;
    format!("{days}d{hours:02}h")
}

/// Format a duration represented in microseconds.  Zero means a known zero;
/// callers that use zero as an unavailable sentinel should handle that first.
pub fn micros(value: u64) -> String {
    duration(Duration::from_micros(value))
}

/// Format a duration represented in milliseconds.
pub fn millis(value: u64) -> String {
    duration(Duration::from_millis(value))
}

/// Format a duration represented in fractional milliseconds.
pub fn millis_f64(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "?".into();
    }
    if value == 0.0 {
        return "0s".into();
    }
    if value < 0.001 {
        return format_duration_number(value * 1_000_000.0, "ns");
    }
    if value < 1.0 {
        return format_duration_number(value * 1_000.0, "µs");
    }
    if value < 1_000.0 {
        return format_duration_number(value, "ms");
    }
    duration(Duration::from_secs_f64(value / 1_000.0))
}

/// Render a Unix timestamp in the host's configured local time zone.
pub fn unix_timestamp(unix_seconds: u64) -> String {
    let Ok(seconds) = i64::try_from(unix_seconds) else {
        return format!("{unix_seconds}s since epoch");
    };
    Local
        .timestamp_opt(seconds, 0)
        .single()
        .map(|time| time.format("%Y-%m-%d %H:%M:%S %:z").to_string())
        .unwrap_or_else(|| format!("{unix_seconds}s since epoch"))
}

fn scaled(value: f64, base: f64, units: &[&str]) -> String {
    let mut scaled = value;
    let mut unit = 0;
    while scaled >= base && unit + 1 < units.len() {
        scaled /= base;
        unit += 1;
    }
    if unit == 0 && scaled.fract() == 0.0 {
        format!("{scaled:.0}{}", units[unit])
    } else {
        format_number(scaled, units[unit])
    }
}

fn scaled_duration(value: f64, base: f64, units: &[&str]) -> String {
    let mut scaled = value;
    let mut unit = 0;
    while scaled >= base && unit + 1 < units.len() {
        scaled /= base;
        unit += 1;
    }
    format_duration_number(scaled, units[unit])
}

fn format_number(value: f64, suffix: &str) -> String {
    let precision = if value >= 100.0 { 0 } else { 1 };
    format!("{value:.precision$}{suffix}")
}

fn format_duration_number(value: f64, suffix: &str) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}{suffix}")
    } else {
        format_number(value, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promotes_byte_and_bit_units() {
        assert_eq!(bytes(999), "999B");
        assert_eq!(bytes(1_500), "1.5KB");
        assert_eq!(bytes_per_second(1_500_000), "1.5MB/s");
        assert_eq!(bits_per_second(1_500_000), "1.5Mbit/s");
    }

    #[test]
    fn promotes_duration_units() {
        assert_eq!(duration(Duration::from_micros(500)), "500µs");
        assert_eq!(duration(Duration::from_millis(1_500)), "1.5s");
        assert_eq!(duration(Duration::from_secs(90)), "1m30s");
        assert_eq!(duration(Duration::from_secs(90_000)), "1d01h");
        assert_eq!(millis_f64(0.5), "500µs");
    }

    #[test]
    fn formats_unix_timestamps_in_the_local_time_zone() {
        let timestamp = 1_709_251_200_u64;
        let expected = Local
            .timestamp_opt(timestamp as i64, 0)
            .single()
            .unwrap()
            .format("%Y-%m-%d %H:%M:%S %:z")
            .to_string();
        assert_eq!(unix_timestamp(timestamp), expected);
    }
}
