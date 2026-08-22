//! Small, integer-only helpers for the fixed-point values used by the policy ABI.
//!
//! The functions in this module deliberately do not use floating point.  A
//! guest can therefore use them on every supported target without introducing
//! a second rounding rule between the native and WASM policy paths.

/// Scale of a `milli` value.
pub const MILLI: u64 = 1_000;
/// Scale of a per-million value.
pub const PPM: u64 = 1_000_000;

/// Convert a non-negative ratio `numerator / denominator` to milli, rounding
/// to nearest and saturating at `u32::MAX`.
pub const fn ratio_to_milli(numerator: u64, denominator: u64) -> u32 {
    ratio_to_scale(numerator, denominator, MILLI)
}

/// Convert a non-negative ratio `numerator / denominator` to ppm, rounding to
/// nearest and saturating at `u32::MAX`.
pub const fn ratio_to_ppm(numerator: u64, denominator: u64) -> u32 {
    ratio_to_scale(numerator, denominator, PPM)
}

/// Convert milli to ppm.  `1_000 milli` is `1_000_000 ppm`.
pub const fn milli_to_ppm(value: u32) -> u32 {
    value.saturating_mul(1_000)
}

/// Convert ppm to milli by truncating the fractional milli.
pub const fn ppm_to_milli(value: u32) -> u32 {
    value / 1_000
}

/// Convert ppm to milli with nearest-integer rounding.
pub const fn ppm_to_milli_round(value: u32) -> u32 {
    value.saturating_add(500) / 1_000
}

/// Saturating signed addition for ABI scores and utility terms.
pub const fn saturating_add_i32(left: i32, right: i32) -> i32 {
    left.saturating_add(right)
}

/// Saturating signed subtraction for ABI scores and utility terms.
pub const fn saturating_sub_i32(left: i32, right: i32) -> i32 {
    left.saturating_sub(right)
}

/// Saturating unsigned addition for byte/rate budgets.
pub const fn saturating_add_u64(left: u64, right: u64) -> u64 {
    left.saturating_add(right)
}

/// Saturating unsigned subtraction for byte/rate budgets.
pub const fn saturating_sub_u64(left: u64, right: u64) -> u64 {
    left.saturating_sub(right)
}

/// Saturating `(left * right) / divisor`, rounded down.
pub const fn mul_div_u64(left: u64, right: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return u64::MAX;
    }
    match left.checked_mul(right) {
        Some(product) => product / divisor,
        None => u64::MAX,
    }
}

const fn ratio_to_scale(numerator: u64, denominator: u64, scale: u64) -> u32 {
    if denominator == 0 {
        return u32::MAX;
    }
    let scaled = match numerator.checked_mul(scale) {
        Some(value) => value,
        None => return u32::MAX,
    };
    let rounded = scaled.saturating_add(denominator / 2) / denominator;
    if rounded > u32::MAX as u64 {
        u32::MAX
    } else {
        rounded as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratio_conversions_round_and_saturate() {
        assert_eq!(ratio_to_milli(1, 2), 500);
        assert_eq!(ratio_to_ppm(1, 2), 500_000);
        assert_eq!(milli_to_ppm(1_000), 1_000_000);
        assert_eq!(ppm_to_milli(1_999), 1);
        assert_eq!(ppm_to_milli_round(1_500), 2);
        assert_eq!(ratio_to_milli(1, 0), u32::MAX);
        assert_eq!(ratio_to_milli(u64::MAX, 1), u32::MAX);
    }

    #[test]
    fn arithmetic_is_saturating() {
        assert_eq!(saturating_add_i32(i32::MAX, 1), i32::MAX);
        assert_eq!(saturating_sub_i32(i32::MIN, 1), i32::MIN);
        assert_eq!(saturating_add_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(saturating_sub_u64(0, 1), 0);
        assert_eq!(mul_div_u64(u64::MAX, 2, 3), u64::MAX);
        assert_eq!(mul_div_u64(10, 3, 2), 15);
    }
}
