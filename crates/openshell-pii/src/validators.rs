// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-FileCopyrightText: Copyright (c) 2025-2026 Infrastacks LLC.
// SPDX-FileCopyrightText: Copyright (c) 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PII entity validators. Reduces false positives from regex detectors.
//! `luhn` relocated from `entities.rs`; email, SSN, phone, and `card_brand`
//! validators are implemented in this crate.

/// Luhn check (ISO/IEC 7812-1). Relocated from `entities.rs`.
pub fn luhn(card_number: &str) -> bool {
    let digits: Vec<u32> = card_number
        .chars()
        .filter(char::is_ascii_digit)
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &digit in digits.iter().rev() {
        let mut value = digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

/// Validate email address using RFC 5322 rules (basic subset)
/// Returns: true if valid, false otherwise
///
/// Validation rules:
/// - Local part (before @): 1-64 characters, alphanumeric + ._%+-
/// - Domain part (after @): Valid domain with TLD
/// - No consecutive dots
/// - No leading/trailing dots
///
/// Note: Full RFC 5322 is complex (allows quoted strings, comments, etc.)
/// This implements the 99% common case for production use
pub fn email(input: &str) -> bool {
    // Basic length check
    if input.len() > 320 || input.len() < 6 {
        // RFC 5321: max 320 chars (64 local + 1 @ + 255 domain)
        return false;
    }

    // Split on @ (must have exactly one)
    let parts: Vec<&str> = input.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Validate local part
    if local.is_empty() || local.len() > 64 {
        return false;
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    if !local
        .chars()
        .all(|c| c.is_alphanumeric() || "._%+-".contains(c))
    {
        return false;
    }

    // Validate domain part
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }

    // Domain must have at least one dot (TLD required)
    if !domain.contains('.') {
        return false;
    }

    // Each domain label must be valid
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }

    true
}

/// Validate SSN format and reserved ranges
/// Returns: true if valid, false otherwise
///
/// Invalid SSN ranges (per SSA):
/// - Area (first 3 digits): 000, 666, 900-999
/// - Group (middle 2 digits): 00
/// - Serial (last 4 digits): 0000
///
/// Note: This validates format only, not whether SSN is actually issued
pub fn ssn(input: &str) -> bool {
    // Remove dashes and validate format
    let cleaned = input.replace('-', "");

    if cleaned.len() != 9 || !cleaned.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    // Parse components
    let area: u32 = cleaned[0..3].parse().unwrap_or(0);
    let group: u32 = cleaned[3..5].parse().unwrap_or(0);
    let serial: u32 = cleaned[5..9].parse().unwrap_or(0);

    // Validate area number (000, 666, 900-999 are invalid)
    if area == 0 || area == 666 || area >= 900 {
        return false;
    }

    // Validate group number (00 is invalid)
    if group == 0 {
        return false;
    }

    // Validate serial number (0000 is invalid)
    if serial == 0 {
        return false;
    }

    true
}

/// Normalize phone number to E.164 format
/// Returns: Normalized phone number (e.g., "+15551234567") or None if invalid
///
/// Supports:
/// - US/Canada: (555) 123-4567, 555-123-4567, 5551234567
/// - International: +1-555-123-4567, +44 20 1234 5678
///
/// Note: Assumes US/Canada (+1) if no country code provided
pub fn normalize_phone(input: &str) -> Option<String> {
    // Extract digits and leading +
    let mut normalized = String::new();
    let mut has_plus = false;

    for c in input.chars() {
        if c == '+' && normalized.is_empty() {
            has_plus = true;
            normalized.push('+');
        } else if c.is_ascii_digit() {
            normalized.push(c);
        }
    }

    // Remove leading +
    let digits = if has_plus {
        normalized.trim_start_matches('+')
    } else {
        &normalized
    };

    // Validate length and format
    match digits.len() {
        10 => {
            // US/Canada number without country code
            Some(format!("+1{digits}"))
        }
        11 if digits.starts_with('1') => {
            // US/Canada number with country code
            Some(format!("+{digits}"))
        }
        7..=15 if has_plus => {
            // International number with country code
            Some(format!("+{digits}"))
        }
        _ => None, // Invalid length
    }
}

/// Get card brand from card number using IIN (Issuer Identification Number)
/// Returns: Card brand name or "UNKNOWN"
///
/// BIN ranges (first 6 digits):
/// - Visa: 4
/// - `MasterCard`: 51-55, 2221-2720
/// - American Express: 34, 37
/// - Discover: 6011, 622126-622925, 644-649, 65
pub fn card_brand(input: &str) -> &'static str {
    let digits: String = input.chars().filter(char::is_ascii_digit).collect();

    if digits.is_empty() {
        return "UNKNOWN";
    }

    let first_digit = digits.chars().next().unwrap();
    let first_two: u32 = if digits.len() >= 2 {
        digits[0..2].parse().unwrap_or(0)
    } else {
        0
    };
    let first_four: u32 = if digits.len() >= 4 {
        digits[0..4].parse().unwrap_or(0)
    } else {
        0
    };

    match first_digit {
        '4' => "VISA",
        '3' if first_two == 34 || first_two == 37 => "AMEX",
        '5' if (51..=55).contains(&first_two) => "MASTERCARD",
        '2' if (2221..=2720).contains(&first_four) => "MASTERCARD",
        '6' if first_four == 6011 || first_two == 65 => "DISCOVER",
        '6' if (644..=649).contains(&first_two) => "DISCOVER",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Luhn algorithm tests
    #[test]
    fn luhn_valid_visa() {
        assert!(luhn("4111111111111111")); // Visa test card
    }

    #[test]
    fn luhn_valid_mastercard() {
        assert!(luhn("5555555555554444")); // MasterCard test card
    }

    #[test]
    fn luhn_valid_with_spaces() {
        assert!(luhn("4111 1111 1111 1111"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn("4111111111111112")); // Wrong check digit
    }

    #[test]
    fn luhn_too_short() {
        assert!(!luhn("411111")); // Only 6 digits
    }

    // Email validation tests
    #[test]
    fn email_valid_basic() {
        assert!(email("user@example.com"));
    }

    #[test]
    fn email_valid_subdomain() {
        assert!(email("user@mail.example.com"));
    }

    #[test]
    fn email_valid_plus() {
        assert!(email("user+tag@example.com"));
    }

    #[test]
    fn email_invalid_no_at() {
        assert!(!email("userexample.com"));
    }

    #[test]
    fn email_invalid_no_domain() {
        assert!(!email("user@"));
    }

    #[test]
    fn email_invalid_no_tld() {
        assert!(!email("user@localhost"));
    }

    #[test]
    fn email_invalid_consecutive_dots() {
        assert!(!email("user..name@example.com"));
    }

    // SSN validation tests
    #[test]
    fn ssn_valid_with_dashes() {
        assert!(ssn("123-45-6789"));
    }

    #[test]
    fn ssn_valid_no_dashes() {
        assert!(ssn("123456789")); // Area=123 (valid), Group=45, Serial=6789
    }

    #[test]
    fn ssn_invalid_area_000() {
        assert!(!ssn("000-45-6789"));
    }

    #[test]
    fn ssn_invalid_area_666() {
        assert!(!ssn("666-45-6789"));
    }

    #[test]
    fn ssn_invalid_area_900() {
        assert!(!ssn("900-45-6789"));
    }

    #[test]
    fn ssn_invalid_group_00() {
        assert!(!ssn("123-00-6789"));
    }

    #[test]
    fn ssn_invalid_serial_0000() {
        assert!(!ssn("123-45-0000"));
    }

    // Phone normalization tests
    #[test]
    fn normalize_phone_us_with_parens() {
        assert_eq!(
            normalize_phone("(555) 123-4567"),
            Some("+15551234567".to_string())
        );
    }

    #[test]
    fn normalize_phone_us_with_dashes() {
        assert_eq!(
            normalize_phone("555-123-4567"),
            Some("+15551234567".to_string())
        );
    }

    #[test]
    fn normalize_phone_us_no_formatting() {
        assert_eq!(
            normalize_phone("5551234567"),
            Some("+15551234567".to_string())
        );
    }

    #[test]
    fn normalize_phone_international() {
        assert_eq!(
            normalize_phone("+44 20 1234 5678"),
            Some("+442012345678".to_string())
        );
    }

    #[test]
    fn normalize_phone_invalid_too_short() {
        assert_eq!(normalize_phone("12345"), None);
    }

    // Card brand detection tests
    #[test]
    fn card_brand_visa() {
        assert_eq!(card_brand("4111111111111111"), "VISA");
    }

    #[test]
    fn card_brand_mastercard() {
        assert_eq!(card_brand("5555555555554444"), "MASTERCARD");
    }

    #[test]
    fn card_brand_amex() {
        assert_eq!(card_brand("378282246310005"), "AMEX");
    }

    #[test]
    fn card_brand_discover() {
        assert_eq!(card_brand("6011111111111117"), "DISCOVER");
    }

    #[test]
    fn card_brand_unknown() {
        assert_eq!(card_brand("9999999999999999"), "UNKNOWN");
    }
}
