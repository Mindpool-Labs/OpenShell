// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII entity type definitions with compiled regex patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::LazyLock;

/// Supported PII entity types.
///
/// Variants fall into two categories:
/// - **Regex-detected**: Have compiled patterns in `builtin_patterns()` (Ssn through Passport).
/// - **NER-only**: Detected by the ML-based NER service (Person through NationalId).
///   These have no regex patterns and require the `ner` feature and a running NER service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    // -- Regex-detected entity types --
    Ssn,
    CreditCard,
    Email,
    Phone,
    IpAddress,
    AwsAccessKey,
    AwsSecretKey,
    Jwt,
    ApiKey,
    Passport,
    // -- Additional regex-detected entity types (Financial/Technical/Tax) --
    Iban,
    RoutingNumber,
    SwiftCode,
    BankAccount,
    BitcoinAddress,
    EthereumAddress,
    Vin,
    MacAddress,
    Ipv6,
    Url,
    Username,
    Coordinates,
    TaxIdEin,
    TaxIdItin,
    // -- NER-only entity types (no regex pattern) --
    Person,
    Organization,
    Address,
    DateOfBirth,
    MedicalTerm,
    Location,
    NationalId,
    /// User-defined custom pattern (name carried in PiiDetection metadata).
    Custom,
}

impl fmt::Display for EntityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ssn => write!(f, "ssn"),
            Self::CreditCard => write!(f, "credit_card"),
            Self::Email => write!(f, "email"),
            Self::Phone => write!(f, "phone"),
            Self::IpAddress => write!(f, "ip_address"),
            Self::AwsAccessKey => write!(f, "aws_access_key"),
            Self::AwsSecretKey => write!(f, "aws_secret_key"),
            Self::Jwt => write!(f, "jwt"),
            Self::ApiKey => write!(f, "api_key"),
            Self::Passport => write!(f, "passport"),
            Self::Iban => write!(f, "iban"),
            Self::RoutingNumber => write!(f, "routing_number"),
            Self::SwiftCode => write!(f, "swift_code"),
            Self::BankAccount => write!(f, "bank_account"),
            Self::BitcoinAddress => write!(f, "bitcoin_address"),
            Self::EthereumAddress => write!(f, "ethereum_address"),
            Self::Vin => write!(f, "vin"),
            Self::MacAddress => write!(f, "mac_address"),
            Self::Ipv6 => write!(f, "ipv6"),
            Self::Url => write!(f, "url"),
            Self::Username => write!(f, "username"),
            Self::Coordinates => write!(f, "coordinates"),
            Self::TaxIdEin => write!(f, "tax_id_ein"),
            Self::TaxIdItin => write!(f, "tax_id_itin"),
            Self::Person => write!(f, "person"),
            Self::Organization => write!(f, "organization"),
            Self::Address => write!(f, "address"),
            Self::DateOfBirth => write!(f, "date_of_birth"),
            Self::MedicalTerm => write!(f, "medical_term"),
            Self::Location => write!(f, "location"),
            Self::NationalId => write!(f, "national_id"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl EntityType {
    /// Parse from the YAML/JSON string form.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ssn" => Some(Self::Ssn),
            "credit_card" => Some(Self::CreditCard),
            "email" => Some(Self::Email),
            "phone" => Some(Self::Phone),
            "ip_address" => Some(Self::IpAddress),
            "aws_access_key" => Some(Self::AwsAccessKey),
            "aws_secret_key" => Some(Self::AwsSecretKey),
            "jwt" => Some(Self::Jwt),
            "api_key" => Some(Self::ApiKey),
            "passport" => Some(Self::Passport),
            "iban" => Some(Self::Iban),
            "routing_number" => Some(Self::RoutingNumber),
            "swift_code" => Some(Self::SwiftCode),
            "bank_account" => Some(Self::BankAccount),
            "bitcoin_address" => Some(Self::BitcoinAddress),
            "ethereum_address" => Some(Self::EthereumAddress),
            "vin" => Some(Self::Vin),
            "mac_address" => Some(Self::MacAddress),
            "ipv6" => Some(Self::Ipv6),
            "url" => Some(Self::Url),
            "username" => Some(Self::Username),
            "coordinates" => Some(Self::Coordinates),
            "tax_id_ein" => Some(Self::TaxIdEin),
            "tax_id_itin" => Some(Self::TaxIdItin),
            "person" => Some(Self::Person),
            "organization" | "org" => Some(Self::Organization),
            "address" => Some(Self::Address),
            "date_of_birth" | "dob" => Some(Self::DateOfBirth),
            "medical_term" | "medical" => Some(Self::MedicalTerm),
            "location" | "loc" | "gpe" => Some(Self::Location),
            "national_id" => Some(Self::NationalId),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// Returns `true` for entity types that can only be detected by a NER model,
    /// not by regex patterns.
    pub fn is_ner_only(&self) -> bool {
        matches!(
            self,
            Self::Person
                | Self::Organization
                | Self::Address
                | Self::DateOfBirth
                | Self::MedicalTerm
                | Self::Location
                | Self::NationalId
        )
    }
}

/// A compiled pattern for a single entity type.
pub struct EntityPattern {
    pub entity_type: EntityType,
    pub regex: &'static Regex,
    /// Base confidence for regex matches (0.0–1.0).
    pub confidence: f32,
    /// Optional post-match validator (e.g., Luhn check for credit cards).
    pub validator: Option<fn(&str) -> bool>,
}

// ---------- Compiled regex patterns (built once, reused) ----------

static RE_SSN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("SSN regex"));

static RE_CREDIT_CARD: LazyLock<Regex> = LazyLock::new(|| {
    // 13–19 digit sequences, optionally separated by a single space or dash.
    // Uses `[ -]?` (0 or 1) instead of `[ -]*?` to avoid nested quantifiers.
    Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").expect("credit card regex")
});

static RE_EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("email regex")
});

static RE_PHONE: LazyLock<Regex> = LazyLock::new(|| {
    // US/intl formats: +1-555-123-4567, (555) 123-4567, 555.123.4567, etc.
    Regex::new(r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").expect("phone regex")
});

static RE_IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
        .expect("IPv4 regex")
});

static RE_AWS_ACCESS_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("AWS access key regex"));

static RE_AWS_SECRET_KEY: LazyLock<Regex> = LazyLock::new(|| {
    // 40-char base64 string (letters, digits, +, /) commonly following an access key.
    Regex::new(r"\b[A-Za-z0-9/+=]{40}\b").expect("AWS secret key regex")
});

static RE_JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_.+-]+\b").expect("JWT regex")
});

static RE_API_KEY: LazyLock<Regex> = LazyLock::new(|| {
    // High-entropy hex or base64 strings of 32+ characters, typically prefixed by
    // common key identifiers. Deliberately conservative to reduce false positives.
    Regex::new(r"\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[A-Za-z0-9_-]{32,}\b")
        .expect("API key regex")
});

static RE_PASSPORT: LazyLock<Regex> = LazyLock::new(|| {
    // Common passport formats: US (9 digits), UK (9 digits), EU (2 letters + 7 digits).
    Regex::new(r"\b[A-Z]{1,2}\d{6,9}\b").expect("passport regex")
});

// ---------- Financial / Technical / Tax patterns (Task 6a) ----------
// Patterns ported verbatim from the pre-consolidation NeuronEdge redaction-engine
// detectors (`regex.rs` and `regex_extended.rs`). See task 6a report for source line refs.

static RE_IBAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,16})?\b").expect("IBAN regex")
});

static RE_ROUTING_NUMBER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:0[0-9]|1[0-2]|2[1-9]|3[0-2]|6[1-9]|7[0-2]|80)\d{7}\b")
        .expect("routing number regex")
});

static RE_SWIFT_CODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b").expect("SWIFT code regex")
});

static RE_BANK_ACCOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{8,17}\b").expect("bank account regex"));

static RE_BANK_ACCOUNT_US: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{8,17}\b").expect("US bank account regex"));

static RE_BITCOIN_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b").expect("bitcoin address regex")
});

static RE_BITCOIN_BECH32: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\bbc1[ac-hj-np-z02-9]{39,59}\b").expect("bitcoin bech32 regex"));

static RE_ETHEREUM_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b0x[a-f0-9]{40}\b").expect("ethereum address regex"));

static RE_VIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-HJ-NPR-Z0-9]{17}\b").expect("VIN regex"));

static RE_MAC_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b").expect("MAC address regex")
});

static RE_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|\b:(?::[0-9a-f]{1,4}){1,7}\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b")
            .expect("IPv6 regex")
});

static RE_URL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bhttps?://[a-z0-9](?:[a-z0-9._~:/?#\[\]@!$&'()*+,;=-]*[a-z0-9/])?|\bwww\.[a-z0-9](?:[a-z0-9._~:/?#\[\]@!$&'()*+,;=-]*[a-z0-9/])?\b")
            .expect("URL regex")
});

static RE_USERNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[\s\(\[\{,;:!?/\-])@([a-zA-Z0-9_]{2,32})").expect("username regex")
});

static RE_COORDINATES_DECIMAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[+-]?(?:90|[0-8]?\d)(?:\.\d{1,8})?)[,\s]+[+-]?(?:180|1[0-7]\d|[0-9]{1,2})(?:\.\d{1,8})?")
            .expect("decimal coordinates regex")
});

static RE_COORDINATES_DMS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[0-8]?\d[dD][0-5]?\d[mM][0-5]?\d(?:\.\d+)?[sS][NSEWnsew]\s+(?:1[0-7]\d|[0-9]{1,2})[dD][0-5]?\d[mM][0-5]?\d(?:\.\d+)?[sS][NSEWnsew])")
            .expect("DMS coordinates regex")
});

static RE_TAX_ID_EIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b\d{2}-\d{7}\b").expect("tax ID EIN regex"));

static RE_TAX_ID_ITIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b9\d{2}-\d{2}-\d{4}\b").expect("tax ID ITIN regex"));

static RE_ITIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b9\d{2}-\d{2}-\d{4}\b").expect("ITIN regex"));

/// All built-in entity patterns.
pub fn builtin_patterns() -> Vec<EntityPattern> {
    vec![
        EntityPattern {
            entity_type: EntityType::Ssn,
            regex: &RE_SSN,
            confidence: 0.9,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::CreditCard,
            regex: &RE_CREDIT_CARD,
            confidence: 0.95,
            validator: Some(crate::validators::luhn),
        },
        EntityPattern {
            entity_type: EntityType::Email,
            regex: &RE_EMAIL,
            confidence: 0.95,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Phone,
            regex: &RE_PHONE,
            confidence: 0.7,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::IpAddress,
            regex: &RE_IPV4,
            confidence: 0.6,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::AwsAccessKey,
            regex: &RE_AWS_ACCESS_KEY,
            confidence: 0.99,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::AwsSecretKey,
            regex: &RE_AWS_SECRET_KEY,
            confidence: 0.4, // Low confidence: pattern matches many base64 strings (commit SHAs, UUIDs)
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Jwt,
            regex: &RE_JWT,
            confidence: 0.99,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::ApiKey,
            regex: &RE_API_KEY,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Passport,
            regex: &RE_PASSPORT,
            confidence: 0.5,
            validator: None,
        },
        // -- Financial / Technical / Tax patterns (Task 6a) --
        EntityPattern {
            entity_type: EntityType::Iban,
            regex: &RE_IBAN,
            confidence: 0.85,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::RoutingNumber,
            regex: &RE_ROUTING_NUMBER,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::SwiftCode,
            regex: &RE_SWIFT_CODE,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::BankAccount,
            regex: &RE_BANK_ACCOUNT,
            confidence: 0.3,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::BankAccount,
            regex: &RE_BANK_ACCOUNT_US,
            confidence: 0.3,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::BitcoinAddress,
            regex: &RE_BITCOIN_ADDRESS,
            confidence: 0.7,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::BitcoinAddress,
            regex: &RE_BITCOIN_BECH32,
            confidence: 0.7,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::EthereumAddress,
            regex: &RE_ETHEREUM_ADDRESS,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Vin,
            regex: &RE_VIN,
            confidence: 0.6,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::MacAddress,
            regex: &RE_MAC_ADDRESS,
            confidence: 0.85,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Ipv6,
            regex: &RE_IPV6,
            confidence: 0.6,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Url,
            regex: &RE_URL,
            confidence: 0.5,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Username,
            regex: &RE_USERNAME,
            confidence: 0.4,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Coordinates,
            regex: &RE_COORDINATES_DECIMAL,
            confidence: 0.5,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::Coordinates,
            regex: &RE_COORDINATES_DMS,
            confidence: 0.5,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::TaxIdEin,
            regex: &RE_TAX_ID_EIN,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::TaxIdItin,
            regex: &RE_TAX_ID_ITIN,
            confidence: 0.8,
            validator: None,
        },
        EntityPattern {
            entity_type: EntityType::TaxIdItin,
            regex: &RE_ITIN,
            confidence: 0.8,
            validator: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SSN ----
    #[test]
    fn ssn_detects_valid() {
        assert!(RE_SSN.is_match("123-45-6789"));
        assert!(RE_SSN.is_match("My SSN is 078-05-1120 ok"));
    }

    #[test]
    fn ssn_rejects_partial() {
        assert!(!RE_SSN.is_match("123-456-789"));
        assert!(!RE_SSN.is_match("12-34-5678"));
    }

    // ---- Credit card + Luhn ----
    #[test]
    fn credit_card_luhn_valid() {
        assert!(crate::validators::luhn("4111111111111111")); // Visa test
        assert!(crate::validators::luhn("5500000000000004")); // MC test
        assert!(crate::validators::luhn("378282246310005")); // Amex test
    }

    #[test]
    fn credit_card_luhn_invalid() {
        assert!(!crate::validators::luhn("4111111111111112"));
        assert!(!crate::validators::luhn("1234567890"));
    }

    // ---- Email ----
    #[test]
    fn email_detects_valid() {
        assert!(RE_EMAIL.is_match("user@example.com"));
        assert!(RE_EMAIL.is_match("test.user+tag@sub.domain.io"));
    }

    #[test]
    fn email_rejects_invalid() {
        assert!(!RE_EMAIL.is_match("@example.com"));
        assert!(!RE_EMAIL.is_match("user@"));
    }

    // ---- AWS access key ----
    #[test]
    fn aws_access_key_detects() {
        assert!(RE_AWS_ACCESS_KEY.is_match("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn aws_access_key_rejects_short() {
        assert!(!RE_AWS_ACCESS_KEY.is_match("AKIA1234"));
    }

    // ---- JWT ----
    #[test]
    fn jwt_detects_valid() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        assert!(RE_JWT.is_match(jwt));
    }

    #[test]
    fn jwt_rejects_random() {
        assert!(!RE_JWT.is_match("not.a.jwt"));
        assert!(!RE_JWT.is_match("eyJ.short.x"));
    }

    // ---- API key ----
    #[test]
    fn api_key_detects() {
        assert!(RE_API_KEY.is_match("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(RE_API_KEY.is_match("api_key_Abcdefghijklmnopqrstuvwxyz12345"));
    }

    #[test]
    fn api_key_rejects_short() {
        assert!(!RE_API_KEY.is_match("sk-short"));
    }

    // ---- IP address ----
    #[test]
    fn ip_detects_valid() {
        assert!(RE_IPV4.is_match("192.168.1.1"));
        assert!(RE_IPV4.is_match("10.0.0.255"));
    }

    #[test]
    fn ip_rejects_out_of_range() {
        assert!(!RE_IPV4.is_match("999.999.999.999"));
    }

    // ---- Phone ----
    #[test]
    fn phone_detects_us_formats() {
        assert!(RE_PHONE.is_match("(555) 123-4567"));
        assert!(RE_PHONE.is_match("+1-555-123-4567"));
        assert!(RE_PHONE.is_match("555.123.4567"));
    }

    // ---- Passport ----
    #[test]
    fn passport_detects() {
        assert!(RE_PASSPORT.is_match("AB1234567"));
        assert!(RE_PASSPORT.is_match("C12345678"));
    }

    #[test]
    fn passport_rejects_lowercase() {
        assert!(!RE_PASSPORT.is_match("ab1234567"));
    }

    // ---- NER entity types ----
    #[test]
    fn ner_entity_types_parse() {
        assert_eq!(EntityType::parse("person"), Some(EntityType::Person));
        assert_eq!(
            EntityType::parse("organization"),
            Some(EntityType::Organization)
        );
        assert_eq!(EntityType::parse("org"), Some(EntityType::Organization));
        assert_eq!(EntityType::parse("address"), Some(EntityType::Address));
        assert_eq!(
            EntityType::parse("date_of_birth"),
            Some(EntityType::DateOfBirth)
        );
        assert_eq!(EntityType::parse("dob"), Some(EntityType::DateOfBirth));
        assert_eq!(
            EntityType::parse("medical_term"),
            Some(EntityType::MedicalTerm)
        );
        assert_eq!(EntityType::parse("medical"), Some(EntityType::MedicalTerm));
        assert_eq!(EntityType::parse("location"), Some(EntityType::Location));
        assert_eq!(EntityType::parse("loc"), Some(EntityType::Location));
        assert_eq!(EntityType::parse("gpe"), Some(EntityType::Location));
        assert_eq!(
            EntityType::parse("national_id"),
            Some(EntityType::NationalId)
        );
    }

    #[test]
    fn ner_entity_types_display() {
        assert_eq!(EntityType::Person.to_string(), "person");
        assert_eq!(EntityType::Organization.to_string(), "organization");
        assert_eq!(EntityType::Address.to_string(), "address");
        assert_eq!(EntityType::DateOfBirth.to_string(), "date_of_birth");
        assert_eq!(EntityType::MedicalTerm.to_string(), "medical_term");
        assert_eq!(EntityType::Location.to_string(), "location");
        assert_eq!(EntityType::NationalId.to_string(), "national_id");
    }

    #[test]
    fn is_ner_only_discriminator() {
        // Regex-detected types should return false.
        assert!(!EntityType::Ssn.is_ner_only());
        assert!(!EntityType::CreditCard.is_ner_only());
        assert!(!EntityType::Email.is_ner_only());
        assert!(!EntityType::ApiKey.is_ner_only());

        // NER-only types should return true.
        assert!(EntityType::Person.is_ner_only());
        assert!(EntityType::Organization.is_ner_only());
        assert!(EntityType::Address.is_ner_only());
        assert!(EntityType::DateOfBirth.is_ner_only());
        assert!(EntityType::MedicalTerm.is_ner_only());
        assert!(EntityType::Location.is_ner_only());
        assert!(EntityType::NationalId.is_ner_only());
    }

    // ---- Task 6a: Financial / Technical / Tax regex patterns ----

    #[test]
    fn iban_detects_and_rejects() {
        assert!(RE_IBAN.is_match("GB29NWBK60161331926819"));
        assert!(RE_IBAN.is_match("DE89370400440532013000"));
        assert!(!RE_IBAN.is_match("GB2"));
    }

    #[test]
    fn routing_number_detects_and_rejects() {
        assert!(RE_ROUTING_NUMBER.is_match("021000021"));
        assert!(!RE_ROUTING_NUMBER.is_match("999999999")); // invalid prefix
    }

    #[test]
    fn swift_code_detects_and_rejects() {
        assert!(RE_SWIFT_CODE.is_match("DEUTDEDB"));
        assert!(RE_SWIFT_CODE.is_match("DEUTDEDBXXX"));
        assert!(!RE_SWIFT_CODE.is_match("DEUT"));
    }

    #[test]
    fn bank_account_detects_and_rejects() {
        assert!(RE_BANK_ACCOUNT.is_match("12345678901234567"));
        assert!(RE_BANK_ACCOUNT_US.is_match("12345678901234567"));
        assert!(!RE_BANK_ACCOUNT.is_match("1234567")); // too short
    }

    #[test]
    fn bitcoin_address_detects_and_rejects() {
        assert!(RE_BITCOIN_ADDRESS.is_match("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(RE_BITCOIN_BECH32.is_match("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(!RE_BITCOIN_ADDRESS.is_match("1abc"));
    }

    #[test]
    fn ethereum_address_detects_and_rejects() {
        assert!(RE_ETHEREUM_ADDRESS.is_match("0x1234567890abcdef1234567890abcdef12345678"));
        assert!(RE_ETHEREUM_ADDRESS.is_match("0xABCDEF1234567890ABCDEF1234567890ABCDEF12"));
        assert!(!RE_ETHEREUM_ADDRESS.is_match("0x1234"));
    }

    #[test]
    fn vin_detects_and_rejects() {
        assert!(RE_VIN.is_match("1HGBH41JXMN109186"));
        assert!(!RE_VIN.is_match("1HGBH41JXMN10918")); // 16 chars
    }

    #[test]
    fn mac_address_detects_and_rejects() {
        assert!(RE_MAC_ADDRESS.is_match("00:1A:2B:3C:4D:5E"));
        assert!(RE_MAC_ADDRESS.is_match("AA-BB-CC-DD-EE-FF"));
        assert!(!RE_MAC_ADDRESS.is_match("00:1A:2B:3C")); // too few octets
    }

    #[test]
    fn ipv6_detects_and_rejects() {
        assert!(RE_IPV6.is_match("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assert!(!RE_IPV6.is_match("not-an-ipv6-address"));
    }

    #[test]
    fn url_detects_and_rejects() {
        assert!(RE_URL.is_match("https://example.com"));
        assert!(RE_URL.is_match("www.example.com"));
        assert!(!RE_URL.is_match("not a url here"));
    }

    #[test]
    fn username_detects_and_rejects() {
        assert!(RE_USERNAME.is_match("Follow @john_doe"));
        assert!(!RE_USERNAME.is_match("no mention here"));
    }

    #[test]
    fn coordinates_detects_and_rejects() {
        assert!(RE_COORDINATES_DECIMAL.is_match("40.7128, -74.0060"));
        assert!(RE_COORDINATES_DMS.is_match("40d42m46sN 74d0m22sW"));
        assert!(!RE_COORDINATES_DECIMAL.is_match("no coords here"));
    }

    #[test]
    fn tax_id_ein_detects_and_rejects() {
        assert!(RE_TAX_ID_EIN.is_match("12-3456789"));
        assert!(!RE_TAX_ID_EIN.is_match("12-345678")); // 6 digits after dash
    }

    #[test]
    fn tax_id_itin_detects_and_rejects() {
        assert!(RE_TAX_ID_ITIN.is_match("901-23-4567"));
        assert!(RE_ITIN.is_match("901-23-4567"));
        assert!(!RE_TAX_ID_ITIN.is_match("801-23-4567")); // does not start with 9
    }

    #[test]
    fn task_6a_variants_parse_and_display() {
        let cases = [
            (EntityType::Iban, "iban"),
            (EntityType::RoutingNumber, "routing_number"),
            (EntityType::SwiftCode, "swift_code"),
            (EntityType::BankAccount, "bank_account"),
            (EntityType::BitcoinAddress, "bitcoin_address"),
            (EntityType::EthereumAddress, "ethereum_address"),
            (EntityType::Vin, "vin"),
            (EntityType::MacAddress, "mac_address"),
            (EntityType::Ipv6, "ipv6"),
            (EntityType::Url, "url"),
            (EntityType::Username, "username"),
            (EntityType::Coordinates, "coordinates"),
            (EntityType::TaxIdEin, "tax_id_ein"),
            (EntityType::TaxIdItin, "tax_id_itin"),
        ];
        for (variant, label) in cases {
            assert_eq!(variant.to_string(), label);
            assert_eq!(EntityType::parse(label), Some(variant));
        }
    }

    #[test]
    fn task_6a_variants_are_regex_not_ner() {
        for variant in [
            EntityType::Iban,
            EntityType::RoutingNumber,
            EntityType::SwiftCode,
            EntityType::BankAccount,
            EntityType::BitcoinAddress,
            EntityType::EthereumAddress,
            EntityType::Vin,
            EntityType::MacAddress,
            EntityType::Ipv6,
            EntityType::Url,
            EntityType::Username,
            EntityType::Coordinates,
            EntityType::TaxIdEin,
            EntityType::TaxIdItin,
        ] {
            assert!(!variant.is_ner_only());
        }
    }

    #[test]
    fn task_6a_patterns_registered_in_builtin() {
        let patterns = builtin_patterns();
        for variant in [
            EntityType::Iban,
            EntityType::RoutingNumber,
            EntityType::SwiftCode,
            EntityType::BankAccount,
            EntityType::BitcoinAddress,
            EntityType::EthereumAddress,
            EntityType::Vin,
            EntityType::MacAddress,
            EntityType::Ipv6,
            EntityType::Url,
            EntityType::Username,
            EntityType::Coordinates,
            EntityType::TaxIdEin,
            EntityType::TaxIdItin,
        ] {
            assert!(
                patterns.iter().any(|p| p.entity_type == variant),
                "missing builtin pattern for {variant:?}"
            );
        }
    }
}
