// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-FileCopyrightText: Copyright (c) 2025-2026 Infrastacks LLC.
// SPDX-FileCopyrightText: Copyright (c) 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Synthetic redaction — realistic fake values of the same type, deterministic
//! via SHA-256 seeding.

// Style-only clippy allows: the verbatim port preserves the upstream casts and
// formatting style. None of these alter behavior.
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::checked_conversions,
    clippy::uninlined_format_args
)]

use crate::entities::EntityType;
use sha2::{Digest, Sha256};

// ============================================================================
// Static Data Arrays (Compiled into binary)
// ============================================================================

/// First names for PERSON entity synthesis (100 common names)
static FIRST_NAMES: &[&str] = &[
    "James",
    "Mary",
    "John",
    "Patricia",
    "Robert",
    "Jennifer",
    "Michael",
    "Linda",
    "William",
    "Elizabeth",
    "David",
    "Barbara",
    "Richard",
    "Susan",
    "Joseph",
    "Jessica",
    "Thomas",
    "Sarah",
    "Charles",
    "Karen",
    "Christopher",
    "Nancy",
    "Daniel",
    "Lisa",
    "Matthew",
    "Betty",
    "Anthony",
    "Margaret",
    "Mark",
    "Sandra",
    "Donald",
    "Ashley",
    "Steven",
    "Kimberly",
    "Paul",
    "Emily",
    "Andrew",
    "Donna",
    "Joshua",
    "Michelle",
    "Kenneth",
    "Dorothy",
    "Kevin",
    "Carol",
    "Brian",
    "Amanda",
    "George",
    "Melissa",
    "Timothy",
    "Deborah",
    "Ronald",
    "Stephanie",
    "Edward",
    "Rebecca",
    "Jason",
    "Sharon",
    "Jeffrey",
    "Laura",
    "Ryan",
    "Cynthia",
    "Jacob",
    "Kathleen",
    "Gary",
    "Amy",
    "Nicholas",
    "Angela",
    "Eric",
    "Shirley",
    "Jonathan",
    "Anna",
    "Stephen",
    "Brenda",
    "Larry",
    "Pamela",
    "Justin",
    "Emma",
    "Scott",
    "Nicole",
    "Brandon",
    "Helen",
    "Benjamin",
    "Samantha",
    "Samuel",
    "Katherine",
    "Raymond",
    "Christine",
    "Gregory",
    "Debra",
    "Frank",
    "Rachel",
    "Alexander",
    "Carolyn",
    "Patrick",
    "Janet",
    "Jack",
    "Catherine",
    "Dennis",
    "Maria",
    "Jerry",
    "Heather",
];

/// Last names for PERSON entity synthesis (100 common surnames)
static LAST_NAMES: &[&str] = &[
    "Smith",
    "Johnson",
    "Williams",
    "Brown",
    "Jones",
    "Garcia",
    "Miller",
    "Davis",
    "Rodriguez",
    "Martinez",
    "Hernandez",
    "Lopez",
    "Gonzalez",
    "Wilson",
    "Anderson",
    "Thomas",
    "Taylor",
    "Moore",
    "Jackson",
    "Martin",
    "Lee",
    "Perez",
    "Thompson",
    "White",
    "Harris",
    "Sanchez",
    "Clark",
    "Ramirez",
    "Lewis",
    "Robinson",
    "Walker",
    "Young",
    "Allen",
    "King",
    "Wright",
    "Scott",
    "Torres",
    "Nguyen",
    "Hill",
    "Flores",
    "Green",
    "Adams",
    "Nelson",
    "Baker",
    "Hall",
    "Rivera",
    "Campbell",
    "Mitchell",
    "Carter",
    "Roberts",
    "Gomez",
    "Phillips",
    "Evans",
    "Turner",
    "Diaz",
    "Parker",
    "Cruz",
    "Edwards",
    "Collins",
    "Reyes",
    "Stewart",
    "Morris",
    "Morales",
    "Murphy",
    "Cook",
    "Rogers",
    "Gutierrez",
    "Ortiz",
    "Morgan",
    "Cooper",
    "Peterson",
    "Bailey",
    "Reed",
    "Kelly",
    "Howard",
    "Ramos",
    "Kim",
    "Cox",
    "Ward",
    "Richardson",
    "Watson",
    "Brooks",
    "Chavez",
    "Wood",
    "James",
    "Bennett",
    "Gray",
    "Mendoza",
    "Ruiz",
    "Hughes",
    "Price",
    "Alvarez",
    "Castillo",
    "Sanders",
    "Patel",
    "Myers",
    "Long",
    "Ross",
    "Foster",
];

/// Email domains for EMAIL entity synthesis
static EMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "icloud.com",
    "mail.com",
    "protonmail.com",
    "zoho.com",
    "live.com",
];

/// Street names for ADDRESS entity synthesis
static STREET_NAMES: &[&str] = &[
    "Main",
    "Oak",
    "Maple",
    "Cedar",
    "Pine",
    "Elm",
    "Washington",
    "Lake",
    "Hill",
    "Park",
    "River",
    "Forest",
    "Spring",
    "Valley",
    "Meadow",
    "Sunset",
    "Highland",
    "Cherry",
    "Walnut",
    "Birch",
];

/// Street types for ADDRESS entity synthesis
static STREET_TYPES: &[&str] = &[
    "Street",
    "Avenue",
    "Road",
    "Boulevard",
    "Drive",
    "Lane",
    "Court",
    "Way",
    "Place",
    "Circle",
];

// ============================================================================
// Deterministic Seed Generation
// ============================================================================

/// Convert hash to deterministic seed for array selection.
/// Uses first 4 bytes of SHA-256 hash as u32 seed.
#[inline]
fn hash_to_seed(original: &str) -> u32 {
    let mut hasher = Sha256::new();
    hasher.update(original.as_bytes());
    let result = hasher.finalize();
    u32::from_be_bytes([result[0], result[1], result[2], result[3]])
}

/// Select item from array using seed with offset for variety.
#[inline]
fn select_from_array<'a>(array: &'a [&str], seed: u32, offset: u32) -> &'a str {
    let index = ((seed.wrapping_add(offset.wrapping_mul(17))) as usize) % array.len();
    array[index]
}

// ============================================================================
// Entity-Specific Generators
// ============================================================================

/// Generate synthetic email: first.last@domain.com
fn generate_synthetic_email(original: &str) -> String {
    let seed = hash_to_seed(original);
    let first = select_from_array(FIRST_NAMES, seed, 0).to_lowercase();
    let last = select_from_array(LAST_NAMES, seed, 1).to_lowercase();
    let domain = select_from_array(EMAIL_DOMAINS, seed, 2);
    format!("{}.{}@{}", first, last, domain)
}

/// Generate synthetic phone: (XXX) XXX-XXXX format
fn generate_synthetic_phone(original: &str) -> String {
    let seed = hash_to_seed(original);
    // Generate digits from seed (using different bit ranges for variety)
    let area = 200 + (seed % 800) as u16; // 200-999 range
    let exchange = 200 + ((seed >> 10) % 800) as u16; // 200-999 range
    let line = (seed >> 20) % 10000;
    format!("({:03}) {:03}-{:04}", area, exchange, line)
}

/// Generate synthetic SSN: XXX-XX-XXXX format (valid format, fake numbers)
fn generate_synthetic_ssn(original: &str) -> String {
    let seed = hash_to_seed(original);
    // Area: 001-665, 667-899 (excluding 000, 666, 900-999)
    let mut area = 1 + (seed % 899) as u16;
    if area == 666 {
        area = 667;
    }
    if area > 899 {
        area -= 234; // Wrap back to valid range
    }
    let group = 1 + ((seed >> 10) % 99) as u8; // 01-99
    let serial = 1 + ((seed >> 17) % 9999) as u16; // 0001-9999
    format!("{:03}-{:02}-{:04}", area, group, serial)
}

/// Generate synthetic person name: First Last
fn generate_synthetic_person(original: &str) -> String {
    let seed = hash_to_seed(original);
    let first = select_from_array(FIRST_NAMES, seed, 0);
    let last = select_from_array(LAST_NAMES, seed, 1);
    format!("{} {}", first, last)
}

/// Generate synthetic credit card: XXXX-XXXX-XXXX-XXXX (valid Luhn)
#[allow(clippy::needless_range_loop)]
fn generate_synthetic_credit_card(original: &str) -> String {
    let seed = hash_to_seed(original);
    // Generate first 15 digits from seed
    let mut digits = [0u8; 16];
    digits[0] = 4; // Visa prefix
    for i in 1..15 {
        digits[i] = ((seed >> ((i * 2) % 32)) % 10) as u8;
    }
    // Calculate Luhn check digit
    digits[15] = calculate_luhn_check_digit(&digits[0..15]);
    format!(
        "{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}",
        digits[0],
        digits[1],
        digits[2],
        digits[3],
        digits[4],
        digits[5],
        digits[6],
        digits[7],
        digits[8],
        digits[9],
        digits[10],
        digits[11],
        digits[12],
        digits[13],
        digits[14],
        digits[15]
    )
}

/// Calculate Luhn check digit for credit card validation
fn calculate_luhn_check_digit(digits: &[u8]) -> u8 {
    let mut sum = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let mut value = d as u32;
        if i % 2 == 0 {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
    }
    ((10 - (sum % 10)) % 10) as u8
}

/// Generate synthetic address: 123 Street Name Type
fn generate_synthetic_address(original: &str) -> String {
    let seed = hash_to_seed(original);
    let number = 100 + (seed % 9900); // 100-9999
    let street = select_from_array(STREET_NAMES, seed, 1);
    let street_type = select_from_array(STREET_TYPES, seed, 2);
    format!("{} {} {}", number, street, street_type)
}

/// Generate synthetic date of birth: MM/DD/YYYY format
fn generate_synthetic_date_of_birth(original: &str) -> String {
    let seed = hash_to_seed(original);
    let year = 1950 + (seed % 50) as u16; // 1950-1999
    let month = 1 + ((seed >> 8) % 12) as u8; // 01-12
    let day = 1 + ((seed >> 12) % 28) as u8; // 01-28 (safe day range)
    format!("{:02}/{:02}/{}", month, day, year)
}

/// Generate synthetic IP address
fn generate_synthetic_ip_address(original: &str) -> String {
    let seed = hash_to_seed(original);
    let o1 = 10 + (seed % 200) as u8; // Avoid special ranges (10-209)
    let o2 = ((seed >> 8) % 256) as u8;
    let o3 = ((seed >> 16) % 256) as u8;
    let o4 = 1 + ((seed >> 24) % 254) as u8; // Avoid .0 and .255
    format!("{}.{}.{}.{}", o1, o2, o3, o4)
}

/// Generate synthetic URL.
///
/// Dispatched from [`generate`] for [`EntityType::Url`].
fn generate_synthetic_url(original: &str) -> String {
    let seed = hash_to_seed(original);
    let domains = &[
        "example.com",
        "test.org",
        "sample.net",
        "demo.io",
        "mock.dev",
    ];
    let paths = &["page", "content", "resource", "item", "data"];
    let domain = domains[(seed as usize) % domains.len()];
    let path = paths[((seed >> 10) as usize) % paths.len()];
    let id = (seed >> 20) % 10000;
    format!("https://{}/{}/{}", domain, path, id)
}

/// Generate synthetic username.
///
/// Dispatched from [`generate`] for [`EntityType::Username`].
fn generate_synthetic_username(original: &str) -> String {
    let seed = hash_to_seed(original);
    let first = select_from_array(FIRST_NAMES, seed, 0).to_lowercase();
    let num = (seed >> 16) % 1000;
    format!("@{}{}", first, num)
}

/// Generate synthetic IBAN.
///
/// Dispatched from [`generate`] for [`EntityType::Iban`].
fn generate_synthetic_iban(original: &str) -> String {
    let seed = hash_to_seed(original);
    let countries = &["DE", "FR", "GB", "ES", "IT", "NL"];
    let country = countries[(seed as usize) % countries.len()];
    let check = 10 + ((seed >> 8) % 90);
    let bban: u64 = ((seed as u64) << 32) | ((seed >> 16) as u64);
    format!(
        "{}{}{:018}",
        country,
        check,
        bban % 1_000_000_000_000_000_000
    )
}

/// Generate synthetic passport number
fn generate_synthetic_passport(original: &str) -> String {
    let seed = hash_to_seed(original);
    let letter = (b'A' + (seed % 26) as u8) as char;
    let number = (seed >> 8) % 100_000_000;
    format!("{}{:08}", letter, number)
}

/// Fallback generator for unsupported entity types
fn generate_synthetic_default(entity_type: &str, original: &str) -> String {
    let seed = hash_to_seed(original);
    let hash = format!("{:08x}", seed);
    format!("[{}:{}]", entity_type, &hash[0..4])
}

// ============================================================================
// Public Dispatch
// ============================================================================

/// Produce a deterministic synthetic replacement for `original` of `entity_type`.
///
/// Same input always yields the same output (SHA-256 seeded). Each entity type
/// produces a realistic-looking value of the same shape as the original.
#[allow(clippy::trivially_copy_pass_by_ref)] // brief-fixed signature: `&EntityType`
pub fn generate(entity_type: &EntityType, original: &str) -> String {
    match entity_type {
        EntityType::Email => generate_synthetic_email(original),
        EntityType::Phone => generate_synthetic_phone(original),
        EntityType::Ssn => generate_synthetic_ssn(original),
        EntityType::CreditCard => generate_synthetic_credit_card(original),
        EntityType::IpAddress => generate_synthetic_ip_address(original),
        EntityType::Person => generate_synthetic_person(original),
        EntityType::Address => generate_synthetic_address(original),
        EntityType::DateOfBirth => generate_synthetic_date_of_birth(original),
        EntityType::Passport => generate_synthetic_passport(original),
        EntityType::Url => generate_synthetic_url(original),
        EntityType::Username => generate_synthetic_username(original),
        EntityType::Iban => generate_synthetic_iban(original),
        // All other types: fall back to a deterministic name-shaped token so
        // Synthetic redaction never echoes the original.
        _ => generate_synthetic_default(&entity_type.to_string(), original),
    }
}
