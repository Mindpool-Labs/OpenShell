// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! PII redaction — replaces matched text with redaction tokens.

use crate::policy::PiiDetection;
use sha2::{Digest, Sha256};

/// Redaction output format. `Redacted` is the historical default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFormat {
    /// `[REDACTED:{entity_type}]` (historical behavior).
    Redacted,
    /// `[HASH:xxxxxxxx]` — truncated SHA-256 correlation token (Task 4).
    Hash,
    /// Realistic fake value of the same type (Task 5).
    Synthetic,
}

/// Redact all detections in the body, processing right-to-left to preserve offsets.
///
/// Returns the number of redactions applied.
pub fn redact(body: &mut Vec<u8>, detections: &[PiiDetection]) -> usize {
    redact_with(RedactionFormat::Redacted, body, detections)
}

/// Truncated SHA-256 (first 4 bytes → 8 lowercase hex chars).
/// Deterministic, non-reversible. Ported from `NeuronEdge` `redactors/hash.rs`.
pub fn compute_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        result[0], result[1], result[2], result[3]
    )
}

/// Redact all detections in `body` using the given [`RedactionFormat`], processing
/// right-to-left to preserve offsets. Returns the number of redactions applied.
pub fn redact_with(
    format: RedactionFormat,
    body: &mut Vec<u8>,
    detections: &[PiiDetection],
) -> usize {
    // Sort by span start descending so we replace right-to-left.
    let mut sorted: Vec<&PiiDetection> = detections.iter().collect();
    sorted.sort_by(|a, b| b.span.start.cmp(&a.span.start));

    let mut count = 0;
    for detection in sorted {
        let replacement: String = match format {
            RedactionFormat::Redacted => format!("[REDACTED:{}]", detection.entity_type),
            RedactionFormat::Hash => format!("[HASH:{}]", compute_hash(&detection.matched_text)),
            // Replaced by the real implementation in Task 5.
            RedactionFormat::Synthetic => {
                format!("[REDACTED:{}]", detection.entity_type)
            }
        };
        let start = detection.span.start;
        let end = detection.span.end.min(body.len());
        if start < end && start < body.len() {
            body.splice(start..end, replacement.bytes());
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::EntityType;

    fn detection(entity: EntityType, start: usize, end: usize, text: &str) -> PiiDetection {
        PiiDetection {
            entity_type: entity,
            span: start..end,
            matched_text: text.to_string(),
            confidence: 0.9,
        }
    }

    #[test]
    fn redact_single() {
        let mut body = b"SSN is 123-45-6789 here".to_vec();
        let detections = vec![detection(EntityType::Ssn, 7, 18, "123-45-6789")];
        let count = redact(&mut body, &detections);
        assert_eq!(count, 1);
        assert_eq!(String::from_utf8_lossy(&body), "SSN is [REDACTED:ssn] here");
    }

    #[test]
    fn redact_multiple_preserves_offsets() {
        let mut body = b"A 123-45-6789 B 078-05-1120 C".to_vec();
        let detections = vec![
            detection(EntityType::Ssn, 2, 13, "123-45-6789"),
            detection(EntityType::Ssn, 16, 27, "078-05-1120"),
        ];
        let count = redact(&mut body, &detections);
        assert_eq!(count, 2);
        let result = String::from_utf8_lossy(&body);
        assert!(result.contains("[REDACTED:ssn]"));
        assert!(!result.contains("123-45-6789"));
        assert!(!result.contains("078-05-1120"));
    }

    #[test]
    fn redact_empty_detections() {
        let mut body = b"no pii here".to_vec();
        let count = redact(&mut body, &[]);
        assert_eq!(count, 0);
        assert_eq!(String::from_utf8_lossy(&body), "no pii here");
    }

    #[test]
    fn redact_delegates_to_redacted_format() {
        let mut body = b"SSN is 123-45-6789 here".to_vec();
        let d = vec![detection(EntityType::Ssn, 7, 18, "123-45-6789")];
        assert_eq!(redact(&mut body, &d), 1);
        assert_eq!(String::from_utf8_lossy(&body), "SSN is [REDACTED:ssn] here");
        // redact_with(Redacted) is identical:
        let mut body2 = b"SSN is 123-45-6789 here".to_vec();
        assert_eq!(redact_with(RedactionFormat::Redacted, &mut body2, &d), 1);
        assert_eq!(
            String::from_utf8_lossy(&body2),
            "SSN is [REDACTED:ssn] here"
        );
    }

    #[test]
    fn hash_is_deterministic_and_8_hex() {
        let h1 = compute_hash("john@example.com");
        let h2 = compute_hash("john@example.com");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 8);
        assert!(
            h1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
    }

    #[test]
    fn hash_distinct_inputs_differ() {
        assert_ne!(
            compute_hash("john@example.com"),
            compute_hash("jane@example.com")
        );
    }

    #[test]
    fn redact_with_hash_emits_hash_token() {
        let mut body = b"Contact john@example.com now".to_vec();
        let d = vec![detection(EntityType::Email, 8, 24, "john@example.com")];
        let n = redact_with(RedactionFormat::Hash, &mut body, &d);
        assert_eq!(n, 1);
        let s = String::from_utf8_lossy(&body);
        assert!(s.starts_with("Contact [HASH:") && s.ends_with("] now"));
        assert!(!s.contains("john@example.com"));
    }
}
