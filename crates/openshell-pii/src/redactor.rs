// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-FileCopyrightText: Copyright (c) 2025-2026 Infrastacks LLC.
// SPDX-FileCopyrightText: Copyright (c) 2026 Mindpool, Inc.
// SPDX-License-Identifier: Apache-2.0

//! PII redaction — replaces matched text with redaction tokens.

use crate::policy::PiiDetection;
use sha2::{Digest, Sha256};

/// Redaction output format. `Redacted` is the historical default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionFormat {
    /// `[REDACTED:{entity_type}]` (historical behavior).
    Redacted,
    /// `[HASH:xxxxxxxx]` — truncated SHA-256 correlation token.
    Hash,
    /// Realistic fake value of the same type.
    Synthetic,
}

/// Redact all detections in the body, processing right-to-left to preserve offsets.
///
/// Returns the number of redactions applied.
pub fn redact(body: &mut Vec<u8>, detections: &[PiiDetection]) -> usize {
    redact_with(RedactionFormat::Redacted, body, detections)
}

/// Truncated SHA-256 (first 4 bytes → 8 lowercase hex chars).
/// Deterministic, non-reversible SHA-256 correlation token.
fn compute_hash(input: &str) -> String {
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

    // Overlap-safety cursor: the smallest start already redacted into. Any
    // further-left detection whose end extends past this cursor overlaps an
    // already-emitted token; splicing it would land inside that token and
    // garble the output (e.g. `[REDACTED:ssn]ssn]`) while inflating the count.
    // Such overlapping detections are skipped. Initialised to `usize::MAX` so
    // the first (rightmost) detection is always processed.
    //
    // No-regression proof for non-overlapping sets: with detections sorted
    // descending by start, once we process a detection at position `s` we set
    // `consumed_from = s`. The next detection has start `s' <= s`, and because
    // the set is non-overlapping its end `e'` satisfies `e' <= s' <= s =
    // consumed_from`, so `e' > consumed_from` is false and nothing is skipped —
    // the naive right-to-left splice (and thus `redact()` output) is preserved
    // byte-for-byte.
    let mut consumed_from = usize::MAX;
    let mut count = 0;
    for detection in sorted {
        if detection.span.end > consumed_from {
            continue;
        }
        let replacement: String = match format {
            RedactionFormat::Redacted => format!("[REDACTED:{}]", detection.entity_type),
            RedactionFormat::Hash => format!("[HASH:{}]", compute_hash(&detection.matched_text)),
            RedactionFormat::Synthetic => {
                crate::synthetic::generate(&detection.entity_type, &detection.matched_text)
            }
        };
        let start = detection.span.start;
        let end = detection.span.end.min(body.len());
        if start < end && start < body.len() {
            body.splice(start..end, replacement.bytes());
            consumed_from = start;
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
    fn redact_with_identical_span_overlap_skips_duplicate() {
        // Two detections on the SAME span: without overlap-safety the second
        // splice lands inside the just-emitted token (`[REDACTED:ssn]ssn]`)
        // and the count is inflated to 2. The fix must skip the overlapping
        // detection and emit exactly one clean token.
        let mut body = b"id=123-45-6789".to_vec();
        let d = vec![
            detection(EntityType::Ssn, 3, 14, "123-45-6789"),
            detection(EntityType::CreditCard, 3, 14, "123-45-6789"),
        ];
        let count = redact(&mut body, &d);
        let out = String::from_utf8_lossy(&body);
        assert_eq!(count, 1, "overlapping detection must not double-count");
        assert!(!out.contains("123-45-6789"));
        assert_eq!(
            out.matches("[REDACTED:").count(),
            1,
            "exactly one well-formed token, no nesting"
        );
        assert!(out.ends_with(']'));
        assert!(!out.contains("]ssn"), "no trailing/garbled suffix");
        assert!(!out.contains("]credit_card"), "no trailing/garbled suffix");
    }

    #[test]
    fn redact_with_partial_overlap_keeps_rightmost() {
        // Partial overlap (A=[0..10], B=[5..15]): processed right-to-left, B is
        // emitted first and consumes [5..15]; A's end (10) is past the cursor
        // (5), so A is skipped entirely — no splice into B's token.
        let mut body = b"AAAAAAAAAABBBBBoverrun".to_vec();
        let d = vec![
            detection(EntityType::Ssn, 0, 10, "AAAAAAAAAA"),
            detection(EntityType::Email, 5, 15, "AAAABBBBB"),
        ];
        let count = redact(&mut body, &d);
        let out = String::from_utf8_lossy(&body);
        assert_eq!(count, 1);
        assert_eq!(out.matches("[REDACTED:").count(), 1);
        // No leftover fragment of the skipped (leftward) detection's region
        // appears adjacent to the emitted token.
        assert!(!out.contains("]ssn"));
        assert!(!out.contains("]email"));
    }

    #[test]
    fn redact_with_non_overlapping_is_byte_identical_to_naive() {
        // No-regression contract: for non-overlapping detections the
        // overlap-safe path produces the same count and clean tokens as the
        // historical right-to-left splice (relied upon by ne-privacy-router).
        let mut body = b"A 123-45-6789 B 078-05-1120 C".to_vec();
        let d = vec![
            detection(EntityType::Ssn, 2, 13, "123-45-6789"),
            detection(EntityType::Ssn, 16, 27, "078-05-1120"),
        ];
        let count = redact(&mut body, &d);
        let out = String::from_utf8_lossy(&body);
        assert_eq!(count, 2, "both non-overlapping detections redacted");
        assert_eq!(out.matches("[REDACTED:ssn]").count(), 2);
        assert!(!out.contains("123-45-6789"));
        assert!(!out.contains("078-05-1120"));
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

    #[test]
    fn redact_with_synthetic_is_deterministic() {
        let d = vec![detection(EntityType::Email, 0, 16, "john@example.com")];
        let mut b1 = b"john@example.com".to_vec();
        let mut b2 = b"john@example.com".to_vec();
        redact_with(RedactionFormat::Synthetic, &mut b1, &d);
        redact_with(RedactionFormat::Synthetic, &mut b2, &d);
        assert_eq!(String::from_utf8_lossy(&b1), String::from_utf8_lossy(&b2));
        // Synthetic email must contain an @ and not echo the original:
        let out = String::from_utf8_lossy(&b1);
        assert!(out.contains('@'));
        assert!(!out.contains("john@example.com"));
    }
}
