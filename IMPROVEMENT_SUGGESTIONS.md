# FideX Protocol — Improvement Suggestions Report

**Date:** February 23, 2026  
**Scope:** Review of all 7 specification documents  
**Status:** All Changes Applied (Phase 5 — Final)

---

## Executive Summary

The FideX (AS5) specification is architecturally sound and well-positioned as a modern REST/JOSE replacement for AS2/AS4. The review identified and fixed **26 issues total** across all specification documents: 14 in the initial pass on the normative spec, and 12 more across the normative spec, OpenAPI, annotated spec, implementation guide, and quick start guide. The changes strengthen interoperability, eliminate ambiguities that would cause incompatible implementations, and close security gaps.

---

## Part 1: Changes Already Applied to `fidex-protocol-specification.md`

### 1.1 `receipt_webhook` Made Optional (Critical)

**Problem:** `receipt_webhook` was REQUIRED in every routing header, but the receiver already knows the sender's receipt endpoint from the AS5 configuration exchanged during partner discovery. Requiring it in every message was redundant and created a single point of failure — if the webhook URL ever changed, in-flight messages would fail.

**Fix:** Changed to OPTIONAL. When omitted, the receiver falls back to the sender's `receive_receipt` endpoint from the AS5 configuration. Added fallback logic to Section 7.3.5. Made `receive_receipt` REQUIRED in the AS5 config endpoints schema (Appendix E.5).

### 1.2 JWE `cty: "JWT"` Header Required (Critical — RFC Compliance)

**Problem:** RFC 7516 §4.1.12 requires the `cty` (content type) header to be set to `"JWT"` when the JWE payload is a nested JWS/JWT. The specification used nested JWE(JWS()) but never mentioned this required header. Implementations omitting it would produce non-compliant JOSE tokens.

**Fix:** Added `"cty": "JWT"` to the JWE header example in Section 4.2, to the test vector in Appendix D.3, and added normative text explaining the requirement.

### 1.3 ECDSA (ES256/ES384) Added as Recommended Algorithms (Important)

**Problem:** The spec only offered RSA algorithms. Modern B2B deployments increasingly prefer Elliptic Curve cryptography for smaller key sizes, faster operations, and better mobile/edge performance.

**Fix:** Added ES256 and ES384 as RECOMMENDED optional algorithms in Section 4.1, with minimum curve requirements (P-256 minimum, P-384 recommended).

### 1.4 Sender Identity Verification (Critical — Security)

**Problem:** No normative text required receivers to verify that the JWS signing key actually belonged to the claimed `sender_id`. An attacker who compromised one partner's key could forge messages appearing to come from a different partner by simply changing `sender_id` in the routing header.

**Fix:** Added Section 4.4 requiring receivers to verify the `kid` resolves to the sender's JWKS, fetched from the `public_domain` associated with the `sender_id` in the partner database.

### 1.5 Payload Encoding Rules (Important)

**Problem:** No guidance on what the JWS payload bytes should be — is it raw UTF-8? Base64? What about binary payloads (images, PDFs)?

**Fix:** Added Section 4.3 specifying UTF-8 encoding for JSON documents and mandatory base64 encoding for binary payloads.

### 1.6 Message Size Limit (Important — Interoperability)

**Problem:** No defined maximum message size meant implementations would have unpredictable limits, causing silent failures.

**Fix:** Added Section 2.5 requiring all implementations to accept at least 10 MB, with HTTP 413 for oversized messages.

### 1.7 Idempotency Requirement (Critical — Reliability)

**Problem:** No requirement for idempotent message handling. If a sender retried a message (because the HTTP 202 response was lost), the receiver could process it twice, potentially creating duplicate orders or invoices.

**Fix:** Added idempotency requirement in Section 7.2: receivers MUST handle duplicate `message_id` values by returning HTTP 202 without reprocessing.

### 1.8 Appendix A J-MDN Example Fixed (Correctness)

**Problem:** The J-MDN example in Appendix A had multiple errors:
- Hash format used hyphen (`sha256-`) instead of colon (`sha256:`)
- Missing `receiver_id` field
- Missing `X-FideX-Original-Message-ID` header
- Timestamp missing millisecond precision

**Fix:** Corrected all four issues to match the normative schema in Section 7.3.1.

### 1.9 Test Vector JWE Header Fixed (Correctness)

**Problem:** Appendix D.3 JWE test header was missing the `cty: "JWT"` field.

**Fix:** Added `"cty":"JWT"` to the test vector JWE header.

### 1.10 JSON Schema: `receipt_webhook` Removed from Required (Consistency)

**Problem:** Appendix E.1 routing header schema listed `receipt_webhook` in the `required` array, contradicting the updated Section 3.2.

**Fix:** Removed from `required` array.

### 1.11 JSON Schema: `receive_receipt` Made Required in AS5 Config (Consistency)

**Problem:** Since `receipt_webhook` is now optional, the `receive_receipt` endpoint in the AS5 configuration becomes the mandatory fallback. The schema didn't require it.

**Fix:** Added `receive_receipt` to the `required` array in the AS5 config endpoints schema (Appendix E.5).

### 1.12 Conformance Table Updated (Consistency)

**Problem:** The Core conformance table (Appendix C.1) stated "Routing header with ALL required fields (including `receipt_webhook`)" which was incorrect after making it optional.

**Fix:** Removed the parenthetical, added a new row for "J-MDN fallback delivery via AS5 config `receive_receipt` endpoint".

### 1.13 `payload_digest` Definition Clarified (Ambiguity)

**Problem:** The description "SHA-256 digest of the encrypted_payload string" was ambiguous — is it the hash of the JWE compact serialization string, or of the decrypted payload?

**Fix:** Clarified to: `"sha256:" + hex(SHA-256(UTF-8 bytes of the encrypted_payload string as it appears in the JSON envelope))`.

### 1.14 Changelog Updated

Added comprehensive Phase 4 changelog entry documenting all changes.

---

## Part 2: Additional Changes Applied (Phase 5)

All remaining recommendations from the initial review have been implemented across all documents.

### 2.1 ✅ JWKS Format: EC Key Types Added (Section 5.2)

**Applied to:** `fidex-protocol-specification.md`, `openapi.yaml`, `fidex-annotated-specification.md`

Added `kty: "EC"` support alongside `kty: "RSA"`. Added EC key JWK example with `crv: "P-256"`, `x`, `y` fields. Updated OpenAPI `JwkEntry` schema with EC-specific fields and expanded algorithm enum. Updated annotated spec key type documentation.

### 2.2 ✅ J-MDN Canonical Serialization: Alphabetical Key Order (Section 7.3.3)

**Applied to:** `fidex-protocol-specification.md`

Defined explicit alphabetical key ordering for J-MDN canonical serialization: `error_log`, `hash_verification`, `original_message_id`, `receiver_id`, `status`, `timestamp`.

### 2.3 ✅ NTP / Clock Synchronization Requirement (Section 9.2)

**Applied to:** `fidex-protocol-specification.md`

Added requirement: "Synchronize system clocks using NTP (RFC 5905) or equivalent time synchronization protocol."

### 2.4 ✅ Registration Request: Content-Type Defined (Section 6.3)

**Applied to:** `fidex-protocol-specification.md`

Specified `Content-Type: application/jose` for the registration POST request. Added normative text in both Section 6.3 (Phase 2, Step 3) and Section 6.4.

### 2.5 ✅ Security Token Minimum Entropy (Section 6.4)

**Applied to:** `fidex-protocol-specification.md`

Added: "Security tokens MUST have at least 128 bits of entropy (e.g., UUID v4, 32 hex characters, or 22 base64url characters generated from a CSPRNG)."

### 2.6 ✅ OpenAPI Fully Synced

**Applied to:** `openapi.yaml`

- `receipt_webhook` removed from `required` arrays in both `TransmitRequest` and `RoutingHeader`
- `receipt_webhook` descriptions updated to document optional behavior with AS5 config fallback
- JWE `encrypted_payload` description updated to require `cty: "JWT"`
- `JwkEntry` updated: `kty` enum now includes `EC`, `alg` enum expanded with ES256/ES384/PS256/RSA-OAEP-256, added `crv`/`x`/`y` EC fields, removed `n`/`e` from required (conditional on kty)
- `receive_receipt` added to `NodeEndpoints` as required field
- `encrypted_payload` example updated with `cty` in JWE header

### 2.7 ✅ Annotated Spec Synced

**Applied to:** `fidex-annotated-specification.md`

- `receipt_webhook` marked as optional in routing header field definitions table
- JWE header updated with `cty: "JWT"` and normative note added
- JWE header parameters table updated with `cty` row
- ES256/ES384 added to optional algorithms table
- Idempotency requirement added to Section 4.1
- J-MDN payload example fixed: added `receiver_id`, fixed hash format to `sha256:`, added millisecond timestamp
- Appendix A J-MDN example fixed: added `receiver_id`, `X-FideX-Original-Message-ID` header, corrected hash format
- Key type documentation updated for EC key support

### 2.8 ✅ Quick Start Guide Synced

**Applied to:** `fidex-quickstart.md`

- Crypto concept row updated to mention JWE `cty: "JWT"` requirement

### 2.9 ✅ Web Server Deployability Note (Section 9.5)

**Applied to:** `fidex-protocol-specification.md`

Added Section 9.5 noting that FideX is deployable on standard web infrastructure (Nginx, Apache, Caddy, cloud load balancers) without specialized B2B middleware.

### 2.10 ✅ Replay Detection Cache Duration (Section 9.2)

**Applied to:** `fidex-protocol-specification.md`

Added: "Maintain the message ID replay cache for at least 24 hours."

### 2.11 ✅ Rate Limiting Response Headers (Section 8.1)

**Applied to:** `fidex-protocol-specification.md`

Added: "Implementations SHOULD include `Retry-After` header (RFC 7231 §7.1.3)" to the HTTP 429 status code row.

---

## Part 3: Cross-Document Consistency Status

| Issue | spec | openapi | annotated | impl-guide | quickstart | Status |
|-------|------|---------|-----------|------------|------------|--------|
| `receipt_webhook` optional with fallback | ✅ | ✅ | ✅ | ✅ | ✅ | **Complete** |
| JWE `cty: "JWT"` header | ✅ | ✅ | ✅ | — | ✅ | **Complete** |
| ECDSA algorithms (ES256/ES384) | ✅ | ✅ | ✅ | — | — | **Complete** |
| EC key types in JWKS | ✅ | ✅ | ✅ | — | — | **Complete** |
| Message size limit (10 MB) | ✅ | ✅ | — | — | — | **Complete** |
| Idempotency requirement | ✅ | — | ✅ | ✅ | — | **Complete** |
| Sender identity verification (§4.4) | ✅ | — | — | — | — | **Complete** |
| `receive_receipt` in AS5 config | ✅ | ✅ | — | — | — | **Complete** |
| J-MDN canonical key order | ✅ | — | — | — | — | **Complete** |
| NTP clock sync requirement | ✅ | — | — | — | — | **Complete** |
| Registration Content-Type | ✅ | ✅ | ✅ | — | — | **Complete** |
| Security token entropy | ✅ | — | — | — | — | **Complete** |
| Replay cache 24h minimum | ✅ | — | — | — | — | **Complete** |
| Rate limiting Retry-After | ✅ | ✅ | — | — | — | **Complete** |
| Deployability note | ✅ | — | — | — | — | **Complete** |

---

## Summary of All Changes Applied

### Phase 4 — Normative Spec (14 changes)

| # | Change | Section(s) | Severity |
|---|--------|-----------|----------|
| 1 | `receipt_webhook` → OPTIONAL with fallback | 3.2, 7.3.5, C.1, E.1, E.5 | Critical |
| 2 | JWE `cty: "JWT"` requirement | 4.2, D.3 | Critical |
| 3 | ECDSA (ES256/ES384) algorithms | 4.1 | Important |
| 4 | Sender identity verification | 4.4 (new) | Critical |
| 5 | Payload encoding rules | 4.3 (new) | Important |
| 6 | Message size limit (10 MB) | 2.5 (new) | Important |
| 7 | Idempotency requirement | 7.2 | Critical |
| 8 | Appendix A J-MDN example fixed | Appendix A | Correctness |
| 9 | Test vector JWE header fixed | D.3 | Correctness |
| 10 | JSON schema receipt_webhook not required | E.1 | Consistency |
| 11 | JSON schema receive_receipt required | E.5 | Consistency |
| 12 | Conformance table updated | C.1 | Consistency |
| 13 | payload_digest definition clarified | 3.2 | Ambiguity |
| 14 | Changelog updated | Document Status | Tracking |

### Phase 5 — Full Cross-Document Sync (12 changes)

| # | Change | Files Updated | Severity |
|---|--------|--------------|----------|
| 15 | EC key types in JWKS | spec 5.2, openapi, annotated | HIGH |
| 16 | J-MDN canonical key order (alphabetical) | spec 7.3.3 | HIGH |
| 17 | NTP clock synchronization | spec 9.2 | MEDIUM |
| 18 | Registration Content-Type: application/jose | spec 6.3, 6.4 | MEDIUM |
| 19 | Security token 128-bit entropy minimum | spec 6.4 | MEDIUM |
| 20 | OpenAPI full sync | openapi.yaml | HIGH |
| 21 | Annotated spec sync (JWE cty, J-MDN, EC keys, idempotency) | annotated spec | MEDIUM |
| 22 | Quick start guide sync (cty header) | quickstart | LOW |
| 23 | Deployability note | spec 9.5 | LOW |
| 24 | Replay cache 24h minimum | spec 9.2 | MEDIUM |
| 25 | Rate limiting Retry-After header | spec 8.1 | LOW |
| 26 | IMPROVEMENT_SUGGESTIONS.md finalized | this file | Tracking |

---

*End of Improvement Suggestions Report*
