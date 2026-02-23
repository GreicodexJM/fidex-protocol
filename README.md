<p align="center">
  <img src="fidex-as5-logo.png" alt="FideX AS5 Protocol Logo" width="320" />
</p>

<h1 align="center">FideX Protocol (AS5)</h1>

<p align="center">
  <strong>Fast Integration for Digital Enterprises eXchange</strong><br/>
  A modern B2B interchange protocol — REST/JSON/JOSE over HTTPS
</p>

<p align="center">
  <img alt="Status: Draft" src="https://img.shields.io/badge/status-Proposed_Standard-blue" />
  <img alt="Version: 1.0" src="https://img.shields.io/badge/version-1.0_Draft-orange" />
  <img alt="License: CC BY 4.0" src="https://img.shields.io/badge/license-CC_BY_4.0-green" />
</p>

---

## Overview

**FideX (AS5)** is a next-generation application-layer protocol for secure Business-to-Business (B2B) electronic data interchange. It provides cryptographic **non-repudiation**, **data integrity**, and **end-to-end confidentiality** using the JOSE (JSON Object Signing and Encryption) framework over HTTPS.

FideX is the evolutionary successor to the legacy **AS2** (RFC 4130, S/MIME over HTTP) and **AS4** (OASIS ebMS 3.0, SOAP/WS-Security) standards, redesigned from the ground up for the modern web. If you can call a REST API, you can use FideX.

> **Formal Designation: AS5 (Application Statement 5)** — The "AS" naming lineage signals continuity with established B2B interchange standards while marking a generational leap to web-native architecture.

## Key Features

- 🔏 **Non-Repudiation** — Cryptographic proof of message origin and delivery via JWS signatures and signed J-MDN receipts
- 🔐 **Sign-then-Encrypt** — Nested `JWE(JWS(payload))` ensures both authenticity and confidentiality using standard JOSE (RFC 7515 / RFC 7516)
- 🤝 **Automated Partner Discovery** — QR-code-friendly, cryptographically-signed onboarding handshake eliminates manual certificate exchange
- 📬 **J-MDN Receipts** — Asynchronous JSON Message Disposition Notifications provide legally binding proof of delivery
- 📦 **Payload Agnostic** — Wrap GS1 JSON, ANSI X12, UN/EDIFACT, UBL, CSV, or any business document format
- 🌐 **REST-Native** — Plain HTTP POST + JSON — no SOAP, no XML, no S/MIME
- 📐 **Conformance Profiles** — Three progressive tiers (Core, Enhanced, Edge) for flexible adoption

## How It Works

```
1. SIGN  →  2. ENCRYPT  →  3. SEND  →  4. GET RECEIPT
```

```
YOUR ERP                YOUR NODE              PARTNER NODE           PARTNER ERP
   │                       │                       │                      │
   │── POST /transmit ────>│                       │                      │
   │<── 202 QUEUED ────────│                       │                      │
   │                       │── Sign (JWS) ────────>│                      │
   │                       │── Encrypt (JWE) ─────>│                      │
   │                       │── POST /receive ─────>│                      │
   │                       │<── 202 Accepted ──────│                      │
   │                       │                       │── Decrypt ──────────>│
   │                       │                       │── Verify Sig ───────>│
   │                       │                       │── Deliver to ERP ───>│
   │                       │<── POST J-MDN ────────│                      │
   │<── Webhook receipt ───│                       │                      │
```

The sender's FideX node signs the business payload with the sender's private key (JWS), encrypts it with the receiver's public key (JWE), and transmits the envelope. The receiver decrypts, verifies the signature, processes the document, and sends back a signed J-MDN receipt — providing **legal proof of delivery**.

## AS2 vs AS4 vs FideX AS5

| | AS2 (2005) | AS4 (2013) | **FideX AS5 (2026)** |
|---|---|---|---|
| **Format** | S/MIME | SOAP/XML | **REST/JSON** |
| **Crypto** | CMS | WS-Security | **JOSE (JWS + JWE)** |
| **Key Exchange** | Manual email | Manual | **Auto-discovery** |
| **Receipts** | MDN (email-style) | ebMS Receipt | **J-MDN (JSON webhook)** |
| **Learning Curve** | Weeks | Weeks | **Hours** |

## Protocol at a Glance

### Required Algorithms

| Purpose | Algorithm | Standard |
|---|---|---|
| Signing | RS256 | RFC 7518 |
| Key Encryption | RSA-OAEP | RFC 7518 |
| Content Encryption | A256GCM | RFC 7518 |
| Hashing | SHA-256 | FIPS 180-4 |
| Min Key Size | 2048-bit RSA | (4096-bit recommended) |

### Key Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/receive` | POST | Receive a FideX envelope (public) |
| `/api/v1/receipt` | POST | Receive a J-MDN receipt (public) |
| `/.well-known/jwks.json` | GET | Public keys discovery (public, no auth) |
| `/as5/config` | GET | Node configuration discovery (public) |
| `/api/v1/register` | POST | Partner registration (public) |
| `/api/v1/transmit` | POST | Submit a message (internal, from ERP) |
| `/health` | GET | Liveness probe |

## Documentation

This repository contains the complete FideX AS5 protocol specification and supporting documents:

| Document | Status | Description |
|---|---|---|
| [`fidex-protocol-specification.md`](fidex-protocol-specification.md) | **NORMATIVE** | Authoritative protocol specification — the single source of truth |
| [`openapi.yaml`](openapi.yaml) | **NORMATIVE** | OpenAPI 3.0 machine-readable API contract |
| [`fidex-annotated-specification.md`](fidex-annotated-specification.md) | INFORMATIVE | Companion document with rationale, architecture details, and code samples |
| [`fidex-implementation-guide.md`](fidex-implementation-guide.md) | INFORMATIVE | Multi-language implementation examples (JS, Go, PHP, Python, Java) |
| [`fidex-security-guide.md`](fidex-security-guide.md) | INFORMATIVE | Operational security best practices and threat model |
| [`fidex-quickstart.md`](fidex-quickstart.md) | INFORMATIVE | 5-minute quick start guide |

> In case of conflict between documents, the **normative specification** takes precedence.

## Getting Started

**5-minute quick start** → [`fidex-quickstart.md`](fidex-quickstart.md)

Send a message through your local FideX node:

```bash
curl -X POST http://localhost:8080/api/v1/transmit \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "destination_partner_id": "urn:gln:0614141000012",
    "document_type": "GS1_ORDER_JSON",
    "receipt_webhook": "https://your-erp.com/fidex/receipt",
    "payload": {
      "order_id": "PO-2026-001",
      "total_amount": 2499.00
    }
  }'
```

Your node automatically signs, encrypts, and transmits the envelope to the partner. You receive a signed J-MDN receipt at your webhook when the partner processes it.

## Supported Document Types

FideX is **payload-agnostic** — any business document can be wrapped in the cryptographic envelope.

**Standard Types (Tier 1)** — Managed by the FideX Working Group:

| Standard | Examples |
|---|---|
| **GS1** | `GS1_ORDER_JSON`, `GS1_INVOICE_JSON`, `GS1_DESADV_JSON`, `GS1_RECADV_JSON`, `GS1_CATALOG_JSON` |
| **ANSI X12** | `X12_850`, `X12_810`, `X12_856` |
| **UN/EDIFACT** | `EDIFACT_ORDERS`, `EDIFACT_INVOIC`, `EDIFACT_DESADV` |
| **OASIS UBL 2.1** | `UBL_ORDER_21`, `UBL_INVOICE_21` |

**Custom Types (Tier 2)** — Organization-defined using reverse domain notation:

```
COM_ACME_WAREHOUSE_RECEIPT_V2
ORG_MYCOMPANY_INTERNAL_MEMO
```

## Conformance Profiles

FideX defines three progressive conformance tiers:

| Profile | Level | Highlights |
|---|---|---|
| **Core** | Required | HTTP/1.1 + TLS 1.3, RS256/RSA-OAEP/A256GCM, JWKS, discovery handshake, J-MDN, replay detection |
| **Enhanced** | Recommended | Core + HTTP/2, separate signing/encryption keys, 4096-bit RSA, key rotation, rate limiting, structured logging |
| **Edge** | Optional | Enhanced + HTTP/3 (QUIC), mutual TLS, HSM key storage, batch receipts |

See [Appendix C of the specification](fidex-protocol-specification.md#appendix-c-conformance-profiles) for the complete conformance requirements.

## Contributing

FideX is an open protocol developed by the FideX Protocol Working Group.

- **Propose changes** via the RFC process
- **Submit issues** at [github.com/fidex-protocol/specification/issues](https://github.com/fidex-protocol/specification/issues)
- **Join the discussion** at [discuss.fidex.org](https://discuss.fidex.org)
- **Working group meetings** are held monthly

Contributions to the reference implementation are welcome under the Apache 2.0 license.

## License

This specification is licensed under the **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

You are free to share and adapt the material for any purpose, provided you give appropriate attribution.

## Status

| Field | Value |
|---|---|
| **Version** | 1.0 (Draft) |
| **Status** | Proposed Standard |
| **Date** | February 23, 2026 |
| **Authors** | FideX Protocol Working Group |

---

<p align="center">
  <em>FideX AS5 — Enterprise-grade B2B interchange for the modern web.</em>
</p>
