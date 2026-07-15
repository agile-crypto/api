# Abstract Cryptographic API

A transport-agnostic, provider-agnostic, policy-driven cryptographic API specification defined in Protocol Buffers. It separates cryptographic **intent** ("I need an authenticated-encryption key") from **implementation** ("use AES-256-GCM on this HSM"), so that algorithms can be governed and migrated centrally — including the transition to post-quantum cryptography — without rewriting application code.

This repository contains the specification only. It is designed to be implemented in any language and deployed on-premise, in the cloud, or embedded in-process.

---

## Core Concepts

The design rests on five architectural characteristics - abstraction, stability, temporal flexibility, separation, and extensibility. This is realized through four concepts:

- **Scopes** express cryptographic *intent* as a typed vocabulary (authenticated encryption, digital signature, key encapsulation, key derivation, MAC, key wrapping, …). A scope names *what* the caller needs and the parameter shape they must provide without needing to specify any algorithm.

- **Templates** are concrete algorithm configurations (e.g. `aes-256-gcm`, `ml-dsa-65`). Each template declares the scopes it satisfies plus properties (security strength, FIPS approval, quantum safety) used for discovery and matching. New algorithms are added to the catalog as data without changing the API or breaking existing clients.

- **Policies** are an abstract governance object. A policy decides which templates are permitted for a scope and enforces requirements (minimum strength, FIPS-only, quantum-safe). The API treats the policy document opaquely, so deployments choose their own policy language.

- **Named keys** are referenced by stable logical names. Key material is never exposed to clients, and a key's identity is preserved across rotation and algorithm change.

**Cryptographic agility** enablers: `TransformKey` migrates a key to a new algorithm and `MigrateKey` moves it to a new provider, both while keeping the key identifier so that every existing call site keeps working without any code changes

### The API shape

Intent-based creation and use, expressed as request messages (algorithm never appears at the call site):

```proto
// Create a key by intent - the policy resolves the concrete algorithm.
CreateKeyRequest {
  name:   "contract-signing-key"
  policy: "prod-signing"
  scope_spec { signature { scope: SIGNATURE_SCOPE_STANDARD } }
}
// => policy selects e.g. ecdsa-p256-sha256; the key is used only by name.

// Sign by name - no algorithm identifier in the request.
SignRequest { key_name: "contract-signing-key", input: <bytes> }

// Later, migrate to post-quantum without touching application code:
TransformKeyRequest {
  name: "contract-signing-key"
  scope_spec { signature {
    scope: SIGNATURE_SCOPE_STANDARD
    security { quantum_safe: true }
  } }
}
// => policy selects e.g. ml-dsa-65; existing Sign/Verify call sites are unchanged.
```

---

## API Surface

| Service | RPCs | Purpose |
|---------|------|---------|
| `KeyManagementService` | 12 | Key lifecycle - CRUD, rotate, transform, migrate, state transitions, import/export |
| `CryptoService` | 12 | Single-shot operations - encrypt, sign, MAC, digest, XOF, random |
| `StreamingCryptoService` | 50 | Multi-part and message-based stateful operations (PKCS#11 Init/Update/Final) |
| `KeyEstablishmentService` | 6 | Key-to-key operations - wrap, unwrap, derive, agree, encapsulate, decapsulate |
| `CryptoPolicyService` | 7 | Policy CRUD and evaluation (pre-flight authorization checks) |
| `AlgorithmDiscoveryService` | 3 | Template and scope discovery |
| `ProviderService` | 8 | Provider catalog, instance management, and matching |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Client Applications                       │
└─────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
   ┌──────────┐         ┌──────────┐        ┌──────────┐
   │   gRPC   │         │   REST   │        │ Embedded │
   │  Client  │         │  (HTTP)  │        │   SDK    │
   └────┬─────┘         └────┬─────┘        └────┬─────┘
        │                    │                    │
        └────────────────────┼────────────────────┘
                             │
         ┌───────────────────▼───────────────────┐
         │           Service Layer               │
         ├───────────────────────────────────────┤
         │  KeyManagementService   (keys CRUD)   │
         │  CryptoPolicyService    (policies)    │
         │  CryptoService          (single-shot) │
         │  StreamingCryptoService (multi-part)  │
         │  KeyEstablishmentService (wrap/KEM)   │
         │  AlgorithmDiscoveryService (catalog)  │
         │  ProviderService        (backends)    │
         └───────────────────┬───────────────────┘
                             │
                   ┌─────────▼─────────┐
                   │   Policy Engine   │ ◄── Policies (abstract governance object)
                   └─────────┬─────────┘
                             │
                   ┌─────────▼─────────┐
                   │     Providers     │
                   ├───────────────────┤
                   │  • Software       │
                   │  • HSM (PKCS#11)  │
                   │  • Cloud KMS      │
                   └───────────────────┘
```

**Deployment modes:** gRPC (high-performance client-server), REST (browser/curl/legacy via the generated gateway), and embedded (direct function calls, no RPC overhead).

---

## Standards Alignment

- **Operation coverage:** PKCS#11 v3.x — encrypt, sign, digest, MAC, wrap, derive, KEM; single-shot, multi-part, and message-based flows.
- **Post-quantum:** ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid classical+PQ compositions.
- **Classical:** FIPS 197/186, SP 800-38D (GCM), SP 800-56A (key agreement), SP 800-108 (KDF), IEEE 1619 (XTS), and the relevant IETF RFCs.
- **Assurance:** FIPS 140-3 provider properties; NIST SP 800-57 key lifecycle; SP 800-131A algorithm transitions.
- **Reporting:** CycloneDX v1.7 cryptographic bill of materials (CBOM) export.

---

## Repository Layout

```
proto/
  api.proto                 # Barrel file importing all services and messages
  types/                    # Scopes, templates, algorithm & operation parameters, providers
  messages/                 # Request/response messages per operation family
  services/                 # gRPC service definitions (+ REST annotations)
  standard_algorithms.json  # Standard algorithm catalog (data, not schema)
  build_proto.sh            # Code generation entry point
gen/
  go/                       # Generated Go gRPC stubs + REST gateway
  openapi/                  # Generated OpenAPI (Swagger) specs
```

Protobuf package: `caas.crypto.v1`.

### Generate code

```bash
cd proto && ./build_proto.sh    # runs buf generate
```

A single protobuf definition generates gRPC stubs, a REST gateway, OpenAPI specs, and client SDKs for any protobuf-supported language.

---

## Publications

The peer-reviewed paper describing this work appeared at **MAgiCS 2026** — the Workshop on Migration and Agility in Cryptographic Systems, co-located with **EUROCRYPT 2026** (Rome, Italy) — with proceedings published by Springer in the *Communications in Computer and Information Science* (CCIS) series:

> Navaneeth Rameshan and Grégoire Messmer.
> **Cryptographic Agility for Applications: An Assessment Framework and Principled API Design.**
> MAgiCS 2026 (co-located with EUROCRYPT 2026), Springer CCIS, 2026.
> https://doi.org/10.1007/978-3-032-28946-9_9

Extended versions with the full assessment framework and design rationale:

- *An Assessment Framework for Application-Level Cryptographic Agility* — https://arxiv.org/abs/2606.13425
- *Intent-Based Cryptographic API Design for Cryptographic Agility* — https://arxiv.org/abs/2606.13445

### Citation

```bibtex
@inproceedings{rameshan2026cryptoagility,
  author    = {Rameshan, Navaneeth and Messmer, Gr\'egoire},
  title     = {Cryptographic Agility for Applications: An Assessment
               Framework and Principled API Design},
  booktitle = {Migration and Agility in Cryptographic Systems (MAgiCS 2026),
               co-located with EUROCRYPT 2026},
  series    = {Communications in Computer and Information Science},
  publisher = {Springer},
  year      = {2026},
  doi       = {10.1007/978-3-032-28946-9_9}
}
```

---

## Status & License

Specification version 0.1.0. Licensed under Apache-2.0 (`SPDX-License-Identifier: Apache-2.0`).
