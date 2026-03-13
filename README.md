# Abstract Cryptographic API

A Protocol Buffers-based cryptographic service API that separates cryptographic intent from implementation details.

---

## Overview

This API lets applications use cryptography without hardcoding algorithms. Specify *what* you need (digital signature, authenticated encryption), and policies control *how* it's done.

```protobuf
// Traditional approach - algorithm hardcoded in application
signer := ecdsa.GenerateKey(elliptic.P256())
signature := ecdsa.Sign(signer, hash)

// This API - intent-based, algorithm controlled by policy
CreateKey(name="signing-key", scope_spec={signature: {scope: SIGNATURE_SCOPE_STANDARD}})
Sign(key_name="signing-key", input=message)
```

**Result:** Security teams can upgrade algorithms (e.g., ECDSA → Ed25519 → ML-DSA) without any application code changes.

---

## Why This API?

| Audience | Benefit |
|----------|---------|
| **Developers** | Use crypto safely without understanding algorithm details. Keys by name, never exposed. |
| **Security Teams** | Centralized policy control. Algorithm upgrades without code deployments. |
| **Integrators** | Multi-transport support (gRPC, REST, SDKs). Universal compatibility. |

---

## Key Capabilities

| Capability | Description |
|------------|-------------|
| **Intent-Based** | Multiple cryptographic scopes (authenticated encryption, digital signature, etc.) |
| **Named Keys** | Keys identified by logical names, never exposed to clients |
| **Cryptographic Agility** | `TransformKey` migrates algorithms while preserving key identity |
| **Runtime Discovery** | `ListTemplates()` discovers algorithms without API changes |
| **Multi-Transport** | Single protobuf generates gRPC, REST, and SDKs for 10+ languages |
| **Provider Pluggable** | Switch software/HSM/cloud KMS backends transparently |
| **Policy-Driven** | Flexible policy integration (API abstracts policy details) |
| **Extensible** | Map-based properties and runtime templates for future algorithms |

---

## Design Strengths

The API is designed for three critical requirements:

### Cryptographic Agility
- **Scope-based selection**: Applications specify intent, policy selects algorithm
- **TransformKey operation**: Migrate to new algorithms without changing key names
- **Property-based filtering**: Select algorithms by characteristics (security level, FIPS approval)

### Extensibility Without API Changes
- **Map-based properties**: Add new algorithm properties without schema changes
- **Runtime templates**: Add new algorithms via configuration, not code
- **Enum additions**: New scopes/mechanisms are backward-compatible

### PKCS#11 v3.2 Compliance
- **Full operation coverage**: Encrypt, Sign, Digest, MAC, Wrap, Derive, KEM
- **Multi-part operations**: Init/Update/Final pattern for streaming
- **Post-quantum KEMs**: Native Encapsulate/Decapsulate operations

---

## Quick Start

### 1. Generate Code

```bash
cd proto && ./build_proto.sh
```

**Output:**
- `gen/go/` — Go code with gRPC stubs
- `gen/go/services/*.pb.gw.go` — REST gateway
- `gen/openapi/*.swagger.json` — OpenAPI specs

### 2. API Surface

| Service | RPCs | Purpose |
|---------|------|---------|
| `KeyManagementService` | 11 | Key lifecycle — CRUD, rotate, transform, migrate, import/export |
| `CryptoPolicyService` | 7 | Policy CRUD and evaluation (pre-flight checks) |
| `CryptoService` | 12 | Single-shot operations — encrypt, sign, MAC, digest, random |
| `StreamingCryptoService` | 43 | Multi-part and message-based stateful operations (PKCS#11 Init/Update/Final) |
| `KeyEstablishmentService` | 6 | Key-to-key operations — wrap, unwrap, derive, agree, encapsulate, decapsulate |
| `AlgorithmDiscoveryService` | 3 | Template and scope discovery |
| `ProviderService` | 7 | Provider catalog and instance management |

### 3. Example Usage

```go
// Step 1: Create a signing key — policy selects the algorithm (e.g., ECDSA P-256)
keyMgmt.CreateKey(&CreateKeyRequest{
    Name:   "contract-signing-key",
    Policy: "production-signing",
    ScopeSpec: &ScopeSpecification{
        Signature: &SignatureScopeSpec{
            Scope:    SIGNATURE_SCOPE_STANDARD,
            Security: &UniversalSecurityProperties{SecurityStrengthBits: 128},
        },
    },
})

// Step 2: Sign data — algorithm determined by policy, key never exposed
resp := crypto.Sign(&SignRequest{
    KeyName:   "contract-signing-key",
    Input:     documentHash,
    NoContext: &NoParams{},  // Classical signature (ECDSA)
})

// Response includes full metadata for verification
fmt.Printf("Template: %s, Key Version: %d\n",
    resp.Metadata.AlgorithmParameters["template_id"],
    resp.Metadata.KeyVersion)

// Step 3: Later — migrate to post-quantum ML-DSA without changing key name
keyMgmt.TransformKey(&TransformKeyRequest{
    Name:           "contract-signing-key",
    RetainKeyBytes: false,  // Must regenerate for algorithm family change
    ScopeSpec: &ScopeSpecification{
        Signature: &SignatureScopeSpec{
            Scope:    SIGNATURE_SCOPE_STANDARD,
            Security: &UniversalSecurityProperties{
                SecurityStrengthBits: 192,
                QuantumSafe:          boolPtr(true),
            },
        },
    },
})
// Policy selects ML-DSA-65 (NIST Level 3, 192-bit strength)
// All existing Sign() calls continue to work — zero code changes
```

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
                   │   Policy Engine   │ ◄── Policies (JSON/YAML/HCL)
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

**Deployment Modes:**
- **gRPC** — High-performance client-server
- **REST** — Browser/curl/legacy integration
- **Embedded** — Direct function calls, no RPC overhead

---

## Algorithm Coverage

**72 templates** across 8 cryptographic primitives, defined in `standard_algorithms.json`.

### Digital Signatures (48 templates)

| Family | Templates | Strength | FIPS | Quantum-Safe |
|--------|-----------|----------|------|-------------|
| **ECDSA** | P-256/SHA-256, P-384/SHA-384, P-521/SHA-512, secp256k1 | 128–256 bit | ✅ (NIST curves) | ✗ |
| **EdDSA** | Ed25519 (pure, ctx, ph), Ed448 | 128–224 bit | ✅ (Ed25519) | ✗ |
| **RSA-PSS** | 2048/SHA-256, 3072/SHA-256, 4096/SHA-384 | 112–152 bit | ✅ | ✗ |
| **RSA-PKCS1v15** | 2048/SHA-256 | 112 bit | ✅ | ✗ |
| **ML-DSA** | ML-DSA-44, ML-DSA-65, ML-DSA-87 (+ prehashed) | 128–256 bit | ✅ | ✅ |
| **SLH-DSA** | SHA2-128f, SHA2-128s, SHAKE-256s (+ prehashed) | 128–256 bit | ✅ | ✅ |
| **Hybrid Signatures** | ECDSA-P256+ML-DSA-65, Ed25519+ML-DSA-65, RSA-3072+ML-DSA-65 | 192 bit | ✗ | ✅ |

All signature templates support both direct signing and prehashed variants (for large data or external hashing).

### Authenticated Encryption / AEAD (5 templates)

| Template | Key Size | Nonce | Tag | FIPS |
|----------|----------|-------|-----|------|
| AES-128-GCM | 128 bit | 96 bit | 128 bit | ✅ |
| AES-192-GCM | 192 bit | 96 bit | 128 bit | ✅ |
| AES-256-GCM | 256 bit | 96 bit | 128 bit | ✅ |
| ChaCha20-Poly1305 | 256 bit | 96 bit | 128 bit | ✗ |
| XChaCha20-Poly1305 | 256 bit | 192 bit | 128 bit | ✗ |

### Symmetric Ciphers — Legacy/Non-AEAD (6 templates)

| Template | Mode | Key Size | FIPS | Notes |
|----------|------|----------|------|-------|
| AES-128/192/256-CBC | CBC + PKCS7 | 128–256 bit | ✅ | Legacy interop; prefer AEAD |
| AES-128/192/256-CTR | CTR | 128–256 bit | ✅ | Streaming; no authentication |

### Key Encapsulation Mechanisms — KEM (5 templates)

| Template | Strength | FIPS | Quantum-Safe | Notes |
|----------|----------|------|-------------|-------|
| ML-KEM-512 | 128 bit (Level 1) | ✅ | ✅ | FIPS 203 |
| ML-KEM-768 | 192 bit (Level 3) | ✅ | ✅ | FIPS 203, recommended default |
| ML-KEM-1024 | 256 bit (Level 5) | ✅ | ✅ | FIPS 203 |
| X25519+ML-KEM-768 | 192 bit | ✗ | ✅ | Hybrid classical+PQ |
| X448+ML-KEM-1024 | 224 bit | ✗ | ✅ | Hybrid classical+PQ |

### Key Agreement (4 templates)

| Template | Strength | FIPS | Notes |
|----------|----------|------|-------|
| X25519 | 128 bit | ✗ | Curve25519 ECDH |
| X448 | 224 bit | ✗ | Curve448 ECDH |
| X25519+ML-KEM-768 | 192 bit | ✗ | Hybrid (also listed under KEM) |
| X448+ML-KEM-1024 | 224 bit | ✗ | Hybrid (also listed under KEM) |

### Message Authentication Codes — MAC (6 templates)

| Template | Output Size | FIPS | Notes |
|----------|------------|------|-------|
| HMAC-SHA256 | 256 bit | ✅ | Most common |
| HMAC-SHA384 | 384 bit | ✅ | |
| HMAC-SHA512 | 512 bit | ✅ | |
| HMAC-SHA3-256 | 256 bit | ✅ | SHA-3 based |
| KMAC128 | 256 bit | ✅ | NIST SP 800-185 |
| KMAC256 | 512 bit | ✅ | NIST SP 800-185 |

### Key Derivation Functions — KDF (7 templates)

| Template | Scope | FIPS | Notes |
|----------|-------|------|-------|
| HKDF-SHA256 | Extract-Expand | ✅ | RFC 5869, general purpose |
| HKDF-SHA384 | Extract-Expand | ✅ | |
| HKDF-SHA512 | Extract-Expand | ✅ | |
| PBKDF2-SHA256 (600K iterations) | Password | ✅ | OWASP recommended minimum |
| PBKDF2-SHA512 (210K iterations) | Password | ✅ | |
| Argon2i (64 MB, 4 iterations) | Password | ✗ | Memory-hard, RFC 9106 |
| Argon2id (64 MB, 3 iterations) | Password | ✗ | Memory-hard, recommended |

### Key Wrapping (6 templates)

| Template | Key Size | FIPS | Standard |
|----------|----------|------|----------|
| AES-KW-128/192/256 | 128–256 bit | ✅ | RFC 3394 / NIST SP 800-38F |
| AES-KWP-128/192/256 | 128–256 bit | ✅ | RFC 5649 / NIST SP 800-38F (with padding) |

### Coverage Summary

| Primitive | Templates | FIPS Coverage | Quantum-Safe | Scope |
|-----------|-----------|--------------|-------------|-------|
| Digital Signatures | 48 | 42/48 (88%) | 18 templates | `signature` |
| AEAD | 5 | 3/5 (60%) | — | `aead` |
| Symmetric Cipher | 6 | 6/6 (100%) | — | `symmetricCipher` |
| KEM | 5 | 3/5 (60%) | 5/5 (100%) | `kem` |
| Key Agreement | 4 | 0/4 (0%) | 2/4 (50%) | `keyAgreement` |
| MAC | 6 | 6/6 (100%) | — | `mac` |
| KDF | 7 | 5/7 (71%) | — | `kdf` |
| Key Wrapping | 6 | 6/6 (100%) | — | `keyWrapping` |
| **Total** | **72** | **56/72 (78%)** | **25 templates** | |

> Templates are extensible at runtime — new algorithms can be added via configuration without API schema changes. See `AlgorithmDiscoveryService.ListTemplates` for runtime discovery.

---

This specification is designed to be implemented in any language (Go, Java, Python, C++, etc.) and deployed across any infrastructure (on-premise, cloud, hybrid).
