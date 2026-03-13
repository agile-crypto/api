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
    Input:     document,
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

This specification is designed to be implemented in any language (Go, Java, Python, C++, etc.) and deployed across any infrastructure (on-premise, cloud, hybrid).
