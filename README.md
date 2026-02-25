# Abstract Cryptographic API

A Protocol Buffers-based cryptographic service API that separates cryptographic intent from implementation details.

---

## Overview

This API lets applications use cryptography without hardcoding algorithms. Specify *what* you need (authenticated encryption, digital signature), and policies control *how* it's done.

```protobuf
// Traditional approach - algorithm hardcoded in application
key := aes.NewCipher(256, "GCM", 96, "PKCS7")

// This API - intent-based, algorithm controlled by policy
CreateKey(name="app-key", scope=CRYPTO_SCOPE_AUTHENTICATED_ENCRYPTION)
Encrypt(key_name="app-key", plaintext=data)
```

**Result:** Security teams can upgrade algorithms (e.g., AES-GCM → ChaCha20-Poly1305 → post-quantum) without any application code changes.

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


| Service |  Purpose |
|---------|---------|
| `CryptoService` | Encryption, signing, key management, digest, MAC, wrap, derive |
| `ProviderService` | List and get provider info |
| `AlgorithmDiscoveryService` | List templates, scopes, get template details |

### 3. Example Usage

```go
// Create key with policy-driven algorithm selection
client.CreateKey(CreateKeyRequest{
    Name:   "payment-key",
    Scope:  CRYPTO_SCOPE_AUTHENTICATED_ENCRYPTION,
    Policy: "production-policy",
})

// Encrypt data - algorithm determined by policy
resp := client.Encrypt(EncryptRequest{
    KeyName:   "payment-key",
    Plaintext: sensitiveData,
})

// Response includes full metadata
fmt.Printf("Algorithm: %s, Key Version: %d\n",
    resp.Metadata.TemplateId,
    resp.Metadata.KeyVersion)

// Later: migrate to post-quantum without changing key name
client.TransformKey(TransformKeyRequest{
    Name:  "payment-key",
    Scope: CRYPTO_SCOPE_HYBRID_ENCRYPTION,
})
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
                   ┌─────────▼─────────┐
                   │   CryptoService   │
                   │   (Proto Types)   │
                   └─────────┬─────────┘
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

| Category | Examples |
|----------|----------|
| **Modern Symmetric** | AES-GCM, ChaCha20-Poly1305 |
| **Asymmetric** | RSA-OAEP, RSA-PSS, ECDSA, Ed25519 |
| **Post-Quantum** | ML-KEM, ML-DSA, SLH-DSA |
| **Hybrid** | ML-DSA+ECDSA, ML-KEM+ECDH |
| **Key Derivation** | HKDF, PBKDF2, scrypt, Argon2 |
| **Legacy** | 3DES, RSA-PKCS1v15 (for interop) |

---

This specification is designed to be implemented in any language (Go, Java, Python, C++, etc.) and deployed across any infrastructure (on-premise, cloud, hybrid).
