# API Design Philosophy

This document explains the design principles behind the Abstract Cryptographic API, focusing on cryptographic agility, extensibility, and standards compliance.

**Version:** 0.1.0

---

## Table of Contents

1. [True Identity: What This Work Actually Is](#true-identity-what-this-work-actually-is)
2. [Cryptographic Agility](#cryptographic-agility)
3. [Extensibility Without API Changes](#extensibility-without-api-changes)
4. [PKCS#11 v3.2 Compliance](#pkcs11-v32-compliance)
5. [Post-Quantum Readiness](#post-quantum-readiness)
6. [Security Design](#security-design)

---

## True Identity: What This Work Actually Is

This is not a cryptographic service. Calling it "Cryptography-as-a-Service" understates the work to the point of misdirection — it implies a remote service provider doing encryption on your behalf, which is only one of five deployment modes and the least interesting architectural property.

The work is better understood as a **new abstraction layer for cryptography** — the layer that networking and storage have already completed but cryptography has not. Just as file systems abstracted disk sectors, and TCP/IP abstracted network hardware, and Kubernetes abstracted infrastructure scheduling, this work abstracts the *consumption and governance of cryptography itself*.

**Cryptographic agility is a consequence of the abstraction, not the goal.** When you abstract correctly, agility is what you get. The goal is the abstraction.

| Aspect | What It Actually Is |
|--------|---------------------|
| **Abstraction** | Separates cryptographic *intent* from *implementation* — like file systems abstracting disk sectors. Applications express *what* they need; the framework decides *how*. |
| **Control/Data Plane Separation** | The policy engine is the control plane; providers are the data plane — precisely the SDN model. Algorithm governance and crypto execution are architecturally separated, owned by different teams, and independently evolvable. |
| **Self-Healing Posture** | Declarative security posture in the Kubernetes sense: state the intent ("all signing must be quantum-safe"), and the system continuously converges and maintains that state — detecting drift, triggering `TransformKey()`, switching providers on CVE. |
| **Transparent Adoption** | PKCS#11, OpenSSL, and JCA adapters allow existing code to gain cryptographic agility *without rewrites*. The adapter implements the familiar interface; the agile framework runs underneath. |
| **Governance Separation** | Developers use cryptography; security teams govern cryptography. These are different organizational concerns, separated by the API boundary. This is a new operational model, not just a technical feature. |
| **Deployment Spectrum** | Library → policy-managed → lifecycle-managed → key-managed → fully centralized. This is a *framework* with five deployment modes, not a service with one. The same application code works across all modes. |
| **Agility as Consequence** | The abstraction *produces* agility. Agility is the effect, not the cause. Just as SDN does not call itself "Agile Networking", this work should not be defined by agility — the abstraction is the identity. |

### The Infrastructure Evolution Parallel

Every foundational infrastructure domain has completed the same four-phase abstraction journey. Cryptography has not:

```
Phase 1: EXPLICIT       Phase 2: ABSTRACTED     Phase 3: POLICY-DRIVEN   Phase 4: INTENT-BASED
(Hardcoded)             (API Layer)              (Governed)               (Declarative)

Networking:
"Use eth0, TCP/80"  →  DNS + Load Balancer   →  SDN, NetworkPolicy    →  K8s Service mesh

Storage:
"Write to /dev/sda" →  Filesystem, Volume API →  StorageClass, CSI     →  K8s PVC (dynamic)

Cryptography:
"AES_encrypt(...)"  →  Vault Transit, AWS KMS →  ◀─── This work ───▶   →  Declarative policies
```

**Vault and AWS KMS are Phase 2.** They provide an API abstraction layer, but applications still specify which algorithm, which key type, which provider. This work implements Phase 3 (policy-driven algorithm selection, governance separation) and Phase 4 (declarative posture, self-healing), completing the abstraction journey for cryptography.

---

## Cryptographic Agility

Cryptographic agility is the ability to change cryptographic algorithms without modifying application code. This is critical for:
- Responding to cryptographic breaks (e.g., SHA-1 deprecation)
- Compliance requirements (e.g., FIPS algorithm updates)
- Post-quantum migration (transitioning to quantum-resistant algorithms)

### How the API Achieves This

| Feature | Implementation | Benefit |
|---------|---------------|---------|
| **Scope-Based Selection** | `ScopeSpecification` with per-primitive typed scopes | Applications specify *what* they need, not *how* |
| **Template Abstraction** | `template_id` in all requests | Decouples client from algorithm details |
| **Policy-Driven Selection** | `scope` field lets policy determine algorithm | Security teams control algorithm selection |
| **TransformKey Operation** | Change algorithm without changing key identity | Zero-downtime algorithm migrations |
| **OperationMetadata** | Every response includes algorithm details | Self-describing outputs for audit and decryption |
| **Scope-Based Discovery** | `ListTemplates` with `ScopeSpecification` + status/standards filters | Find algorithms by characteristics |

### The Scope/Template Selection Pattern

The API uses a `oneof` pattern that elegantly supports both policy-driven and explicit algorithm selection:

```protobuf
message CreateKeyRequest {
  string name = 1;
  string policy = 2;
  string provider_id = 3;                              // Optional: preferred provider
  map<string, string> provider_configuration = 4;     // Optional: provider-specific settings
  
  oneof key_specification {
    ScopeSpecification scope_spec = 5;  // Policy-driven: typed per-primitive scope
    string template_id = 6;             // Explicit: "I need AES-256-GCM specifically"
  }
}
```

**Policy-Driven (Recommended):**
```go
// Application specifies intent via typed scope
CreateKey(name="app-key", scope_spec={aead: {scope: AEAD_SCOPE_STANDARD}})
// Policy decides: AES-256-GCM in production, ChaCha20-Poly1305 in dev
```

**Explicit (When Required):**
```go
// Application needs specific algorithm (rare, for interoperability)
CreateKey(name="legacy-key", template_id="3des-cbc-64-pkcs7")
```

### Cryptographic Scopes

The API uses **per-primitive typed scopes** via `ScopeSpecification`, a oneof that selects the appropriate scope sub-spec for each cryptographic primitive. Each sub-spec carries typed properties relevant to that primitive (e.g., `non_malleable` for signatures, `memory_hard` for KDFs).

| Primitive | Scope Spec | Example Scopes |
|-----------|------------|----------------|
| **AEAD** | `AeadScopeSpec` | `AEAD_SCOPE_STANDARD`, `AEAD_SCOPE_DETERMINISTIC`, `AEAD_SCOPE_STREAMING` |
| **Digital Signatures** | `SignatureScopeSpec` | `SIGNATURE_SCOPE_STANDARD`, `SIGNATURE_SCOPE_WITH_CONTEXT`, `SIGNATURE_SCOPE_PREHASHED`, `SIGNATURE_SCOPE_PREHASHED_WITH_CONTEXT` |
| **MAC** | `MacScopeSpec` | `MAC_SCOPE_STANDARD`, `MAC_SCOPE_STREAMING` |
| **Key Encapsulation** | `KemScopeSpec` | `KEM_SCOPE_STANDARD`, `KEM_SCOPE_HYBRID` |
| **Key Agreement** | `KeyAgreementScopeSpec` | `KEY_AGREEMENT_SCOPE_STANDARD`, `KEY_AGREEMENT_SCOPE_HYBRID` |
| **Key Derivation** | `KdfScopeSpec` | `KDF_SCOPE_EXTRACT_EXPAND`, `KDF_SCOPE_PASSWORD`, `KDF_SCOPE_AGREEMENT`, `KDF_SCOPE_COUNTER`, `KDF_SCOPE_TLS`, `KDF_SCOPE_GOST`, `KDF_SCOPE_VENDOR` |
| **Hash / XOF** | `HashScopeSpec` | `HASH_SCOPE_STANDARD`, `HASH_SCOPE_XOF` |
| **Key Wrapping** | `KeyWrappingScopeSpec` | `KEY_WRAPPING_SCOPE_STANDARD`, `KEY_WRAPPING_SCOPE_WITH_PADDING` |
| **Disk Encryption** | `DiskEncryptionScopeSpec` | `DISK_ENCRYPTION_SCOPE_STANDARD` |
| **Symmetric Cipher** | `SymmetricCipherScopeSpec` | `SYMMETRIC_CIPHER_SCOPE_BLOCK`, `SYMMETRIC_CIPHER_SCOPE_STREAM` |
| **Generic Secret** | `GenericSecretScopeSpec` | `GENERIC_SECRET_SCOPE_STANDARD` |

**Design rationale:** Scope = caller input shape. Algorithms within the same scope share the same parameter interface, enabling transparent algorithm rotation (the core agility guarantee).

### TransformKey: The Migration Enabler

The `TransformKey` operation is the key enabler for cryptographic agility. It allows changing a key's algorithm while preserving its identity:

```protobuf
// Migrate from ECDSA to post-quantum ML-DSA
TransformKeyRequest {
  name: "signing-key"
  retain_key_bytes: false  // Regenerate key material (required for algorithm family change)
  scope_spec: {
    signature: {
      scope: SIGNATURE_SCOPE_PQ,
      security: { security_strength_bits: 256 }
    }
  }
}
```

**Key Retention Rules:**
- `retain_key_bytes=true`: Same key material, different operation properties (e.g., change hash algorithm)
- `retain_key_bytes=false`: Regenerate key material (required when changing key size or algorithm family)

---

## Extensibility Without API Changes

The API is designed so that new algorithms, providers, and capabilities can be added without modifying the protobuf schema.

### Extension Mechanisms

| What to Extend | Mechanism | Schema Change Required? |
|----------------|-----------|------------------------|
| New algorithms | Add templates via configuration | No |
| New CryptoScopes | Add to enum | Backward-compatible addition |
| New digest algorithms | Add hash templates (e.g., `sha3-512-512`) | No |
| New algorithm parameters | Add to `algorithm_parameters` map | No |
| New providers | Register at runtime | No |
| Provider-specific config | Use `provider_configuration` map | No |
| New encodings | Document in `algorithm_parameters["encoding"]` | No |

### Typed Fields over Generic Maps

The API favors typed fields over `map<string, string>` for core schema constructs.
Templates define algorithm truth through `AlgorithmDetails` and `ScopedCapabilities`;
providers declare their own capabilities at runtime. Maps are reserved for
genuinely open-ended extension points such as `provider_configuration` and `user_context`:

```protobuf
message TemplateInfo {
  string template_id = 1;
  string display_name = 2;
  string description = 3;
  repeated ScopedCapabilities scoped_capabilities = 4;
  AlgorithmDetails algorithm = 5;
  TemplateStatus status = 6;
  string deprecation_notice = 7;
  // fields 8, 9, 11 reserved (capabilities, available_providers, algorithm_properties removed)
  repeated string standards = 10;
  CycloneDXAlgorithmProperties cyclonedx = 13;
}

message OperationMetadata {
  int32 key_version = 1;
  ProviderOutput provider_output = 2;  // Typed algorithm output + encoding
  string api_version = 3;
  map<string, string> user_context = 4;  // Open-ended audit context (appropriate map usage)
}
```

### Scope-Based Discovery

Clients can discover algorithms by their characteristics, not just by name:

```go
// Find all FIPS-approved, active, 256-bit signatures
templates := ListTemplates(ListTemplatesRequest{
  ScopeSpec: &ScopeSpecification{
    Signature: &SignatureScopeSpec{
      Scope: SIGNATURE_SCOPE_STANDARD,
      Security: &SecurityRequirements{SecurityStrengthBits: 256, FipsApproved: true},
    },
  },
  AllowedStatuses: []TemplateStatus{TEMPLATE_STATUS_ACTIVE},
})
```

---

## PKCS#11 v3.2 Compliance

The API provides comprehensive coverage of PKCS#11 v3.2 operations, mapped to modern gRPC/REST patterns.

### Operation Coverage

| PKCS#11 Function | CaaS API | Notes |
|------------------|----------|-------|
| **Key Management** | | |
| `C_CreateObject` | `CreateKey` | With scope or template selection |
| `C_DestroyObject` | `DeleteKey` | |
| `C_GetAttributeValue` | `ReadKey` | Returns `KeyMetadata` |
| `C_FindObjects` | `ListKeys` | With filtering |
| **Encryption** | | |
| `C_Encrypt` | `Encrypt` | Single-shot |
| `C_EncryptInit/Update/Final` | `EncryptInit`, `EncryptUpdate`, `EncryptFinal` | Multi-part streaming |
| `C_Decrypt` | `Decrypt` | Single-shot |
| `C_DecryptInit/Update/Final` | `DecryptInit`, `DecryptUpdate`, `DecryptFinal` | Multi-part streaming |
| `C_MessageEncryptInit/Final` | `MessageEncryptInit`, `MessageEncryptFinal` | AEAD message-based |
| **Signing** | | |
| `C_Sign` | `Sign` | Single-shot |
| `C_SignInit/Update/Final` | `SignInit`, `SignUpdate`, `SignFinal` | Multi-part streaming |
| `C_Verify` | `Verify` | Single-shot |
| `C_VerifyInit/Update/Final` | `VerifyInit`, `VerifyUpdate`, `VerifyFinal` | Multi-part streaming |
| `C_SignRecover/VerifyRecover` | `SignRecover`, `VerifyRecover` | With data recovery |
| **Digesting** | | |
| `C_DigestInit/Update/Final` | `DigestInit`, `DigestUpdate`, `DigestFinal` | Multi-part hashing |
| `C_DigestKey` | `DigestKey` | Hash key material |
| **MAC** | | |
| `C_GenerateMac` | `GenerateMac` | |
| `C_VerifyMac` | `VerifyMac` | |
| **Key Wrapping** | | |
| `C_WrapKey` | `WrapKey` | |
| `C_UnwrapKey` | `UnwrapKey` | |
| **Key Derivation** | | |
| `C_DeriveKey` | `DeriveKey` | HKDF, PBKDF2, etc. |
| **Random** | | |
| `C_GenerateRandom` | `GenerateRandom` | |
| `C_SeedRandom` | `SeedRandom` | |
| **Key Encapsulation (v3.2)** | | |
| `C_Encapsulate` | `EncapsulateKey` | Post-quantum KEMs |
| `C_Decapsulate` | `DecapsulateKey` | |
| **Dual-Function** | | |
| `C_DigestEncryptUpdate` | `DigestEncrypt` | Hash while encrypting |
| `C_DecryptDigestUpdate` | `DecryptDigest` | Hash while decrypting |
| `C_SignEncryptUpdate` | `SignEncrypt` | Sign while encrypting |
| `C_DecryptVerifyUpdate` | `DecryptVerify` | Verify while decrypting |

### Multi-Part Operation Pattern

The API follows the PKCS#11 Init/Update/Final pattern for streaming operations:

```go
// Multi-part encryption (for large data)
client.EncryptInit(&EncryptInitRequest{KeyName: "my-key", OperationId: "op-123"})
client.EncryptUpdate(&EncryptUpdateRequest{OperationId: "op-123", PlaintextChunk: chunk1})
client.EncryptUpdate(&EncryptUpdateRequest{OperationId: "op-123", PlaintextChunk: chunk2})
result := client.EncryptFinal(&EncryptFinalRequest{OperationId: "op-123"})
// result.CiphertextFinal contains final ciphertext block
// result.Metadata contains OperationMetadata for decryption
```
```

### Digest Operations (Stateless - Explicit Selection)

Digest operations are stateless and don't involve keys or policies. The API uses explicit template selection with optional policy enforcement:

```protobuf
message DigestRequest {
  // Required: Explicit algorithm template (e.g., "sha-256", "sha3-512")
  string template_id = 1;
  
  bytes data = 10;
  
  // Optional: Policy name for validation (does NOT select algorithm)
  string policy_name = 11;
}
```

**Design Rationale:**
- **No key binding**: Digest operations don't use keys, so there's no natural policy association
- **Explicit is better**: Caller explicitly chooses hash algorithm (no ambiguity)
- **Optional enforcement**: Policy can still validate if the operation/template is allowed
- **Separation of concerns**: Algorithm selection vs. access control are separate

**Supported Hash Templates:**

| Category | Templates |
|----------|------------|
| **SHA-2 Family** | `sha-256`, `sha-384`, `sha-512` |
| **SHA-3 Family** | `sha3-256`, `sha3-384`, `sha3-512` |
| **BLAKE** | `blake2b-256`, `blake2b-512`, `blake3` |

**Policy Enforcement (Optional):**
If `policy_name` is provided, the policy can control:
- Which hash algorithms are allowed (e.g., prohibit SHA-1)
- Minimum security levels (e.g., 256-bit only)
- Allowed operations (e.g., disable digest in certain contexts)

**Benefits:**
- Simple and predictable (caller knows exactly what algorithm is used)
- Policy enforcement available when needed
- `OperationMetadata` captures which algorithm was used for audit

---

## Post-Quantum Readiness

The API is designed for the post-quantum transition with first-class support for:

### Post-Quantum Scopes

| Scope Spec | Scope Value | Use Case |
|------------|-------------|----------|
| `SignatureScopeSpec` | `SIGNATURE_SCOPE_PQ` | ML-DSA, SLH-DSA signatures |
| `KemScopeSpec` | `KEM_SCOPE_STANDARD` | ML-KEM key encapsulation |
| `SignatureScopeSpec` | `SIGNATURE_SCOPE_HYBRID` | ML-DSA + ECDSA combined |
| `KemScopeSpec` | `KEM_SCOPE_HYBRID` | ML-KEM + ECDH combined |
| `AeadScopeSpec` | `AEAD_SCOPE_STANDARD` + hybrid template | Hybrid encryption schemes |

### Key Encapsulation Mechanism (KEM) Operations

Native support for post-quantum KEMs (PKCS#11 v3.2):

```go
// EncapsulateKey (generate shared secret for recipient)
resp := client.EncapsulateKey(EncapsulateKeyRequest{
  RecipientPublicKeyName: "recipient-ml-kem-768",
  SharedSecretName:       "derived-aes-key",
  SharedSecretTemplateId: "aes-256-gcm",
})
// resp.Ciphertext -> send to recipient
// resp.Metadata -> includes algorithm parameters

// DecapsulateKey (recover shared secret)
resp := client.DecapsulateKey(DecapsulateKeyRequest{
  PrivateKeyName:        "my-ml-kem-768",
  Ciphertext:            receivedCiphertext,
  SharedSecretName:      "derived-aes-key",
  SharedSecretTemplateId: "aes-256-gcm",
  Metadata:              encapsulateMetadata,  // From EncapsulateKey response
})
// Shared secret stored as "derived-aes-key"
```

### Migration Path

```go
// Step 1: Create hybrid key (classical + PQ)
client.CreateKey(&CreateKeyRequest{
  Name:   "signing-key",
  Policy: "prod-signing",
  ScopeSpec: &ScopeSpecification{
    Signature: &SignatureScopeSpec{Scope: SIGNATURE_SCOPE_HYBRID},
  },
})

// Step 2: Later, transform to pure PQ when ready
client.TransformKey(&TransformKeyRequest{
  Name:           "signing-key",
  RetainKeyBytes: false,
  ScopeSpec: &ScopeSpecification{
    Signature: &SignatureScopeSpec{Scope: SIGNATURE_SCOPE_PQ},
  },
})
```

---

## Security Design

### Metadata Does NOT Require Signing

The `OperationMetadata` fields are informational and do NOT require cryptographic authentication:

1. **Algorithm Parameters (IV, nonce):**
   - Authenticated by the AEAD authentication tag
   - Tampering invalidates the tag

2. **Key Version:**
   - Wrong version = wrong key = decryption fails or produces garbage

3. **Template ID:**
   - Wrong algorithm = parsing fails or produces garbage

**Threat Model:** Attackers can tamper with metadata, but cryptographic verification will fail. Signing metadata would be redundant.

### Separation of Concerns

Three separate operations for fine-grained access control:

| Operation | Purpose | Typical Access |
|-----------|---------|----------------|
| `TransformKey` | Change algorithm/template | Developers (IAM) |
| `UpdateKeyPolicy` | Change governance policy | Security admins |
| `MigrateKey` | Change HSM/KMS backend | Infrastructure admins |

### Server-Side Key Management

- Keys referenced by name, never exposed to clients
- Key material stays within the provider (HSM, KMS)
- Complete audit trail of all operations
- Automatic key versioning on rotation

### Authentication and Authorization Architecture

The API uses a **two-policy architecture** that cleanly separates authentication/authorization from cryptographic governance:

#### Two Orthogonal Policy Systems

| Policy Type | Source | Purpose | Scope |
|-------------|--------|---------|-------|
| **ACL Policy** | Bearer token (authentication system) | **Authorization**: Who can access which resources/operations | Identity & access control |
| **Crypto Policy** | Request `policy` field | **Algorithm governance**: Which algorithms/templates are allowed | Cryptographic decisions |

#### Authentication via Bearer Token

Authentication is handled entirely at the transport layer via standard bearer tokens:

```
gRPC:  metadata "authorization" = "Bearer <token>"
REST:  Header "Authorization: Bearer <token>"
```

**The token contains or references an ACL policy** that controls:
- Which keys the caller can access (e.g., `keys/payment-*`)
- Which operations are permitted (e.g., `encrypt`, `decrypt`, `create_key`)
- Resource-level permissions

**Why no authentication fields in proto messages?**
- Clean separation of concerns (Vault model)
- Authentication is orthogonal to cryptographic operations
- Implementation flexibility (JWT, opaque tokens, mTLS)
- Existing identity providers can be integrated without API changes

#### Crypto Policy in Request Messages

The `policy` field in request messages (e.g., `CreateKeyRequest.policy`) refers to **Crypto Policy**, which governs:
- Allowed algorithms/templates for a scope
- Security level requirements (e.g., 256-bit minimum)
- Compliance constraints (e.g., FIPS-approved only)
- Template selection preferences

#### Request Validation Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Request: CreateKey(name="payment-key", policy="prod-encrypt")  │
│  Header:  Authorization: Bearer <token>                         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 1: ACL Authorization (from bearer token)                  │
│  "Can this principal create keys matching 'payment-*'?" ✓       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 2: Crypto Policy Validation (from request.policy)         │
│  "Does 'prod-encrypt' allow AUTHENTICATED_ENCRYPTION scope?"    │
│  "Which template should be used?" → aes-256-gcm                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  STEP 3: Execute Operation (both checks passed)                 │
└─────────────────────────────────────────────────────────────────┘
```

#### Example: Complete Request

```bash
# ACL policy (from token): allows "encrypt" on "keys/payment-*"
# Crypto policy (prod-encrypt): allows aes-256-gcm for authenticated encryption

curl -X POST https://crypto.example.com/v1/keys/payment-key \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "prod-encrypt",
    "scope_spec": {
      "aead": { "scope": "AEAD_SCOPE_STANDARD" }
    }
  }'
```

#### Design Benefits

| Benefit | Description |
|---------|-------------|
| **Separation of Concerns** | Security teams manage ACL policies; crypto teams manage crypto policies |
| **No Schema Changes for Auth** | New auth methods don't require proto changes |
| **Audit Attribution** | Token identifies the caller; crypto policy identifies the governance |
| **Flexible Integration** | Works with Vault, Keycloak, Auth0, custom auth systems |

---

## Summary

The Abstract Cryptographic API achieves:

| Goal | How |
|------|-----|
| **Cryptographic Agility** | Scope-based selection, TransformKey, policy-driven algorithms |
| **Extensibility** | Map-based properties, runtime template discovery |
| **PKCS#11 Compliance** | Full operation coverage including v3.2 KEMs |
| **Post-Quantum Ready** | Native PQ and hybrid scopes |
| **Security** | Server-side keys, AEAD authentication, two-policy architecture |
| **Long-Term Compatibility** | API versioning in OperationMetadata for artifact migration |

This design ensures that applications built on this API can adapt to future cryptographic requirements without code changes, while maintaining strong security and compliance posture.
