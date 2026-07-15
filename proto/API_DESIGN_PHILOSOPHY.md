# API Design Philosophy

This document explains the design principles behind the Abstract Cryptographic API, focusing on cryptographic agility, extensibility, and standards compliance.

**Version:** 0.1.0

---

## Table of Contents

1. [True Identity: What This Work Actually Is](#true-identity-what-this-work-actually-is)
2. [Cryptographic Agility](#cryptographic-agility)
3. [Extensibility Without API Changes](#extensibility-without-api-changes)
4. [PKCS#11 Coverage](#pkcs11-coverage)
5. [Post-Quantum Readiness](#post-quantum-readiness)
6. [Security Design](#security-design)

---

## True Identity: What This Work Actually Is

This is not a cryptographic service. Calling it "Cryptography-as-a-Service" understates the work to the point of misdirection — it implies a remote service provider doing encryption on your behalf, which is only one of several deployment modes and the least interesting architectural property.

The work is better understood as a **new abstraction layer for cryptography** — the layer that networking and storage have already completed but cryptography has not. Just as file systems abstracted disk sectors, and TCP/IP abstracted network hardware, and Kubernetes abstracted infrastructure scheduling, this work abstracts the *consumption and governance of cryptography itself*.

**Cryptographic agility is a consequence of the abstraction, not the goal.** When you abstract correctly, agility is what you get. The goal is the abstraction.

| Aspect | What It Actually Is |
|--------|---------------------|
| **Abstraction** | Separates cryptographic *intent* from *implementation* — like file systems abstracting disk sectors. Applications express *what* they need; the framework decides *how*. |
| **Control/Data Plane Separation** | The policy engine is the control plane; providers are the data plane — precisely the SDN model. Algorithm governance and crypto execution are architecturally separated, owned by different teams, and independently evolvable. |
| **Self-Healing Posture** | Declarative security posture in the Kubernetes sense: state the intent ("all signing must be quantum-safe"), and the system continuously converges and maintains that state — detecting drift, triggering `TransformKey`, switching providers on CVE. |
| **Transparent Adoption** | PKCS#11, OpenSSL, and JCA adapters allow existing code to gain cryptographic agility *without rewrites*. The adapter implements the familiar interface; the agile framework runs underneath. |
| **Governance Separation** | Developers use cryptography; security teams govern cryptography. These are different organizational concerns, separated by the API boundary. This is a new operational model, not just a technical feature. |
| **Deployment Spectrum** | Library → policy-managed → lifecycle-managed → key-managed → fully centralized. This is a *framework* with multiple deployment modes, not a service with one. The same application code works across all modes. |
| **Agility as Consequence** | The abstraction *produces* agility. Agility is the effect, not the cause. Just as SDN does not call itself "Agile Networking", this work should not be defined by agility — the abstraction is the identity. |


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
| **Template Abstraction** | Optional `template_id` in requests | Explicit selection when interoperability demands it |
| **Policy-Driven Selection** | `policy` + `scope_spec` let the policy pick the algorithm | Security teams control algorithm selection |
| **TransformKey Operation** | Change algorithm without changing key identity | Zero-downtime algorithm migrations |
| **MigrateKey Operation** | Move a key to a new provider with an explicit strategy | Backend changes without changing key identity |
| **OperationMetadata** | Every response carries key version and system-generated parameters | Self-describing outputs for audit and decryption |
| **Scope-Based Discovery** | `ListTemplates` with `ScopeSpecification` + status/standards filters | Find algorithms by characteristics |

### The Scope / Template Selection Pattern

Key creation takes a scope specification (intent) and an optional explicit template. They are **independent**, not mutually exclusive:

```protobuf
message CreateKeyRequest {
  string name = 1;                                       // Logical key name
  string policy = 2;                                     // Crypto policy governing this key
  string provider_id = 3;                                // Optional: pin a provider
  map<string, string> provider_configuration = 4;        // Optional: ad-hoc provider settings
  ScopeSpecification scope_spec = 5;                     // Intent — policy resolves the algorithm
  optional string template_id = 6;                       // Optional: pin an explicit template
  ProviderRequirements provider_requirements = 7;        // Optional: FIPS level, constant-time, …
  optional google.protobuf.Timestamp activation_time = 8;  // Optional: cryptoperiod start
  optional google.protobuf.Timestamp expiration_time = 9;  // Optional: cryptoperiod end
}
```

- **`scope_spec` only** — policy selects a template that satisfies the scope (recommended).
- **`template_id` only** — explicit algorithm; policy must still permit it.
- **Both** — the template must satisfy the scope *and* be policy-allowed (used to pin a specific algorithm within an intent).

**Policy-Driven (Recommended):**
```
// Application specifies intent via a typed scope
CreateKey(name="app-key", policy="prod", scope_spec={aead: {scope: AEAD_SCOPE_STANDARD}})
// Policy decides: AES-256-GCM in production, ChaCha20-Poly1305 in dev
```

**Explicit (When Required):**
```
// Application needs a specific algorithm (rare, for interoperability)
CreateKey(name="legacy-key", policy="legacy", template_id="3des-cbc")
```

### Cryptographic Scopes

The API uses **per-primitive typed scopes** via `ScopeSpecification`, a oneof that selects the appropriate scope sub-spec for each cryptographic primitive. Each sub-spec carries typed properties relevant to that primitive (e.g., `non_malleable` for signatures, `memory_hard` for KDFs) plus universal `security` properties (strength, FIPS approval, quantum safety).

| Primitive | Scope Spec | Example Scopes |
|-----------|------------|----------------|
| **AEAD / Symmetric Encryption** | `AeadScopeSpec` | `AEAD_SCOPE_STANDARD`, `AEAD_SCOPE_DISK`, `AEAD_SCOPE_ASYMMETRIC` |
| **Digital Signatures** | `SignatureScopeSpec` | `SIGNATURE_SCOPE_STANDARD`, `SIGNATURE_SCOPE_PQ`, `SIGNATURE_SCOPE_HYBRID` |
| **MAC** | `MacScopeSpec` | `MAC_SCOPE_STANDARD`, `MAC_SCOPE_CUSTOMIZABLE` |
| **Key Encapsulation** | `KemScopeSpec` | `KEM_SCOPE_STANDARD`, `KEM_SCOPE_HYBRID` |
| **Key Agreement** | `KeyAgreementScopeSpec` | `KEY_AGREEMENT_SCOPE_STANDARD` |
| **Key Derivation** | `KdfScopeSpec` | `KDF_SCOPE_EXTRACT_EXPAND`, `KDF_SCOPE_PASSWORD`, `KDF_SCOPE_AGREEMENT`, `KDF_SCOPE_COUNTER`, `KDF_SCOPE_TLS` |
| **Hash / XOF** | `HashScopeSpec` | `HASH_SCOPE_STANDARD`, `HASH_SCOPE_XOF` |
| **Key Wrapping** | `KeyWrappingScopeSpec` | `KEY_WRAPPING_SCOPE_STANDARD`, `KEY_WRAPPING_SCOPE_WITH_PADDING` |
| **Asymmetric Encryption** | `AsymmetricEncryptionScopeSpec` | `ASYMMETRIC_ENCRYPTION_SCOPE_STANDARD`, `ASYMMETRIC_ENCRYPTION_SCOPE_RAW` |
| **Disk Encryption** | `DiskEncryptionScopeSpec` | `DISK_ENCRYPTION_SCOPE_STANDARD` |
| **Symmetric Cipher** | `SymmetricCipherScopeSpec` | `SYMMETRIC_CIPHER_SCOPE_BLOCK`, `SYMMETRIC_CIPHER_SCOPE_STREAM` |
| **Generic Secret** | `GenericSecretScopeSpec` | `GENERIC_SECRET_SCOPE_STANDARD` |

**Design rationale:** A scope names the caller's *input shape*. Algorithms within the same scope share the same operational-parameter interface, enabling transparent algorithm rotation (the core agility guarantee). Post-quantum is *not* a separate scope — it is a **property** (`security.quantum_safe`), so a quantum-safe ML-DSA key and a classical ECDSA key present the identical `SIGNATURE_SCOPE_STANDARD` interface.

### TransformKey: The Migration Enabler

The `TransformKey` operation is the key enabler for cryptographic agility. It changes a key's algorithm while preserving its identity (name and version history):

```protobuf
// Migrate to a post-quantum signature — policy selects e.g. ML-DSA-65
TransformKeyRequest {
  name: "signing-key"
  retain_key_bytes: false            // Regenerate material (required for algorithm family change)
  scope_spec: {
    signature: {
      scope: SIGNATURE_SCOPE_STANDARD
      security: { quantum_safe: true, security_strength_bits: 192 }
    }
  }
}
```

**Key retention rules:**
- `retain_key_bytes=true`: Same key material, different operation properties (e.g., change the signing hash).
- `retain_key_bytes=false`: Regenerate key material (required when changing key size or algorithm family). The service rejects `retain_key_bytes=true` when the transform is incompatible with the existing material.

---

## Extensibility Without API Changes

The API is designed so that most new algorithms, providers, and capabilities can be added without modifying the protobuf schema; the remainder are additive, backward-compatible changes.

### Extension Mechanisms

| What to Extend | Mechanism | Schema Change? |
|----------------|-----------|----------------|
| New standard algorithms | Add templates to the catalog | No |
| New scopes / statuses | Add enum value | Additive, backward-compatible |
| New algorithm parameters (existing family) | Add a field to the typed params message | Additive |
| Vendor / pre-standard algorithms | `CustomAlgorithm` + `Vendor*Params` escape hatches | No |
| New providers | Register a `ProviderInstance` at runtime | No |
| Provider-specific config | `provider_configuration` map | No |
| New artifact encodings | `provider_output.encoding` value | No |

### Map-Based Extensibility

The API favors typed fields over `map<string, string>` for core schema constructs. Templates define algorithm truth through the typed `AlgorithmDetails` oneof and `ScopedCapabilities`; providers declare their own capabilities at runtime. Maps are reserved for genuinely open-ended extension points such as `provider_configuration`, `additional_properties`, and `user_context`:

```protobuf
message TemplateInfo {
  string template_id = 1;
  string display_name = 2;
  string description = 3;
  repeated ScopedCapabilities scoped_capabilities = 4;  // scope + operations + guarantees
  AlgorithmDetails algorithm = 5;                       // typed algorithm config (oneof)
  TemplateStatus status = 6;
  string deprecation_notice = 7;
  repeated string standards = 8;
  CycloneDXAlgorithmProperties cyclonedx = 9;           // CBOM export
  SecurityGuarantees security_guarantees = 10;
}

message OperationMetadata {
  uint32 key_version = 1;                 // Key version used (for rotation-aware verify/decrypt)
  ProviderOutput provider_output = 2;     // Typed system-generated params (IV/nonce/salt) + encoding
  string api_version = 3;                 // Producing API version (for long-lived artifacts)
  map<string, string> user_context = 4;   // Open-ended audit context (appropriate map usage)
}
```

System-generated parameters are carried in the typed `ProviderOutput` oneof (`AeadOutput`, `BlockCipherOutput`, `CounterModeOutput`, `StreamCipherOutput`, `KdfOutput`, `NoAlgorithmOutput`, `VendorOutput`), each one-to-one with a PKCS#11 mechanism output structure — not a free-form parameter map.

### Scope-Based Discovery

Clients can discover algorithms by their characteristics, not just by name:

```
// Find all FIPS-approved, active, 256-bit signature templates
templates := ListTemplates(ListTemplatesRequest{
  ScopeSpec: {
    Signature: {
      Scope:    SIGNATURE_SCOPE_STANDARD,
      Security: UniversalSecurityProperties{ SecurityStrengthBits: 256, FipsApproved: true },
    },
  },
  AllowedStatuses: [TEMPLATE_STATUS_ACTIVE],
})
```

---

## PKCS#11 Coverage

The API provides comprehensive coverage of PKCS#11 v3.x operations (KEM support was added in v3.1), mapped to modern gRPC/REST patterns. Key-lifecycle state transitions additionally follow the KMIP / NIST SP 800-57 model.

### Operation Coverage

| PKCS#11 Function | This API | Notes |
|------------------|----------|-------|
| **Key Management** | | |
| `C_CreateObject` | `CreateKey` | Scope-based and/or explicit template selection |
| `C_DestroyObject` | `DeleteKey` | Zeroizes material; metadata retained for audit by default |
| `C_GetAttributeValue` | `ReadKey` | Returns `KeyMetadata` |
| `C_FindObjects` | `ListKeys` | With filtering |
| *(KMIP state machine)* | `UpdateKeyState` | Explicit, auditable lifecycle transitions (SP 800-57 §7) |
| **Encryption** | | |
| `C_Encrypt` | `Encrypt` | Single-shot |
| `C_EncryptInit/Update/Final` | `EncryptInit`, `EncryptUpdate`, `EncryptFinal` | Multi-part streaming |
| `C_Decrypt` | `Decrypt` | Single-shot |
| `C_DecryptInit/Update/Final` | `DecryptInit`, `DecryptUpdate`, `DecryptFinal` | Multi-part streaming |
| `C_Message*Init` / `C_*Message` / `C_Message*Final` | `EncryptMessageInit`, `EncryptMessage` / `EncryptMessageBegin`+`Next`, `EncryptMessageFinal` | Message-based AEAD (mirrored for decrypt) |
| **Signing** | | |
| `C_Sign` | `Sign` | Single-shot |
| `C_SignInit/Update/Final` | `SignInit`, `SignUpdate`, `SignFinal` | Multi-part streaming |
| `C_Verify` | `Verify` | Single-shot |
| `C_VerifyInit/Update/Final` | `VerifyInit`, `VerifyUpdate`, `VerifyFinal` | Multi-part streaming |
| **Digesting** | | |
| `C_Digest` | `Digest` | Single-shot |
| `C_DigestInit/Update/Final` | `DigestInit`, `DigestUpdate`, `DigestFinal` | Multi-part hashing |
| `C_DigestKey` | `DigestKey` | Hash key material |
| **XOF** | | `Xof`, `XofInit/Update/Final` | SHAKE128/256, caller-specified output length |
| **MAC** | | |
| `C_SignInit/Update/Final` (MAC mechanism) | `GenerateMAC` / `GenerateMACInit/Update/Final` | Single-shot and streaming |
| `C_VerifyInit/Update/Final` (MAC mechanism) | `VerifyMAC` / `VerifyMACInit/Update/Final` | Single-shot and streaming |
| **Key Wrapping** | | |
| `C_WrapKey` | `WrapKey` | |
| `C_UnwrapKey` | `UnwrapKey` | |
| **Key Derivation** | | |
| `C_DeriveKey` | `DeriveKey`, `KeyAgreement` | HKDF, PBKDF2, Argon2; ECDH/X25519/X448 agreement |
| **Random** | | |
| `C_GenerateRandom` | `GenerateRandom` | |
| `C_SeedRandom` | `SeedRandom` | |
| **Key Encapsulation (v3.1+)** | | |
| `C_Encapsulate` | `EncapsulateKey` | Post-quantum KEMs (ML-KEM) |
| `C_Decapsulate` | `DecapsulateKey` | |
| **Dual-Function** | | |
| `C_DigestEncryptUpdate` | `DigestEncryptUpdate` | Hash while encrypting |
| `C_DecryptDigestUpdate` | `DecryptDigestUpdate` | Hash while decrypting |
| `C_SignEncryptUpdate` | `SignEncryptUpdate` | Sign while encrypting |
| `C_DecryptVerifyUpdate` | `DecryptVerifyUpdate` | Verify while decrypting |
| **Session** | | |
| `C_CloseSession` (active op) | `CancelOperation` | Abort a streaming session and release state |

> `C_SignRecover` / `C_VerifyRecover` (RSA message recovery) are intentionally **out of scope** and not exposed.

### Multi-Part Operation Pattern

The API follows the PKCS#11 Init/Update/Final pattern for streaming operations. Operation IDs are **server-generated**: `Init` returns the `operation_id`, and the client passes it to every subsequent call. This prevents session-ID collision and hijacking.

```
// Multi-part encryption (for large data)
init   := EncryptInit(EncryptInitRequest{ key_name: "my-key", aead_params: {…} })
op     := init.operation_id                                  // server-generated
EncryptUpdate(EncryptUpdateRequest{ operation_id: op, plaintext_chunk: chunk1 })
EncryptUpdate(EncryptUpdateRequest{ operation_id: op, plaintext_chunk: chunk2 })
final  := EncryptFinal(EncryptFinalRequest{ operation_id: op })
// final.ciphertext_final  -> last ciphertext block (+ auth tag for AEAD)
// final.metadata          -> OperationMetadata (key version + IV/nonce) for decryption
```

Message-based sessions (`EncryptMessage*`) amortize one key setup across many independent messages; within a session a message is delimited by an `end_of_message` marker on the final `EncryptMessageNext`, and `EncryptMessageFinal` tears the session down.

### Digest Operations (Scope-Based or Explicit)

Digest and XOF operations are stateless and involve no keys. Like every other operation they accept either a scope specification (intent) or an explicit template, with optional policy validation:

```protobuf
message DigestRequest {
  ScopeSpecification scope_spec = 1;   // Intent, e.g. hash { scope: HASH_SCOPE_STANDARD }
  optional string template_id = 2;     // Or pin an explicit hash, e.g. "sha-256"
  bytes data = 3;
  string policy_name = 4;              // Optional: validate the operation/template (does not select)
  map<string, string> user_context = 15;
}
```

**Design rationale:**
- **Intent or explicit:** callers who want agility supply a hash scope and let policy choose; callers who need a specific hash pin the template.
- **Optional enforcement:** policy can reject weak algorithms (e.g., prohibit SHA-1) or enforce a minimum strength, independent of selection.
- **Auditable:** `OperationMetadata` records which algorithm was used.

**Representative hash templates:**

| Category | Templates |
|----------|-----------|
| **SHA-2 Family** | `sha-256`, `sha-384`, `sha-512` |
| **SHA-3 Family** | `sha3-256`, `sha3-384`, `sha3-512` |
| **XOF** | `shake-128`, `shake-256` |
| **BLAKE** | `blake2b-256`, `blake2b-512`, `blake3` |

---

## Post-Quantum Readiness

The API is designed for the post-quantum transition. Crucially, **post-quantum is expressed as a property, not a new scope** — so PQ and classical algorithms share the same operational interface and remain interchangeable by policy.

### Expressing Post-Quantum Intent

| Intent | How to express it | Algorithms |
|--------|-------------------|------------|
| PQ signature | `SignatureScopeSpec` `SIGNATURE_SCOPE_STANDARD` + `security.quantum_safe = true` | ML-DSA (FIPS 204), SLH-DSA (FIPS 205) |
| Hybrid signature | `SignatureScopeSpec` `SIGNATURE_SCOPE_STANDARD` + a hybrid template | ML-DSA + ECDSA |
| PQ KEM | `KemScopeSpec` `KEM_SCOPE_STANDARD` | ML-KEM (FIPS 203) |
| Hybrid KEM | `KemScopeSpec` `KEM_SCOPE_HYBRID` | ML-KEM + ECDH |
| Hybrid encryption | `AeadScopeSpec` `AEAD_SCOPE_STANDARD` + a hybrid template | HPKE, ECIES |

Hybrid compositions are described by `HybridAlgorithmParams` (concatenation, nesting, or KDF-combination of two or more component algorithms).

### Key Encapsulation Mechanism (KEM) Operations

Native support for post-quantum KEMs (PKCS#11 v3.1+):

```
// EncapsulateKey (generate a shared secret for a recipient)
resp := EncapsulateKey(EncapsulateKeyRequest{
  RecipientPublicKeyName: "recipient-ml-kem-768",
  SharedSecretName:       "derived-aes-key",
  SharedSecretTemplateId: "aes-256-gcm",
})
// resp.Ciphertext -> send to recipient
// resp.Metadata   -> provider_output.encoding documents the ciphertext encoding

// DecapsulateKey (recover the shared secret)
resp := DecapsulateKey(DecapsulateKeyRequest{
  PrivateKeyName:         "my-ml-kem-768",
  Ciphertext:             receivedCiphertext,
  SharedSecretName:       "derived-aes-key",
  SharedSecretTemplateId: "aes-256-gcm",
  Metadata:               encapsulateMetadata,   // relayed from the EncapsulateKey response
})
// Shared secret stored as "derived-aes-key"
```

The decapsulator resolves the KEM algorithm from its own private key's template — the algorithm is deliberately not carried (and therefore not trusted) in the unauthenticated response metadata.

### Migration Path

```
// Step 1: deploy a hybrid signature via a hybrid template (classical + PQ)
CreateKey(CreateKeyRequest{
  Name:       "signing-key",
  Policy:     "prod-signing",
  ScopeSpec:  { Signature: { Scope: SIGNATURE_SCOPE_STANDARD } },
  TemplateId: "ml-dsa-65-ecdsa-p256-hybrid",
})

// Step 2: later, transform to pure PQ — policy selects ML-DSA; call sites unchanged
TransformKey(TransformKeyRequest{
  Name:           "signing-key",
  RetainKeyBytes: false,
  ScopeSpec:      { Signature: { Scope: SIGNATURE_SCOPE_STANDARD, Security: { QuantumSafe: true } } },
})
```

---

## Security Design

### Metadata Does NOT Require Signing

`OperationMetadata` is informational and does not require cryptographic authentication. Its only fields are `key_version`, `provider_output` (system-generated IV/nonce/salt + encoding), `api_version`, and `user_context`:

1. **System-generated parameters (IV, nonce):** authenticated by the AEAD tag — tampering invalidates the tag.
2. **Key version:** wrong version = wrong key = decryption fails or produces garbage.
3. **Template ID is intentionally excluded** from the metadata (it is not authenticated and could be tampered with). Clients recover a key's template via `ReadKey → key_metadata.template_id`; assuming the wrong algorithm simply fails verification/decryption.

**Threat model:** an attacker can tamper with metadata, but the cryptographic verification (AEAD tag or signature) still fails. Signing the metadata would be redundant. For audit-trail integrity, sign the log entry that binds the cryptographic result to its metadata — not the metadata alone.

### Separation of Concerns

Distinct operations enable fine-grained, separately-grantable access:

| Operation | Purpose | Typical Access |
|-----------|---------|----------------|
| `TransformKey` | Change algorithm / template | Developers (IAM) |
| `UpdateKeyState` | Activate / suspend / deactivate / mark compromised | Key administrators |
| `UpdateKeyPolicy` | Change governance policy | Security admins |
| `MigrateKey` | Change HSM / KMS backend | Infrastructure admins |

### Server-Side Key Management

- Keys referenced by name, never exposed to clients.
- Key material stays within the provider (HSM, KMS).
- Explicit, auditable lifecycle states (`UpdateKeyState`) and cryptoperiods (`activation_time` / `expiration_time`) per NIST SP 800-57.
- Automatic key versioning on rotation.

### Authentication and Authorization Architecture

The API uses a **two-policy architecture** that cleanly separates authentication/authorization from cryptographic governance.

#### Two Orthogonal Policy Systems

| Policy Type | Source | Purpose | Scope |
|-------------|--------|---------|-------|
| **ACL Policy** | Bearer token (authentication system) | **Authorization**: who can access which resources/operations | Identity & access control |
| **Crypto Policy** | Request `policy` field | **Algorithm governance**: which algorithms/templates are allowed | Cryptographic decisions |

#### Authentication via Bearer Token

Authentication is handled entirely at the transport layer via standard bearer tokens:

```
gRPC:  metadata "authorization" = "Bearer <token>"
REST:  Header "Authorization: Bearer <token>"
```

**The token contains or references an ACL policy** that controls which keys the caller can access (e.g., `keys/payment-*`), which operations are permitted (e.g., `encrypt`, `decrypt`, `create_key`), and resource-level permissions.

**Why no authentication fields in proto messages?**
- Clean separation of concerns.
- Authentication is orthogonal to cryptographic operations.
- Implementation flexibility (JWT, opaque tokens, mTLS).
- Existing identity providers integrate without API changes.

#### Crypto Policy in Request Messages

The `policy` field in request messages (e.g., `CreateKeyRequest.policy`) refers to the **Crypto Policy**, which governs allowed algorithms/templates for a scope, security-level requirements, compliance constraints (e.g., FIPS-approved only), and selection preferences. The API treats the policy document as an abstract object, so deployments choose their own policy language (a `format` field identifies it).

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
│  "Does 'prod-encrypt' allow the AEAD scope?"                    │
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
# ACL policy (from token): allows "create_key" on "keys/payment-*"
# Crypto policy (prod-encrypt): allows aes-256-gcm for authenticated encryption

curl -X POST https://crypto.example.com/v1/keys/payment-key \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json" \
  -d '{
    "policy": "prod-encrypt",
    "scope_spec": { "aead": { "scope": "AEAD_SCOPE_STANDARD" } }
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
| **Cryptographic Agility** | Scope-based selection, `TransformKey`, `MigrateKey`, policy-driven algorithms |
| **Extensibility** | Typed algorithm catalog, runtime template discovery, additive-only schema evolution |
| **PKCS#11 Coverage** | Full operation coverage including v3.1+ KEMs and streaming MAC |
| **Post-Quantum Ready** | PQ as a property (not a scope), plus hybrid compositions |
| **Security** | Server-side keys, AEAD authentication, two-policy architecture, auditable lifecycle |
| **Long-Term Compatibility** | `api_version` in `OperationMetadata` for artifact migration |

This design ensures that applications built on this API can adapt to future cryptographic requirements without code changes, while maintaining a strong security and compliance posture.
