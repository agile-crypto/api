# Cryptographic Key Creation: From Primitives to Intent-Based Agility

## 1. Introduction

Cryptographic agility requires that algorithms can be changed without modifying application code. Key creation presents the central challenge in achieving this goal, because creating a key necessarily requires specifying what the key is for. The specification must carry enough meaning for the system to select an appropriate algorithm, yet it must not carry so much specificity that changing the algorithm requires changing the specification. If an application requests "an AES-256-GCM key," the request is precise but brittle: migrating to ChaCha20-Poly1305 or a post-quantum algorithm demands a code change at every creation site. If an application requests simply "an encryption key," the request is stable but ambiguous: the system cannot distinguish whether the application needs authenticated encryption, deterministic encryption, or asymmetric encryption, and selecting the wrong variant may silently compromise security guarantees.

The problem, therefore, is one of abstraction granularity. The vocabulary used to express cryptographic intent at key creation must be narrow enough to guarantee well-defined security properties and a consistent operational interface, yet broad enough to admit multiple algorithms so that substitution remains transparent. This document examines how cryptographic primitives provide the foundation for such a vocabulary, why primitives alone are insufficient due to operational parameter inconsistency, and how subdividing primitives into scopes defined by their operational interface resolves the tension, yielding a stable, intent-based abstraction that enables true cryptographic agility.

## 2. Cryptographic Primitives as Security Contracts

A cryptographic primitive defines a contract of security properties that every conforming algorithm must satisfy. The primitive AEAD (Authenticated Encryption with Associated Data), for example, guarantees confidentiality, integrity, and authenticity; any algorithm assigned to this primitive, whether AES-256-GCM or ChaCha20-Poly1305, provides exactly these properties. This invariant is what makes the primitive a meaningful unit of abstraction: selecting a primitive is equivalent to selecting a set of security guarantees, independent of the algorithm that ultimately fulfils them.

This observation aligns with industry practice. Google Tink organises its API around primitives such as `Aead`, `Mac`, and `PublicKeySign`, each representing a security contract rather than an algorithm. CycloneDX defines a parallel taxonomy (`ae`, `mac`, `signature`, `kem`) for cryptographic bill-of-materials generation. Both systems recognise that primitives, not algorithms, constitute the stable vocabulary for expressing cryptographic intent.

A primitive-based design satisfies several desirable properties simultaneously. Primitives are stable across algorithm changes, since adding ML-KEM-768 does not alter the definition of key encapsulation. Primitives are orthogonal, since each captures a distinct combination of security properties. And primitives are sufficiently specific for policy-driven algorithm selection, since a policy engine that knows the application requires AEAD can restrict candidates to algorithms providing the requisite security guarantees.

## 3. The Need for Scopes Within Primitives

Primitives alone, however, are insufficient as the sole unit of API abstraction. The difficulty arises from operational parameter inconsistency: algorithms within the same primitive may require different inputs from the application, and substituting one algorithm for another can therefore break application code.

Consider the digital signature primitive. Ed25519 requires only a message and a key. Ed25519ctx additionally requires a context string for domain separation. ML-DSA supports an optional context parameter whose presence changes the verification interface. If a policy engine substitutes Ed25519ctx for Ed25519 within a single "digital signature" abstraction, the application must suddenly provide a context parameter it was not designed to supply. The algorithm change, which the abstraction was meant to hide, has leaked through to the application interface.

A similar problem arises within authenticated encryption. AES-GCM requires a nonce and optional associated data. AES-XTS, used for disk encryption, requires a tweak parameter that encodes sector information. Both algorithms satisfy the AEAD security contract, but they present incompatible operational interfaces. Grouping them under a single scope creates a substitution hazard: policy cannot swap one for the other without requiring application code changes.

This tension reveals a design principle that pure primitive-based abstraction overlooks. For cryptographic agility to hold, it is not sufficient that substituted algorithms provide the same security properties; they must also accept the same operational parameters from the application. Security property equivalence is necessary but not sufficient; operational interface equivalence is the additional constraint.

## 4. Scope as Operational Interface

The resolution is to subdivide primitives into scopes, where each scope groups algorithms that share both the same security properties (inherited from the primitive) and the same operational parameters. A scope therefore defines the complete contract between the application and the cryptographic system: the security guarantees the application receives, and the inputs the application must provide.

Under this design, the digital signature primitive yields four scopes:

| Scope | Required Input | Example Algorithms |
|-------|---------------|-------------------|
| `SIGNATURE` | message | Ed25519, ECDSA-P256, RSA-PSS |
| `SIGNATURE_WITH_CONTEXT` | message, context | Ed25519ctx, ML-DSA |
| `SIGNATURE_PREHASHED` | digest, hash OID | Ed25519ph |
| `SIGNATURE_PREHASHED_WITH_CONTEXT` | digest, context, hash OID | ML-DSA (prehash mode) |

Within each scope, every algorithm accepts identical parameters. Policy can substitute Ed25519 for ECDSA-P256 within `SIGNATURE`, or Ed25519ctx for ML-DSA within `SIGNATURE_WITH_CONTEXT`, without any change to application code. The scope boundary is drawn precisely where operational parameters diverge.

The same principle applies to authenticated encryption. Standard AEAD (AES-GCM, ChaCha20-Poly1305) forms one scope requiring plaintext and optional nonce and associated data. Tweakable AEAD (AES-XTS) forms a separate scope requiring plaintext and a tweak. Deterministic AEAD (AES-SIV) forms a third scope where identical plaintexts produce identical ciphertexts. Each scope inherits the security properties of the AEAD primitive while guaranteeing a consistent operational interface.

## 5. Scope as Intent

A scope, defined by its operational parameters, simultaneously serves as an expression of developer intent. When an application selects `SCOPE_AEAD`, it declares: "I will provide plaintext and optional associated data; I require confidentiality, integrity, and authenticity in return." This declaration is complete. The application has specified what it can provide (parameters) and what it needs (security properties), without naming any algorithm.

This framing resolves the tension between abstraction granularity that plagues alternative designs. Scopes that are too broad (such as a single `ENCRYPTION` scope encompassing symmetric ciphers, AEAD, and hybrid encryption) fail because they cannot guarantee consistent security properties or operational parameters. A policy engine selecting AES-CBC under an `ENCRYPTION` scope would provide confidentiality without integrity, silently degrading the security contract. Scopes that are too narrow (such as `AES_256_GCM_SCOPE`) eliminate the abstraction benefit entirely, since only one algorithm can satisfy them, and any algorithm change requires a scope change and therefore a code change.

Primitive-derived scopes occupy the precise middle ground. They are narrow enough to guarantee both security properties and parameter consistency, yet broad enough to admit multiple algorithms, which is the precondition for agility. The scope boundary is not arbitrary; it is determined by the operational interface, which is an objective, verifiable criterion.

## 6. Properties as Orthogonal Filters

Within a scope, algorithms may differ in characteristics that do not affect the operational interface but are nonetheless important for selection. Ed25519 produces deterministic signatures; ECDSA does not. ECDSA signatures are malleable; Ed25519 signatures are not. These differences do not change what parameters the application provides, but they may matter for correctness (blockchain transactions require non-malleable signatures) or compliance (FIPS environments require approved algorithms).

The design captures these differences as filter properties specified alongside the scope:

```
CreateKey(
  scope = SCOPE_SIGNATURE,
  required_properties = {non_malleable: true, security_strength: "128-bit"}
)
```

This request expresses: "I need a signature algorithm with a standard signing interface, and among those, I require non-malleability and at least 128-bit security." The scope constrains the operational interface; the properties constrain the algorithm selection within that interface. Policy can further narrow the selection based on organisational rules (such as FIPS approval or quantum safety), producing a final algorithm choice that satisfies the scope contract, the application's property requirements, and the organisation's governance constraints.

The critical distinction is between properties that vary across algorithms within a scope (and are therefore meaningful as filters) and properties that are invariant within a scope (and are therefore informational). All algorithms in the `SIGNATURE` scope provide EUF-CMA security; filtering by this property is vacuous. All algorithms in the `AEAD` scope provide IND-CCA2 security; requesting it adds no information. These invariant properties belong in documentation and audit metadata, not in selection criteria.

## 7. Agility Through Scope Stability

The architectural consequence of this design is that cryptographic agility reduces to algorithm substitution within a scope. Because all algorithms in a scope share the same operational parameters and security properties, substitution is transparent to the application. Adding a new post-quantum signature algorithm (such as ML-DSA) to the `SIGNATURE_WITH_CONTEXT` scope requires no changes to applications that already use that scope. Deprecating an algorithm (such as RSA-PKCS1v1.5) removes it from consideration without affecting the scope definition or any application interface.

This stability extends to the policy layer. A policy that maps `SCOPE_SIGNATURE` to Ed25519 today can be updated to map it to a post-quantum algorithm tomorrow. The application code, which expresses intent through scope selection and property requirements, remains unchanged. The migration is an administrative action rather than a development project, which is precisely the definition of cryptographic agility.
