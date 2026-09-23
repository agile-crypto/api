#!/usr/bin/env python3
"""Semantically validate the standard algorithm catalog using only stdlib."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import populate_standard_algorithm_metadata as metadata_generator


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "proto" / "standard_algorithms.json"

# Exact CycloneDX 1.7 cryptography-defs.schema.json algorithmFamiliesEnum.
CYCLONEDX_FAMILIES = frozenset({
    "3DES", "3GPP-XOR", "A5/1", "A5/2", "AES", "ARIA", "Ascon", "BLAKE2",
    "BLAKE3", "BLS", "Blowfish", "CAMELLIA", "CAST5", "CAST6", "CMAC",
    "CMEA", "ChaCha", "ChaCha20", "DES", "DSA", "ECDH", "ECDSA", "ECIES",
    "EdDSA", "ElGamal", "FFDH", "Fortuna", "GOST", "HC", "HKDF", "HMAC",
    "IDEA", "IKE-PRF", "KMAC", "LMS", "MD2", "MD4", "MD5", "MILENAGE",
    "ML-DSA", "ML-KEM", "MQV", "PBES1", "PBES2", "PBKDF1", "PBKDF2",
    "PBMAC1", "Poly1305", "RABBIT", "RC2", "RC4", "RC5", "RC6", "RIPEMD",
    "RSAES-OAEP", "RSAES-PKCS1", "RSASSA-PKCS1", "RSASSA-PSS", "SEED",
    "SHA-1", "SHA-2", "SHA-3", "SLH-DSA", "SNOW3G", "SP800-108",
    "Salsa20", "Serpent", "SipHash", "Skipjack", "TUAK", "Twofish",
    "Whirlpool", "X3DH", "XMSS", "Yarrow", "ZUC", "bcrypt",
})

PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "key-wrap", "other",
    "unknown",
}
MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "other", "unknown"}
PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"}
FUNCTIONS = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
}
KEY_FAMILY_BY_KIND = {
    "aesGcm": "AES", "aesCbc": "AES", "aesCtr": "AES", "aesKeyWrap": "AES",
    "aesXts": "AES-XTS", "chacha20Poly1305": "ChaCha20", "ecdsa": "ECDSA",
    "ed25519": "Ed25519", "ed448": "Ed448", "rsaPss": "RSA",
    "rsaPkcs1v15": "RSA", "rsaOaep": "RSA", "mlDsa": "ML-DSA",
    "slhDsa": "SLH-DSA", "mlKem": "ML-KEM", "ecdh": "ECDH",
    "x25519": "X25519", "x448": "X448", "hmac": "HMAC", "kmac": "KMAC",
}
NO_KEY_FAMILY = {"hkdf", "pbkdf2", "argon2", "hybrid"}
CYCLONEDX_FAMILY_BY_KIND = {
    "aesGcm": "AES", "aesCbc": "AES", "aesCtr": "AES", "aesXts": "AES",
    "aesKeyWrap": "AES", "chacha20Poly1305": "ChaCha20", "ecdsa": "ECDSA",
    "ed25519": "EdDSA", "ed448": "EdDSA", "rsaPss": "RSASSA-PSS",
    "rsaPkcs1v15": "RSASSA-PKCS1", "rsaOaep": "RSAES-OAEP",
    "mlDsa": "ML-DSA", "slhDsa": "SLH-DSA", "mlKem": "ML-KEM",
    "ecdh": "ECDH", "x25519": "ECDH", "x448": "ECDH", "hkdf": "HKDF",
    "pbkdf2": "PBKDF2", "hmac": "HMAC", "kmac": "KMAC",
    "argon2": None, "hybrid": None,
}
SECURITY_OMITTED_KINDS = frozenset({"hkdf", "pbkdf2", "argon2", "hybrid", "hmac", "kmac"})
KEY_FAMILY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
ELLIPTIC_CURVES = frozenset({
    "nist/P-256", "nist/P-384", "nist/P-521", "secg/secp256k1",
    "other/Curve25519", "other/Curve448", "other/Ed25519", "other/Ed448",
})
PRIMITIVE_BY_KIND = {
    "aesGcm": "ae", "aesCbc": "block-cipher", "aesCtr": "stream-cipher",
    "aesXts": "block-cipher", "aesKeyWrap": "key-wrap",
    "chacha20Poly1305": "ae", "ecdsa": "signature", "ed25519": "signature",
    "ed448": "signature", "rsaPss": "signature", "rsaPkcs1v15": "signature",
    "rsaOaep": "pke", "mlDsa": "signature", "slhDsa": "signature",
    "mlKem": "kem", "ecdh": "key-agree", "x25519": "key-agree",
    "x448": "key-agree", "hkdf": "kdf", "pbkdf2": "kdf", "argon2": "kdf",
    "hmac": "mac", "kmac": "mac", "hybrid": "combiner",
}
FAMILY_DISPLAY_NAME = {
    "AES": "Advanced Encryption Standard",
    "ChaCha20": "ChaCha20",
    "ECDH": "Elliptic Curve Diffie-Hellman",
    "ECDSA": "Elliptic Curve Digital Signature Algorithm",
    "EdDSA": "Edwards-Curve Digital Signature Algorithm",
    "HKDF": "HMAC-based Extract-and-Expand Key Derivation Function",
    "HMAC": "Hash-based Message Authentication Code",
    "KMAC": "Keccak Message Authentication Code",
    "ML-DSA": "Module-Lattice-Based Digital Signature Algorithm",
    "ML-KEM": "Module-Lattice-Based Key-Encapsulation Mechanism",
    "PBKDF2": "Password-Based Key Derivation Function 2",
    "RSASSA-PKCS1": "RSA Signature Scheme with PKCS #1 v1.5",
    "RSASSA-PSS": "RSA Signature Scheme with Probabilistic Signature Scheme",
    "SLH-DSA": "Stateless Hash-Based Digital Signature Algorithm",
}
FAMILY_DEFAULT_TEMPLATE = {
    "AES": "aes-256-gcm-128-96", "ChaCha20": "chacha20-poly1305",
    "ECDH": "x25519", "ECDSA": "ecdsa-p256-sha256-der", "EdDSA": "ed25519",
    "HKDF": "hkdf-sha256", "HMAC": "hmac-sha256-256", "KMAC": "kmac128-256",
    "ML-DSA": "ml-dsa-65", "ML-KEM": "ml-kem-768",
    "PBKDF2": "pbkdf2-sha256-600000-32",
    "RSASSA-PKCS1": "rsa-pkcs1v15-sha256-2048",
    "RSASSA-PSS": "rsa-pss-sha256-mgf1-32-3072",
    "SLH-DSA": "slh-dsa-sha2-128s",
}


def algorithm_kind(template: dict[str, Any]) -> str | None:
    algorithm = template.get("algorithm")
    if not isinstance(algorithm, dict):
        return None
    kinds = [key for key in algorithm if key not in {"oid", "primitive"}]
    if len(kinds) != 1 or not isinstance(algorithm.get(kinds[0]), dict):
        return None
    return kinds[0]


def scoped_security(
    template: dict[str, Any], prefix: str, errors: list[str]
) -> tuple[list[int], bool]:
    """Validate scope containers and safely collect security projections."""
    capabilities = template.get("scopedCapabilities")
    if not isinstance(capabilities, list) or not capabilities:
        errors.append(f"{prefix}.scopedCapabilities: must be a non-empty array")
        return [], False
    strengths: list[int] = []
    has_pqc = False
    for index, capability in enumerate(capabilities):
        capability_prefix = f"{prefix}.scopedCapabilities[{index}]"
        if not isinstance(capability, dict):
            errors.append(f"{capability_prefix}: must be an object")
            continue
        scope = capability.get("scope")
        if not isinstance(scope, dict):
            errors.append(f"{capability_prefix}.scope: must be an object")
            continue
        if len(scope) != 1:
            errors.append(f"{capability_prefix}.scope: must contain exactly one scope arm")
            continue
        arm_name, arm = next(iter(scope.items()))
        if not isinstance(arm, dict):
            errors.append(f"{capability_prefix}.scope.{arm_name}: must be an object")
            continue
        security = arm.get("security", {})
        if security is None or not isinstance(security, dict):
            errors.append(f"{capability_prefix}.scope.{arm_name}.security: must be an object")
            continue
        strength = security.get("securityStrengthBits", 0)
        if isinstance(strength, bool) or not isinstance(strength, int) or not 0 <= strength <= 0xFFFFFFFF:
            errors.append(f"{capability_prefix}.scope.{arm_name}.security.securityStrengthBits: invalid uint32")
        elif strength:
            strengths.append(strength)
        level = security.get("nistSecurityLevel", "NIST_SECURITY_LEVEL_UNSPECIFIED")
        if not isinstance(level, str):
            errors.append(f"{capability_prefix}.scope.{arm_name}.security.nistSecurityLevel: must be a string")
        else:
            match = re.fullmatch(r"NIST_SECURITY_LEVEL_([1-6])", level)
            if match:
                has_pqc = True
            elif level != "NIST_SECURITY_LEVEL_UNSPECIFIED":
                errors.append(f"{capability_prefix}.scope.{arm_name}.security.nistSecurityLevel: invalid value")
    return strengths, has_pqc


def validate(catalog: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(catalog, dict):
        return ["catalog: must be an object"]
    templates = catalog.get("templates", {})
    families = catalog.get("families", [])
    if not isinstance(templates, dict):
        errors.append("templates: must be an object")
        return errors
    if not isinstance(families, list):
        errors.append("families: must be an array")
        families = []

    valid_templates: dict[str, tuple[dict[str, Any], dict[str, Any], str, list[int], bool]] = {}
    used_families: set[str] = set()
    for template_id, template in templates.items():
        prefix = f"templates.{template_id}"
        if not isinstance(template, dict):
            errors.append(f"{prefix}: must be an object")
            continue
        strengths, has_pqc = scoped_security(template, prefix, errors)
        if template.get("templateId") != template_id:
            errors.append(f"{prefix}: map key and templateId differ")
        kind = algorithm_kind(template)
        if kind is None:
            errors.append(f"{prefix}.algorithm: expected exactly one object-valued algorithm kind")
            continue
        cyclonedx = template.get("cyclonedx")
        if not isinstance(cyclonedx, dict):
            errors.append(f"{prefix}: cyclonedx metadata is required")
            continue
        for field in ("name", "primitive", "cryptoFunctions"):
            if not cyclonedx.get(field):
                errors.append(f"{prefix}.cyclonedx.{field}: required")
        if not isinstance(cyclonedx.get("primitive"), str) or cyclonedx.get("primitive") not in PRIMITIVES:
            errors.append(f"{prefix}: invalid CycloneDX primitive")
        family = cyclonedx.get("algorithmFamily")
        if family is not None and (not isinstance(family, str) or family not in CYCLONEDX_FAMILIES):
            errors.append(f"{prefix}: non-standard CycloneDX algorithmFamily")
        expected_family = CYCLONEDX_FAMILY_BY_KIND.get(kind)
        if kind not in CYCLONEDX_FAMILY_BY_KIND:
            errors.append(f"{prefix}: no CycloneDX family policy for algorithm kind {kind}")
        elif expected_family != family:
            errors.append(
                f"{prefix}: algorithmFamily for {kind} must be {expected_family!r}, found {family!r}"
            )
        if isinstance(family, str) and family:
            used_families.add(family)
        if "mode" in cyclonedx and (
            not isinstance(cyclonedx["mode"], str) or cyclonedx["mode"] not in MODES
        ):
            errors.append(f"{prefix}: invalid CycloneDX mode")
        if "padding" in cyclonedx and (
            not isinstance(cyclonedx["padding"], str) or cyclonedx["padding"] not in PADDINGS
        ):
            errors.append(f"{prefix}: invalid CycloneDX padding")
        curve = cyclonedx.get("ellipticCurve")
        if curve is not None and (not isinstance(curve, str) or curve not in ELLIPTIC_CURVES):
            errors.append(f"{prefix}: invalid CycloneDX ellipticCurve")
        classical = cyclonedx.get("classicalSecurityLevel")
        if classical is not None and (
            isinstance(classical, bool) or not isinstance(classical, int) or not 0 <= classical <= 0xFFFFFFFF
        ):
            errors.append(f"{prefix}: invalid CycloneDX classicalSecurityLevel")
        quantum = cyclonedx.get("nistQuantumSecurityLevel")
        if quantum is not None and (
            isinstance(quantum, bool) or not isinstance(quantum, int) or not 0 <= quantum <= 6
        ):
            errors.append(f"{prefix}: invalid CycloneDX nistQuantumSecurityLevel")
        crypto_functions = cyclonedx.get("cryptoFunctions", [])
        if not isinstance(crypto_functions, list) or any(
            not isinstance(value, str) or value not in FUNCTIONS for value in crypto_functions
        ):
            errors.append(f"{prefix}: invalid CycloneDX cryptoFunctions")
        algorithm_oid = template["algorithm"].get("oid")
        if algorithm_oid and cyclonedx.get("oid") != algorithm_oid:
            errors.append(f"{prefix}: algorithm and CycloneDX OIDs differ")
        if kind in SECURITY_OMITTED_KINDS and any(
            field in cyclonedx for field in ("classicalSecurityLevel", "nistQuantumSecurityLevel")
        ):
            errors.append(f"{prefix}: security levels are not defensible for {kind}")
        expected_key_family = KEY_FAMILY_BY_KIND.get(kind)
        actual_key_family = template.get("keyMaterialFamily")
        if expected_key_family is not None and expected_key_family != actual_key_family:
            errors.append(
                f"{prefix}: retained-material kind {kind} requires keyMaterialFamily {expected_key_family!r}, "
                f"found {actual_key_family!r}"
            )
        if kind in NO_KEY_FAMILY and actual_key_family is not None:
            errors.append(f"{prefix}: {kind} must not declare keyMaterialFamily")
        if actual_key_family is not None and (
            not isinstance(actual_key_family, str) or not KEY_FAMILY_PATTERN.fullmatch(actual_key_family)
        ):
            errors.append(f"{prefix}: invalid keyMaterialFamily syntax")
        valid_templates[template_id] = (template, cyclonedx, kind, strengths, has_pqc)

    valid_family_records = [family for family in families if isinstance(family, dict)]
    if len(valid_family_records) != len(families):
        errors.append("families: every record must be an object")
    family_names = [family.get("family") for family in valid_family_records]
    invalid_family_names = [name for name in family_names if not isinstance(name, str) or not name]
    if invalid_family_names:
        errors.append("families: every family name must be a non-empty string")
    family_names = [name for name in family_names if isinstance(name, str) and name]
    if len(family_names) != len(set(family_names)):
        errors.append("families: duplicate family records")
    if set(family_names) != used_families:
        errors.append("families: records do not exactly match template algorithmFamily values")
    for family in valid_family_records:
        name = family.get("family")
        prefix = f"families.{name}"
        if not isinstance(name, str) or not name:
            continue
        members = [
            (template_id, values) for template_id, values in valid_templates.items()
            if values[1].get("algorithmFamily") == name
        ]
        expected_ids = [template_id for template_id, _ in members]
        expected_standards_set: set[str] = set()
        for _, (template, _, _, _, _) in members:
            template_standards = template.get("standards", [])
            if not isinstance(template_standards, list):
                errors.append(f"{prefix}.standards: member template standards must be arrays")
                continue
            expected_standards_set.update(
                standard for standard in template_standards
                if isinstance(standard, str) and standard
            )
        expected_standards = sorted(expected_standards_set)
        expected_primitives = {PRIMITIVE_BY_KIND.get(values[2]) for _, values in members}
        expected_strengths = [strength for _, values in members for strength in values[3]]
        expected_fields: dict[str, Any] = {
            "displayName": FAMILY_DISPLAY_NAME.get(name),
            "description": f"CycloneDX {name} algorithm family represented by this catalog.",
            "primitive": next(iter(expected_primitives)) if len(expected_primitives) == 1 else "other",
            "standards": expected_standards,
            "templateIds": expected_ids,
            "defaultTemplateId": FAMILY_DEFAULT_TEMPLATE.get(name),
            "hasPqcVariants": any(values[4] for _, values in members),
            "minSecurityLevel": min(expected_strengths) if expected_strengths else 0,
        }
        for field, expected in expected_fields.items():
            if expected is None:
                errors.append(f"{prefix}.{field}: no independent family policy")
            else:
                actual = family.get(field)
                if type(actual) is not type(expected) or actual != expected:
                    errors.append(f"{prefix}.{field}: expected {expected!r}, found {actual!r}")

    # Deterministic generation detects stale data only. Independent policy
    # checks above run first, avoiding circular correctness.
    for template_id, (template, cyclonedx, _, _, _) in valid_templates.items():
        try:
            _, expected_cyclonedx = metadata_generator.metadata(template_id, template)
        except Exception as error:
            # The input is untrusted JSON. Generation is a stale-data check, not
            # a reason malformed nested containers may terminate validation.
            errors.append(f"templates.{template_id}: metadata generation failed: {error}")
        else:
            if cyclonedx != expected_cyclonedx:
                errors.append(f"templates.{template_id}: generated CycloneDX projection is stale")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", nargs="?", type=Path, default=DEFAULT_CATALOG)
    args = parser.parse_args(argv)
    try:
        catalog = json.loads(args.catalog.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"catalog load failed: {error}", file=sys.stderr)
        return 1
    errors = validate(catalog)
    if errors:
        print("standard algorithm catalog validation failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"validated {len(catalog['templates'])} templates and {len(catalog['families'])} families")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())