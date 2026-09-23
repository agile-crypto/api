#!/usr/bin/env python3
"""Populate derived metadata in proto/standard_algorithms.json deterministically."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "proto" / "standard_algorithms.json"

FAMILY_BY_KIND = {
    "aesGcm": "AES",
    "aesCbc": "AES",
    "aesCtr": "AES",
    "aesXts": "AES",
    "aesKeyWrap": "AES",
    "chacha20Poly1305": "ChaCha20",
    "ecdsa": "ECDSA",
    "ed25519": "EdDSA",
    "ed448": "EdDSA",
    "rsaPss": "RSASSA-PSS",
    "rsaPkcs1v15": "RSASSA-PKCS1",
    "rsaOaep": "RSAES-OAEP",
    "mlDsa": "ML-DSA",
    "slhDsa": "SLH-DSA",
    "mlKem": "ML-KEM",
    "ecdh": "ECDH",
    "x25519": "ECDH",
    "x448": "ECDH",
    "hkdf": "HKDF",
    "pbkdf2": "PBKDF2",
    "hmac": "HMAC",
    "kmac": "KMAC",
}

PRIMITIVE = {
    "CRYPTO_PRIMITIVE_MAC": "mac",
    "CRYPTO_PRIMITIVE_BLOCK_CIPHER": "block-cipher",
    "CRYPTO_PRIMITIVE_STREAM_CIPHER": "stream-cipher",
    "CRYPTO_PRIMITIVE_SIGNATURE": "signature",
    "CRYPTO_PRIMITIVE_KDF": "kdf",
    "CRYPTO_PRIMITIVE_KEY_AGREE": "key-agree",
    "CRYPTO_PRIMITIVE_KEM": "kem",
    "CRYPTO_PRIMITIVE_AE": "ae",
    "CRYPTO_PRIMITIVE_COMBINER": "combiner",
    "CRYPTO_PRIMITIVE_KEY_WRAP": "key-wrap",
}

FUNCTION = {
    "CRYPTO_OPERATION_ENCRYPT": "encrypt",
    "CRYPTO_OPERATION_DECRYPT": "decrypt",
    "CRYPTO_OPERATION_SIGN": "sign",
    "CRYPTO_OPERATION_VERIFY": "verify",
    "CRYPTO_OPERATION_DIGEST_SIGN": "sign",
    "CRYPTO_OPERATION_DIGEST_VERIFY": "verify",
    "CRYPTO_OPERATION_ENCAPSULATE": "encapsulate",
    "CRYPTO_OPERATION_DECAPSULATE": "decapsulate",
    "CRYPTO_OPERATION_KEY_AGREEMENT": "keyderive",
    "CRYPTO_OPERATION_DERIVE_KEY": "keyderive",
    "CRYPTO_OPERATION_WRAP_KEY": "encrypt",
    "CRYPTO_OPERATION_UNWRAP_KEY": "decrypt",
    "CRYPTO_OPERATION_GENERATE_MAC": "tag",
    "CRYPTO_OPERATION_VERIFY_MAC": "verify",
}

CURVE = {
    "ELLIPTIC_CURVE_P256": "nist/P-256",
    "ELLIPTIC_CURVE_P384": "nist/P-384",
    "ELLIPTIC_CURVE_P521": "nist/P-521",
    "ELLIPTIC_CURVE_SECP256K1": "secg/secp256k1",
}

HASH = {
    "HASH_ALGORITHM_SHA256": "SHA-256",
    "HASH_ALGORITHM_SHA384": "SHA-384",
    "HASH_ALGORITHM_SHA512": "SHA-512",
    "HASH_ALGORITHM_SHA3_256": "SHA3-256",
}

DISPLAY_NAME = {
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
    "SHA-3": "Secure Hash Algorithm 3",
    "SLH-DSA": "Stateless Hash-Based Digital Signature Algorithm",
}

DEFAULT_TEMPLATE = {
    "AES": "aes-256-gcm-128-96",
    "ChaCha20": "chacha20-poly1305",
    "ECDH": "x25519",
    "ECDSA": "ecdsa-p256-sha256-der",
    "EdDSA": "ed25519",
    "HKDF": "hkdf-sha256",
    "HMAC": "hmac-sha256-256",
    "KMAC": "kmac128-256",
    "ML-DSA": "ml-dsa-65",
    "ML-KEM": "ml-kem-768",
    "PBKDF2": "pbkdf2-sha256-600000-32",
    "RSASSA-PKCS1": "rsa-pkcs1v15-sha256-2048",
    "RSASSA-PSS": "rsa-pss-sha256-mgf1-32-3072",
    "SHA-3": "kmac128-256",
    "SLH-DSA": "slh-dsa-sha2-128s",
}


def algorithm_kind(algorithm: dict[str, Any]) -> str:
    kinds = [key for key in algorithm if key not in {"oid", "primitive"}]
    if len(kinds) != 1:
        raise ValueError(f"expected one typed algorithm, found {kinds}")
    return kinds[0]


def security(template: dict[str, Any]) -> tuple[int, int]:
    classical = 0
    quantum = 0
    for capability in template["scopedCapabilities"]:
        scope = next(iter(capability["scope"].values()))
        properties = scope.get("security", {})
        classical = max(classical, properties.get("securityStrengthBits", 0))
        level = properties.get("nistSecurityLevel", "NIST_SECURITY_LEVEL_UNSPECIFIED")
        if level.startswith("NIST_SECURITY_LEVEL_"):
            suffix = level.removeprefix("NIST_SECURITY_LEVEL_")
            quantum = max(quantum, int(suffix) if suffix.isdigit() else 0)
    return classical, quantum


def functions(template: dict[str, Any]) -> list[str]:
    result = {
        FUNCTION[operation]
        for capability in template["scopedCapabilities"]
        for operation in capability["operations"]
        if operation in FUNCTION
    }
    return sorted(result)


def parameter_set(kind: str, params: dict[str, Any], template_id: str) -> str:
    if "keySizeBits" in params:
        return str(params["keySizeBits"])
    if kind in {"mlDsa", "mlKem"}:
        return params["parameterSet"].rsplit("_", 1)[-1]
    if kind == "slhDsa":
        hash_name = params["hashType"].removeprefix("SLH_DSA_")
        set_name = params["parameterSet"].removeprefix("SLH_DSA_")
        return f"{hash_name}-{set_name}"
    if kind in {"hkdf", "hmac"}:
        return HASH[params["hash"]]
    if kind == "pbkdf2":
        return f'{HASH[params["hash"]]}-{params["iterations"]}-{params["outputLength"]}'
    if kind == "argon2":
        variant = params["variant"].removeprefix("ARGON2_VARIANT_").lower()
        return f'{variant}-{params["memoryKib"]}-{params["iterations"]}-{params["parallelism"]}'
    if kind == "kmac":
        return f'{params["variant"]}-{params["outputBits"]}'
    if kind == "chacha20Poly1305":
        return "256"
    if kind == "hybrid":
        return template_id.removeprefix("hybrid-").removesuffix("-concat").upper()
    return ""


def family_for(kind: str) -> str | None:
    """Return only exact CycloneDX 1.7 algorithmFamiliesEnum values."""
    return FAMILY_BY_KIND.get(kind)


def key_material_family(kind: str) -> str:
    if kind in {"aesGcm", "aesCbc", "aesCtr", "aesKeyWrap"}:
        return "AES"
    if kind == "aesXts":
        return "AES-XTS"
    return {
        "chacha20Poly1305": "ChaCha20",
        "ecdsa": "ECDSA",
        "ed25519": "Ed25519",
        "ed448": "Ed448",
        "rsaPss": "RSA",
        "rsaPkcs1v15": "RSA",
        "rsaOaep": "RSA",
        "mlDsa": "ML-DSA",
        "slhDsa": "SLH-DSA",
        "mlKem": "ML-KEM",
        "ecdh": "ECDH",
        "x25519": "X25519",
        "x448": "X448",
        "hmac": "HMAC",
        "kmac": "KMAC",
    }.get(kind, "")


def metadata(template_id: str, template: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    algorithm = template["algorithm"]
    kind = algorithm_kind(algorithm)
    params = algorithm[kind]
    family = family_for(kind)
    classical, quantum = security(template)
    value: dict[str, Any] = {
        "name": template["displayName"],
        "primitive": PRIMITIVE[algorithm["primitive"]],
    }
    if family:
        value["algorithmFamily"] = family
    parameter = parameter_set(kind, params, template_id)
    if parameter:
        value["parameterSetIdentifier"] = parameter
    if kind == "ecdsa":
        value["ellipticCurve"] = CURVE[params["curve"]]
    elif kind == "ed25519":
        value["ellipticCurve"] = "other/Ed25519"
    elif kind == "ed448":
        value["ellipticCurve"] = "other/Ed448"
    elif kind == "x25519":
        value["ellipticCurve"] = "other/Curve25519"
    elif kind == "x448":
        value["ellipticCurve"] = "other/Curve448"
    if kind in {"aesGcm", "aesCbc", "aesCtr"}:
        value["mode"] = kind.removeprefix("aes").lower()
    if kind == "aesXts":
        value["mode"] = "other"
    if kind == "aesCbc":
        value["padding"] = "pkcs7"
    elif kind == "aesKeyWrap":
        value["padding"] = "other" if params["withPadding"] else "raw"
    elif kind == "rsaPkcs1v15":
        value["padding"] = "pkcs1v15"
    elif kind == "rsaOaep":
        value["padding"] = "oaep"
    elif kind == "rsaPss":
        value["padding"] = "other"
    value["cryptoFunctions"] = functions(template)
    # KDF/password output sizes, hybrid combiners, and variable retained MAC
    # keys do not support a defensible template-level security projection.
    if kind not in {"hkdf", "pbkdf2", "argon2", "hybrid", "hmac", "kmac"}:
        if classical:
            value["classicalSecurityLevel"] = classical
        if quantum:
            value["nistQuantumSecurityLevel"] = quantum
    if algorithm.get("oid"):
        value["oid"] = algorithm["oid"]
    return family, value


def main() -> None:
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    catalog["version"] = "0.2.0"
    catalog["lastUpdated"] = "2026-09-23T00:00:00Z"
    grouped: dict[str, list[str]] = {}
    for template_id, template in catalog["templates"].items():
        family, template["cyclonedx"] = metadata(template_id, template)
        material_family = key_material_family(algorithm_kind(template["algorithm"]))
        if material_family:
            template["keyMaterialFamily"] = material_family
        else:
            template.pop("keyMaterialFamily", None)
        if family:
            grouped.setdefault(family, []).append(template_id)

    families = []
    for family in sorted(grouped):
        template_ids = grouped[family]
        templates = [catalog["templates"][template_id] for template_id in template_ids]
        primitives = {template["cyclonedx"]["primitive"] for template in templates}
        strengths = [security(template)[0] for template in templates if security(template)[0]]
        families.append(
            {
                "family": family,
                "displayName": DISPLAY_NAME[family],
                "description": f"CycloneDX {family} algorithm family represented by this catalog.",
                "primitive": next(iter(primitives)) if len(primitives) == 1 else "other",
                "standards": sorted({standard for template in templates for standard in template["standards"]}),
                "templateIds": template_ids,
                "defaultTemplateId": DEFAULT_TEMPLATE[family],
                "hasPqcVariants": any(security(template)[1] for template in templates),
                "minSecurityLevel": min(strengths) if strengths else 0,
            }
        )
    catalog["families"] = families
    CATALOG_PATH.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()