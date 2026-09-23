#!/usr/bin/env python3

import copy
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import validate_standard_algorithms as validator


# Independent fixtures: one representative for every production algorithm kind.
REPRESENTATIVE_FAMILIES = {
    "aesGcm": "AES", "aesCbc": "AES", "aesCtr": "AES",
    "aesKeyWrap": "AES", "chacha20Poly1305": "ChaCha20", "ecdsa": "ECDSA",
    "ed25519": "EdDSA", "ed448": "EdDSA", "rsaPss": "RSASSA-PSS",
    "rsaPkcs1v15": "RSASSA-PKCS1",
    "mlDsa": "ML-DSA", "slhDsa": "SLH-DSA", "mlKem": "ML-KEM",
    "x25519": "ECDH", "x448": "ECDH", "hkdf": "HKDF",
    "pbkdf2": "PBKDF2", "hmac": "HMAC", "kmac": "KMAC",
    "argon2": None, "hybrid": None,
}


class StandardAlgorithmCatalogTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = json.loads(validator.DEFAULT_CATALOG.read_text(encoding="utf-8"))

    def test_catalog_is_semantically_valid(self) -> None:
        self.assertEqual([], validator.validate(self.catalog))

    def test_official_family_set_has_kmac_but_not_argon2(self) -> None:
        self.assertIn("KMAC", validator.CYCLONEDX_FAMILIES)
        self.assertNotIn("Argon2", validator.CYCLONEDX_FAMILIES)
        self.assertNotIn("CTR_DRBG", validator.CYCLONEDX_FAMILIES)

    def test_every_production_kind_has_independent_expected_family(self) -> None:
        production_kinds = {
            next(key for key in template["algorithm"] if key not in {"oid", "primitive"})
            for template in self.catalog["templates"].values()
        }
        self.assertEqual(set(REPRESENTATIVE_FAMILIES), production_kinds)
        self.assertEqual(
            REPRESENTATIVE_FAMILIES,
            {kind: validator.CYCLONEDX_FAMILY_BY_KIND[kind] for kind in production_kinds},
        )

    def test_rejects_wrong_family_for_every_algorithm_kind(self) -> None:
        representatives = {}
        for template_id, template in self.catalog["templates"].items():
            kind = next(key for key in template["algorithm"] if key not in {"oid", "primitive"})
            representatives.setdefault(kind, template_id)
        for kind, template_id in representatives.items():
            with self.subTest(kind=kind):
                catalog = copy.deepcopy(self.catalog)
                expected = REPRESENTATIVE_FAMILIES[kind]
                wrong = "AES" if expected != "AES" else "KMAC"
                catalog["templates"][template_id]["cyclonedx"]["algorithmFamily"] = wrong
                self.assertTrue(any("algorithmFamily for" in error for error in validator.validate(catalog)))

    def test_rejects_key_family_missing_on_retained_material_template(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        del catalog["templates"]["hmac-sha256-256"]["keyMaterialFamily"]
        self.assertTrue(any("retained-material" in error for error in validator.validate(catalog)))

    def test_rejects_key_family_on_kdf(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["templates"]["hkdf-sha256"]["keyMaterialFamily"] = "HMAC"
        self.assertTrue(any("must not declare" in error for error in validator.validate(catalog)))

    def test_rejects_security_claim_for_password_template(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        catalog["templates"]["argon2id-65536-3-4"]["cyclonedx"]["classicalSecurityLevel"] = 256
        self.assertTrue(any("not defensible" in error for error in validator.validate(catalog)))

    def test_rejects_stale_generated_metadata(self) -> None:
        catalog = copy.deepcopy(self.catalog)
        del catalog["templates"]["aes-256-gcm-128-96"]["cyclonedx"]["mode"]
        self.assertTrue(any("stale" in error for error in validator.validate(catalog)))

    def test_rejects_every_mutated_family_field(self) -> None:
        mutations = {
            "displayName": "Wrong name",
            "description": "Wrong description",
            "primitive": "unknown",
            "standards": ["Wrong standard"],
            "templateIds": ["aes-128-kw"],
            "defaultTemplateId": "aes-128-kw",
            "hasPqcVariants": True,
            "minSecurityLevel": 256,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                catalog = copy.deepcopy(self.catalog)
                catalog["families"][0][field] = value
                errors = validator.validate(catalog)
                self.assertTrue(any(f".{field}: expected" in error for error in errors), errors)

            catalog = copy.deepcopy(self.catalog)
            catalog["families"][0]["family"] = "not-a-cyclonedx-family"
            self.assertTrue(any("records do not exactly match" in error for error in validator.validate(catalog)))

            catalog = copy.deepcopy(self.catalog)
            catalog["families"][0]["hasPqcVariants"] = 0
            errors = validator.validate(catalog)
            self.assertTrue(any(".hasPqcVariants: expected" in error for error in errors), errors)

    def test_rejects_cyclonedx_curve_and_security_bounds(self) -> None:
        mutations = {
            "ellipticCurve": "not/a-registered-curve",
            "classicalSecurityLevel": -1,
            "nistQuantumSecurityLevel": 7,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                catalog = copy.deepcopy(self.catalog)
                catalog["templates"]["ecdsa-p256-sha256-der"]["cyclonedx"][field] = value
                self.assertTrue(any(field in error for error in validator.validate(catalog)))

    def test_malformed_input_returns_errors_instead_of_raising(self) -> None:
        malformed_values = [
            None,
            [],
            {"templates": [], "families": {}},
            {"templates": {"broken": {"templateId": "broken", "algorithm": []}}, "families": [None]},
            {
                "templates": {"broken": {
                    "templateId": "broken",
                    "algorithm": {"primitive": "CRYPTO_PRIMITIVE_MAC", "hmac": {}},
                    "cyclonedx": {"name": "broken", "primitive": [], "algorithmFamily": [], "cryptoFunctions": [[]]},
                }},
                "families": [{"family": []}],
            },
        ]
        for value in malformed_values:
            with self.subTest(value=value):
                self.assertTrue(validator.validate(value))

    def test_null_and_non_object_scope_arms_never_raise(self) -> None:
        malformed_scopes = [
            None,
            [],
            {},
            {"signature": None},
            {"signature": []},
            {"signature": "not-an-object"},
            {"signature": {"security": None}},
            {"signature": {"security": []}},
            {"signature": {"security": {"securityStrengthBits": []}}},
            {"signature": {"security": {"nistSecurityLevel": None}}},
            {"signature": {}, "aead": {}},
        ]
        for scope in malformed_scopes:
            with self.subTest(scope=scope):
                catalog = copy.deepcopy(self.catalog)
                catalog["templates"]["ed25519"]["scopedCapabilities"][0]["scope"] = scope
                self.assertTrue(validator.validate(catalog))


if __name__ == "__main__":
    unittest.main()