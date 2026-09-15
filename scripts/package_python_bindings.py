#!/usr/bin/env python3
"""Assemble raw protoc output into the citius-api-python distribution tree."""

from __future__ import annotations

import argparse
import re
import shutil
from pathlib import Path


PACKAGE_NAME = "citius_api"
GENERATED_IMPORT = re.compile(
    r"^(from) (buf(?:\.[a-zA-Z0-9_]+)*|messages|services|types)( import )", re.MULTILINE
)
PROTOBUF_RUNTIME = re.compile(
    r"_runtime_version\.Domain\.PUBLIC,\s*([0-9]+),\s*([0-9]+),\s*([0-9]+),",
    re.MULTILINE,
)
PEP440_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?"
    r"(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[.-][a-z0-9]+)*)?$"
)


def rewrite_imports(source: str) -> str:
    """Place generated sibling imports beneath the citius_api namespace."""
    return GENERATED_IMPORT.sub(rf"\1 {PACKAGE_NAME}.\2\3", source)


def assemble(
    generated_dir: Path, output_dir: Path, license_file: Path, version: str, source: str
) -> None:
    if not PEP440_VERSION.fullmatch(version):
        raise ValueError(f"not a PEP 440 version: {version}")
    if not generated_dir.is_dir():
        raise FileNotFoundError(f"generated bindings directory does not exist: {generated_dir}")
    if not license_file.is_file():
        raise FileNotFoundError(f"license file does not exist: {license_file}")

    generated_files = sorted(
        path for path in generated_dir.rglob("*") if path.suffix in {".py", ".pyi"}
    )
    if not generated_files:
        raise ValueError(f"no Python bindings found in {generated_dir}")

    protobuf_versions = {
        tuple(int(component) for component in match.groups())
        for source_path in generated_files
        if source_path.suffix == ".py"
        for match in PROTOBUF_RUNTIME.finditer(source_path.read_text(encoding="utf-8"))
    }
    if not protobuf_versions:
        raise ValueError("generated bindings do not declare a protobuf runtime version")
    protobuf_version = ".".join(str(component) for component in max(protobuf_versions))

    if output_dir.exists():
        raise FileExistsError(f"output directory already exists: {output_dir}")
    package_dir = output_dir / "src" / PACKAGE_NAME
    package_dir.mkdir(parents=True)

    for source_path in generated_files:
        relative_path = source_path.relative_to(generated_dir)
        if relative_path.parts[0] == "google":
            continue
        destination_path = package_dir / relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        destination_path.write_text(
            rewrite_imports(source_path.read_text(encoding="utf-8")), encoding="utf-8"
        )

    directories = [package_dir, *sorted(path for path in package_dir.rglob("*") if path.is_dir())]
    for directory in directories:
        (directory / "__init__.py").touch()
    (package_dir / "py.typed").touch()

    unresolved = []
    for generated_file in package_dir.rglob("*"):
        if generated_file.suffix not in {".py", ".pyi"}:
            continue
        if GENERATED_IMPORT.search(generated_file.read_text(encoding="utf-8")):
            unresolved.append(str(generated_file.relative_to(output_dir)))
    if unresolved:
        raise ValueError(f"un-namespaced generated imports remain: {', '.join(unresolved)}")

    (output_dir / "pyproject.toml").write_text(
        f"""[build-system]
requires = ["setuptools>=77", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "citius-api-python"
version = "{version}"
description = "Generated Python protobuf and gRPC bindings for the Citius API"
readme = "README.md"
license = "Apache-2.0"
license-files = ["LICENSE"]
requires-python = ">=3.10"
dependencies = [
  "grpcio>=1.84,<2",
  "googleapis-common-protos>=1.66,<2",
  "protobuf>={protobuf_version}",
]

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-data]
citius_api = ["py.typed", "**/*.pyi"]
""",
        encoding="utf-8",
    )
    shutil.copy2(license_file, output_dir / "LICENSE")
    (output_dir / "README.md").write_text(
        f"""# citius-api-python

Generated Python protobuf messages and gRPC service stubs for the Citius API.

This repository is generated from `{source}`. Do not edit generated files here;
make schema or generation changes in `agile-crypto/api` instead.

```python
from citius_api.services.crypto_service_pb2_grpc import CryptoServiceStub
from citius_api.messages.encryption_pb2 import EncryptRequest
```
""",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generated-dir", required=True, type=Path)
    parser.add_argument("--license-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    assemble(args.generated_dir, args.output_dir, args.license_file, args.version, args.source)


if __name__ == "__main__":
    main()
