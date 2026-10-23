#!/usr/bin/env python3
"""Synchronize the packaged runtime descriptor with its Cargo package version."""

import json
from pathlib import Path
import tomllib


def main():
    root = Path(__file__).resolve().parents[2]
    with (root / "runtime/Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    descriptor_path = root / "runtime/conf/ya-runtime-vm.json"
    descriptors = json.loads(descriptor_path.read_text())
    runtime = next(item for item in descriptors if item["name"] == "vm")
    runtime["version"] = version
    descriptor_path.write_text(json.dumps(descriptors, indent=2) + "\n")
    print(f"Runtime descriptor version: {version}")


if __name__ == "__main__":
    main()
