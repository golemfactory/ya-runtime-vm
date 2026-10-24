#!/usr/bin/env python3
"""Package the native host runtime and the shared Linux guest assets."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tomllib

from runtime_artifacts import release_dir, require_static_linux, require_windows_standalone

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--version")
args = parser.parse_args()
version = tomllib.loads((root / "crates/runtime/Cargo.toml").read_text())["package"]["version"]
label = args.version or f"v{version}"
if not label or any(c in label for c in "/\\") or label in (".", ".."):
    raise SystemExit("Invalid package version")
windows = sys.platform == "win32"
platform = "windows" if windows else "linux"
executable = "ya-runtime-vm.exe" if windows else "ya-runtime-vm"
dest = root / "releases" / f"ya-runtime-vm-{platform}-{label}"
assets = dest / "ya-runtime-vm/runtime"
assets.mkdir(parents=True, exist_ok=True)
binary = release_dir() / executable
if windows:
    require_windows_standalone(binary)
else:
    require_static_linux(binary)
shutil.copy2(binary, dest / "ya-runtime-vm" / executable)
for name in ("vmlinuz-virt", "initramfs.cpio.gz"):
    shutil.copy2(root / "build/guest" / name, assets / name)
shutil.copy2(root / "build/guest/self-test.gvmi", assets / "self-test.gvmi")
licenses = dest / "licenses"
licenses.mkdir(exist_ok=True)
shutil.copy2(root / "LICENSE", licenses / "ya-runtime-vm-GPL-3.0.txt")
shutil.copy2(root / "third_party/fuse/LICENSE", licenses / "OpenVMM-MIT.txt")
descriptors = json.loads((root / "packaging/ya-runtime-vm.json").read_text())
for descriptor in descriptors:
    if descriptor["name"] == "vm":
        descriptor["version"] = version
        descriptor["runtime-path"] = f"ya-runtime-vm/{executable}"
        if windows:
            descriptor["supervisor-path"] = "exe-unit.exe"
(dest / "ya-runtime-vm.json").write_text(json.dumps(descriptors, indent=2) + "\n")
archive = Path(shutil.make_archive(str(dest), "zip" if windows else "gztar", dest.parent, dest.name))
archive.with_name(archive.name + ".sha256").write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")
print(archive)
