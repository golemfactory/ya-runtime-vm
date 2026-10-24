#!/usr/bin/env python3
"""Build the Linux test workload or run native OpenVMM integration checks."""
import argparse
from collections import deque
import os
from pathlib import Path
import shutil
import subprocess
import sys

from runtime_artifacts import LINUX_TARGET, release_dir, require_static_linux, require_windows_standalone

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
PROBE = ROOT / "build/guest/vm-test-probe"
SOURCE = ROOT / "crates/runtime/tests/fixtures/vm_probe.rs"


def run_check(command, label, timeout, bundle):
    log = bundle / f"{label}.stderr.log"
    print(f"Running {label}; boot/runtime log: {log}", flush=True)
    try:
        with log.open("wb") as stderr:
            result = subprocess.run(command, stderr=stderr, timeout=timeout)
        if result.returncode == 0:
            return
        reason = f"{label} failed with exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        reason = f"{label} exceeded {timeout} seconds"
    print(f"{reason}; last log lines:", file=sys.stderr)
    with log.open(errors="replace") as stream:
        print("".join(deque(stream, maxlen=60)), file=sys.stderr, end="")
    raise SystemExit(f"Full log: {log}")


def build_probe():
    if sys.platform != "linux":
        raise SystemExit("Build the Linux probe on Linux and copy build/guest/vm-test-probe here")
    PROBE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["rustc", "--edition=2024", "--target=x86_64-unknown-linux-musl", "-O", "-C", "panic=abort", str(SOURCE), "-o", str(PROBE)], check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-probe", action="store_true")
    args = parser.parse_args()
    if args.build_probe:
        build_probe()
        return
    if sys.platform == "linux":
        build_probe()
    assets = ["vmlinuz-virt", "initramfs.cpio.gz", "self-test.gvmi", "vm-test-probe"]
    for name in assets:
        if not (ROOT / "build/guest" / name).is_file():
            raise SystemExit(f"Missing build/guest/{name}; run mise run guest-image, fetch-self-test and vm-probe-build on Linux")
    command = ["cargo", "build", "--locked", "--release", "-p", "ya-runtime-vm", "--example", "vm_smoke", "--bin", "ya-runtime-vm"]
    if sys.platform == "linux":
        command += ["--target", LINUX_TARGET]
    else:
        command += ["--target", "x86_64-pc-windows-msvc"]
    subprocess.run(command, cwd=ROOT, check=True)
    suffix = ".exe" if sys.platform == "win32" else ""
    bundle = TARGET / "vm-test"
    runtime = bundle / "runtime"
    runtime.mkdir(parents=True, exist_ok=True)
    for name in assets:
        shutil.copy2(ROOT / "build/guest" / name, runtime / name)
    for name, source in [("ya-runtime-vm", release_dir()), ("vm_smoke", release_dir() / "examples")]:
        binary = source / (name + suffix)
        if sys.platform == "linux":
            require_static_linux(binary)
        else:
            require_windows_standalone(binary)
        shutil.copy2(binary, bundle / (name + suffix))
    run_check([str(bundle / ("ya-runtime-vm" + suffix)), "test"], "self-test", 40, bundle)
    run_check([str(bundle / ("vm_smoke" + suffix)), str(PROBE), str(runtime / "self-test.gvmi")], "integration", 90, bundle)


if __name__ == "__main__":
    main()
