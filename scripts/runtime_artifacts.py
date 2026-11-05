"""Locations and link checks shared by native packaging and VM validation."""
import os
from pathlib import Path
import struct
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
LINUX_TARGET = "x86_64-unknown-linux-musl"


def release_dir():
    if sys.platform == "linux":
        return TARGET / LINUX_TARGET / "release"
    return TARGET / "x86_64-pc-windows-msvc" / "release"


def require_static_linux(path):
    """Reject GNU/dynamic host artifacts before they can be tested or shipped."""
    binary = Path(path).read_bytes()
    if len(binary) < 64 or binary[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", binary, 18)[0] != 62:
        raise SystemExit(f"Expected a Linux x86_64 ELF: {path}")
    offset = struct.unpack_from("<Q", binary, 32)[0]
    entry_size, count = struct.unpack_from("<HH", binary, 54)
    if entry_size < 56 or offset + entry_size * count > len(binary):
        raise SystemExit(f"Invalid ELF program headers: {path}")
    for index in range(count):
        header = offset + index * entry_size
        kind = struct.unpack_from("<I", binary, header)[0]
        if kind == 3:
            raise SystemExit(f"Dynamic ELF interpreter in {path}; rebuild with mise run build-release")
        if kind == 2:
            start = struct.unpack_from("<Q", binary, header + 8)[0]
            size = struct.unpack_from("<Q", binary, header + 32)[0]
            if start + size > len(binary) or size % 16:
                raise SystemExit(f"Invalid ELF dynamic table: {path}")
            for item in range(start, start + size, 16):
                tag = struct.unpack_from("<q", binary, item)[0]
                if tag == 0:
                    break
                if tag == 1:
                    raise SystemExit(f"Shared-library dependency in {path}; expected static musl")


def require_windows_standalone(path):
    """Check the native MSVC build in its developer environment before shipping."""
    output = subprocess.check_output(["dumpbin", "/DEPENDENTS", str(path)], text=True, errors="replace")
    libraries = re.findall(r"^\s*([A-Za-z0-9_.+-]+\.dll)\s*$", output, flags=re.IGNORECASE | re.MULTILINE)
    forbidden = [name for name in libraries if re.match(
        r"(?:vcruntime[0-9]|msvcp[0-9]|concrt[0-9]|libssl|libcrypto|libgcc|libstdc|symcrypt)",
        name, flags=re.IGNORECASE)]
    if forbidden:
        raise SystemExit(f"Additional runtime DLLs in {path}: {', '.join(forbidden)}")
    if not libraries:
        raise SystemExit(f"Could not read PE dependencies from {path}")
