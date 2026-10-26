"""Third-party license texts and source links shipped with every package."""
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/golemfactory/ya-runtime-vm"
STANDARD = ROOT / "packaging/licenses"
TAG = "v" + tomllib.loads((ROOT / "crates/runtime/Cargo.toml").read_text())["package"]["version"]
# Both packages ship the same guest image; list the host crates for both platforms.
TARGETS = ("x86_64-unknown-linux-musl", "x86_64-pc-windows-msvc")
SHIPPED = ("ya-runtime-vm", "ya-vm-guest-agent")
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|notice|unlicense)", re.IGNORECASE)


def shipped_packages():
    """Return the third-party packages linked into the runtime or guest agent."""
    packages = {}
    for target in TARGETS:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", target],
            cwd=ROOT))
        by_id = {package["id"]: package for package in metadata["packages"]}
        nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
        members = set(metadata["workspace_members"])
        pending = [id for id in members if by_id[id]["name"] in SHIPPED]
        seen = set()
        while pending:
            id = pending.pop()
            if id in seen:
                continue
            seen.add(id)
            # A -sys crate links the native library that its -src build dependency compiles.
            pending += [dep["pkg"] for dep in nodes[id]["deps"]
                        if any(kind["kind"] is None for kind in dep["dep_kinds"])
                        or by_id[id]["name"].endswith("-sys") and by_id[dep["pkg"]]["name"].endswith("-src")]
        # Vendored OpenVMM crates under third_party/ keep their MIT license.
        for id in seen:
            if not Path(by_id[id]["manifest_path"]).is_relative_to(ROOT / "crates"):
                packages[id] = by_id[id]
    return sorted(packages.values(), key=lambda package: (package["name"], package["version"]))


def license_files(package):
    """Find the crate's license files, falling back to its repository checkout root."""
    directory = Path(package["manifest_path"]).parent
    while True:
        files = sorted(path for path in directory.iterdir() if path.is_file() and LICENSE_FILE.match(path.name))
        # Cargo marks the root of every unpacked crate and git checkout with .cargo-ok.
        if files or (directory / ".cargo-ok").exists() or directory == directory.parent:
            return files
        directory = directory.parent


def standard_texts(package):
    """Stand in for crates published without license files."""
    expression = package.get("license") or ""
    texts = []
    if "MIT" in expression:
        authors = ", ".join(package.get("authors") or [package["name"] + " authors"])
        texts.append((STANDARD / "MIT.txt").read_text().replace("[year] [fullname]", authors))
    if "Apache-2.0" in expression:
        texts.append((STANDARD / "Apache-2.0.txt").read_text())
    if "GPL-3.0" in expression:
        texts.append("See licenses/ya-runtime-vm-GPL-3.0.txt.\n")
    if not texts:
        raise SystemExit(f"No license text for {package['name']} {package['version']} ({expression})")
    return texts


def source_link(package):
    source = package.get("source") or ""
    if source.startswith("git+"):
        url, commit = source.removeprefix("git+").split("#")
        return f"{url.split('?')[0].removesuffix('.git')}/tree/{commit}"
    if source.startswith("registry+"):
        return package.get("repository") or f"https://crates.io/crates/{package['name']}/{package['version']}"
    return f"{REPOSITORY}/tree/{TAG}/{Path(package['manifest_path']).parent.relative_to(ROOT).as_posix()}"


def components(pkginfo, openssl):
    kernel = dict(line.split(" = ", 1) for line in pkginfo.splitlines() if " = " in line)
    version = kernel["pkgver"].split("-")[0]
    dockerfile = (ROOT / "guest/mkfs/Dockerfile").read_text()
    busybox = re.search(r"git clone (\S+)", dockerfile)[1]
    busybox_commit = re.search(r"git checkout ([0-9a-f]{40})", dockerfile)[1]
    self_test = re.search(r'"(https://github.com/[^"]+)/releases/download/([^/"]+)/',
                          (ROOT / "scripts/fetch-self-test.py").read_text())
    return [
        ("Linux kernel and modules (vmlinuz-virt, initramfs.cpio.gz)", kernel["license"], [
            f"Source: https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tag/?h=v{version}",
            f"Alpine {kernel['origin']} {kernel['pkgver']} build: "
            f"https://gitlab.alpinelinux.org/alpine/aports/-/tree/{kernel['commit']}/main/{kernel['origin']}",
        ], STANDARD / "GPL-2.0.txt"),
        ("BusyBox mkfs.ext2 (initramfs.cpio.gz)", "GPL-2.0-only", [
            f"Source: {busybox}/tree/{busybox_commit}",
            f"Configuration: {REPOSITORY}/tree/{TAG}/guest/mkfs",
        ], STANDARD / "GPL-2.0.txt"),
        (f"OpenSSL {openssl['version'].split('+')[-1]} (statically linked into the host runtime)", "Apache-2.0", [
            f"Source: https://github.com/openssl/openssl/tree/openssl-{openssl['version'].split('+')[-1]}",
        ], Path(openssl["manifest_path"]).parent / "openssl/LICENSE.txt"),
        ("Self-test task image (self-test.gvmi)", "see source", [
            f"Source: {self_test[1]}/tree/{self_test[2]}",
        ], None),
    ]


def write(path, pkginfo):
    packages = shipped_packages()
    openssl = next(package for package in packages if package["name"] == "openssl-src")
    out = ["Third-party software distributed with ya-runtime-vm", "=" * 51, "",
           f"ya-runtime-vm is licensed under GPL-3.0; its source is at {REPOSITORY}.", "",
           "Components", "----------", ""]
    texts = {}
    for name, expression, sources, text in components(pkginfo, openssl):
        out += [name, f"  License: {expression}"] + [f"  {source}" for source in sources] + [""]
        if text:
            texts.setdefault(text.read_text(), []).append(name)
    out += ["Rust crates", "-----------", ""]
    for package in packages:
        out.append(f"{package['name']} {package['version']}: "
                   f"{package.get('license') or 'see license text'}; {source_link(package)}")
        files = license_files(package)
        for text in [file.read_text(errors="replace") for file in files] or standard_texts(package):
            texts.setdefault(text, []).append(f"{package['name']} {package['version']}")
    out += ["", "License texts", "-------------"]
    for text, users in texts.items():
        out += ["", "=" * 79, "Used by: " + ", ".join(dict.fromkeys(users)), "=" * 79, "", text.rstrip()]
    path.write_text("\n".join(out) + "\n")
    print(f"Third-party notices: {path} ({len(packages)} crates, {len(texts)} license texts)")
