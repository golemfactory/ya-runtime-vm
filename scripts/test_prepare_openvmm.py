"""Offline regressions for reproducible checkout preparation."""
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from prepare_openvmm import git, prepare, standalone_manifest


class PrepareOpenVmmTests(unittest.TestCase):
    def test_standalone_dependencies_preserve_features_and_one_git_source(self):
        package = tomllib.loads('''
            [package]
            name = "virt_kvm"
            edition.workspace = true
            [target.'cfg(target_os = "linux")'.dependencies]
            inspect = { workspace = true, features = ["std"] }
            libc.workspace = true
            [build-dependencies]
            builder.workspace = true
            [lints]
            workspace = true
        ''')
        workspace = {
            "package": {"edition": "2024"},
            "dependencies": {
                "inspect": {"path": "support/inspect", "default-features": False, "features": ["derive"]},
                "libc": "0.2",
                "builder": {"path": "support/builder"},
            },
            "lints": {"rust": {"unsafe_code": "deny"}},
        }
        config = {"repository": "https://example.test/openvmm.git", "revision": "a" * 40}
        result = tomllib.loads(standalone_manifest(package, workspace, config))
        deps = result["target"]['cfg(target_os = "linux")']["dependencies"]
        self.assertEqual(deps["inspect"], {
            "git": config["repository"], "rev": config["revision"],
            "default-features": False, "features": ["derive", "std"],
        })
        self.assertEqual(deps["libc"], {"version": "0.2"})
        self.assertEqual(result["build-dependencies"]["builder"], {
            "git": config["repository"], "rev": config["revision"],
        })
        self.assertEqual(result["package"]["edition"], "2024")
        self.assertEqual(result["lints"], workspace["lints"])
        self.assertEqual(result["package"]["workspace"], "../../../..")
        self.assertNotIn("workspace", result)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Treat the fixture as its own runtime workspace. On Windows the real
        # checkout and the system temp directory can live on different drives.
        root_patch = patch("prepare_openvmm.ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        source = self.root / "source"
        source.mkdir()
        git(source, "init", "--quiet")
        git(source, "config", "core.autocrlf", "false")
        git(source, "config", "user.email", "test@example.invalid")
        git(source, "config", "user.name", "Test")
        (source / "Cargo.toml").write_text('[workspace.package]\nedition = "2024"\n')
        (source / "backend").mkdir()
        (source / "backend/Cargo.toml").write_text(
            '[package]\nname = "virt_kvm"\nedition.workspace = true\n'
        )
        (source / "backend/lib.rs").write_text("// original\n", newline="\n")
        git(source, "add", ".")
        git(source, "commit", "--quiet", "-m", "fixture")
        git(source, "tag", "v-test")
        self.revision = git(source, "rev-parse", "HEAD").decode().strip()
        self.config = self.root / "config.toml"
        self.config.write_text(
            f'repository = {json.dumps(str(source))}\n'
            f'revision = "{self.revision}"\n'
            'tag = "v-test"\ncrate = "backend"\npatch = "fix.patch"\n'
        )
        self.patch = self.root / "fix.patch"
        self.patch.write_text(
            '--- a/backend/lib.rs\n+++ b/backend/lib.rs\n@@ -1 +1 @@\n'
            '-// original\n+// patched\n', newline="\n"
        )
        self.destination = self.root / "prepared"

    def test_prepare_is_offline_after_first_run_and_preserves_local_edits(self):
        prepare(self.config, self.destination)
        self.assertEqual((self.destination / "backend/lib.rs").read_text(), "// patched\n")
        # A second invocation must not fetch: the origin is no longer reachable.
        (self.root / "source").rename(self.root / "source-unavailable")
        stamp = self.destination / ".git/ya-runtime-vm-prepare.json"
        before = stamp.stat().st_mtime_ns
        prepare(self.config, self.destination)
        self.assertEqual(stamp.stat().st_mtime_ns, before)
        (self.destination / "backend/lib.rs").write_text("// manual edit\n")
        with self.assertRaisesRegex(RuntimeError, "local changes"):
            prepare(self.config, self.destination)
        self.assertEqual((self.destination / "backend/lib.rs").read_text(), "// manual edit\n")

    def test_patch_update_and_failed_patch_preserve_previous_checkout(self):
        prepare(self.config, self.destination)
        self.patch.write_text(self.patch.read_text().replace("+// patched", "+// updated"), newline="\n")
        prepare(self.config, self.destination)
        self.assertEqual((self.destination / "backend/lib.rs").read_text(), "// updated\n")
        self.patch.write_text(self.patch.read_text().replace("-// original", "-// wrong base"), newline="\n")
        with self.assertRaises(subprocess.CalledProcessError):
            prepare(self.config, self.destination)
        self.assertEqual((self.destination / "backend/lib.rs").read_text(), "// updated\n")

    def test_moved_tag_is_rejected(self):
        self.config.write_text(self.config.read_text().replace(self.revision, "0" * 40))
        with self.assertRaisesRegex(RuntimeError, "tag changed"):
            prepare(self.config, self.destination)
        self.assertFalse(self.destination.exists())

    def test_multiple_crates_share_revision_and_detect_edits(self):
        source = self.root / "source"
        (source / "wrapper").mkdir()
        (source / "wrapper/Cargo.toml").write_text(
            '[package]\nname = "kvm"\nedition.workspace = true\n'
        )
        with (source / "backend/Cargo.toml").open("a") as manifest:
            manifest.write('[dependencies]\nkvm.workspace = true\n')
        with (source / "Cargo.toml").open("a") as manifest:
            manifest.write('[workspace.dependencies]\nkvm = { path = "wrapper" }\n')
        git(source, "add", ".")
        git(source, "commit", "--quiet", "-m", "second crate")
        git(source, "tag", "v-multi")
        revision = git(source, "rev-parse", "HEAD").decode().strip()
        self.config.write_text(self.config.read_text()
                               .replace(self.revision, revision)
                               .replace('tag = "v-test"', 'tag = "v-multi"')
                               .replace('crate = "backend"', 'crates = ["backend", "wrapper"]'))
        prepare(self.config, self.destination)
        backend = tomllib.loads((self.destination / "backend/Cargo.toml").read_text())
        wrapper = tomllib.loads((self.destination / "wrapper/Cargo.toml").read_text())
        self.assertEqual(backend["dependencies"]["kvm"]["rev"], revision)
        self.assertEqual(wrapper["package"]["edition"], "2024")
        self.assertEqual(backend["package"]["workspace"], wrapper["package"]["workspace"])
        source.rename(self.root / "source-unavailable")
        prepare(self.config, self.destination)
        with (self.destination / "wrapper/Cargo.toml").open("a") as manifest:
            manifest.write("# manual edit\n")
        with self.assertRaisesRegex(RuntimeError, "local changes"):
            prepare(self.config, self.destination)

    def test_unmanaged_checkout_is_not_replaced(self):
        self.destination.mkdir()
        (self.destination / "keep.txt").write_text("keep")
        with self.assertRaisesRegex(RuntimeError, "unmanaged"):
            prepare(self.config, self.destination)
        self.assertEqual((self.destination / "keep.txt").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
