"""Regressions for source attribution of generated OpenVMM overrides."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import third_party_notices as notices


class SourceLinkTests(unittest.TestCase):
    def test_each_generated_crate_links_to_its_own_upstream_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "patches/openvmm/config.toml"
            config.parent.mkdir(parents=True)
            # Exercise both the original configuration and the multi-crate one.
            for selection in ('crate = "vmm_core/virt_kvm"',
                              'crates = ["vmm_core/virt_kvm", "vm/kvm"]'):
                config.write_text(
                    'repository = "https://github.com/microsoft/openvmm.git"\n'
                    'revision = "pinned-revision"\n'
                    'patch = "hypervisor-cpuid.patch"\n' + selection + '\n'
                )
                with patch.object(notices, "ROOT", root):
                    for crate in ("vmm_core/virt_kvm", "vm/kvm"):
                        with self.subTest(selection=selection, crate=crate):
                            package = {"source": None, "manifest_path": str(
                                root / "build/openvmm" / crate / "Cargo.toml")}
                            self.assertEqual(notices.source_link(package),
                                "https://github.com/microsoft/openvmm/tree/"
                                f"pinned-revision/{crate} (local patch: "
                                f"{notices.REPOSITORY}/blob/{notices.TAG}/"
                                "patches/openvmm/hypervisor-cpuid.patch)")


if __name__ == "__main__":
    unittest.main()
