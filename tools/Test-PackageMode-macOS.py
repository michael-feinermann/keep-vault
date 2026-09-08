#!/usr/bin/env python3
"""Private, unprivileged regression checks for the sealed installer adapter.

The tests never install/sign an app or exercise administrator prompts. Native
verifier crypto, full installation transactions and Apple release policy have
their own gates; the function-level probes here isolate object/byte binding.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parent
SCRIPTS = ("Install-KeepVault-macOS.sh", "Verify-KeepVault-macOS.sh",
           "Verify-QR-Scanner-macOS.sh")
RUNTIME = (TOOLS / "PackageRuntime-macOS.sh").read_text()
FUNCTIONS = RUNTIME[:RUNTIME.index("\npackage_root_identity=$(package_identity")]


class PackageModeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="keep-vault-package-unit-", dir="/private/tmp")
        self.base = Path(self.temporary.name)
        self.functions = self.base / "functions.zsh"
        self.functions.write_text(FUNCTIONS)
        self.package = self.base / "Paket mit Ä und spaces"
        self.installer = self.package / "Keep Vault Installer.app"
        self.macos = self.installer / "Contents/MacOS"
        self.macos.mkdir(parents=True)
        self.verifier = self.macos / "Keep Vault Release Verifier"
        self.helper = self.macos / "InstallerBoundDelete"
        self.verifier.write_text('#!/bin/zsh -f\n[[ $# == 0 ]] || print changed >> "$1"\nexit 0\n')
        self.helper.write_text("synthetic helper bytes\n")
        self.verifier.chmod(0o700)
        self.helper.chmod(0o700)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, body):
        code = '''set -euo pipefail
source "$1"
package_root=$2
package_installer=${package_root}/Keep\\ Vault\\ Installer.app
package_verifier=${package_installer}/Contents/MacOS/Keep\\ Vault\\ Release\\ Verifier
package_bound_delete=${package_installer}/Contents/MacOS/InstallerBoundDelete
package_root_identity=$(package_identity ${package_root})
package_installer_identity=$(package_bundle_identity ${package_installer})
package_verifier_identity=$(package_regular_identity ${package_verifier})
package_bound_delete_identity=$(package_regular_identity ${package_bound_delete})
'''+body
        return subprocess.run(["/bin/zsh", "-f", "-c", code, "package-unit",
                               str(self.functions), str(self.package)], capture_output=True, text=True)

    def test_valid_bound_native_invocation(self):
        result = self.invoke("package_run_verifier\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def change_xattr(self, variable):
        # Real filesystem metadata operation, with an explicit tick so the
        # stat format used by production must observe a changed ctime.
        return ('ctime_before=$(/usr/bin/stat -f %c -- ${' + variable + '})\n'
                '/bin/sleep 1.1\n'
                '/usr/bin/xattr -w de.keep-vault.test.identity metadata-change ${' + variable + '}\n'
                '[[ $(/usr/bin/stat -f %c -- ${' + variable + '}) != ${ctime_before} ]] || exit 70\n')

    def test_installer_directory_ctime_only_update_is_accepted(self):
        result = self.invoke(self.change_xattr('package_installer') + 'package_run_verifier\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_package_root_ctime_change_is_still_rejected(self):
        result = self.invoke(self.change_xattr('package_root') + 'package_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound package root changed identity', result.stderr)

    def test_helper_ctime_only_change_is_still_rejected(self):
        result = self.invoke(self.change_xattr('package_bound_delete') + 'package_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound rollback helper changed identity', result.stderr)

    def test_installer_directory_mode_change_is_rejected(self):
        result = self.invoke('chmod 0710 ${package_installer}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound installer bundle changed identity', result.stderr)

    def test_writable_installer_directory_is_rejected(self):
        result = self.invoke('chmod 0722 ${package_installer}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_installer_directory_mtime_change_is_rejected(self):
        result = self.invoke('/usr/bin/touch -t 202001010000 ${package_installer}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound installer bundle changed identity', result.stderr)

    def test_identical_replacement_installer_inode_is_rejected(self):
        result = self.invoke('mv ${package_installer} ${package_installer}.held\n'
                             'cp -Rp ${package_installer}.held ${package_installer}\n'
                             # Isolate the bundle check from the independent
                             # parent-directory mutation caused by the rename.
                             'package_root_identity=$(package_identity ${package_root})\n'
                             'package_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound installer bundle changed identity', result.stderr)

    def test_symlinked_installer_directory_is_rejected(self):
        result = self.invoke('mv ${package_installer} ${package_installer}.held\n'
                             'ln -s ${package_installer}.held ${package_installer}\n'
                             'package_root_identity=$(package_identity ${package_root})\n'
                             'package_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('bound installer bundle changed identity', result.stderr)

    def test_helper_byte_change_before_execution(self):
        result = self.invoke('print changed >> ${package_bound_delete}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_native_mutation_is_rejected_after_execution(self):
        result = self.invoke("package_run_verifier ${package_bound_delete}\n")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("changed", self.helper.read_text())

    def test_replaced_helper_inode_is_rejected(self):
        result = self.invoke('mv ${package_bound_delete} ${package_bound_delete}.held\n'
                             'cp ${package_bound_delete}.held ${package_bound_delete}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_hard_linked_helper_is_rejected(self):
        result = self.invoke('ln ${package_bound_delete} ${package_bound_delete}.link\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_writable_helper_is_rejected(self):
        result = self.invoke('chmod 0722 ${package_bound_delete}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_symlinked_helper_is_rejected(self):
        result = self.invoke('mv ${package_bound_delete} ${package_bound_delete}.held\n'
                             'ln -s ${package_bound_delete}.held ${package_bound_delete}\npackage_run_verifier\n')
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_foreign_local_ticket_rejected_before_apple_policy(self):
        source = self.package / "QR-Scanner.app/Contents"
        target = self.base / "stage/QR-Scanner.app/Contents"
        source.mkdir(parents=True)
        target.mkdir(parents=True)
        (source / "CodeResources").write_bytes(b"synthetic source ticket")
        (target / "CodeResources").write_bytes(b"different foreign ticket")
        result = self.invoke('package_run_verifier() { return 0; }\n'
                             'package_validate_distribution ${package_root:h}/stage/QR-Scanner.app\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("differs from the authenticated release ticket", result.stderr)

    def test_missing_local_ticket_rejected_before_apple_policy(self):
        result = self.invoke('package_run_verifier() { return 0; }\n'
                             'package_validate_distribution ${package_root}/QR-Scanner.app\n')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("no safe, local stapled ticket", result.stderr)

    def test_user_owned_packages_fail_before_sdk_discovery(self):
        script_root = self.installer / "Contents/Resources/tools"
        script_root.mkdir(parents=True)
        for name in SCRIPTS:
            with self.subTest(script=name):
                script = script_root / name
                shutil.copyfile(TOOLS / name, script)
                result = subprocess.run(["/bin/zsh", "-fx", str(script), "--package-root", str(self.package)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotRegex(result.stderr, r"> /usr/bin/xcrun ")
                self.assertNotIn("provision_verified_dotnet", result.stderr)
                self.assertNotIn("run_dotnet_clean restore", result.stderr)

    def test_metadata_gate_needs_no_developer_tools(self):
        result = subprocess.run(["/bin/zsh", "-fx", str(TOOLS / "Verify-ReleasePairMetadata-macOS.sh"),
                                 "--tool-path-self-test"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("xcrun", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
