#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Test access-name generation against an isolated synthetic kernel tree.

Malformed fixtures ensure header drift and unsupported forms fail closed.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parent.parent
SCRIPT = REPOSITORY / "scripts/generate-access-names.py"
FIXTURE = REPOSITORY / "tests/fixtures/access-names"


class GenerateAccessNamesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.kernel_tree = Path(self.temporary.name) / "linux"
        shutil.copytree(FIXTURE, self.kernel_tree)
        self.output = Path(self.temporary.name) / "access_names.rs"

    def run_generator(self, *arguments):
        return subprocess.run(
            [
                str(SCRIPT),
                "--kernel-tree",
                str(self.kernel_tree),
                "--output",
                str(self.output),
                *arguments,
            ],
            check=False,
            capture_output=True,
            encoding="utf-8",
        )

    def replace_uapi(self, old, new):
        path = self.kernel_tree / "include/uapi/linux/landlock.h"
        path.write_text(
            path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
        )

    def replace_internal(self, old, new):
        path = self.kernel_tree / "include/linux/landlock.h"
        path.write_text(
            path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
        )

    def assert_rejected(self, message):
        result = self.run_generator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_generates_all_categories_multiline_and_sorted(self):
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)
        generated = self.output.read_text(encoding="utf-8")
        self.assertIn("FILESYSTEM_ACCESS_NAMES", generated)
        self.assertIn("NETWORK_ACCESS_NAMES", generated)
        self.assertIn("SCOPE_NAMES", generated)
        self.assertIn('(1_u32 << 1, "connect_tcp")', generated)
        self.assertLess(generated.index('"execute"'), generated.index('"read_file"'))
        self.assertLess(generated.index('"bind_tcp"'), generated.index('"connect_tcp"'))
        self.assertLess(
            generated.index('"abstract_unix_socket"'), generated.index('"signal"')
        )

    def test_explicit_relative_output_is_relative_to_caller(self):
        caller = Path(self.temporary.name) / "caller"
        caller.mkdir()
        relative_output = Path("generated/access_names.rs")
        result = subprocess.run(
            [
                str(SCRIPT),
                "--kernel-tree",
                str(self.kernel_tree),
                "--output",
                str(relative_output),
            ],
            cwd=caller,
            check=False,
            capture_output=True,
            encoding="utf-8",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((caller / relative_output).is_file())

    def test_check_mode_accepts_matching_fixture(self):
        self.output.write_bytes((FIXTURE / "expected.rs").read_bytes())
        result = self.run_generator("--check")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_check_mode_reports_drift_without_rewriting(self):
        drift = b"drift\n"
        self.output.write_bytes(drift)
        result = self.run_generator("--check")
        self.assertEqual(result.returncode, 1)
        self.assertIn("---", result.stderr)
        self.assertIn("+++", result.stderr)
        self.assertEqual(self.output.read_bytes(), drift)

    def test_rejects_duplicate_bit(self):
        self.replace_uapi(
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)",
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)\n"
            "#define LANDLOCK_ACCESS_FS_OTHER (1ULL << 0)",
        )
        self.assert_rejected("duplicate filesystem bit 0")

    def test_rejects_duplicate_uapi_constant(self):
        self.replace_uapi(
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)",
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)\n"
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 3)",
        )
        self.assert_rejected("duplicate UAPI constant")

    def test_rejects_duplicate_display_name(self):
        self.replace_internal('"read_file"', '"execute"')
        self.assert_rejected("duplicate display name")

    def test_rejects_duplicate_list_entry(self):
        self.replace_internal(
            '_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_EXECUTE, "execute")',
            '_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_EXECUTE, "execute"), \\\n'
            '\t_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_EXECUTE, "execute")',
        )
        self.assert_rejected("duplicate list entry")

    def test_rejects_duplicate_list_definition(self):
        self.replace_internal(
            "#define _LANDLOCK_ACCESS_NET_NAMES \\",
            "#define _LANDLOCK_ACCESS_NET_NAMES \\\n"
            "\t_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_NET_BIND_TCP, \"bind_tcp\")\n\n"
            "#define _LANDLOCK_ACCESS_NET_NAMES \\",
        )
        self.assert_rejected("duplicate name-list definition")

    def test_rejects_uapi_constant_missing_from_list(self):
        self.replace_uapi(
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)",
            "#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)\n"
            "#define LANDLOCK_ACCESS_FS_NEW_RIGHT (1ULL << 3)",
        )
        self.assert_rejected("UAPI constants missing")

    def test_rejects_list_entry_without_uapi_constant(self):
        self.replace_internal(
            '_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_EXECUTE, "execute")',
            '_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_EXECUTE, "execute"), \\\n'
            '\t_LANDLOCK_NAME_ENTRY(LANDLOCK_ACCESS_FS_GHOST, "ghost")',
        )
        self.assert_rejected("entries without matching UAPI constants")

    def test_rejects_malformed_list_entry(self):
        self.replace_internal(
            '_LANDLOCK_NAME_ENTRY(LANDLOCK_SCOPE_SIGNAL, "signal")',
            "_LANDLOCK_NAME_ENTRY(LANDLOCK_SCOPE_SIGNAL)",
        )
        self.assert_rejected("malformed entry")

    def test_rejects_malformed_expression(self):
        self.replace_uapi("(1ULL << 2)", "(3ULL << 2)")
        self.assert_rejected("malformed single-bit expression")

    def test_rejects_bit_outside_u32(self):
        self.replace_uapi("(1ULL << 2)", "(1ULL << 32)")
        self.assert_rejected("does not fit in u32: 32")

    def test_rejects_unrecognized_landlock_access_category(self):
        self.replace_uapi(
            "#define UNRELATED_ACCESS_FS_VALUE (4)",
            "#define LANDLOCK_ACCESS_FUTURE_VALUE (1ULL << 0)",
        )
        self.assert_rejected("unrecognized Landlock access category")

    def test_rejects_whitespace_after_continuation_backslash(self):
        self.replace_internal(
            "#define _LANDLOCK_ACCESS_FS_NAMES \\",
            "#define _LANDLOCK_ACCESS_FS_NAMES \\ ",
        )
        self.assert_rejected("whitespace follows a continuation backslash")

    def test_ignores_unrelated_macros(self):
        self.replace_uapi(
            "#define UNRELATED_ACCESS_FS_VALUE (4)",
            "#define UNRELATED_ACCESS_FS_VALUE nonsense",
        )
        result = self.run_generator()
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
