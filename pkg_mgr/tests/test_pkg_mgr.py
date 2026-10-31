"""Tests for pkg_mgr. Run with: python3 -m unittest discover -s pkg_mgr/tests -v

All writes go to a repo-local scratch directory (.test-tmp/, gitignored) and
every install uses a staging --root, so nothing touches the real /urados.
"""

import io
import os
import shutil
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from importlib.machinery import SourceFileLoader
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SCRIPT = os.path.join(HERE, "..", "pkg_mgr")
EXAMPLE = os.path.join(HERE, "..", "examples", "exampleapp")
SCRATCH = os.path.join(REPO, ".test-tmp")

pkg_mgr = SourceFileLoader("pkg_mgr", SCRIPT).load_module()

VALID_MANIFEST = """\
[Application]
Name=ExampleApp
ID=com.example.exampleapp
Version=1.0.0
Description=test
Type=executable

[Installation]
Prefix=/urados/apps/exampleapp

[Files]
File1.Source=bin/app
File1.Destination=bin/app

File2.Source=data/config.ini
File2.Destination=config/config.ini

File3.Source=data/icon.png
File3.Destination=share/icon.png

[Execution]
Executable=bin/app
Arguments=--verbose
RunAs=root
"""


class PkgTestCase(unittest.TestCase):
    def setUp(self):
        os.makedirs(SCRATCH, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="case-", dir=SCRATCH)
        self.root = os.path.join(self.tmp, "root")
        self.pkg = os.path.join(self.tmp, "pkg")
        os.makedirs(self.root)
        os.makedirs(self.pkg)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # helpers ---------------------------------------------------------------
    def write(self, rel, data, mode=0o644, base=None):
        path = os.path.join(base or self.pkg, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as fh:
            fh.write(data)
        os.chmod(path, mode)
        return path

    def make_pkg(self, manifest=VALID_MANIFEST):
        self.write("manifest.ini", manifest)
        self.write("bin/app", "#!/bin/sh\necho app\n", 0o755)
        self.write("data/config.ini", "[a]\nb=1\n")
        self.write("data/icon.png", "PNGDATA")
        return self.pkg

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = pkg_mgr.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def install(self, *extra):
        return self.run_cli("install", self.pkg, "--root", self.root, *extra)

    def install_dir(self):
        return os.path.join(self.root, "urados/apps/exampleapp")

    def expect_rejected(self, manifest, needle=None):
        self.make_pkg(manifest)
        rc, _, err = self.install()
        self.assertEqual(rc, 1, f"expected rejection, got rc={rc}")
        self.assertFalse(os.path.exists(self.install_dir()), "nothing may be written")
        if needle:
            self.assertIn(needle, err)
        return err


class ValidInstallTests(PkgTestCase):
    def test_install_places_files_with_correct_modes(self):
        self.make_pkg()
        rc, out, err = self.install()
        self.assertEqual(rc, 0, err)
        d = self.install_dir()
        self.assertEqual(stat.S_IMODE(os.stat(f"{d}/bin/app").st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(f"{d}/config/config.ini").st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(f"{d}/share/icon.png").st_mode), 0o644)
        with open(f"{d}/share/icon.png") as fh:
            self.assertEqual(fh.read(), "PNGDATA")
        self.assertIn("Installed com.example.exampleapp 1.0.0", out)

    def test_script_under_scripts_is_executable(self):
        self.make_pkg(VALID_MANIFEST.replace("File2.Source=data/config.ini",
                                             "File2.Source=bin/app")
                      .replace("File2.Destination=config/config.ini",
                               "File2.Destination=scripts/setup.sh"))
        rc, _, err = self.install()
        self.assertEqual(rc, 0, err)
        mode = stat.S_IMODE(os.stat(f"{self.install_dir()}/scripts/setup.sh").st_mode)
        self.assertEqual(mode, 0o755)

    def test_metadata_records_manifest_and_file_list(self):
        self.make_pkg()
        self.assertEqual(self.install()[0], 0)
        meta = os.path.join(self.install_dir(), ".pkg")
        with open(os.path.join(meta, "manifest.ini")) as fh:
            self.assertEqual(fh.read(), VALID_MANIFEST)
        with open(os.path.join(meta, "files.txt")) as fh:
            self.assertEqual(fh.read().split(), ["bin/app", "config/config.ini", "share/icon.png"])

    def test_dry_run_writes_nothing(self):
        self.make_pkg()
        rc, out, _ = self.install("--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("dry run: nothing was written", out)
        self.assertFalse(os.path.exists(os.path.join(self.root, "urados")))

    def test_existing_destination_needs_force(self):
        self.make_pkg()
        self.assertEqual(self.install()[0], 0)
        rc, _, err = self.install()
        self.assertEqual(rc, 1)
        self.assertIn("already exists", err)

    def test_force_replaces_existing_files(self):
        self.make_pkg()
        self.assertEqual(self.install()[0], 0)
        self.write("data/icon.png", "NEWICON")
        rc, _, err = self.install("--force")
        self.assertEqual(rc, 0, err)
        with open(f"{self.install_dir()}/share/icon.png") as fh:
            self.assertEqual(fh.read(), "NEWICON")

    def test_run_from_relative_package_path(self):
        self.make_pkg()
        cwd = os.getcwd()
        try:
            os.chdir(self.tmp)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                rc = pkg_mgr.main(["install", "pkg", "--root", self.root])
        finally:
            os.chdir(cwd)
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(f"{self.install_dir()}/bin/app"))

    def test_root_must_be_absolute(self):
        self.make_pkg()
        rc, _, err = self.run_cli("install", self.pkg, "--root", "relative/root")
        self.assertEqual(rc, 1)
        self.assertIn("--root must be an absolute path", err)

    def test_example_package_dry_run_and_install(self):
        rc, _, err = self.run_cli("install", EXAMPLE, "--root", self.root)
        self.assertEqual(rc, 0, err)
        d = self.install_dir()
        for rel in ("bin/exampleapp", "bin/helper", "scripts/setup.sh",
                    "config/config.ini", "share/icon.png", ".pkg/manifest.ini"):
            self.assertTrue(os.path.isfile(os.path.join(d, rel)), rel)


class ManifestRejectionTests(PkgTestCase):
    def base(self, **repl):
        text = VALID_MANIFEST
        for old, new in repl.items():
            self.assertIn(old, text)
            text = text.replace(old, new)
        return text

    def test_prefix_outside_apps_rejected(self):
        self.expect_rejected(self.base(**{"Prefix=/urados/apps/exampleapp": "Prefix=/usr/bin/exampleapp"}),
                             "must be under /urados/apps/")

    def test_prefix_relative_rejected(self):
        self.expect_rejected(self.base(**{"Prefix=/urados/apps/exampleapp": "Prefix=urados/apps/x"}),
                             "must be absolute")

    def test_prefix_traversal_rejected(self):
        self.expect_rejected(self.base(**{"Prefix=/urados/apps/exampleapp": "Prefix=/urados/apps/../../etc"}),
                             "normalized")

    def test_prefix_trailing_slash_rejected(self):
        self.expect_rejected(self.base(**{"Prefix=/urados/apps/exampleapp": "Prefix=/urados/apps/x/"}),
                             "normalized")

    def test_prefix_equal_to_base_rejected(self):
        self.expect_rejected(self.base(**{"Prefix=/urados/apps/exampleapp": "Prefix=/urados/apps"}),
                             "must be under /urados/apps/")

    def test_source_traversal_rejected(self):
        self.expect_rejected(self.base(**{"File1.Source=bin/app": "File1.Source=../etc/passwd"}),
                             "must not contain '..'")

    def test_source_absolute_rejected(self):
        self.expect_rejected(self.base(**{"File1.Source=bin/app": "File1.Source=/bin/sh"}),
                             "must be relative")

    def test_missing_source_rejected(self):
        self.make_pkg(self.base(**{"File1.Source=bin/app": "File1.Source=bin/nothere"}))
        rc, _, err = self.install()
        self.assertEqual(rc, 1)
        self.assertIn("not found in package", err)
        self.assertFalse(os.path.exists(self.install_dir()))

    def test_symlink_source_rejected(self):
        self.make_pkg()
        os.symlink("/etc/hostname", os.path.join(self.pkg, "data/link.png"))
        manifest = self.base(**{"File3.Source=data/icon.png": "File3.Source=data/link.png"})
        self.write("manifest.ini", manifest)
        rc, _, err = self.install()
        self.assertEqual(rc, 1)
        self.assertIn("symlinks are not allowed", err)
        self.assertFalse(os.path.exists(self.install_dir()))

    def test_destination_traversal_rejected(self):
        self.expect_rejected(self.base(**{"File2.Destination=config/config.ini": "File2.Destination=../../evil"}),
                             "must not contain '..'")

    def test_reserved_metadata_destination_rejected(self):
        self.expect_rejected(self.base(**{"File2.Destination=config/config.ini": "File2.Destination=.pkg/manifest.ini"}),
                             "reserved name")

    def test_duplicate_destination_rejected(self):
        self.expect_rejected(self.base(**{"File2.Destination=config/config.ini": "File2.Destination=bin/app"}),
                             "listed more than once")

    def test_file_and_directory_conflict_rejected(self):
        self.expect_rejected(self.base(**{"File2.Destination=config/config.ini": "File2.Destination=bin/app/x"}),
                             "needs it as a directory")

    def test_unknown_application_key_rejected(self):
        self.expect_rejected(self.base(**{"Version=1.0.0": "Version=1.0.0\nVerison=typo"}),
                             "unknown key")

    def test_unknown_files_key_rejected(self):
        self.expect_rejected(self.base(**{"File1.Source=bin/app": "Source1=bin/app"}),
                             "unknown key")

    def test_missing_required_key_rejected(self):
        self.expect_rejected(self.base(**{"ID=com.example.exampleapp\n": ""}), "ID is required")

    def test_bad_id_rejected(self):
        self.expect_rejected(self.base(**{"ID=com.example.exampleapp": "ID=../evil"}),
                             "not a valid identifier")

    def test_executable_must_be_listed_in_files(self):
        self.expect_rejected(self.base(**{"Executable=bin/app": "Executable=bin/other"}),
                             "is not a Destination")

    def test_executable_type_requires_executable(self):
        self.expect_rejected(self.base(**{"Executable=bin/app\n": ""}), "Executable is required")

    def test_working_directory_must_contain_files(self):
        self.expect_rejected(self.base(**{"Arguments=--verbose": "WorkingDirectory=nowhere\nArguments=--verbose"}),
                             "has no files installed under it")

    def test_invalid_run_as_rejected(self):
        self.expect_rejected(self.base(**{"RunAs=root": "RunAs=root;rm"}), "not a valid user name")

    def test_missing_manifest_rejected(self):
        rc, _, err = self.install()
        self.assertEqual(rc, 1)
        self.assertIn("no regular manifest.ini", err)

    def test_missing_files_section_rejected(self):
        text = VALID_MANIFEST.split("[Files]")[0] + "[Execution]\nExecutable=bin/app\n"
        self.expect_rejected(text, "missing [Files]")


class SafetyTests(PkgTestCase):
    def test_refuses_to_install_through_symlink(self):
        self.make_pkg()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        os.makedirs(os.path.join(self.root, "urados/apps"))
        os.symlink(outside, os.path.join(self.root, "urados/apps/exampleapp"))
        rc, _, err = self.install()
        self.assertEqual(rc, 1)
        self.assertIn("refusing to install through symlink", err)
        self.assertEqual(os.listdir(outside), [], "nothing may land outside the root")

    def test_refuses_symlink_at_destination(self):
        self.make_pkg()
        d = os.path.join(self.install_dir(), "bin")
        os.makedirs(d)
        target = os.path.join(self.tmp, "victim")
        with open(target, "w") as fh:
            fh.write("keep")
        os.symlink(target, os.path.join(d, "app"))
        rc, _, err = self.install("--force")
        self.assertEqual(rc, 1)
        self.assertIn("refusing to install through symlink", err)
        with open(target) as fh:
            self.assertEqual(fh.read(), "keep")


class RollbackTests(PkgTestCase):
    def test_failed_write_rolls_back_and_restores_originals(self):
        self.make_pkg()
        # Pre-existing config that --force will replace before the failure.
        cfg = os.path.join(self.install_dir(), "config/config.ini")
        os.makedirs(os.path.dirname(cfg))
        with open(cfg, "w") as fh:
            fh.write("ORIGINAL")

        real_copy = shutil.copyfile

        def failing_copy(src, dst, *a, **kw):
            if src.endswith("icon.png"):
                raise OSError(28, "No space left on device", dst)
            return real_copy(src, dst, *a, **kw)

        with mock.patch.object(pkg_mgr.shutil, "copyfile", side_effect=failing_copy):
            rc, _, err = self.install("--force")

        self.assertEqual(rc, 2)
        self.assertIn("rolled back", err)
        with open(cfg) as fh:
            self.assertEqual(fh.read(), "ORIGINAL", "replaced file must be restored")
        self.assertFalse(os.path.exists(os.path.join(self.install_dir(), "bin/app")),
                         "files written before the failure must be removed")
        self.assertFalse(os.path.exists(os.path.join(self.install_dir(), "share")),
                         "directories created by the install must be removed")
        leftovers = [n for n in os.listdir(os.path.join(self.install_dir(), "config"))
                     if ".pkgtmp-" in n]
        self.assertEqual(leftovers, [])

    def test_fresh_install_failure_leaves_no_install_dir(self):
        self.make_pkg()
        with mock.patch.object(pkg_mgr.shutil, "copyfile", side_effect=OSError(5, "EIO")):
            rc, _, _ = self.install()
        self.assertEqual(rc, 2)
        self.assertFalse(os.path.exists(os.path.join(self.root, "urados")))


if __name__ == "__main__":
    unittest.main()
