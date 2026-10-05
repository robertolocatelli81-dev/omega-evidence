"""2026-10-05 — the README's install-from-tag example names the version this tree is: a release that bumps pyproject.toml
without the README (it said @v0.8.3 when the release was 0.11.1) turns this test red."""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestReadmeVersion(unittest.TestCase):
    def test_tagged_install_example_is_this_version(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            version = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M).group(1)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            tags = re.findall(r"omega-evidence@v([0-9][0-9.]*)", f.read())
        self.assertTrue(tags, "the README has no install-from-tag example")
        self.assertEqual(set(tags), {version})


if __name__ == "__main__":
    unittest.main()
