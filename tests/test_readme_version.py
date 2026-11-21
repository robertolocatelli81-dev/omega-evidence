"""2026-10-05 — the README's install-from-tag example names the version this tree is: a release that bumps pyproject.toml
without the README (it said @v0.8.3 when the release was 0.11.1) turns this test red."""
import os, re, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestReadmeVersion(unittest.TestCase):
    def test_tagged_install_example_is_this_version(self):
        with open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8") as f:
            version = re.search(r'^version\s*=\s*"([^"]+)"', f.read(), re.M).group(1)
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            readme = f.read()
        tags = re.findall(r"omega-evidence@v([0-9][0-9.]*)", readme)
        self.assertTrue(tags, "the README has no install-from-tag example")
        self.assertEqual(set(tags), {version})
        # 21/11/2026: the pinned install from the index names it too (a README left at ==0.13.0 passed this test)
        pins = re.findall(r"pip install omega-evidence==([0-9][0-9.]*)", readme)
        self.assertTrue(pins, "the README has no pinned install example")
        self.assertEqual(set(pins), {version})


if __name__ == "__main__":
    unittest.main()
