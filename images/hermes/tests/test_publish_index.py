"""Registry index validation tests; fixtures are not real registry responses."""
import importlib.util
from pathlib import Path
import unittest


class PublishIndexTests(unittest.TestCase):
    def load_validator(self):
        path = Path(__file__).resolve().parents[3] / ".github/scripts/verify_hermes_index.py"
        self.assertTrue(path.is_file(), "publisher index validator is not implemented")
        spec = importlib.util.spec_from_file_location("verify_hermes_index", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.verify_index

    def fixture(self):
        return {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "digest": "sha256:" + "a" * 64,
            "manifests": [
                {"digest": "sha256:" + "b" * 64, "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": "sha256:" + "c" * 64, "platform": {"os": "linux", "architecture": "amd64"}},
            ],
        }

    def test_returns_digest_for_exactly_both_linux_architectures(self):
        self.assertEqual(self.load_validator()(self.fixture()), "sha256:" + "a" * 64)


    def test_rejects_invalid_or_incomplete_registry_indexes(self):
        verify = self.load_validator()
        cases = []
        for field, value in (("digest", "not-a-digest"), ("schemaVersion", 1), ("mediaType", "application/vnd.oci.image.manifest.v1+json")):
            item = self.fixture()
            item[field] = value
            cases.append(item)
        item = self.fixture()
        item["manifests"].pop()
        cases.append(item)
        item = self.fixture()
        item["manifests"][1]["platform"]["architecture"] = "arm64"
        cases.append(item)
        item = self.fixture()
        item["manifests"][1]["platform"]["os"] = "windows"
        cases.append(item)
        item = self.fixture()
        item["manifests"][1]["digest"] = "invalid"
        cases.append(item)
        for index in cases:
            with self.subTest(index=index), self.assertRaises(ValueError):
                verify(index)


if __name__ == "__main__":
    unittest.main()
