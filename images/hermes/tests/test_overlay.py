"""Unit checks for the minimal manifest override; no containers or installs."""
import importlib.util
from pathlib import Path
import unittest

MODULE = Path(__file__).resolve().parents[1] / "build_overlay.py"


class ManifestOverrideTests(unittest.TestCase):
    def load(self):
        self.assertTrue(MODULE.is_file(), "the manifest-override implementation is missing")
        spec = importlib.util.spec_from_file_location("hermes_build_overlay", MODULE)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def load_verify(self):
        path = Path(__file__).with_name("verify_image.py")
        spec = importlib.util.spec_from_file_location("hermes_verify_image", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_accepts_actual_native_decoder_error_string(self):
        self.load_verify().require_native_patch_marker(b"_ERROR_FORMAT_BLOCK_SWITCH")

    def test_rejects_an_unknown_native_decoder_error(self):
        for marker in (None, b"INVALID", b"_ERROR_FORMAT_PADDING_1"):
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, "patch marker"):
                self.load_verify().require_native_patch_marker(marker)

    def test_updates_only_the_brotli_requirement(self):
        original = '[project]\nname = "example"\nversion = "1"\n[project.optional-dependencies]\nmessaging = ["aiohttp==3.14.5", "brotlicffi==1.2.0.2"]\n'
        patched, changed = self.load().rewrite_brotlicffi_pin(original, "1.2.1.0")
        self.assertTrue(changed)
        self.assertEqual(patched, original.replace("brotlicffi==1.2.0.2", "brotlicffi==1.2.1.0"))

    def test_is_idempotent(self):
        original = '[project]\ndependencies = ["brotlicffi==1.2.1.0"]\n'
        self.assertEqual(self.load().rewrite_brotlicffi_pin(original, "1.2.1.0"), (original, False))

    def test_refuses_downgrade(self):
        original = '[project]\ndependencies = ["brotlicffi==1.3.0.0"]\n'
        with self.assertRaisesRegex(ValueError, "downgrade"):
            self.load().rewrite_brotlicffi_pin(original, "1.2.1.0")

    def test_refuses_vulnerable_target(self):
        with self.assertRaisesRegex(ValueError, "fixed"):
            self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ["brotlicffi==1.2.0.2"]\n', "1.2.0.2")

    def test_refuses_missing_or_ambiguous_pin(self):
        for deps in ('["requests==2.33.0"]', '["brotlicffi==1.2.0.2", "brotlicffi==1.2.0.2"]'):
            with self.subTest(deps=deps), self.assertRaisesRegex(ValueError, "exactly one"):
                self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ' + deps + '\n', "1.2.1.0")

    def test_rejects_invalid_target(self):
        with self.assertRaisesRegex(ValueError, "version"):
            self.load().rewrite_brotlicffi_pin('[project]\ndependencies = ["brotlicffi==1.2.0.2"]\n', "1.2.1.0; bad")
    def test_security_exception_is_narrow(self):
        original = '[tool.uv]\nexclude-newer = "3 days"\nexclude-newer-package = { certifi = false }\n'
        updated = self.load().allow_brotli_security_release(original)
        import tomllib
        policy = tomllib.loads(updated)["tool"]["uv"]
        self.assertEqual(policy["exclude-newer"], "3 days")
        self.assertEqual(policy["exclude-newer-package"], {"certifi": False, "brotlicffi": False})
        self.assertEqual(self.load().allow_brotli_security_release(updated), updated)

    def test_does_not_add_a_policy_when_no_age_gate_exists(self):
        original = '[project]\nname = "example"\n'
        self.assertEqual(self.load().allow_brotli_security_release(original), original)

    def test_requires_review_for_an_existing_package_age_limit(self):
        original = '[tool.uv]\nexclude-newer = "3 days"\nexclude-newer-package = { brotlicffi = "5 days" }\n'
        with self.assertRaisesRegex(ValueError, "review"):
            self.load().allow_brotli_security_release(original)

    def test_lock_comparison_detects_artifact_changes(self):
        before = '[[package]]\nname = "example"\nversion = "1"\nwheels = [{url = "https://example.invalid/a.whl", hash = "sha256:abc"}]\n'
        after = before.replace("sha256:abc", "sha256:def")
        self.assertNotEqual(self.load().lock_identities(before), self.load().lock_identities(after))


if __name__ == "__main__":
    unittest.main()
