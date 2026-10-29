import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("relay_config", ROOT / "lib" / "config.py")
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


def wireguard_key(number):
    return base64.b64encode(bytes([number]) * 32).decode("ascii")


def valid_bundle():
    return {
        "version": 1,
        "endpoint": "8.8.8.8:51888",
        "server_public_key": wireguard_key(1),
        "antizapret_private_key": wireguard_key(2),
        "antizapret_address": "10.203.240.2/32",
        "vpn_private_key": wireguard_key(3),
        "vpn_address": "10.203.240.3/32",
    }


class TemporaryFiles(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def write_json(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path


class BundleValidationTests(TemporaryFiles):
    def test_valid_bundle_has_exact_six_line_contract(self):
        value = valid_bundle()
        bundle = self.write_json("bundle.json", value)
        result = subprocess.run([sys.executable, str(ROOT / "lib" / "config.py"), "validate-bundle", str(bundle)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [value[name] for name in config.FIELDS])

    def test_invalid_bundle_values_are_rejected(self):
        cases = [
            ("version", True), ("version", 2),
            ("endpoint", "localhost:51888"), ("endpoint", "127.0.0.1:51888"),
            ("endpoint", "10.1.1.1:51888"), ("endpoint", "224.0.0.1:51888"),
            ("endpoint", "8.8.8.8:0"), ("endpoint", "8.8.8.8:65536"),
            ("endpoint", "8.8.8.8:01234"),
            ("endpoint", "8.8.8.8:51888\nPostUp = evil"),
            ("endpoint", "$(touch /tmp/owned):51888"),
            ("server_public_key", wireguard_key(0)),
            ("server_public_key", "A" * 43 + "="),
            ("server_public_key", wireguard_key(1) + "\n"),
            ("antizapret_private_key", "$(id)"),
            ("vpn_private_key", wireguard_key(2)),
            ("vpn_address", "10.203.240.2/32"),
            ("vpn_address", "10.203.241.3/32"),
            ("vpn_address", "10.203.240.3/24"),
            ("vpn_address", "8.8.8.8/32"),
            ("vpn_address", "10.29.8.2/32"),
            ("vpn_address", "10.30.8.2/32"),
            ("vpn_address", "172.28.8.2/32"),
            ("vpn_address", "10.203.240.255/32"),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                bundle = valid_bundle()
                bundle[field] = value
                path = self.write_json("invalid.json", bundle)
                with self.assertRaises(config.ConfigError):
                    config.validate_bundle(path)

    def test_unknown_missing_and_duplicate_fields_fail(self):
        value = valid_bundle()
        value["post_up"] = "evil"
        with self.assertRaises(config.ConfigError):
            config.validate_bundle(self.write_json("unknown.json", value))
        del value["post_up"]
        del value["vpn_address"]
        with self.assertRaises(config.ConfigError):
            config.validate_bundle(self.write_json("missing.json", value))
        path = self.root / "duplicate.json"
        path.write_text('{"version":1,"version":1}', encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.validate_bundle(path)

    def test_different_private_encodings_of_same_x25519_key_are_rejected(self):
        value = valid_bundle()
        same_scalar = bytearray(base64.b64decode(value["antizapret_private_key"]))
        same_scalar[0] ^= 1
        value["vpn_private_key"] = base64.b64encode(same_scalar).decode("ascii")
        with self.assertRaises(config.ConfigError):
            config.validate_bundle(self.write_json("same-effective-key.json", value))

    def test_failure_prints_no_private_key_or_partial_bundle(self):
        value = valid_bundle()
        value["vpn_address"] = "invalid"
        path = self.write_json("invalid.json", value)
        result = subprocess.run([sys.executable, str(ROOT / "lib" / "config.py"), "validate-bundle", str(path)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertNotIn(value["antizapret_private_key"], result.stderr)
        self.assertNotIn(value["vpn_private_key"], result.stderr)

    def test_transit_routes_reject_overlapping_host_network_or_broad_route(self):
        bundle = self.write_json("bundle.json", valid_bundle())
        for destination in ("10.203.240.1", "10.203.240.0/24", "10.0.0.0/8"):
            with self.subTest(destination=destination):
                routes = self.write_json("routes.json", [{"dst": "default"}, {"dst": destination}])
                with self.assertRaises(config.ConfigError):
                    config.check_routes(bundle, routes)
        routes = self.write_json("routes.json", [{"dst": "default"}, {"dst": "10.29.0.0/16"}, {"dst": "198.18.0.0/15"}, {"dst": "10.203.241.0/24"}])
        config.check_routes(bundle, routes)

    def test_malformed_route_inventory_is_rejected(self):
        bundle = self.write_json("bundle.json", valid_bundle())
        for value in ({"dst": "default"}, [None], [{"dst": "invalid"}]):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                config.check_routes(bundle, self.write_json("routes.json", value))


class SetupTransactionTests(TemporaryFiles):
    def setUp(self):
        super().setUp()
        self.setup = self.root / "setup"
        self.backup = self.root / "backup.json"
        self.original = "# settings\nANTIZAPRET_WARP=1 # original mode\nUNRELATED='keep me'\nVPN_WARP=2\n"
        self.setup.write_text(self.original, encoding="utf-8")
        self.changes = self.write_json("changes.json", {
            "ANTIZAPRET_WARP": "4", "WARP_PROTECTION": "y",
            "ANTIZAPRET_WARP_ENDPOINT": "8.8.8.8:51888",
        })

    def apply(self):
        config.apply_setup(self.setup, self.backup, self.changes)

    def test_apply_and_restore_preserve_unrelated_new_settings(self):
        self.apply()
        updated = self.setup.read_text(encoding="utf-8")
        self.assertIn("ANTIZAPRET_WARP=4\n", updated)
        self.assertIn("UNRELATED='keep me'\n", updated)
        self.assertIn("VPN_WARP=2\n", updated)
        self.setup.write_text(updated.replace("'keep me'", "'edited later'") + "NEW_VARIABLE=42\n", encoding="utf-8")
        config.restore_setup(self.setup, self.backup)
        restored = self.setup.read_text(encoding="utf-8")
        self.assertIn("ANTIZAPRET_WARP=1 # original mode\n", restored)
        self.assertIn("UNRELATED='edited later'\n", restored)
        self.assertIn("NEW_VARIABLE=42\n", restored)
        self.assertNotIn("ANTIZAPRET_WARP_ENDPOINT=", restored)
        self.assertNotIn("WARP_PROTECTION=", restored)
        config.restore_setup(self.setup, self.backup)
        self.assertEqual(self.setup.read_text(encoding="utf-8"), restored)

    def test_duplicate_managed_keys_abort_without_touching_files(self):
        self.setup.write_text(self.original + "export ANTIZAPRET_WARP=2\n", encoding="utf-8")
        before = self.setup.read_bytes()
        with self.assertRaises(config.ConfigError):
            self.apply()
        self.assertEqual(self.setup.read_bytes(), before)
        self.assertFalse(self.backup.exists())

    def test_reapply_never_overwrites_original_backup(self):
        self.apply()
        original_backup = self.backup.read_bytes()
        current_setup = self.setup.read_bytes()
        with self.assertRaises(config.ConfigError):
            self.apply()
        self.assertEqual(self.backup.read_bytes(), original_backup)
        self.assertEqual(self.setup.read_bytes(), current_setup)

    def test_stale_managed_config_does_not_partially_restore(self):
        self.apply()
        self.setup.write_text(self.setup.read_text(encoding="utf-8").replace("ANTIZAPRET_WARP=4", "ANTIZAPRET_WARP=3"), encoding="utf-8")
        stale = self.setup.read_bytes()
        with self.assertRaises(config.ConfigError):
            config.restore_setup(self.setup, self.backup)
        self.assertEqual(self.setup.read_bytes(), stale)

    def test_check_restore_validates_without_writes(self):
        self.apply()
        before = self.setup.read_bytes()
        config.restore_setup(self.setup, self.backup, check_only=True)
        self.assertEqual(self.setup.read_bytes(), before)
        self.setup.write_text(self.setup.read_text(encoding="utf-8").replace("ANTIZAPRET_WARP=4", "ANTIZAPRET_WARP=3"), encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.restore_setup(self.setup, self.backup, check_only=True)

    def test_restore_missing_final_newline_does_not_join_later_assignments(self):
        self.setup.write_text("ANTIZAPRET_WARP=1", encoding="utf-8")
        self.apply()
        with self.setup.open("a", encoding="utf-8") as handle:
            handle.write("LATER_SETTING=42\n")
        config.restore_setup(self.setup, self.backup)
        self.assertEqual(self.setup.read_text(encoding="utf-8"), "ANTIZAPRET_WARP=1\nLATER_SETTING=42\n")

    def test_shell_injection_and_unmanaged_changes_fail_without_writes(self):
        for changes in (
            {"ANTIZAPRET_WARP_ENDPOINT": "8.8.8.8:51888\nBAD=$(id)"},
            {"ANTIZAPRET_WARP_PRIVATE_KEY": "$(touch /tmp/pwned)"},
            {"UNRELATED": "edited"}, {"DNS_WARP": "y"},
            {"WARP_PROTECTION": "n"}, {"WARP_MTU": "1279"},
        ):
            with self.subTest(changes=changes):
                changes_path = self.write_json("bad.json", changes)
                with self.assertRaises(config.ConfigError):
                    config.apply_setup(self.setup, self.backup, changes_path)
                self.assertEqual(self.setup.read_text(encoding="utf-8"), self.original)
                self.assertFalse(self.backup.exists())

    def test_corrupt_backup_is_not_executed_or_written_to_setup(self):
        self.apply()
        backup = json.loads(self.backup.read_text(encoding="utf-8"))
        backup["original"]["ANTIZAPRET_WARP"] = "ANTIZAPRET_WARP=1\nBAD=$(id)\n"
        self.backup.write_text(json.dumps(backup), encoding="utf-8")
        before = self.setup.read_bytes()
        with self.assertRaises(config.ConfigError):
            config.restore_setup(self.setup, self.backup)
        self.assertEqual(self.setup.read_bytes(), before)

    @unittest.skipIf(os.name == "nt", "Windows does not expose Unix chmod semantics")
    def test_private_files_have_mode_600(self):
        self.apply()
        self.assertEqual(self.setup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o600)


class DomainListTests(TemporaryFiles):
    def test_url_idna_and_case_are_normalized(self):
        self.assertEqual(config.normalize_domain("https://old.yummyani.me/"), "old.yummyani.me")
        self.assertEqual(config.normalize_domain("Example.COM."), "example.com")
        self.assertEqual(config.normalize_domain("сайт.рф"), "xn--80aswg.xn--p1ai")

    def test_broad_invalid_or_injected_domains_are_rejected(self):
        for value in (".", "com", "*.example.com", "-bad.example", "bad-.example", "127.0.0.1", "example.com:443", "example.com\nBAD=1", "https://example.com\n/", "https://user:pass@example.com/", "https://example.com:443/", "https://example.com/path", "https://example.com/?a=1", "$(id).com", "example..com"):
            with self.subTest(value=value), self.assertRaises(config.ConfigError):
                config.normalize_domain(value)

    def test_duplicate_add_and_exact_drop_preserve_comments_and_subdomains(self):
        path = self.root / "relay-include-warp-hosts.txt"
        path.write_text("# custom relay\nexample.com\nsub.example.com\n", encoding="utf-8")
        config.domains("domain-add", path, "https://EXAMPLE.com/")
        self.assertEqual(path.read_text(encoding="utf-8").count("\nexample.com\n"), 1)
        config.domains("domain-add", path, "old.yummyani.me")
        config.domains("domain-drop", path, "example.com")
        self.assertEqual(config.domains("domain-list", path), ["old.yummyani.me", "sub.example.com"])
        self.assertIn("# custom relay\n", path.read_text(encoding="utf-8"))

    def test_invalid_list_update_does_not_write(self):
        path = self.root / "relay-include-warp-hosts.txt"
        path.write_text("# keep\nexample.com\n", encoding="utf-8")
        before = path.read_bytes()
        with self.assertRaises(config.ConfigError):
            config.domains("domain-add", path, "*.example.com")
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
