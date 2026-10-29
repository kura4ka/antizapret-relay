"""Bundled WARP defaults must be excluded without losing user configuration."""

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('exclusion_config', ROOT / 'lib/config.py')
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)


class DefaultExclusionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.download = self.root / 'download'
        self.download.mkdir()
        self.target = self.root / 'exclude-warp-hosts.txt'
        self.output = self.root / 'staged-excludes.txt'
        self.metadata = self.root / 'before.json'

    def defaults(self, text='cloudflare.com\nstun.cloudflare.com\n', name='include-warp-hosts.txt'):
        path = self.download / name
        path.write_bytes(text.encode('utf-8'))
        return path

    def prepare(self):
        config.prepare_default_exclusions(self.download, self.target, self.output, self.metadata)

    def apply(self):
        self.prepare()
        config.apply_default_exclusions(self.target, self.metadata)

    def test_all_bundled_files_are_merged_and_user_input_is_untouched_when_staging(self):
        first = self.defaults('# shipped\n Cloudflare.COM\r\nstun.cloudflare.com\n')
        second = self.defaults('stun.cloudflare.com\n turn.l.google.com # inline comment\nCOM\n', 'extra-include-warp-hosts.txt')
        unrelated = self.defaults('never.example\n', 'not-a-warp-list.txt')
        self.target.write_bytes(b'# custom\ncustom.example\nCloudflare.COM\n')
        user_include = self.root / 'include-warp-hosts.txt'
        user_include.write_bytes(b'my.example\n')
        originals = {path: path.read_bytes() for path in (first, second, unrelated, self.target, user_include)}
        self.prepare()
        metadata = json.loads(self.metadata.read_text())
        self.assertEqual(metadata['added'], ['com', 'stun.cloudflare.com', 'turn.l.google.com'])
        self.assertEqual(self.output.read_text().count('Cloudflare.COM'), 1)
        self.assertTrue(self.output.read_text().startswith(originals[self.target].decode()))
        for path, before in originals.items():
            self.assertEqual(path.read_bytes(), before)

    def test_existing_exclusions_and_comments_survive_apply_and_exact_uninstall(self):
        self.defaults()
        original = b'# My settings\r\ncustom.example\r\nSTUN.CLOUDFLARE.COM # already excluded\r\n'
        self.target.write_bytes(original)
        self.apply()
        self.assertEqual(json.loads(self.metadata.read_text())['added'], ['cloudflare.com'])
        self.assertTrue(self.target.read_bytes().startswith(original))
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), original)

    def test_explicit_include_does_not_silently_override_an_automatic_exclusion(self):
        self.defaults()
        user_include = self.root / 'include-warp-hosts.txt'
        user_include.write_text('cloudflare.com\nmy.example\n')
        self.apply()
        self.assertIn('\ncloudflare.com\n', self.target.read_text())
        self.assertEqual(user_include.read_text(), 'cloudflare.com\nmy.example\n')

    def test_missing_default_files_fail_before_any_output_or_live_edit(self):
        self.target.write_text('keep.example\n')
        with self.assertRaises(config.ConfigError):
            self.prepare()
        self.assertEqual(self.target.read_text(), 'keep.example\n')
        self.assertFalse(self.output.exists())
        self.assertFalse(self.metadata.exists())

    def test_invalid_and_catchall_defaults_fail_before_outputs(self):
        for text in ('.\n', 'bad..example\n', '192.0.2.1\n', 'сайт.рф\n'):
            with self.subTest(text=text):
                self.defaults(text)
                with self.assertRaises(config.ConfigError):
                    self.prepare()
                self.assertFalse(self.target.exists())
                self.assertFalse(self.metadata.exists())
                self.assertFalse(self.output.exists())

    def test_native_comments_punctuation_and_punycode_are_handled(self):
        self.defaults('# comment\n; another ignored line\n*.ignored.example\n\n'
                      'XN--80ASWG.XN--P1AI\n clean.example/path\nclean.example\n')
        self.prepare()
        self.assertEqual(json.loads(self.metadata.read_text())['added'],
                         ['clean.example', 'xn--80aswg.xn--p1ai'])

    def test_empty_bundled_file_does_not_create_missing_native_list(self):
        self.defaults('# empty list\n')
        self.apply()
        self.assertFalse(self.target.exists())
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertFalse(self.target.exists())

    def test_rollback_restores_original_missing_file_and_missing_final_newline(self):
        self.defaults()
        self.apply()
        self.assertTrue(self.target.exists())
        config.restore_default_exclusions(self.target, self.metadata, rollback=True)
        self.assertFalse(self.target.exists())
        self.output.unlink()
        self.metadata.unlink()
        self.target.write_bytes(b'# originally no final newline')
        self.apply()
        config.restore_default_exclusions(self.target, self.metadata, rollback=True)
        self.assertEqual(self.target.read_bytes(), b'# originally no final newline')

    def test_prepare_refuses_existing_backup_or_managed_block(self):
        self.defaults()
        self.apply()
        before = self.target.read_bytes()
        with self.assertRaises(config.ConfigError):
            self.prepare()
        self.assertEqual(self.target.read_bytes(), before)
        self.output.unlink()
        self.metadata.unlink()
        with self.assertRaises(config.ConfigError):
            self.prepare()
        self.assertFalse(self.metadata.exists())

    def test_apply_is_idempotent_and_refuses_drift_after_staging(self):
        self.defaults()
        self.target.write_text('old.example\n')
        self.prepare()
        self.target.write_text('user-edited.example\n')
        with self.assertRaises(config.ConfigError):
            config.apply_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_text(), 'user-edited.example\n')
        self.target.write_text('old.example\n')
        config.apply_default_exclusions(self.target, self.metadata)
        applied = self.target.read_bytes()
        config.apply_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), applied)

    def test_uninstall_preserves_later_edits_inside_and_outside_block(self):
        self.defaults()
        self.target.write_text('# user config\ncustom.example\n')
        self.apply()
        current = self.target.read_text().replace('cloudflare.com\n', '', 1)
        current = current.replace(config.EXCLUSIONS_END, '# user note\nnew-inside.example\n' + config.EXCLUSIONS_END)
        current += 'new-outside.example\n'
        self.target.write_text(current)
        config.restore_default_exclusions(self.target, self.metadata, check_only=True)
        self.assertEqual(self.target.read_text(), current)
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_text(), '# user config\ncustom.example\n# user note\n'
                         'new-inside.example\nnew-outside.example\n')

    def test_uninstall_retains_manually_changed_owned_entries(self):
        self.defaults('cloudflare.com\n')
        self.apply()
        self.target.write_text(self.target.read_text().replace('cloudflare.com', 'CLOUDFLARE.COM # user changed'))
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_text(), 'CLOUDFLARE.COM # user changed\n')

    def test_removing_entire_block_is_respected_and_partial_markers_fail_safely(self):
        self.defaults()
        self.apply()
        applied = self.target.read_text()
        malformed = applied.replace(config.EXCLUSIONS_END, '# renamed marker')
        self.target.write_text(malformed)
        with self.assertRaises(config.ConfigError):
            config.restore_default_exclusions(self.target, self.metadata, check_only=True)
        self.assertEqual(self.target.read_text(), malformed)
        self.target.write_text('entirely-user-owned.example\n')
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertEqual(self.target.read_text(), 'entirely-user-owned.example\n')

    def test_rollback_refuses_user_drift_and_keeps_recovery_metadata(self):
        self.defaults()
        self.apply()
        self.target.write_text(self.target.read_text() + 'new-user.example\n')
        current = self.target.read_bytes()
        with self.assertRaises(config.ConfigError):
            config.restore_default_exclusions(self.target, self.metadata, rollback=True)
        self.assertEqual(self.target.read_bytes(), current)
        self.assertTrue(self.metadata.exists())

    def test_metadata_cannot_claim_preexisting_entries_or_another_target(self):
        self.defaults()
        self.target.write_text('custom.example\n')
        self.prepare()
        valid = json.loads(self.metadata.read_text())
        for updates in ({'added': ['custom.example']}, {'target': '/some/other/file'},
                        {'added': ['$(touch /tmp/file)']}, {'mode': 0o4755}, {'version': True}):
            with self.subTest(updates=updates):
                self.metadata.write_text(json.dumps({**valid, **updates}))
                with self.assertRaises(config.ConfigError):
                    config.apply_default_exclusions(self.target, self.metadata)
                self.assertEqual(self.target.read_text(), 'custom.example\n')

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits are not preserved on Windows')
    def test_apply_and_restore_keep_original_file_permissions(self):
        self.defaults()
        self.target.write_text('custom.example\n')
        self.target.chmod(0o640)
        self.apply()
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        config.restore_default_exclusions(self.target, self.metadata)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)

    @unittest.skipIf(os.name == 'nt', 'Creating symlinks may require extra Windows privileges')
    def test_targets_and_metadata_symlinks_are_rejected(self):
        self.defaults()
        other = self.root / 'other.txt'
        other.write_text('do-not-change.example\n')
        self.target.symlink_to(other)
        with self.assertRaises(config.ConfigError):
            self.prepare()
        self.assertEqual(other.read_text(), 'do-not-change.example\n')
        self.target.unlink()
        self.apply()
        metadata_text = self.metadata.read_text()
        self.metadata.unlink()
        other.write_text(metadata_text)
        self.metadata.symlink_to(other)
        with self.assertRaises(config.ConfigError):
            config.restore_default_exclusions(self.target, self.metadata)


if __name__ == '__main__':
    unittest.main()
