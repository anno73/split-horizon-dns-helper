import contextlib
import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name('split-dns-helper.py')
MODULE_SPEC = importlib.util.spec_from_file_location('split_dns_helper', MODULE_PATH)
helper = importlib.util.module_from_spec(MODULE_SPEC)
sys.modules[MODULE_SPEC.name] = helper
MODULE_SPEC.loader.exec_module(helper)


class CustomFilteringRulesTests(unittest.TestCase):
    class FakeResponse:
        def __init__(self, body=b''):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def read(self):
            return self.body

    def test_builds_qnap_a_only_rules_in_explanatory_marked_block(self):
        rule_map = helper.build_custom_filtering_rule_map({
            '192.168.2.9': [
                'traefik.backup.hubmann.casa',
                'backup.hubmann.casa',
            ],
        })

        self.assertEqual(
            helper.build_custom_filtering_rule_block(rule_map),
            [
                helper.CUSTOM_FILTERING_RULES_START,
                helper.CUSTOM_FILTERING_RULES_REASON,
                '|backup.hubmann.casa|$dnsrewrite=NOERROR;A;192.168.2.9,dnstype=A',
                '|traefik.backup.hubmann.casa|$dnsrewrite=NOERROR;A;192.168.2.9,dnstype=A',
                helper.CUSTOM_FILTERING_RULES_END,
            ],
        )

    def test_reconciles_owned_block_and_preserves_unmanaged_rules(self):
        current_rules = [
            '! user rule before',
            helper.CUSTOM_FILTERING_RULES_START,
            helper.CUSTOM_FILTERING_RULES_REASON,
            '|old.example.com|$dnsrewrite=NOERROR;A;192.168.1.2,dnstype=A',
            helper.CUSTOM_FILTERING_RULES_END,
            '! user rule after',
        ]
        desired_map = {'new.example.com': '192.168.1.3'}

        reconciled = helper.reconcile_custom_filtering_rules(current_rules, desired_map)

        self.assertEqual(reconciled[0], '! user rule before')
        self.assertEqual(reconciled[-1], '! user rule after')
        self.assertIn(
            '|new.example.com|$dnsrewrite=NOERROR;A;192.168.1.3,dnstype=A',
            reconciled,
        )
        self.assertNotIn(
            '|old.example.com|$dnsrewrite=NOERROR;A;192.168.1.2,dnstype=A',
            reconciled,
        )

    def test_empty_config_removes_only_the_owned_block(self):
        current_rules = [
            '! preserved',
            helper.CUSTOM_FILTERING_RULES_START,
            helper.CUSTOM_FILTERING_RULES_REASON,
            '|old.example.com|$dnsrewrite=NOERROR;A;192.168.1.2,dnstype=A',
            helper.CUSTOM_FILTERING_RULES_END,
            '! also preserved',
        ]

        self.assertEqual(
            helper.reconcile_custom_filtering_rules(current_rules, {}),
            ['! preserved', '! also preserved'],
        )

    def test_rejects_malformed_owned_block(self):
        with self.assertRaisesRegex(ValueError, 'Unmatched'):
            helper.reconcile_custom_filtering_rules(
                [helper.CUSTOM_FILTERING_RULES_START, '! incomplete'],
                {},
            )

    def test_detects_case_insensitive_hostname_overlap(self):
        config = {
            'permanent': {'192.168.2.9': ['Traefik.Backup.Hubmann.Casa']},
            'custom_filtering_rules': {
                '192.168.2.9': ['traefik.backup.hubmann.casa'],
            },
        }

        self.assertEqual(
            helper.find_custom_filtering_rule_conflicts(config),
            ['traefik.backup.hubmann.casa'],
        )
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaisesRegex(ValueError, 'Remove overlapping hostnames'):
                helper.validate_custom_filtering_rule_conflicts(config)
        self.assertIn('Warning:', stderr.getvalue())

    def test_sync_updates_custom_rules_and_preserves_existing_user_rules(self):
        config = {
            'permanent': {},
            'custom_filtering_rules': {'192.168.2.9': ['backup.example.com']},
        }
        agh_config = {'type': 'adguardhome'}
        managed_rules = helper.build_custom_filtering_rule_block({
            'backup.example.com': '192.168.2.9',
        })
        expected_rules = ['! existing user rule', ''] + managed_rules

        with (
            patch.object(helper, 'find_agh_config', return_value=agh_config),
            patch.object(helper, 'fetch_agh_dns_rewrites', return_value=[]),
            patch.object(helper, 'fetch_agh_custom_filtering_rules', return_value=['! existing user rule']) as fetch_rules,
            patch.object(helper, 'set_agh_custom_filtering_rules') as set_rules,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            helper.command_sync(config, dry_run=False)

        fetch_rules.assert_called_once_with(agh_config)
        set_rules.assert_called_once_with(agh_config, expected_rules)

    def test_sync_dry_run_does_not_update_custom_rules(self):
        config = {
            'permanent': {},
            'custom_filtering_rules': {'192.168.2.9': ['backup.example.com']},
        }

        with (
            patch.object(helper, 'find_agh_config', return_value={'type': 'adguardhome'}),
            patch.object(helper, 'fetch_agh_dns_rewrites', return_value=[]),
            patch.object(helper, 'fetch_agh_custom_filtering_rules', return_value=[]),
            patch.object(helper, 'set_agh_custom_filtering_rules') as set_rules,
            contextlib.redirect_stdout(io.StringIO()) as stdout,
        ):
            helper.command_sync(config, dry_run=True)

        set_rules.assert_not_called()
        self.assertIn('Would update AdGuard Home custom filtering rules', stdout.getvalue())

    def test_sync_does_not_create_dns_rewrite_for_custom_managed_source_host(self):
        config = {
            'permanent': {},
            'source': {
                'backup': {
                    'type': 'traefik_api',
                    'default_target': '192.168.2.9',
                },
            },
            'custom_filtering_rules': {'192.168.2.9': ['backup.example.com']},
        }

        with (
            patch.object(helper, 'find_agh_config', return_value={'type': 'adguardhome'}),
            patch.object(helper, 'fetch_agh_dns_rewrites', return_value=[]),
            patch.object(helper, 'fetch_agh_custom_filtering_rules', return_value=[]),
            patch.object(helper, 'merge_traefik_data', return_value=[
                {'source': 'backup', 'hostnames': ['backup.example.com']},
            ]),
            patch.object(helper, 'set_agh_custom_filtering_rules'),
            patch.object(helper, 'add_agh_rewrite') as add_rewrite,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            helper.command_sync(config, dry_run=False)

        add_rewrite.assert_not_called()

    def test_add_rejects_host_managed_by_custom_filtering_rules(self):
        config = {
            'permanent': {},
            'custom_filtering_rules': {'192.168.2.9': ['backup.example.com']},
        }
        with (
            patch.object(helper, 'fetch_agh_dns_rewrites') as fetch_rewrites,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                helper.command_add(config, SimpleNamespace(
                    domain='BACKUP.EXAMPLE.COM',
                    target='192.168.2.9',
                ))

        fetch_rewrites.assert_not_called()

    def test_filtering_api_uses_status_and_set_rules_endpoints(self):
        agh_config = {
            'url': 'https://adguard.example.test/',
            'api_user': 'user',
            'api_password': 'secret',
            'ignore_tls_errors': True,
        }
        with patch.object(
            helper,
            'urlopen',
            return_value=self.FakeResponse(b'{"user_rules":["! existing"]}'),
        ) as urlopen:
            rules = helper.fetch_agh_custom_filtering_rules(agh_config)
        status_request = urlopen.call_args.args[0]
        self.assertEqual(status_request.full_url, 'https://adguard.example.test/control/filtering/status')
        self.assertEqual(status_request.get_method(), 'GET')
        self.assertEqual(rules, ['! existing'])

        desired_rules = ['! BEGIN split-dns-helper managed custom filtering rules']
        with patch.object(helper, 'urlopen', return_value=self.FakeResponse()) as urlopen:
            helper.set_agh_custom_filtering_rules(agh_config, desired_rules)
        set_rules_request = urlopen.call_args.args[0]
        self.assertEqual(
            set_rules_request.full_url,
            'https://adguard.example.test/control/filtering/set_rules',
        )
        self.assertEqual(set_rules_request.get_method(), 'POST')
        self.assertEqual(json.loads(set_rules_request.data), {'rules': desired_rules})

    def test_main_aborts_on_collision_before_api_calls(self):
        config = {
            'permanent': {'192.168.2.9': ['duplicate.example.com']},
            'custom_filtering_rules': {
                '192.168.2.9': ['duplicate.example.com'],
            },
        }
        with (
            patch.object(sys, 'argv', ['dsh', 'sync']),
            patch.object(helper, 'load_config', return_value=config),
            patch.object(helper, 'fetch_agh_dns_rewrites') as fetch_rewrites,
            patch.object(helper, 'fetch_agh_custom_filtering_rules') as fetch_rules,
            contextlib.redirect_stderr(io.StringIO()) as stderr,
        ):
            with self.assertRaises(SystemExit):
                helper.main()

        fetch_rewrites.assert_not_called()
        fetch_rules.assert_not_called()
        self.assertIn('Warning:', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
