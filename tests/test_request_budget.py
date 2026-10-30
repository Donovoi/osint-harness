import json
from pathlib import Path
import tempfile
import unittest

from backend_extensions.request_budget import budget_snapshot, budget_text, read_budget, report_views


class RequestBudgetTests(unittest.TestCase):
    def test_exhausted_case_cannot_claim_another_url(self):
        state = budget_snapshot({'max_urls': 1}, {'requested_urls': ['https://example.com/']})
        self.assertEqual((state['used_unique_urls'], state['remaining_unique_urls']), (1, 0))
        self.assertFalse(state['additional_unique_urls_available'])
        self.assertIn('No additional unique URLs', budget_text(state))

    def test_duplicates_failed_captures_and_tool_results(self):
        state = budget_snapshot({'max_urls': 3}, {
            'requested_urls': ['https://example.com/', 'https://example.com/'],
            'captures': [{'http_status': 500}],
            'observed_links': ['https://example.com/other'],
            'uploads': ['file.pdf'], 'tools': ['ocr']})
        self.assertEqual((state['used_unique_urls'], state['remaining_unique_urls']), (1, 2))

    def test_unknown_or_malformed_is_not_free_budget(self):
        for ledger in (None, [], {'captures': []}, {'requested_urls': 'url'}, {'requested_urls': [None]}):
            with self.subTest(ledger=ledger):
                state = budget_snapshot({'max_urls': 1}, ledger)
                self.assertIsNone(state['remaining_unique_urls'])
                self.assertFalse(state['additional_unique_urls_available'])

    def test_missing_or_invalid_file_remains_unknown(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'ledger.json'
            for raw in (None, b'not json'):
                if raw is not None:
                    path.write_bytes(raw)
                self.assertEqual(read_budget({}, path)['status'], 'unavailable')
            path.write_text(json.dumps({'requested_urls': ['https://example.com/']}))
            self.assertEqual(len(read_budget({}, path)['ledger_sha256']), 64)

    def test_empty_preflight_ledger_and_limit_cap(self):
        self.assertEqual(budget_snapshot({'max_urls': 100}, {})['remaining_unique_urls'], 40)
        self.assertEqual(budget_snapshot({}, {})['maximum_unique_urls'], 30)
        for limit in (True, '2', -1):
            self.assertEqual(budget_snapshot({'max_urls': limit}, {})['status'], 'unavailable')

    def test_over_budget_never_becomes_negative(self):
        state = budget_snapshot({'max_urls': 0}, {'requested_urls': ['https://example.com/']})
        self.assertEqual(state['status'], 'over_budget')
        self.assertEqual(state['remaining_unique_urls'], 0)
        self.assertFalse(state['additional_unique_urls_available'])

    def test_legacy_report_is_preserved_with_explicit_correction(self):
        original = '<p>One unique URL budget remains.</p>'
        state = budget_snapshot({'max_urls': 1}, {'requested_urls': ['https://example.com/']})
        rendered, markdown = report_views(original, 'Original output', state)
        self.assertTrue(rendered.endswith(original))
        self.assertTrue(markdown.endswith('Original output'))
        self.assertIn('1 used / 1 maximum; 0 remaining', rendered)
        self.assertIn('override any conflicting model statement', rendered)
