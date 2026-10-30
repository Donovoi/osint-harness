import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from backend_extensions.relay_cleanup import temporary_relay


class RelayCleanupTests(unittest.TestCase):
    def test_collector_failure_removes_partial_transfers(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / 'request.json'
            response = Path(directory) / 'response.json'
            with self.assertRaisesRegex(RuntimeError, 'collection failed'):
                with temporary_relay(request, response):
                    request.write_text('synthetic request')
                    response.write_text('partial synthetic response')
                    raise RuntimeError('collection failed')
            self.assertFalse(request.exists())
            self.assertFalse(response.exists())

    def test_unwritten_response_does_not_mask_original_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / 'request.json'
            response = Path(directory) / 'response.json'
            with self.assertRaisesRegex(ValueError, 'invalid capture'):
                with temporary_relay(request, response):
                    request.write_text('synthetic request')
                    raise ValueError('invalid capture')
            self.assertFalse(request.exists())

    def test_failed_first_removal_still_attempts_second_and_surfaces_error(self):
        request, response = Mock(), Mock()
        request.unlink.side_effect = PermissionError()
        with self.assertRaisesRegex(RuntimeError, 'Transfer cleanup incomplete'):
            with temporary_relay(request, response):
                pass
        response.unlink.assert_called_once_with(missing_ok=True)


if __name__ == '__main__':
    unittest.main()
