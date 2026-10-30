import unittest
from unittest.mock import Mock
from backend_extensions.model_lifecycle import cleanup_owned_session, stop_owned_model

class ModelLifecycleTests(unittest.TestCase):
    def test_preexisting_running_model_is_preserved(self):
        ssh=Mock(side_effect=AssertionError('Must not touch a model this session did not start'))
        self.assertFalse(stop_owned_model('current',False,ssh)['model_stop_required'])
    def test_owned_running_model_is_stopped_and_read_back(self):
        ssh=Mock(side_effect=['running','osint-model-current','exited'])
        self.assertTrue(stop_owned_model('current',True,ssh)['owned_model_stopped'])
        self.assertEqual(ssh.call_args_list[1].args[0],'docker stop --time 15 osint-model-current')
    def test_unexpected_state_is_not_success(self):
        with self.assertRaises(RuntimeError):stop_owned_model('current',True,Mock(return_value='paused'))
    def test_empty_inspection_is_not_success(self):
        with self.assertRaises(RuntimeError):stop_owned_model('current',True,Mock(return_value=''))
    def test_initial_inspection_errors_are_not_suppressed(self):
        ssh=Mock(side_effect=RuntimeError('Docker unavailable'))
        with self.assertRaises(RuntimeError):stop_owned_model('current',True,ssh)
        ssh.assert_called_once_with('docker inspect osint-model-current --format={{.State.Status}}')
    def test_model_cleanup_runs_after_collection_cleanup_error(self):
        ssh=Mock(return_value='exited')
        with self.assertRaises(RuntimeError):cleanup_owned_session(Mock(side_effect=RuntimeError('failure')),'current',True,ssh)
        ssh.assert_called_once()
    def test_model_cleanup_failure_blocks_success_receipt(self):
        cleanup=Mock()
        with self.assertRaises(RuntimeError):cleanup_owned_session(cleanup,'current',True,Mock(side_effect=TimeoutError()))
        cleanup.assert_called_once()

if __name__=='__main__':unittest.main()
