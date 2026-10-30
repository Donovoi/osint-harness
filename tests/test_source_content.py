import unittest
from backend_extensions.source_content import is_access_wall, is_unverified_upload, readable_content, source_provenance


class SourceContentTests(unittest.TestCase):
    def setUp(self):
        self.upload = dict(reference='local:record', origin='operator_supplied', http_status=0, curl_exit=0)

    def test_unverified_upload_can_be_read_without_becoming_network_evidence(self):
        self.assertTrue(readable_content(self.upload))
        provenance = source_provenance(self.upload)
        self.assertEqual(provenance['reported_http_status'], 0)
        self.assertFalse(provenance['verified_successful_network_capture'])

    def test_reference_and_origin_are_both_required(self):
        for change in ({'reference':'url:https://example.com/'}, {'reference':None}, {'origin':'whonix_network_capture'}, {'origin':None}):
            with self.subTest(change=change):
                self.assertFalse(is_unverified_upload(dict(self.upload, **change)))
                self.assertFalse(readable_content(dict(self.upload, **change)))

    def test_failed_and_partial_captures_stay_unavailable(self):
        for status, error in ((403,0),(404,0),(200,28),(0,28)):
            with self.subTest(status=status,error=error):
                self.assertFalse(readable_content(dict(self.upload,http_status=status,curl_exit=error)))

    def test_successful_network_capture_keeps_its_distinct_provenance(self):
        capture=dict(reference='url:https://example.com/',origin='whonix_network_capture',http_status=200,curl_exit=0)
        self.assertTrue(readable_content(capture))
        self.assertTrue(source_provenance(capture)['verified_successful_network_capture'])

    def test_access_wall_text_is_not_an_absence_verdict(self):
        self.assertTrue(is_access_wall('<h1>Sign in to continue.</h1>'))
        self.assertTrue(is_access_wall('Complete the CAPTCHA'))
        self.assertFalse(is_access_wall('Account qf731 does not exist.'))


if __name__ == '__main__':
    unittest.main()
