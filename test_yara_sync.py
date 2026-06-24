import unittest
from unittest.mock import patch, MagicMock
import os
import shutil
import json
import io
import zipfile
from core.yara_sync import YaraRuleSync

class TestYaraRuleSync(unittest.TestCase):
    def setUp(self):
        self.test_rules_dir = "test_yara_rules"
        self.sync_tool = YaraRuleSync(rules_dir=self.test_rules_dir)
        if os.path.exists(self.test_rules_dir):
            shutil.rmtree(self.test_rules_dir)

    def tearDown(self):
        if os.path.exists(self.test_rules_dir):
            shutil.rmtree(self.test_rules_dir)

    @patch('requests.get')
    @patch('yara.compile')
    def test_sync_success(self, mock_yara_compile, mock_get):
        # Create a fake zip in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
            zip_file.writestr('rules-master/malware/test.yar', 'rule test { condition: true }')
            zip_file.writestr('rules-master/readme.txt', 'not a yara rule')
            zip_file.writestr('rules-master/broken.yar', 'rule broken { condition: error }')

        zip_buffer.seek(0)

        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': str(len(zip_buffer.getvalue()))}
        mock_response.iter_content.return_value = [zip_buffer.getvalue()]
        mock_get.return_value = mock_response

        # Mock yara.compile: succeed for test.yar, fail for broken.yar
        def side_effect(source=None, filepath=None):
            if source and 'error' in source:
                raise Exception("Yara compile error")
            return MagicMock()

        mock_yara_compile.side_effect = side_effect

        # Run sync
        manifest = self.sync_tool.sync()

        # Verify results
        self.assertEqual(manifest['file_count'], 1)
        self.assertEqual(len(manifest['skipped_files']), 1)
        self.assertTrue(os.path.exists(os.path.join(self.test_rules_dir, "malware/test.yar")))
        self.assertFalse(os.path.exists(os.path.join(self.test_rules_dir, "broken.yar")))

        manifest_path = os.path.join(self.test_rules_dir, ".sync_manifest.json")
        self.assertTrue(os.path.exists(manifest_path))
        with open(manifest_path, 'r') as f:
            data = json.load(f)
            self.assertEqual(data['file_count'], 1)

    @patch('requests.get')
    def test_sync_network_failure(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("Not Found")
        mock_get.return_value = mock_response

        with self.assertRaises(Exception):
            self.sync_tool.sync()

if __name__ == '__main__':
    unittest.main()
