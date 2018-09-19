import os
import os.path
import unittest
from unittest.mock import mock_open, patch, ANY
from nio_cli.utils.ssl import config_ssl


class TestConfigSSL(unittest.TestCase):

    def _run_config_ssl(self, user_input=None, isfile=True, kwargs={}):
        user_input = user_input or []
        with patch('builtins.open', mock_open()) as self.mock_open, \
                patch('builtins.input', side_effect=user_input) \
                as self.mock_input, \
                patch(config_ssl.__module__ + '.run') as self.mock_run, \
                patch(config_ssl.__module__ + '.isfile', return_value=isfile),\
                patch(config_ssl.__module__ + '.system',
                      # Assume we're running on a mac for unit tests
                      return_value='Darwin'), \
                patch(config_ssl.__module__ + '.ensure_dir_exists'):
            self.cert_path, self.key_path = config_ssl('.')

    def test_create_cert(self):
        self._run_config_ssl(user_input=[
            'etc/ssl/ca.crt',
            'etc/ssl/ca.key',
            'no',
            'localhost',
        ], isfile=False)
        self.assertEqual(
            self.cert_path,
            os.path.join('.', 'etc', 'ssl', 'cert.crt'))
        self.assertEqual(
            self.key_path,
            os.path.join('.', 'etc', 'ssl', 'cert.key'))
        self.mock_open.assert_any_call('./etc/ssl/cert.crt', 'wb')
        self.mock_open.assert_any_call('./etc/ssl/cert.key', 'wb')
        self.mock_run.assert_not_called()

    def test_create_and_trust_cert(self):
        self._run_config_ssl(user_input=[
            'etc/ssl/ca.crt',
            'etc/ssl/ca.key',
            'yes',
            'localhost',
        ], isfile=False)
        self.assertEqual(
            self.cert_path,
            os.path.join('.', 'etc', 'ssl', 'cert.crt'))
        self.assertEqual(
            self.key_path,
            os.path.join('.', 'etc', 'ssl', 'cert.key'))
        self.mock_open.assert_any_call('./etc/ssl/cert.crt', 'wb')
        self.mock_open.assert_any_call('./etc/ssl/cert.key', 'wb')
        self.mock_run.assert_called_once_with(ANY, check=True, shell=True)
