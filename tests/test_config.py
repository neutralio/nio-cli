import sys
import unittest
from unittest.mock import mock_open, patch, ANY, MagicMock

from nio_cli.commands.config import Config, config_project, config_ssl


class TestConfig(unittest.TestCase):

    def _run_config(self, user_input=None, isfile=True):
        options = {
            '--ip': 'host',
            '--port': 'host',
            'blocks': False,
            '<block-name>': None,
            'services': False,
            '<service-name>': None,
        }
        with patch('builtins.print') as self.mock_print, \
                patch(Config.__module__ + '.config_project') as self.mock_conf:
            Config(options).run()

    def test_run_project(self):
        self._run_config()
        self.assertEqual(self.mock_conf.call_count, 1)


class TestConfigSSL(unittest.TestCase):

    def _run_config_ssl(self, user_input=None, isfile=True, kwargs={}):
        sys.modules['OpenSSL'] = MagicMock()
        user_input = user_input or []
        with patch('builtins.open', mock_open()) as self.mock_open, \
                patch('builtins.print') as self.mock_print, \
                patch('builtins.input', side_effect=user_input) \
                as self.mock_input, \
                patch('OpenSSL.crypto') as self.mock_crypto, \
                patch(Config.__module__ + '.os') as self.mock_os:
            self.mock_os.path.isfile.return_value = isfile
            config_ssl('.', './nio.conf')

    def test_config_ssl(self):
        ssl_cert = '/path/to/certificate.pem'
        ssl_key = '/path/to/private_key.pem'
        user_input = ['N', ssl_cert, ssl_key]
        self._run_config_ssl(user_input)
        self.mock_open.assert_called_once_with('./nio.conf', 'r')
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_crypto.dump_certificate.call_count, 0)
        self.assertEqual(self.mock_crypto.dump_privatekey.call_count, 0)
        self.assertEqual(self.mock_input.call_count, len(user_input))

    def test_config_ssl_with_self_signed_cert(self):
        user_input = ['Y', 'US', 'CO', 'Denver', 'testOwner', 'testUser']
        self._run_config_ssl(user_input)
        self.assertEqual(self.mock_open.call_count, 3)
        self.assertEqual(
            self.mock_open.call_args_list[0][0], ('./certificate.pem', 'wt'))
        self.assertEqual(
            self.mock_open.call_args_list[1][0], ('./private_key.pem', 'wt'))
        self.assertEqual(
            self.mock_open.call_args_list[2][0], ('./nio.conf', 'r'))
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_crypto.dump_certificate.call_count, 1)
        self.assertEqual(self.mock_crypto.dump_privatekey.call_count, 1)
        self.assertEqual(self.mock_input.call_count, len(user_input))


class TestConfigProject(unittest.TestCase):

    def _run_config_project(self, user_input=None, isfile=True, kwargs={}):
        user_input = user_input or []
        with patch('builtins.open', mock_open()) as self.mock_open, \
                patch('builtins.print') as self.mock_print, \
                patch('builtins.input', side_effect=user_input) \
                as self.mock_input, \
                patch(Config.__module__ + '.os') as self.mock_os, \
                patch(Config.__module__ + '.config_ssl') as self.mock_ssl:
            self.mock_os.path.isfile.return_value = isfile
            config_project(**kwargs)

    def test_config_project(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        user_input = [pk_host, pk_token, 'N']
        self._run_config_project(user_input)
        self.mock_open.assert_called_once_with('./nio.conf', 'r')
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_ssl.call_count, 0)
        self.assertEqual(self.mock_input.call_count, len(user_input))

    def test_config_with_specified_project_location(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        user_input = [pk_host, pk_token, 'N']
        path = '/path/to/project'
        conf_location = '{}/nio.conf'.format(path)
        self._run_config_project(user_input, kwargs={'name': path})
        self.mock_open.assert_called_once_with(conf_location, 'r')
        self.mock_os.remove.assert_called_once_with(conf_location)
        self.mock_os.rename.assert_called_once_with(ANY, conf_location)

    def test_config_with_pubkeeper_flags(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        user_input = ['N']
        self._run_config_project(user_input, kwargs={
            'pubkeeper_hostname': 'pkhost', 'pubkeeper_token': 'token'})
        self.assertEqual(self.mock_input.call_count, len(user_input))

    def test_config_with_no_nioconf(self):
        self._run_config_project(isfile=False)
        self.mock_print.assert_called_once_with(
            'Command must be run from project root.')
        self.assertEqual(self.mock_open.call_count, 0)

    def test_config_with_ssl(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        user_input = [pk_host, pk_token, 'Y']
        self._run_config_project(user_input)
        self.mock_open.assert_called_once_with('./nio.conf', 'r')
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_ssl.call_count, 1)
