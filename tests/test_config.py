import sys
import unittest
from unittest.mock import mock_open, patch, ANY, MagicMock, call

from nio_cli.commands.config import Config
from nio_cli.utils import config_project, _config_ssl


class TestConfig(unittest.TestCase):

    def _run_config(self, isfile=True):
        options = {
            '--ip': None,
            '--port': None,
            '--username': 'Admin',
            '--password': 'Admin',
            '--project': '.'
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
                patch(_config_ssl.__module__ + '.os') as self.mock_os:
            self.mock_os.path.isfile.return_value = isfile
            _config_ssl('.', './nio.conf')

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
            self.mock_open.call_args_list[0][0], ('./certificate.pem', 'wb'))
        self.assertEqual(
            self.mock_open.call_args_list[1][0], ('./private_key.pem', 'wb'))
        self.assertEqual(
            self.mock_open.call_args_list[2][0], ('./nio.conf', 'r'))
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_crypto.dump_certificate.call_count, 1)
        self.assertEqual(self.mock_crypto.dump_privatekey.call_count, 1)
        self.assertEqual(self.mock_input.call_count, len(user_input))


class TestConfigProject(unittest.TestCase):

    def _run_config_project(self, isfile=True, kwargs={}):
        with patch('builtins.open', mock_open()) as self.mock_open, \
                patch('builtins.print') as self.mock_print, \
                patch(config_project.__module__ + '.os') as self.mock_os, \
                patch(config_project.__module__ + '.json') as mock_json, \
                patch(config_project.__module__ + '._config_ssl') as self.mock_ssl:
            self.mock_os.path.isfile.return_value = isfile
            config_project(**kwargs)

    def test_config_project(self):
        self._run_config_project()

        self.assertEqual(self.mock_open.call_count, 1)
        self.assertEqual(self.mock_open.call_args_list[0],
            call('./nio.conf', 'r'))
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_ssl.call_count, 0)

    def test_config_with_pubkeeper_port_ip_flags(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        self._run_config_project(kwargs={'pubkeeper_hostname': pk_host,
                                         'pubkeeper_token': pk_token,
                                         'niohost': '127.0.0.1',
                                         'nioport': '8182'})
        self.assertEqual(self.mock_open.call_count, 1)
        self.assertEqual(self.mock_open.call_args_list[0],
            call('./nio.conf', 'r'))
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')

    def test_config_with_specified_project_location(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        path = '/path/to/project'
        conf_location = '{}/nio.conf'.format(path)
        self._run_config_project(kwargs={"name": path,
                                         "pubkeeper_hostname": pk_host,
                                         "pubkeeper_token": pk_token})

        self.assertEqual(self.mock_open.call_count, 1)
        self.assertEqual(self.mock_open.call_args_list[0],
            call(conf_location, 'r'))
        self.mock_os.remove.assert_called_once_with(conf_location)
        self.mock_os.rename.assert_called_once_with(ANY, conf_location)

    def test_config_with_added_users(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        conf_location = './nio.conf'
        users_location = './etc/users.json'
        self._run_config_project(kwargs={"username": 'user',
                                         "password": 'pwd',
                                         "pubkeeper_hostname": pk_host,
                                         "pubkeeper_token": pk_token})

        self.assertEqual(self.mock_open.call_count, 5)
        self._test_open_call_order(self.mock_open.call_args_list)
        self.mock_os.remove.assert_called_once_with(conf_location)
        self.mock_os.rename.assert_called_once_with(ANY, conf_location)

    def test_config_with_no_nioconf(self):
        self._run_config_project(isfile=False)
        self.mock_print.assert_called_once_with(
            'Command must be run from project root.')
        self.assertEqual(self.mock_open.call_count, 0)

    def test_config_with_ssl(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        self._run_config_project(kwargs={"username": 'user',
                                         "password": 'pwd',
                                         "pubkeeper_hostname": pk_host,
                                         "pubkeeper_token": pk_token,
                                         "ssl": True})

        self.assertEqual(self.mock_open.call_count, 5)
        self._test_open_call_order(self.mock_open.call_args_list)
        self.mock_os.remove.assert_called_once_with('./nio.conf')
        self.mock_os.rename.assert_called_once_with(ANY, './nio.conf')
        self.assertEqual(self.mock_ssl.call_count, 1)

    def _test_open_call_order(self, call_args_list, path='.'):
        open1_call_args = self.mock_open.call_args_list[0]
        self.assertEqual(open1_call_args, call('{}/nio.conf'\
            .format(path), 'r'))
        open2_call_args = self.mock_open.call_args_list[1]
        self.assertEqual(open2_call_args, call('{}/etc/users.json'\
            .format(path), 'r'))
        open3_call_args = self.mock_open.call_args_list[2]
        self.assertEqual(open3_call_args, call('{}/etc/users.json'\
            .format(path), 'w+'))
        open4_call_args = self.mock_open.call_args_list[3]
        self.assertEqual(open4_call_args, call('{}/etc/permissions.json'\
            .format(path), 'r'))
        open5_call_args = self.mock_open.call_args_list[4]
        self.assertEqual(open5_call_args, call('{}/etc/permissions.json'\
            .format(path), 'w+'))
