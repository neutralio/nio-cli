import responses
import unittest
from unittest import skipIf
from unittest.mock import mock_open, patch, ANY, call
from docopt import docopt, DocoptExit
from io import StringIO
from collections import OrderedDict
import sys

import nio_cli.cli as cli
from nio_cli.commands.base import Base
from nio.block.terminals import input

try:
    import niocore
    niocore_installed = True
except:
    niocore_installed = False


class TestCLI(unittest.TestCase):

    def parse_args(self, command):
        return docopt(cli.__doc__, command.split(' '))

    def test_new_arguments(self):
        """'new' requires a project-name"""
        args = self.parse_args('new project')
        self.assertEqual(args['<project-name>'], 'project')
        with self.assertRaises(DocoptExit):
            self.parse_args('new')

    def test_buildpsec_arguments(self):
        """'buildspec' requires a repo-name"""
        args = self.parse_args('buildspec repo')
        self.assertEqual(args['<repo-name>'], 'repo')
        with self.assertRaises(DocoptExit):
            self.parse_args('buildspec')

    def test_buildreadme_arguments(self):
        """'buildreadme' take no args"""
        args = self.parse_args('buildreadme')
        with self.assertRaises(DocoptExit):
            self.parse_args('buildreadme some-args')

    def test_new_command(self):
        """Clone the project template from GitHub"""
        with patch('nio_cli.commands.new.os.path.isdir', return_value=True), \
                patch('nio_cli.commands.new.subprocess.call') as call, \
                patch('nio_cli.commands.new.config_project') as config:
            self._patched_new_command(call, config)

    def _patched_new_command(self, call, config):
        self._main('new', **{
            '<project-name>': 'project',
            '<template>': None,
            '--pubkeeper-hostname': None,
            '--pubkeeper-token': None
        })
        config.assert_called_once_with(name='project',
                                       niohost='127.0.0.1',
                                       nioport='8181',
                                       pubkeeper_hostname=None,
                                       pubkeeper_token=None,
                                       ssl=True)
        self.assertEqual(call.call_args_list[0][0][0], (
            'git clone '
            'git://github.com/niolabs/project_template.git project'
        ))
        self.assertEqual(call.call_args_list[1][0][0], (
            'cd ./project '
            '&& git submodule update --init --recursive'
        ))
        self.assertEqual(call.call_args_list[2][0][0], (
            'cd ./project '
            '&& git remote remove origin '
            '&& git commit --amend --reset-author --quiet -m "Initial commit"'
        ))

    def test_new_command_set_user(self):
        """Clone the project template from GitHub"""
        with patch('nio_cli.commands.new.os.path.isdir', return_value=True), \
                patch('nio_cli.commands.new.subprocess.call') as call, \
                patch('nio_cli.commands.new.set_user') as user, \
                patch('nio_cli.commands.new.config_project') as config:
            self._patched_new_command_set_user(call, user, config)

    def _patched_new_command_set_user(self, call, user, config):
        self._main('new', **{
            '<project-name>': 'project',
            '<template>': None,
            '--pubkeeper-hostname': None,
            '--pubkeeper-token': None,
            '--username': 'new_user',
            '--password': 'new_password'
        })
        user.assert_called_once_with('project',
                                     'new_user',
                                     'new_password',
                                     True)
        config.assert_called_once_with(name='project',
                                       niohost='127.0.0.1',
                                       nioport='8181',
                                       pubkeeper_hostname=None,
                                       pubkeeper_token=None,
                                       ssl=True)
        self.assertEqual(call.call_args_list[0][0][0], (
            'git clone '
            'git://github.com/niolabs/project_template.git project'
        ))
        self.assertEqual(call.call_args_list[1][0][0], (
            'cd ./project '
            '&& git submodule update --init --recursive'
        ))
        self.assertEqual(call.call_args_list[2][0][0], (
            'cd ./project '
            '&& git remote remove origin '
            '&& git commit --amend --reset-author --quiet -m "Initial commit"'
        ))

    def test_new_command_template(self):
        """Clone the project template from GitHub"""
        with patch('nio_cli.commands.new.os.path.isdir', return_value=True), \
                patch('nio_cli.commands.new.subprocess.call') as call, \
                patch('nio_cli.commands.new.config_project') as config:
            self._patched_new_command_template(call, config)

    def _patched_new_command_template(self, call, config):
        with patch('nio_cli.commands.new.os.walk') as patched_os_walk:
            join_module = 'nio_cli.commands.new.os.path.join'
            with patch(join_module, return_value='join'):
                patched_os_walk.return_value = [
                    ('root', ('dirs'), ['requirements.txt'])]

                self._main('new', **{
                    '<project-name>': 'project',
                    '<template>': 'my_template',
                    '--pubkeeper-hostname': 'pkhost',
                    '--pubkeeper-token': 'pktoken'
                })
                config.assert_called_once_with(name='project',
                                               niohost='127.0.0.1',
                                               nioport='8181',
                                               pubkeeper_hostname='pkhost',
                                               pubkeeper_token='pktoken',
                                               ssl=True)
                self.assertEqual(call.call_args_list[0][0][0], (
                    'git clone '
                    'git://github.com/niolabs/my_template.git project'
                ))
                self.assertEqual(call.call_args_list[1][0][0], (
                    'cd ./project '
                    '&& git submodule update --init --recursive'
                ))
                self.assertEqual(call.call_args_list[2][0][0], (
                    [sys.executable, '-m', 'pip', 'install', '-r', 'join']
                ))
                self.assertEqual(call.call_args_list[3][0][0], (
                    'cd ./project '
                    '&& git remote remove origin '
                    '&& git commit --amend --reset-author --quiet '
                    '-m "Initial commit"'
                ))

    def test_new_command_with_failed_clone(self):
        """Cleanly handle new command when 'git clone' fails"""
        isdir_path = 'nio_cli.commands.new.os.path.isdir'
        with patch(isdir_path, return_value=False) as isdir, \
                patch('nio_cli.commands.new.subprocess.call') as call:
            self._main('new', **{
                '<project-name>': 'project',
                '--username': 'user',
                '--password': 'pwd'
            })
            self.assertEqual(call.call_count, 1)
            isdir.assert_called_once_with('project')

    @responses.activate
    def test_add_command(self):
        """Clone specified blocks as submodules"""
        responses.add(responses.POST,
                      'http://127.0.0.1:8181/project/blocks')
        self._main('add', **{
            '<block-repo>': ['block1'],
            '--project': '.'
        })
        self.assertEqual(len(responses.calls), 1)

        self._main('add', **{
            '<block-repo>': ['block1'],
            '--project': '.',
            '--upgrade': True
        })
        self.assertEqual(len(responses.calls), 3)


    @responses.activate
    def test_list_command(self):
        """List blocks or services from the rest api"""
        service_response = [{'api': 'response'}, {'another': 'service'}]
        responses.add(responses.GET,
                      'http://127.0.0.1:8181/services',
                      json=service_response)
        with patch('builtins.print') as print:
            self._main('list', **{
                "services": True,
                '--username': 'user',
                '--password': 'pwd'
            })
            self.assertEqual(len(responses.calls), 1)
            self.assertEqual(print.call_count, len(service_response))
            for index, service in enumerate(service_response):
                self.assertDictEqual(
                    print.call_args_list[index][0][0], service)

    @responses.activate
    def test_list_command_with_id(self):
        """List blocks or services from the rest api"""
        blk_response = {'id1': {'name': 'name1', 'id': 'id1'},
                        'id2': {'name': 'name2', 'id': 'id2'}}
        responses.add(responses.GET,
                      'http://127.0.0.1:8181/blocks',
                      json=blk_response)
        with patch('builtins.print') as mock_print:
            self._main('list', **{
                "services": False,
                '--username': 'user',
                '--password': 'pwd'
            })
            self.assertEqual(len(responses.calls), 1)
            self.assertEqual(mock_print.call_count, 2)
            call_args = [arg[0] for arg in mock_print.call_args_list]
            for blk in blk_response:
                # the order of responses is not guaranteed
                self.assertTrue(
                    (blk_response[blk]['id'], blk_response[blk]['name'])
                    in call_args)

    @responses.activate
    def test_shutdown_command(self):
        """Shutdown nio through the rest api"""
        responses.add(responses.GET, 'http://127.0.0.1:8181/shutdown')
        self._main('shutdown', **{
                '--username': 'user',
                '--password': 'pwd'
        })
        self.assertEqual(len(responses.calls), 1)

    @responses.activate
    def test_command_command(self):
        """Command a nio block through the rest api"""
        responses.add(responses.POST,
                      'http://127.0.0.1:8181/services/service/block/command')
        self._main('command', **{
            '<command-name>': 'command',
            '<service-name>': 'service',
            '<block-name>': 'block',
            '--username': 'user',
            '--password': 'pwd'
        })
        self.assertEqual(len(responses.calls), 1)

    def test_publishblock_command(self):
        """Create spec.json file from block class"""

        from nio.block.base import Block
        from nio.properties import StringProperty, VersionProperty
        from nio.command import command
        @command('commandit')
        @command('commander')
        @input("testInput")
        @input("testInput2")
        class SampleBlock1(Block):
            version = VersionProperty('1.2.3')
            str_prop = StringProperty(
                title='String Prop',
                default='default string',
            )
            another = StringProperty(
                title='Another Prop',
            )

        get_block_class_path = 'nio_cli.utils.spec._get_block_class'
        requests_path = 'nio_cli.commands.publishblock.requests'
        sample_spec = """
            {
                "nio/SampleBlock1": {
                    "description": "This is the description",
                    "outputs": "The original output",
                    "from_python": "myfile.SampleBlock1"
                }
            }
        """
        sample_release = """
            {
                "nio/SampleBlock1": {
                    "language": "Python",
                    "from_python": "myfile.SampleBlock1",
                    "url": "git://myblock"
                }
            }
        """
        with patch('builtins.open', new_callable=mock_open) as open_calls, \
                patch(get_block_class_path) as mock_get_class, \
                patch(requests_path) as mock_requests:
            open_calls.side_effect = [
                mock_open(read_data=sample_spec).return_value,
                mock_open(read_data=sample_release).return_value
            ]
            # mocks to load existing spec.json and to discover blocks
            mock_get_class.return_value = SampleBlock1
            # Exectute on repo 'myblocks'
            self._main('publishblock', **{
                '--api-url': 'http://fake',
                '--api-token': 'token'})
            mock_get_class.assert_called_with('myfile.SampleBlock1')
            self.maxDiff = None
            # One POST for spec and one for release
            self.assertEqual(mock_requests.post.call_count, 2)
            spec_call_args = mock_requests.post.call_args_list[0][1]['json']
            release_call_args = mock_requests.post.call_args_list[1][1]['json']
            self.assertDictEqual(spec_call_args, {
                'nio/SampleBlock1': {
                    'description': 'This is the description',
                    'commands': {
                        'commander': {'params': {}},
                        'commandit': {'params': {}}
                    },
                    'inputs': {
                        'testInput': {'description': ''},
                        'testInput2': {'description': ''}
                    },
                    'outputs': 'The original output',  # orig output preserved
                    'properties': {
                        'another': {
                            'default': None,
                            'title': 'Another Prop',
                            'type': 'StringType'
                        },
                        'str_prop': {
                            'default': 'default string',
                            'title': 'String Prop',
                            'type': 'StringType'
                        }
                    },
                    'version': '1.2.0'  # Make sure only major.minor
                }
            })
            self.assertDictEqual(release_call_args, {
                'nio/SampleBlock1': {
                    "language": "Python",
                    "version": "1.2.3",
                    "url": "git://myblock"
                }
            })

    @skipIf(not niocore_installed, 'niocore required for buildrelease')
    def test_buildrelease_command(self):
        """create release.json from block class"""

        from nio.block.base import Block
        from nio.properties import StringProperty, VersionProperty
        from nio.command import command

        @command('commandit')
        @command('commander')
        class SampleBlock1(Block):
            version = VersionProperty('0.1.0')
            str_prop = StringProperty(
                title='String Prop',
                default='default string',
            )
            another = StringProperty(
                title='Another Prop',
            )

        class SampleBlock2(Block):
            # if a block has no configured version prop, the version is 0.0.0
            # by default
            pass

        discover_path = \
            'nio_cli.commands.buildrelease.Discover.discover_classes'
        json_dump_path = 'nio_cli.commands.buildrelease.json.dump'
        file_exists_path = 'nio_cli.commands.buildrelease.os.path.exists'
        subprocess_call_path = \
            'nio_cli.commands.buildrelease.subprocess.check_output'
        with patch(discover_path) as discover_classes, \
                patch('builtins.open', mock_open()) as mock_file, \
                patch(file_exists_path) as mock_file_exists, \
                patch(json_dump_path) as mock_json_dump, \
                patch(subprocess_call_path) as check_output:
            # mocks to load existing spec.json and to discover blocks
            mock_file_exists.return_value = True
            discover_classes.return_value = [SampleBlock1, SampleBlock2]
            check_output.return_value = \
                b'origin git@github.com:niolabs/myblocks.git (fetch)'
            # Exectute on repo 'myblocks'
            self._main('buildrelease', **{'<repo-name>': 'myblocks'})
            discover_classes.assert_called_once_with(
                'blocks.myblocks', ANY, ANY)
            # json dump to file with formatting
            mock_json_dump.assert_called_once_with(
                {
                    'nio/SampleBlock2': {
                        'version': '0.0.0', 'language': 'Python',
                        'url': 'git://github.com/niolabs/myblocks.git'
                    },
                    'nio/SampleBlock1': {
                        'version': '0.1.0', 'language': 'Python',
                        'url': 'git://github.com/niolabs/myblocks.git'}
                },
                mock_file(),
                indent=2,
                sort_keys=True)

    def test_newblock_command(self):
        """Clone the block template from GitHub"""
        with patch('nio_cli.commands.new.subprocess.call') as call, \
                patch('builtins.open',
                   mock_open(
                       read_data='Example ..example_block TestExample')
                   ) as mock_file, \
                patch("nio_cli.commands.newblock.os") as os_mock, \
                patch("nio_cli.commands.newblock.move") as move_mock:

            self._main('newblock', **{'<block-name>': 'yaba_daba'})
            self.assertEqual(call.call_args_list[0][0][0], (
                'git clone '
                'git://github.com/nio-blocks/block_template.git yaba_daba'
            ))
            self.assertEqual(mock_file.call_args_list[0][0],
                             ('./yaba_daba/yaba_daba_block.py',))
            self.assertEqual(
                mock_file.return_value.write.call_args_list[0][0][0],
                'YabaDaba ..example_block TestYabaDaba')
            # assert calls to rename block files
            self.assertEqual(os_mock.remove.call_count, 1)
            self.assertEqual(move_mock.call_count, 3)

    def test_blockcheck_command(self):
        self.maxDiff = None
        file_exists_path = 'nio_cli.commands.blockcheck.os.path.exists'
        getcwd_path = 'nio_cli.commands.blockcheck.os.getcwd'
        listdir_path = 'nio_cli.commands.blockcheck.os.listdir'
        subprocess_path = 'nio_cli.commands.blockcheck.subprocess.call'
        sys_exit_path = 'nio_cli.commands.blockcheck.sys.exit'
        print_path = 'nio_cli.commands.blockcheck.sys.stdout'
        json_load_path = 'nio_cli.commands.blockcheck.json.load'
        with patch('builtins.open', mock_open()) as mock_file, \
                patch(file_exists_path) as mock_file_exists, \
                patch(getcwd_path) as mock_getcwd, \
                patch(listdir_path) as mock_listdir, \
                patch(subprocess_path) as mock_subprocess_call, \
                patch(sys_exit_path) as mock_sys_exit, \
                patch(print_path, new_callable=StringIO) as mock_print, \
                patch(json_load_path) as mock_json_load:

            mock_file_exists.return_value = True
            mock_getcwd.return_value = 'nio_lmnopio_block'
            mock_listdir.return_value = ['nio_lmnopio_block.py']

            mock_json_load.side_effect = [
                # json.load() for spec.json (prop1 missing description)
                {
                    'nio/nioLmnopio': {
                        'version': '0.1.0',
                        'description': 'spec description',
                        'properties': {
                            'prop1': {
                                'description': ''
                            }
                        },
                        'inputs': {},
                        'outputs': {},
                        'commands': {},
                    }
                },
                # json.load() for release.json (versions do not match)
                {
                    'nio/nioLmnopio': {
                        'language': 'Python',
                        'url': 'release url',
                        'version': '0.2.0',
                    }
                }
            ]

            mock_file.return_value.readlines.side_effect = [
                # .readlines() for nio_lmnopio_block.py
                [
                    'class nioLmnopio(Block):',
                    "version = VersionProperty('0.1.0')"
                ],
                # .readlines() for README.md (missing 'Outputs')
                [
                    'nioLmnopio', 'Properties', 'Inputs',
                    'Commands', 'Dependencies'
                ]
            ]

            self._main('blockcheck')
            self.assertEqual(
                'pycodestyle .', mock_subprocess_call.call_args_list[0][0][0])

            # Check that print statements are run
            what_was_printed = mock_print.getvalue()
            self.assertIn('Checking PEP8 formatting ...', what_was_printed)
            self.assertIn('Checking spec.json formatting ...', what_was_printed)
            self.assertIn('Fill in the description for the "prop1" property ', what_was_printed)
            self.assertIn('in the nioLmnopio block', what_was_printed)
            self.assertIn('Checking README.md formatting ...', what_was_printed)
            self.assertIn('Add "Outputs" to the nioLmnopio block', what_was_printed)
            self.assertIn('Checking release.json formatting ...', what_was_printed)
            self.assertIn('Checking version formatting ...', what_was_printed)
            self.assertIn('The nioLmnopio version in the release file does not match ', what_was_printed)
            self.assertIn('the version in its block file', what_was_printed)
            self.assertIn('Spec.json and release.json versions do not match ', what_was_printed)
            self.assertIn('for nioLmnopio block', what_was_printed)
            self.assertIn('Checking class and file name formatting ...', what_was_printed)

    def test_add_user_command(self):
        """ Adds a user through the rest api"""
        with patch("nio_cli.commands.add_user.set_user") as set_user_patch:
            self._main('add_user', **{
                '--project': 'testing_project',
                '<username>': 'user',
                '<password>': 'pwd'
            })
            self.assertEqual(set_user_patch.call_count, 1)
            self.assertEqual(set_user_patch.call_args_list[0],
                             call('testing_project', 'user', 'pwd'))

        from nio_cli.utils.users import set_user, _hash_password, \
            _set_permissions
        with patch(set_user.__module__ + '.os') as mock_os, \
                patch(set_user.__module__ + '.json') as mock_json, \
                patch('builtins.open') as mock_open, \
                patch('nio_cli.utils.users._hash_password') as mock_hash, \
                patch('nio_cli.utils.users._set_permissions'):
            mock_os.path.isfile.return_value = True
            mock_hash.return_value = "AdminPwdHash"
            mock_json.load.return_value = {"Admin": "AdminPwd"}

            username = "user1"
            password = "pwd1"

            self._main('add_user', **{
                '--project': 'testing_project',
                '<username>': username,
                '<password>': password
            })
            # one call to read users.json and one to save users.json
            self.assertEqual(mock_open.call_count, 2)
            print(mock_json.dump.call_args_list)
            users, _ = mock_json.dump.call_args_list[0][0]
            self.assertIn(username, users)
            self.assertDictEqual(users[username],
                                 {"password": "AdminPwdHash"})

            _set_permissions('testing_project', username, False)
            # make sure we open permissions.json two times
            # to read and write new permissions
            self.assertEqual(mock_open.call_count, 4)
            print(mock_json.dump.call_args_list)
            permissions, _ = mock_json.dump.call_args_list[0][0]
            self.assertIn(username, permissions)
            self.assertDictEqual(permissions[username],
                                 {".*": "rwx"})

    def test_remove_user_command(self):
        """ Adds a user through the rest api"""
        with patch("nio_cli.commands.remove_user.remove_user") as \
                remove_user_patch:
            self._main('remove_user', **{
                '--project': 'testing_project',
                '<username>': 'user'
            })
            self.assertEqual(remove_user_patch.call_count, 1)
            self.assertEqual(remove_user_patch.call_args_list[0],
                             call('testing_project', 'user'))

        from nio_cli.commands.remove_user import RemoveUser, _remove_permission
        with patch(RemoveUser.__module__ + '.os') as mock_os, \
                patch(RemoveUser.__module__ + '.json') as mock_json, \
                patch('builtins.open') as mock_open, \
                patch('nio_cli.commands.remove_user._remove_permission'):
            mock_os.path.isfile.return_value = True
            mock_json.load.return_value = {"Admin": "AdminPwd"}

            username = "Admin"

            self._main('remove_user', **{
                '--project': 'testing_project',
                '<username>': username
            })
            # one call to read users.json and one to save users.json
            self.assertEqual(mock_open.call_count, 2)
            users, _ = mock_json.dump.call_args_list[0][0]
            self.assertNotIn(username, users)
            self.assertEqual(len(users), 0)
            # make sure we open permissions.json two times
            # to read and write new permissions
            mock_json.load.return_value = {"Admin": {".*": "rwx"}}
            _remove_permission('testing_project', username)
            self.assertEqual(mock_open.call_count, 4)
            permissions, _ = mock_json.dump.call_args_list[0][0]
            self.assertNotIn(username, permissions)
            self.assertEqual(len(permissions), 0)

    def test_cleanup_host(self):
        cli_command = Base({})
        self.assertEqual(
            cli_command._cleanup_host('localhost'),
            'https://localhost')
        self.assertEqual(
            cli_command._cleanup_host('http://localhost'),
            'http://localhost')
        self.assertEqual(
            cli_command._cleanup_host('https://localhost'),
            'https://localhost')
        self.assertEqual(
            cli_command._cleanup_host('https://localhost:8181'),
            'https://localhost:8181')
        self.assertEqual(
            cli_command._cleanup_host('https://localhost:8181/'),
            'https://localhost:8181')

    def _main(self, command, **kwargs):
        args = {
            '--daemon': False,
            '--upgrade': False,
            '-u': False,
            '--template': False,
            '-t': False,
        }
        if command in ('new', 'config'):
            args['--ip'] = '127.0.0.1'
            args['--port'] = '8181'
        else:
            args['--instance-host'] = 'http://127.0.0.1:8181'
        args[command] = True
        for k, v in kwargs.items():
            args[k] = v
        with patch('nio_cli.cli.docopt') as docopt:
            docopt.return_value = args
            cli.main()
