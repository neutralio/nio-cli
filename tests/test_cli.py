import responses
import unittest
from unittest import skipIf
from unittest.mock import mock_open, patch, ANY, MagicMock
from docopt import docopt, DocoptExit
from io import StringIO
from collections import OrderedDict

import nio_cli.cli as cli
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
        with patch('nio_cli.commands.new.os.path.isdir', return_value=True):
            with patch('nio_cli.commands.new.subprocess.call') as call:
                with patch('nio_cli.commands.new.config_project') as config:
                    self._patched_new_command(call, config)

    def _patched_new_command(self, call, config):
        self._main('new', **{'<project-name>': 'project', '<template>': None})
        config.assert_called_once_with('project')
        self.assertEqual(call.call_args_list[0][0][0], (
            'git clone --depth=1 '
            'git://github.com/niolabs/project_template.git project'
        ))
        self.assertEqual(call.call_args_list[1][0][0], (
            'cd ./project '
            '&& git submodule update --init --recursive'
        ))
        self.assertEqual(call.call_args_list[2][0][0], (
            'cd ./project '
            '&& git remote remove origin '
            '&& git commit --amend --reset-author -m "Initial commit"'
        ))

    def test_new_command_template(self):
        """Clone the project template from GitHub"""
        with patch('nio_cli.commands.new.os.path.isdir', return_value=True):
            with patch('nio_cli.commands.new.subprocess.call') as call:
                with patch('nio_cli.commands.new.config_project') as config:
                    self._patched_new_command_template(call, config)

    @patch('nio_cli.commands.new.pip.main')
    def _patched_new_command_template(self, call, config, patch_pip_main):
        with patch('nio_cli.commands.new.os.walk') as patched_os_walk:
            join_module = 'nio_cli.commands.new.os.path.join'
            with patch(join_module, return_value='join'):
                patched_os_walk.return_value = [
                    ('root', ('dirs'), ['requirements.txt'])]

                self._main('new', **{
                    '<project-name>': 'project',
                    '<template>': 'my_template',
                })
                config.assert_called_once_with('project')
                self.assertEqual(call.call_args_list[0][0][0], (
                    'git clone --depth=1 '
                    'git://github.com/niolabs/my_template.git project'
                ))
                self.assertEqual(call.call_args_list[1][0][0], (
                    'cd ./project '
                    '&& git submodule update --init --recursive'
                ))
                self.assertEqual(call.call_args_list[2][0][0], (
                    'cd ./project '
                    '&& git remote remove origin '
                    '&& git commit --amend --reset-author -m "Initial commit"'
                ))
                patch_pip_main.assert_called_once_with(
                    ['install', '-r', 'join'])

    def test_new_command_with_failed_clone(self):
        """Cleanly handle new command when 'git clone' fails"""
        isdir_path = 'nio_cli.commands.new.os.path.isdir'
        with patch(isdir_path, return_value=False) as isdir:
            with patch('nio_cli.commands.new.subprocess.call') as call:
                self._main('new', **{'<project-name>': 'project'})
                self.assertEqual(call.call_count, 1)
                isdir.assert_called_once_with('project')

    def test_config_project(self):
        pk_host = '123.pubkeeper.nio.works'
        pk_token = '123123'
        ws_host = '123.websocket.nio.works'
        with patch('builtins.open', mock_open()) as mopen:
            with patch('builtins.input', side_effect=[pk_host, pk_token]):
                isfile_module = 'nio_cli.commands.config.os.path.isfile'
                with patch(isfile_module, return_value=True):
                    with patch('nio_cli.commands.config.os.rename') as rename:
                        with patch('nio_cli.commands.config.os.remove') as remove:
                            self._main('config')
                            self.assertEqual(mopen.call_count, 1)
                            remove.assert_called_once_with('./nio.conf')
                            self.assertEqual(rename.call_count, 1)

    def test_config_with_no_nioenv(self):
        isfile_module = 'nio_cli.commands.config.os.path.isfile'
        with patch(isfile_module, return_value=False):
            with patch('builtins.print') as print:
                with patch('builtins.open', mock_open()) as mopen:
                    self._main('config')
                    print.assert_called_once_with(
                        'Command must be run from project root.')
                    self.assertEqual(mopen.call_count, 0)

    def test_add_command(self):
        """Clone specified blocks as submodules"""
        with patch('nio_cli.commands.add.subprocess.call') as call:
            self._main('add', **{'<block-repo>': ['block1']})
            self.assertEqual(call.call_args_list[0][0][0], (
                'git submodule add git://github.com/nio-blocks/block1.git '
                './blocks/block1'
            ))
            self.assertEqual(call.call_args_list[1][0][0], (
                'git submodule update --init --recursive'
            ))

    @responses.activate
    def test_list_command(self):
        """List blocks or services from the rest api"""
        service_response=[{'api': 'response'}, {'another': 'service'}]
        responses.add(responses.GET,
                      'http://127.0.0.1:8181/services',
                      json=service_response)
        with patch('builtins.print') as print:
            self._main('list', services=True)
            self.assertEqual(len(responses.calls), 1)
            self.assertEqual(print.call_count, len(service_response))
            for index, service in enumerate(service_response):
                self.assertDictEqual(
                    print.call_args_list[index][0][0], service)

    @responses.activate
    def test_shutdown_command(self):
        """Shutdown nio through the rest api"""
        responses.add(responses.GET, 'http://127.0.0.1:8181/shutdown')
        self._main('shutdown')
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
        })
        self.assertEqual(len(responses.calls), 1)

    @skipIf(not niocore_installed, 'niocore required for buildspec')
    def test_buildspec_command(self):
        """Create spec.json file from block class"""

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

        @input("testInput")
        @input("testInput2")
        class SampleBlock2(Block):
            pass

        discover_path = 'nio_cli.commands.buildspec.Discover.discover_classes'
        json_dump_path = 'nio_cli.commands.buildspec.json.dump'
        json_load_path = 'nio_cli.commands.buildspec.json.load'
        file_exists_path = 'nio_cli.commands.buildspec.os.path.exists'
        with patch(discover_path) as discover_classes, \
                patch('builtins.open', mock_open()) as mock_file, \
                patch(file_exists_path) as mock_file_exists, \
                patch(json_dump_path) as mock_json_dump, \
                patch(json_load_path) as mock_json_load:
            # mocks to load existing spec.json and to discover blocks
            mock_file_exists.return_value = True
            mock_json_load.return_value = {
                'nio/SampleBlock1': {
                    'Description': 'This is the description',
                    'Output': 'The output',
                    'Input': 'The input',
                    'Properties': {
                        'String Prop': {
                            'default': 'this will be overridden',
                            'description': 'this description will stay',
                            'additional thing': 'this will remain',
                        },
                    },
                    'Commands': {
                        'commandit': {
                            'description': 'loaded from previous',
                            'additional thing': 'this will remain',
                        },
                    },
                },
            }
            discover_classes.return_value = [SampleBlock1, SampleBlock2]
            # Exectute on repo 'myblocks'
            self._main('buildspec', **{'<repo-name>': 'myblocks'})
            discover_classes.assert_called_once_with(
                'blocks.myblocks', ANY, ANY)
            # File is opened for reading and then for writting
            self.assertEqual(mock_file.call_args_list[0][0],
                             ('blocks/myblocks/spec.json',))
            self.assertEqual(mock_file.call_args_list[1][0],
                             ('blocks/myblocks/spec.json', 'w'))
            # json dump to file with formatting
            mock_json_dump.assert_called_once_with(
                ANY, mock_file(), indent=2)

            self.maxDiff = None
            ordered_dict = OrderedDict([
                ('nio/SampleBlock1', OrderedDict([
                    ('version', '0.1.0'),
                    ('description', ''),
                    ('categories', []),
                    ('properties', OrderedDict([
                        ('another', OrderedDict([
                            ('title', 'Another Prop'),
                            ('type', 'StringType'),
                            ('description', ''),
                            ('default', None)])),
                        ('id', OrderedDict()),
                        ('str_prop', OrderedDict([
                            ('title', 'String Prop'),
                            ('type', 'StringType'),
                            ('description', ''),
                            ('default', 'default string')]))
                    ])),
                    ('inputs', OrderedDict([
                        ('default', {'description': ''})
                    ])),
                    ('outputs', OrderedDict([
                        ('default', {'description': ''})
                    ])),
                    ('commands', OrderedDict([
                        ('commander', {'params': {}, 'description': ''}),
                        ('commandit', {'params': {}, 'description': ''})]))
                ])),
                ('nio/SampleBlock2', OrderedDict([
                    ('version', '0.0.0'),
                    ('description', ''),
                    ('categories', []),
                    ('properties', OrderedDict()),
                    ('inputs', OrderedDict([
                        ('testInput', {'description': ''}),
                        ('testInput2', {'description': ''})
                    ])),
                    ('outputs', OrderedDict([
                        ('default', {'description': ''})
                    ])),
                    ('commands', OrderedDict())
                ]))
            ])
            self.assertDictEqual(mock_json_dump.call_args[0][0], ordered_dict)

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

    def test_readme_command(self):
        """Create README.md from json.spec"""

        json_load_path = 'nio_cli.commands.buildspec.json.load'
        with patch('builtins.open', mock_open()) as mock_file, \
                patch(json_load_path) as mock_json_load:
            # mocks to load existing spec.json and to discover blocks
            mock_json_load.return_value = {
                'nio/SampleBlock1': {
                    'description': 'This is the description',
                    'properties': {
                        'String Prop': {
                            'default': '',
                            'description': 'this description',
                        },
                    },
                    'outputs': {'default': {}},
                    'inputs': {
                        'default': {
                            'description': 'The input',
                        },
                    },
                    'commands': {
                        'commandit': {
                            'description': 'a command',
                        },
                    },
                },
                'nio/SampleBlock2': {
                    'version': '0.0.0',
                    'description': '',
                    'inputs': {},
                    'outputs': {},
                    'properties': {},
                    'commands': {},
                },
            }
            self._main('buildreadme')
            # README and spec are opened
            self.assertEqual(mock_file.call_args_list[0][0],
                             ('README.md',))
            self.assertEqual(mock_file.call_args_list[1][0],
                             ('spec.json',))
            self.assertEqual(mock_file.call_args_list[2][0],
                             ('README.md', 'w'))
            written = ''
            for call in mock_file.return_value.write.call_args_list:
                written += call[0][0]
            self.maxDiff = None
            self.assertEqual(
                written,
                'SampleBlock1\n'
                '============\n'
                'This is the description\n'
                '\n'
                'Properties\n'
                '----------\n'
                '- **String Prop**: this description\n'
                '\n'
                'Inputs\n'
                '------\n'
                '- **default**: The input\n'
                '\n'
                'Outputs\n'
                '-------\n'
                '- **default**: \n'
                '\n'
                'Commands\n'
                '--------\n'
                '- **commandit**: a command\n'
                '\n'
                '***\n'
                '\n'
                'SampleBlock2\n'
                '============\n'
                '\n'
                '\n'
                'Properties\n'
                '----------\n'
                'None\n'
                '\n'
                'Inputs\n'
                '------\n'
                'None\n'
                '\n'
                'Outputs\n'
                '-------\n'
                'None\n'
                '\n'
                'Commands\n'
                '--------\n'
                'None\n'
                '\n'
            )

    def test_newblock_command(self):
        """Clone the block template from GitHub"""
        with patch('nio_cli.commands.new.subprocess.call') as call, \
                patch(
                    'builtins.open',
                    mock_open(
                        read_data='Example ..example_block TestExample')
                ) as mock_file:
            # need to patch open
            self._main('newblock', **{'<block-name>': 'yaba_daba'})
            self.assertEqual(call.call_args_list[0][0][0], (
                'git clone --depth=1 '
                'git://github.com/nio-blocks/block_template.git yaba_daba'
            ))
            self.assertEqual(call.call_args_list[1][0][0],
                'cd ./yaba_daba '
                '&& mv example_block.py yaba_daba_block.py'
            )
            self.assertEqual(call.call_args_list[2][0][0],
                'cd ./yaba_daba/tests '
                '&& mv test_example_block.py test_yaba_daba_block.py'
            )
            self.assertEqual(call.call_args_list[3][0][0],
                'cd ./yaba_daba && mv BLOCK_README.md README.md'
            )
            self.assertEqual(mock_file.call_args_list[0][0],
                             ('./yaba_daba/yaba_daba_block.py',))
            self.assertEqual(
                mock_file.return_value.write.call_args_list[0][0][0],
                'YabaDaba ..example_block TestYabaDaba')
            self.assertEqual(
                mock_file.return_value.write.call_args_list[1][0][0],
                'Example ..example_block TestYabaDaba')
            self.assertEqual(
                mock_file.return_value.write.call_args_list[2][0][0],
                'YabaDaba ..yaba_daba_block TestYabaDaba')

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
            self.assertEqual(
                'Checking PEP8 formatting ...\n\n'
                'Checking spec.json formatting ...\n'
                'Fill in the description for the "prop1" property '
                'in the nioLmnopio block\n\n'
                'Checking README.md formatting ...\n'
                'Add "Outputs" to the nioLmnopio block\n\n'
                'Checking release.json formatting ...\n\n'
                'Checking version formatting ...\n'
                'The nioLmnopio version in the release file does not match '
                'the version in its block file\n'
                'Spec.json and release.json versions do not match '
                'for nioLmnopio block\n\n'
                'Checking class and file name formatting ...\n\n',
                mock_print.getvalue()
            )

    def _main(self, command, ip='127.0.0.1', port='8181', **kwargs):
        args = {
            '--ip': ip,
            '--port': port,
            '--daemon': False,
            '--upgrade': False,
            '-u': False,
            '--template': False,
            '-t': False,
        }
        args[command] = True
        for k, v in kwargs.items():
            args[k] = v
        with patch('nio_cli.cli.docopt') as docopt:
            docopt.return_value = args
            cli.main()
