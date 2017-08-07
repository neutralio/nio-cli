import unittest
from unittest.mock import mock_open, patch, ANY
from docopt import docopt, DocoptExit
import responses
import nio_cli.cli as cli


class TestCLI(unittest.TestCase):

    def parse_args(self, command):
        return docopt(cli.__doc__, command.split(' '))

    def test_new_arguments(self):
        """'new' requires a project-name"""
        args = self.parse_args('new project')
        self.assertEqual(args['<project-name>'], 'project')
        with self.assertRaises(DocoptExit):
            self.parse_args('new')

    def test_server_arguments(self):
        """'server' has optional daemon flags"""
        args = self.parse_args('server')
        self.assertEqual(args['--daemon'], False)
        self.assertEqual(args['-d'], False)
        args = self.parse_args('server --daemon')
        self.assertEqual(args['--daemon'], True)
        self.assertEqual(args['-d'], False)
        args = self.parse_args('server -d')
        self.assertEqual(args['--daemon'], False)
        self.assertEqual(args['-d'], True)

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
        with patch('nio_cli.commands.new.subprocess.call') as call:
            self._main('new', **{'<project-name>': 'project'})
            self.assertEqual(call.call_args_list[0][0][0], (
                'git clone --depth=1 '
                'git@github.com:nioinnovation/project_template.git project'
            ))
            self.assertEqual(call.call_args_list[1][0][0],
                'cd ./project '
                '&& git submodule update --init --recursive'
            )
            self.assertEqual(call.call_args_list[2][0][0],
                'cd ./project '
                '&& git remote remove origin '
                '&& git commit --amend --reset-author -m "Initial commit"'
            )

    def test_server_command(self):
        """Execute nio_run as a subprocess"""
        with patch('nio_cli.commands.server.subprocess.Popen') as Popen:
            self._main('server')
            self.assertEqual(Popen.call_args[0][0], ['nio_run'])

    def test_add_command(self):
        """Clone specified blocks as submodules"""
        with patch('nio_cli.commands.add.subprocess.call') as call:
            self._main('add', **{'<block-repo>': ['block1']})
            self.assertEqual(call.call_args_list[0][0][0], (
                'git submodule add git@github.com:nio-blocks/block1.git '
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
                "nio/SampleBlock1": {
                    "Description": "This is the description",
                    "Output": "The output",
                    "Input": "The input",
                    "Properties": {
                        "String Prop": {
                            "default": "this will be overridden",
                            "description": "this description will stay",
                            "additional thing": "this will remain",
                        },
                    },
                    "Commands": {
                        "commandit": {
                            "description": "loaded from previous",
                            "additional thing": "this will remain",
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
            self.assertDictEqual(mock_json_dump.call_args[0][0], {
                "nio/SampleBlock1": {
                    "version": "0.1.0",
                    "description": "",
                    "outputs": {
                        "default": {
                            "description": ""
                        }
                    },
                    "inputs": {
                        "default": {
                            "description": ""
                        }
                    },
                    "properties": {
                        "another": {
                            "description": "",
                            "title": "Another Prop",
                            "default": None
                        },
                        "str_prop": {
                            "title": "String Prop",
                            "default": "default string",
                            "description": "",
                        }
                    },
                    "commands": {
                        "commandit": {"description": ""},
                        "commander": {"description": ""},
                    },
                },
                "nio/SampleBlock2": {
                    "version": "0.0.0",
                    "description": "",
                    "outputs": {
                        "default": {
                            "description": ""
                        }
                    },
                    "inputs": {
                        "default": {
                            "description": ""
                        }
                    },
                    "properties": {},
                    "commands": {},
                },
            })

    def test_readme_command(self):
        """Create README.md from json.spec"""

        json_load_path = 'nio_cli.commands.buildspec.json.load'
        with patch('builtins.open', mock_open()) as mock_file, \
                patch(json_load_path) as mock_json_load:
            # mocks to load existing spec.json and to discover blocks
            mock_json_load.return_value = {
                "nio/SampleBlock1": {
                    "Description": "This is the description",
                    "Output": "The output",
                    "Input": "The input",
                    "Dependencies": ["requirements"],
                    "Properties": {
                        "String Prop": {
                            "default": "",
                            "description": "this description",
                        },
                    },
                    "Commands": {
                        "commandit": {
                            "description": "a command",
                        },
                    },
                },
                "nio/SampleBlock2": {
                    "Version": "0.0.0",
                    "Description": "",
                    "Output": "",
                    "Input": "",
                    "Dependencies": [],
                    "Properties": {},
                    "Commands": {},
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
            written = ""
            for call in mock_file.return_value.write.call_args_list:
                written += call[0][0]
            self.maxDiff = None
            self.assertEqual(
                written,
                "SampleBlock1\n"
                "============\n"
                "This is the description\n"
                "\n"
                "Properties\n"
                "----------\n"
                "- **String Prop**: this description\n"
                "\n"
                "Commands\n"
                "--------\n"
                "- **commandit**: a command\n"
                "\n"
                "Dependencies\n"
                "------------\n"
                "- requirements\n"
                "\n"
                "Input\n"
                "-----\n"
                "The input\n"
                "\n"
                "Output\n"
                "------\n"
                "The output\n"
                "\n"
                "SampleBlock2\n"
                "============\n"
                "\n"
                "\n"
                "Properties\n"
                "----------\n"
                "\n"
                "Commands\n"
                "--------\n"
                "\n"
                "Dependencies\n"
                "------------\n"
                "\n"
                "Input\n"
                "-----\n"
                "\n"
                "\n"
                "Output\n"
                "------\n"
                "\n"
                "\n"
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
                'git@github.com:nio-blocks/block_template.git yaba_daba'
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

    def _main(self, command, ip='127.0.0.1', port='8181', **kwargs):
        args = {
            '--ip': ip,
            '--port': port,
            '--daemon': False,
            '-d': False,
            '--upgrade': False,
            '-u': False,
        }
        args[command] = True
        for k, v in kwargs.items():
            args[k] = v
        with patch('nio_cli.cli.docopt') as docopt:
            docopt.return_value = args
            cli.main()
