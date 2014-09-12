import sys
from os.path import expanduser, isfile
from argparse import ArgumentParser
from configparser import ConfigParser
from .actions import ListAction, CommandAction,\
    ConfigAction, BuildAction, UpdateAction
from .util import argument, creds, NIOClient

# TODO: 
### Protect some of the json ser/deser.

def _nio_instance_configure(conf_file):
    conf_file = expanduser(conf_file)
    if isfile(conf_file):
        config = ConfigParser()
        config.read(conf_file)

        inst = config['DEFAULT']
        if 'nio-instance' in config:
            inst = config['nio-instance']

        # initialize the NIOClient
        host = inst.get('host')
        port = inst.getint('port')
        creds = (inst.get('username'), inst.get('password'))
        NIOClient.initialize(host, port, creds)
    else:
        print("No such file or directory: {0}".format(conf_file),
              file=sys.stderr)
        sys.exit(1)
        
def _nio_instance_main():

    argparser = ArgumentParser(
        description=('''Interact with a running NIO instance. '''
                     '''Requires the v1.x.x API.''')
    )

    # path to nio-instance config file
    argparser.add_argument('-f', '--init', default='~/.config/nio-cli.ini')

    subparsers = argparser.add_subparsers(help='sub-command help')

    # subcommand for listing blocks, services
    list_parser = subparsers.add_parser('list', aliases=['ls'])
    list_parser.set_defaults(action=ListAction)
    list_parser.add_argument('resource', type=str)
    list_parser.add_argument('names', nargs='*', default=[''])
    list_parser.add_argument('--cmd', action='store_true')
    list_parser.add_argument('--exec', action='store_true')
    list_parser.add_argument('--filter', type=argument, nargs='*')

    cmd_parser = subparsers.add_parser('command', aliases=['co'])
    cmd_parser.set_defaults(action=CommandAction)
    cmd_parser.add_argument('command', type=str)
    cmd_parser.add_argument('service', type=str)
    cmd_parser.add_argument('block', nargs='?', default='')
    cmd_parser.add_argument('--auto', '-a', action='store_true')
    cmd_parser.add_argument('--args', type=argument, nargs='*', default=[])

    config_parser = subparsers.add_parser('config', aliases=['cfg'])
    config_parser.set_defaults(action=ConfigAction)
    config_parser.add_argument('resource', type=str)
    config_parser.add_argument('name')
    
    build_parser = subparsers.add_parser('build', aliases=['ln'])
    build_parser.set_defaults(action=BuildAction)
    build_parser.add_argument('-rm', action='store_true')
    build_parser.add_argument('name', type=str)
    build_parser.add_argument('froms', nargs='*', default=[])
    build_parser.add_argument('to')

    update_parser = subparsers.add_parser('update')
    update_parser.set_defaults(action=UpdateAction)
    update_parser.add_argument('block_types', type=str, nargs='+')

    args = argparser.parse_args()

    # initialization
    _nio_instance_configure(args.init)

    action = args.action(args)
    try:
        action.perform()
    except Exception as e:
        print("Error while executing nio action {0}".format(
            type(action).__name__), file=sys.stderr)
        print(type(e).__name__, e, file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    status = _nio_instance_main()
    sys.exit(0)
