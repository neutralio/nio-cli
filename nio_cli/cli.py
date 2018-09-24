"""
nio

Usage:
  nio newblock <block-name>
  nio [options] new <project-name> [(--template <template> | -t <template>) --pubkeeper-hostname=HOST --pubkeeper-token=TOKEN --ssl --no-ssl]
  nio [options] add <block-repo>... [(--upgrade | -u)]
  nio [options] (list | ls) services
  nio [options] (list | ls) blocks
  nio [options] (command | co) <command-name> [--args=<args> (<service-name> | <block-name>)]
  nio [options] (config | cfg) [--pubkeeper-hostname=HOST --pubkeeper-token=TOKEN --ssl]
  nio [options] (config | cfg) services <service-name>
  nio [options] (config | cfg) blocks <block-name>
  nio [options] clone services <service-name> <new-name>
  nio [options] buildspec <repo-name>
  nio [options] buildreadme
  nio [options] buildrelease <repo-name>
  nio [options] blockcheck
  nio [options] shutdown
  nio [options] add_user <username> <password>
  nio [options] remove_user <username>
  nio -h | --help
  nio --version

Options:
  -p PORT --port=PORT               Specify nio port.
  -i IP --ip=IP                     Specify nio ip address.
  --username=USERNAME               Specify username [default: Admin].
  --password=PASSWORD               Specify password [default: Admin].
  --project=PROJECT                 Specify project directory [default: .].
  -h --help                         Show this screen.
  --version                         Show version.

Examples:
  nio new my_project -t demo_plant
  nio add counter
  nio ls services
  nio co start Service
  nio add_user Tyler Pyth0nRu13z!

Help:
  Full documentation is available here: https://docs.n.io/cli/
  For help, issues, and feature requests please open an issue on the Github repository:
  https://github.com/niolabs/nio-cli
"""


from inspect import getmembers, isclass
from docopt import docopt
from nio_cli import __version__ as VERSION
from nio_cli import commands


def main():
    """Main CLI entrypoint."""
    options = docopt(__doc__, version=VERSION)
    for k, v in options.items():
        if v and hasattr(commands, k):
            module = getattr(commands, k)
            members = getmembers(module, isclass)
            command = [command[1] for command in members if \
                       command[1] != commands.base.Base and \
                       issubclass(command[1], commands.base.Base)
                       ][0]
            command(options).run()
