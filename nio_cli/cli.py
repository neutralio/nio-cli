"""
nio

Usage:
  nio new <project-name> [(--template <template> | -t <template>)] [(--pubkeeper-hostname=HOSTAME --pubkeeper-token=TOKEN)]
  nio newblock <block-name>
  nio [options] add <block-repo>... [(--upgrade | -u)]
  nio [options] (list | ls) services
  nio [options] (list | ls) blocks
  nio [options] (command | co) <command-name> [<service-name>] [<block-name>] [--args=<args>]
  nio [options] (config | cfg) [project]
  nio [options] (config | cfg) services <service-name>
  nio [options] (config | cfg) blocks <block-name>
  nio [options] clone services <service-name> <new-name>
  nio [options] buildspec <repo-name>
  nio [options] buildreadme
  nio [options] buildrelease <repo-name>
  nio [options] blockcheck
  nio [options] shutdown
  nio -h | --help
  nio --version

Options:
  -p PORT --port=PORT               Specify n.io port [default: 8181].
  -i IP --ip=IP                     Specify n.io ip address [default: 127.0.0.1].
  -h --help                         Show this screen.
  --version                         Show version.

Examples:
  nio new my_project
  nio add util
  nio ls services
  nio co start Service

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
