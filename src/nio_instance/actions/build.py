from sys import stderr
from .base import Action
from ..util import Execution, NIOClient


class BuildAction(Action):

    _exec = None

    def perform(self):
        try:
            service = NIOClient.list('services', self.args.name).json()
        except Exception as e:
            print("Invalid service: {0}".format(self.args.name), file=stderr)
        else:
            self._exec = Execution(service['execution'])
        
            if len(self.args.froms):
                self._process_edges()
            else:
                if not self.args.rm:
                    self._exec.add_block(self.args.to)
                else:
                    self._exec.rm_block(self.args.to)

            # only make the PUT request if something is changing
            service['execution'] = self._exec.pack()
            NIOClient.build(self.args.name, service)

            self.generate_output(self._exec.to_rows())

    def _process_edges(self):
        for frm in self.args.froms:
            if not self.args.rm:
                self._exec.add_edge(frm, self.args.to)
            else:
                self._exec.rm_edge(frm, self.args.to)
