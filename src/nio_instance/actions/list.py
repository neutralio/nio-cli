from .base import Action
from ..util import NIOClient


class ListAction(Action):

    def perform(self):
        for name in self.args.names:
            rsp = NIOClient.list(self.args.resource, name, 
                                 self.args.cmd, self.args.filter)
            if rsp is not None and rsp.text:
                ls_all = not bool(self.args.names[0])
                self.process(rsp, ls_all)

    def process(self, rsp, ls_all):
        data = rsp.json()
        rows = self._get_rows(data)
        self.generate_output(rows)

    def _get_rows(self, data):
        ''' Decide which type of table we want based on
        subcommand arguments.

        '''
        if self.args.cmd and self.args.names[0]:
            return self._gen_command_list(data)
        elif self.args.names[0]:
            return self._gen_spec(data)
        else:
            return self._gen_list(data)
