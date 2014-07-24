from .base import Action
from ..util import Execution, NIOClient


class BuildAction(Action):

    def perform(self):
        service = NIOClient.list('services', self.args.name).json()
        service_exec = Execution(service['execution'])

        for l in self.args.edges:
            frm, to = l
            if self.args.rm:
                service_exec.rm_edge(frm, to)
            else:
                service_exec.add_edge(frm, to)

        # only make the PUT request if something is changing
        if len(self.args.edges) > 0:
            service['execution'] = service_exec.pack()
            NIOClient.build(self.args.name, service)

        self.generate_output(service_exec.to_rows())