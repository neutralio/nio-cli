import requests
from .base import Action
from ..util import NIOClient, try_int


class CommandAction(Action):

    def __init__(self, args):
        super().__init__(args)
        self.resource = 'blocks' if args.block else 'services'
        self.name = args.block or args.service

    @property
    def params(self):
        if self.args.auto:
            return {a[0]: a[1] for a in self.args.args}            
        else:
            return self._collect_params()

    def perform(self):
        if self.args.command == 'shutdown':
            NIOClient.shutdown()
        elif self.args.command == 'restart':
            NIOClient.command('stop', self.args.service)
            NIOClient.command('start', self.args.service)
        else:
            rsp = NIOClient.command(self.args.command,
                                    self.args.service,
                                    self.args.block,
                                    self.params)

            # only print nonempty response bodies
            rsp_body = self.process(rsp)
            if rsp_body is not None:
                print(rsp_body)

    def _collect_params(self):
        data = {}
        prompt="{0} ({1}): "
        commands = NIOClient.list(self.resource, self.name, True).json()
        command_template = commands.get(self.args.command, {}).get('params', [])

        for name in command_template:
            _type = command_template[name]['type']
            if _type == 'dict':
                result = {}
                print(prompt.format(name, _type))
                while 1:
                    k = input("key: ")
                    if not k:
                        break
                    v = try_int(input("value: "))
                    result[k] = v
            else:
                result = input(prompt.format(name, _type))
                if _type == 'int':
                    result = int(result)

            data[name] = result

        return data
