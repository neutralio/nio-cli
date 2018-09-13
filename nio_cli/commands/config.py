from nio_cli.utils import config_project
from .base import Base


class Config(Base):
    """ Get basic nio info """

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._resource = 'services' if self.options.get('services') else \
            'blocks' if self.options.get('blocks') else \
            'project'
        self._resource_name = \
            self.options.get('<service-name>') if self.options.get('services') else \
            self.options.get('<block-name>') if self.options.get('blocks') else \
            ""

    def config_block_or_service(self):
        response = self.get(
            self._base_url.format(
                '{}/{}'.format(self._resource, self._resource_name)))
        try:
            config = response.json()
            print(config)
        except Exception as e:
            print(e)

    def run(self):
        if self._resource == 'project':
            config_project(name=self.options['--project'],
                           pubkeeper_hostname=self.options.get('--pubkeeper-hostname'),
                           pubkeeper_token=self.options.get('--pubkeeper-token'),
                           ssl=self.options.get('--ssl'),
                           niohost=self.options['--ip'],
                           nioport=self.options['--port'])
        else:
            self.config_block_or_service()
