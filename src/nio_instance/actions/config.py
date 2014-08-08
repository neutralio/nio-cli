from .base import Action
from ..util import ConfigProperty, NIOClient

EXCLUDE = ['name', 'sys_metadata', 'mappings', 'execution']
TYPE_DETAIL = {'type': 'str'}


class ConfigAction(Action):

    def perform(self):
        resource = NIOClient.list(self.args.resource, self.args.name)
        if resource is not None:
            self._configure_existing_resource(resource.json())
        else:
            cfg_prop = ConfigProperty('type', TYPE_DETAIL, 'Block')
            cfg_prop.process()
            data = {'type': cfg_prop.value}
            self._configure_existing_resource(data, data)

    def _configure_existing_resource(self, resource, data={}):
        properties = self._get_resource_props(resource)

        for prop in [b for b in properties if b not in EXCLUDE]:
            prop_detail = properties[prop]
            curr_val = resource.get(prop)
            cfg_prop = ConfigProperty(prop, prop_detail, curr_val)
            if not cfg_prop._detail.get('readonly', False):
                cfg_prop.process()
            data[prop] = cfg_prop.value

        rsp = NIOClient.config(self.args.resource, self.args.name, data)
        new_data = self.process(rsp)
        rows = self._gen_spec(new_data)
        self.generate_output(rows)

    def _get_resource_props(self, resource):
        endpoint = "{0}_types".format(self.args.resource)
        all_resources = NIOClient.list(endpoint).json()
        specific_type = resource['type']

        resource_template = all_resources.get(specific_type)
        if resource_template is None:
            raise RuntimeError("Invalid block type: {0}".format(specific_type))
        else:
            return resource_template.get('properties', {})

