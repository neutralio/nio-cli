import re


TD_TEMPLATE = {
    'days': {'type': 'int'}, 
    'minutes': {'type': 'int'}, 
    'seconds': {'type': 'int'},
    'microseconds': {'type': 'int'}
}


class ConfigProperty(object):

    def __init__(self, name, prop_detail, current):
        self.name = name
        self._detail = prop_detail
        self._type = self._detail.get('type')
        self._current = current
        self._template = self._detail.get('template') or TD_TEMPLATE

    @property
    def value(self):
        return self._current
     
    # kind of a ridiculous property, serving double duty
    # TODO: get rid of this. makes no sense...
    @property
    def default(self):
        if self._type == 'timedelta':
            return 0
        else:
            return self._current
 
    def process(self, prompt="\n{0} ({1}): "):
        result = ''
        # TODO: define semantics for adding to lists
        if self._type == 'list':
            return result

        # handle an object property gracefully
        elif self._type == 'object':
            result = self._process_sub_props(self._current, prompt)
        elif self._type == 'timedelta':
            result = self._process_sub_props(self.default, prompt)
        else:
            result = self._process_field(prompt)

        self._current = result

    def _process_sub_props(self, current, prompt):
        result = {}
        
        print(prompt.format(self.name, self._type))
        update = input("Update?[y/n] ")
        
        if re.match(r'[nN]', update) is not None:
            result = self._current
        else:

            # process each of the subproperties
            for key in self._template:
                detail = self._template.get(key)
                default = current

                # the object property case (as opposed to timedelta)
                if isinstance(default, dict):
                    default = default.get(key)
                sub_prop = ConfigProperty(key, detail, default)
                sub_prop.process("+-> {0}".format(prompt[1:]))
                result[key] = sub_prop.value

        return result

    # if a field is left blank, leave the property's value unchanged
    def _process_field(self, prompt):
        result = input(prompt.format(self.name, self._type)) 
        if result == '':
            result = self.default
            print('Using current value:', result)
        elif self._type == 'int':
            try:
                result = int(result)
            except:
                pass
        elif self._type == 'bool':
            result = True if re.match(r'[tT]', result) else False
        return result


