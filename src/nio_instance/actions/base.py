import json
import requests
import sys
from prettytable import PrettyTable

FIELDS = {
    'both': ['name', 'type', 'log_level'],
    'service': ['auto_start', 'mappings']
}

class Action(object):
    def __init__(self, args):
        self.args = args

    def process(self, rsp):
        if rsp is not None and rsp.text:
            return rsp.json()
        else:
            return None

    def _format_line(self, row):
        return ' '.join([str(i) for i in row])

    def generate_output(self, rows):
        if sys.stdout.isatty():
            table = self._get_table(rows)
            print(table)
        else:
            [print(self._format_line(r)) for r in rows]

    #########################################################
    ### Abandon all hope, ye who enter here. -\('_')/-    ###
    ### Here lie some nasty methods for building tables!! ###
    #########################################################

    def _gen_spec(self, data):
        resource_name = 'Name: {0}'.format(data.get('name'))
        excl = ['name', 'execution']
        header = [resource_name, '']
        align = [(resource_name, 'l')]
        rows = [align, header]
        keys = sorted([k for k in data.keys() if k not in excl])
        for k in keys:
            val = data[k]
            if isinstance(val, dict):
                rows.append([k, ''])
                for kp in val:
                    rows.append(["+-> %s" % kp, val[kp] if val[kp] != '' \
                                 else 'NULL'])
            else:
                rows.append([k, data[k] or "NULL"])
                
        return rows

    def _gen_list(self, data, services=False):
        fields = FIELDS.get('both')
        if services:
            fields.extend(FIELDS.get('service'))
        header = keys = [k for k in fields]
        align = [(header[0],'l')]
        rows = [align, header]
        for k in data.keys():
            rows.append([data[k].get(j) for j in keys])
        return rows

    def _gen_command_list(self, data):
        header = ['command']
        align = [(header[0], 'l')]
        rows = [align, header]
        for cmd in data:
            params = data[cmd]['params']
            r = [cmd]
            rows.append([cmd] + ["{0}: ({1})".format(p, params[p]['type']) \
                                 for p in params])

        max_len = max([len(r) for r in rows])
        rows[1] += list(range(max_len-1))
        rows[1:] = [r + [''] * (max_len - len(r)) for r in rows[1:]]
        return rows

    def _get_table(self, rows):
        align = rows.pop(0)
        header = rows.pop(0)
        tbl = PrettyTable(header)
        for col, a in align:
            tbl.align[col] = a
        for r in rows:
            tbl.add_row(r)
        return tbl
