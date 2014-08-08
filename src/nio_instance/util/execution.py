
class Execution(object):
    def __init__(self, execution):
        self._exec = {
            e['name']: e['receivers'] for e in execution
        }
        
    def add_edge(self, frm, to):
        frm_curr = self._exec.get(frm, [])
        if to not in frm_curr and to is not None:
            frm_curr.append(to)
        self._exec[frm] = frm_curr
            
    def rm_edge(self, frm, to):
        frm_curr = self._exec.get(frm, [])
        frm_curr = [t for t in frm_curr if t != to]
        self._exec[frm] = frm_curr

    def add_block(self, name):
        self._exec[name] = self._exec.get(name, [])

    def rm_block(self, name):
        if name in self._exec:
            del self._exec[name]

    def pack(self):
        return [{
            'name': e, 'receivers': self._exec[e]
        } for e in self._exec]

    def to_rows(self):
        header = ['Output Block']
        align = []
        rows = [align, header]
        for frm in self._exec:
            rows.append([frm] + self._exec[frm])

        max_len = max([len(r) for r in rows])
        rows[1] += list(range(max_len-1))
        rows[1:] = [r + [''] * (max_len - len(r)) for r in rows[1:]]
        return rows

