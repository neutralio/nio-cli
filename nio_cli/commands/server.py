import subprocess

from .base import Base


class Server(Base):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._daemon = self.options['--daemon'] or self.options['-d']
        self._executable = 'niod'

    def run(self):
        if self._daemon:
            subprocess.Popen([self._executable],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        else:
            # TODO: this needs to not use 100% cpu
            with subprocess.Popen([self._executable]) as proc:
                try:
                    while proc.poll() is None:
                        continue
                except:
                    pass
