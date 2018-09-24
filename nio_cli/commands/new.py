import os
import subprocess
import sys
from .base import Base
from nio_cli.utils import config_project, set_user


class New(Base):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._name = self.options.get('<project-name>')
        self._template = self.options.get('<template>')
        self._pubkeeper_hostname = self.options.get('--pubkeeper-hostname')
        self._pubkeeper_token = self.options.get('--pubkeeper-token')
        self._username = self.options.get('--username')
        self._password = self.options.get('--password')
        self._ssl = self.options.get('--ssl')
        self._no_ssl = self.options.get('--no-ssl')
        self._niohost = self.options.get('--ip')
        self._nioport = self.options.get('--port')

    def run(self):
        repo = 'git://github.com/niolabs/project_template.git'
        if self._template:
            if 'github.com' in self._template:
                repo = self._template
            else:
                repo = 'git://github.com/niolabs/{}.git'.format(self._template)

        clone = "git clone {} {}".format(repo, self._name)
        submodule_update = (
            'cd ./{} '
            '&& git submodule update --init --recursive'
        ).format(self._name)
        reinit_repo = (
            'cd ./{} '
            '&& git remote remove origin '
            '&& git commit --amend --reset-author --quiet -m "Initial commit"'
        ).format(self._name)
        subprocess.call(clone, shell=True)
        if not os.path.isdir(self._name):
            return
        subprocess.call(submodule_update, shell=True)
        # pip install all requirements.txt
        for root, dirs, files in os.walk('./{}'.format(self._name)):
            for file_name in files:
                if file_name == 'requirements.txt':
                    reqs = os.path.join(root, file_name)
                    subprocess.call(
                        [sys.executable, '-m', 'pip', 'install', '-r', reqs])

        # Overwrite user credentials
        if self._username and self._password:
            set_user(self._name, self._username, self._password, True)

        if self._ssl:
            print("Note: the --ssl flag is deprecated, SSL support is included"
                  " by default. Use --no-ssl to disable SSL")

        config_project(name=self._name,
                       pubkeeper_hostname=self._pubkeeper_hostname,
                       pubkeeper_token=self._pubkeeper_token,
                       ssl=not self._no_ssl,
                       niohost=self._niohost,
                       nioport=self._nioport
        )
        subprocess.call(reinit_repo, shell=True)
