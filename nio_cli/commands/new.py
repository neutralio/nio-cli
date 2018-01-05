import subprocess

from .base import Base


class New(Base):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._name = self.options['<project-name>']
        self._template = self.options['<template>']

    def run(self):

        if self._template:
            # User specified their own repo
            if('github.com' in self._template):
                clone = (
                    "git clone --depth=1 {} {}"
                ).format(self._template, self._name)

            # Use niolabs repo
            else:
                clone = (
                    "git clone --depth=1 git://github.com/{}/{}.git {}"
                ).format('niolabs', self._template, self._name)

        # Clone project template
        else:
            clone = (
                "git clone --depth=1 git://github.com/{}/{}.git {}"
            ).format('niolabs', 'project_template', self._name)

        submodule_update = (
            'cd ./{} '
            '&& git submodule update --init --recursive'
        ).format(self._name)
        reinit_repo = (
            'cd ./{} '
            '&& git remote remove origin '
            '&& git commit --amend --reset-author -m "Initial commit"'
        ).format(self._name)
        subprocess.call(clone, shell=True)
        subprocess.call(submodule_update, shell=True)
        subprocess.call(reinit_repo, shell=True)
