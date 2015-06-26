import pip
import subprocess
import os
from os import path
from argparse import ArgumentParser
from nio_cli.util import NIOClient, Execution


CLONE = "git clone git@github.com:{0}/{1}.git {2}"
CLONE_HTTPS = "git clone https://github.com/{0}/{1}.git {2}"
SUBMODULE_ADD = "git submodule add git@github.com:{0}/{1}.git ./{2}/{1}"
SUBMODULE_HTTPS_ADD = "git submodule add https://github.com/{0}/{1}.git ./{2}/{1}"
INIT_ONE = "cd ./{}/{} && git submodule update --init --recursive"
INIT_RECURSIVE = "git submodule update --init --recursive"
UPDATE_ONE = "cd ./{}/{} && git pull --ff-only --recurse-submodules --all"
GIT_ADD_BLOCK = '''git add ./{}/{}'''
COMMIT_BLOCKS = '''git commit -m "[NIO-UPDATE-BLOCKS] updated blocks {}"'''
GIT_CHECKOUT_BLOCK = "cd ./{}/{} && git checkout {}"


class BlockAdder(object):

    user_org = 'nio-blocks'
    target = "blocks"

    @classmethod
    def config(cls):
        cls.user_org = 'nio-blocks'
        cls.target = './blocks'

    @classmethod
    def add(cls, repo_name, project=False, https=False):
        clone, sm_add = [
            CLONE_HTTPS if https else CLONE,
            SUBMODULE_HTTPS_ADD if https else SUBMODULE_ADD
        ]
        if project:
            subprocess.call(
                clone.format(cls.user_org,
                             'project_template',
                             repo_name),
                shell=True
            )
        else:
            subprocess.call(
                sm_add.format(cls.user_org,
                              repo_name,
                              cls.target),
                shell=True
            )

    @classmethod
    def initialize(cls, block=None):
        if block is not None:
            subprocess.call(INIT_ONE.format(cls.target, block), shell=True)
        else:
            subprocess.call(INIT_RECURSIVE, shell=True)

    @classmethod
    def install(cls, block=None):
        if block is not None:
            # install requirements.txt for the one block
            block_path = '/'.join([cls.target, block])
            cls._recursive_install(block_path)
        else:
            # install requirements.txt for all blocks and project
            cls._recursive_install()

    @classmethod
    def _recursive_install(cls, path='.'):
        for root, dirs, files in os.walk(path):
            for file in files:
                if file == 'requirements.txt':
                    reqs = os.path.join(root, file)
                    pip.main(['install', '-r', reqs])


class BlockUpdater(BlockAdder):

    @classmethod
    def update(cls, block):
        subprocess.call(UPDATE_ONE.format(cls.target, block), shell=True)


    @classmethod
    def git_add(cls, block):
        subprocess.call(GIT_ADD_BLOCK.format(cls.target, block), shell=True)

    @classmethod
    def checkout(cls, block, branch):
        subprocess.call(GIT_CHECKOUT_BLOCK.format(cls.target, block, branch),
                        shell=True)

    @classmethod
    def commit(cls, blocks):
        subprocess.call(COMMIT_BLOCKS.format(blocks), shell=True)

class AddBlocksAction:

    def __init__(self, args):
        self.args = args

    def perform(self):
        BlockAdder.config()

        if self.args.repos:
            for r in self.args.repos:
                BlockAdder.add(r, https=self.args.https)
                BlockAdder.initialize(r)
                BlockAdder.install(r)
        elif self.args.update:
            BlockAdder.initialize()
            BlockAdder.install()

class AddProjectAction:

    def __init__(self, args):
        self.args = args

    def perform(self):
        ''' Clone down the project_template repository

        If the installed version of nio matches a release in the
        project_template repo, then use that tag.
        '''
        BlockAdder.add(self.args.project_name, True, self.args.https)
        version = self._nio_version()
        print('n.io version: {}'.format(version))
        if version:
            try:
                subprocess.call('git -C ./{} checkout tags/{}'.format(
                    self.args.project_name, version), shell=True)
            except Exception as e:
                # This release doesn't have a version
                pass

    def _nio_version(self):
        try:
            import nio
            version = nio.__version__
        except:
            version = None
        return version


class PullBlocksAction:

    def __init__(self, args):
        self.args = args

    def perform(self):
        BlockUpdater.config()

        # do pull of submodules
        blocks = []
        if self.args.blocks:
            for b in self.args.blocks:
                self.process_block(self.args.nc, b)
                blocks.append(b)
        else:
            for b in os.listdir(BlockUpdater.target):
                if path.isdir(path.join(BlockUpdater.target, b)):
                    if b in {"__pycache__", ".git"}:
                        continue
                    self.process_block(self.args.nc, b)
            blocks = "all"

        # commit changes
        if blocks:
            BlockUpdater.commit(blocks)

        # submodule update
        if self.args.blocks:
            for r in self.args.blocks:
                BlockUpdater.initialize(r)
        else:
            BlockUpdater.initialize()

    def process_block(self, no_checkout, b, branch='master'):
        print("#" * 3, "Updating Block:", b, "#" * 3)
        if not no_checkout:
            print("Checking out", b, branch)
            BlockUpdater.checkout(b, branch)
        BlockUpdater.update(b)
        BlockUpdater.git_add(b)

if __name__ == '__main__':
    # TODO: This was removed when merging nio-add-blocks with nio-cli
    pass
