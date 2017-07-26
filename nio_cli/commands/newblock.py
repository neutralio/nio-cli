import subprocess, re

from .base import Base


class NewBlock(Base):

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._block = self.options['<block-name>']

    def run(self):
        clone = (
            "git clone --depth=1 git@github.com:{}/{}.git {}"
        ).format('nio-blocks', 'block_template', self._block)
        rename_block_file = (
            "cd ./{} && mv example_block.py {}_block.py"
        ).format(self._block, self._block)
        rename_test_file = (
            "cd ./tests && mv test_example_block.py test_{}_block.py"
        ).format(self._block, self._block)
        rename_readme = (
            "cd ./{} && mv BLOCK_README.md README.md"
        ).format(self._block)
        reinit_repo = (
            'cd ./{} '
            '&& git remote remove origin '
            '&& git add -A'
            '&& git commit --amend --reset-author -m "Initial commit"'
        ).format(self._block)
        subprocess.call(clone, shell=True)
        subprocess.call(rename_block_file, shell=True)
        subprocess.call(rename_test_file, shell=True)
        subprocess.call(rename_readme, shell=True)

        self.rename_block_class(self._block)
        self.rename_test_class(self._block)
        self.rename_test_imports(self._block)

        subprocess.call(reinit_repo, shell=True)

    @staticmethod
    def rename_block_class(block):
        camel_block_name = block
        if '_' in block:
            camel_block_name = ''
            camel_block_array = block.split('_')
            for word in camel_block_array:
                capitalized = word.title()
                camel_block_name += capitalized
        else:
            camel_block_name = camel_block_name.title()

        with open('{}_block.py'.format(block)) as f:
            file_string = f.read()
        file_string = re.sub('Example', camel_block_name, file_string)

        with open('{}_block.py'.format(block), 'w') as f:
            f.write(file_string)

    @staticmethod
    def rename_test_class(block):
        camel_block_name = block
        if '_' in block:
            camel_block_name = ''
            camel_block_array = block.split('_')
            for word in camel_block_array:
                capitalized = word.title()
                camel_block_name += capitalized
        else:
            camel_block_name = camel_block_name.title()
        camel_block_name = 'Test' + camel_block_name

        with open('tests/test_{}_block.py'.format(block)) as f:
            file_string = f.read()
        file_string = re.sub('TestExample', camel_block_name, file_string)

        with open('tests/test_{}_block.py'.format(block), 'w') as f:
            f.write(file_string)

    @staticmethod
    def rename_test_import(block):
        camel_block_name = block
        if '_' in block:
            camel_block_name = ''
            camel_block_array = block.split('_')
            for word in camel_block_array:
                capitalized = word.title()
                camel_block_name += capitalized
        else:
            camel_block_name = camel_block_name.title()

        with open('tests/test_{}_block.py'.format(block)) as f:
            file_string = f.read()
        file_string = re.sub('Example', camel_block_name, file_string)
        file_string = re.sub(
            '..example_block', '..{}_block'.format(block), file_string)

        with open('tests/test_{}_block.py'.format(block), 'w') as f:
            f.write(file_string)

# TODO: REFACTOR RENAME METHODS TO NOT HAVE SO MUCH DUPLICATE CODE
    # Add filename, what-to-replace as parameters?
    # Make seperate fxns for camel_block_name & replace_in_file?
