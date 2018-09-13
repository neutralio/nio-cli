import sys
import re
from setuptools import setup, find_packages

from setuptools.command.test import test as TestCommand


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass into py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import pytest

        errno = pytest.main(self.pytest_args)
        sys.exit(errno)

with open('nio_cli/__init__.py', 'r') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name='nio-cli',
    version=version,
    description='Command line tools for the nio Platform',
    long_description=readme(),
    url='https://github.com/niolabs/nio-cli',
    author='niolabs',
    author_email='support@n.io',
    keywords=['nio'],
    license='Apache 2.0',
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
    ],
    packages=find_packages(exclude=['docs', 'tests', 'tests.*']),
    install_requires=[
        'nio',
        'requests',
        'docopts',
        'pycodestyle',
        'bcrypt',
        'cryptography',
    ],
    tests_require=['pytest', 'pytest-cov', 'responses'],
    extras_require={
        'dev': ['responses'],
    },
    cmdclass={'test': PyTest},
    entry_points={
        'console_scripts': [
            'nio=nio_cli.cli:main'
        ]
    },
)
