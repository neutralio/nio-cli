from setuptools import setup, find_packages
setup(
    name='nio-cli',
    version="0.1",
    packages=find_packages(
        where='src'
    ),
    package_dir = {'': 'src'},

    entry_points={
        'console_scripts': [
            'nio=nio_instance.main:_nio_instance_main'
        ]
    },
    author="Oren Leiman",
    author_email="oren@neutral.io",
    description="Command line tools for NIO",
    license="Apache",
    url="docs.n.io/en/latest/nio_cli.html"
)
