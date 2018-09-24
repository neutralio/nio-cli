# Deals with persisting files for use in the CLI


from os import makedirs
from os.path import expanduser, join


DEFAULT_ROOT = expanduser(join('~', '.nio'))


def ensure_dir_exists(directory_name, root=None):
    if root is not None:
        directory_name = join(root, directory_name)
    makedirs(directory_name, exist_ok=True)
