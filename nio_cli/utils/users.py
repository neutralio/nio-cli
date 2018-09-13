import os
import json
from bcrypt import hashpw, gensalt


def set_user(project_name, username, password, replace=False):
    # load users
    users_location = '{}/etc/users.json'.format(project_name)
    if os.path.isfile(users_location) and not replace:
        with open(users_location, 'r') as f:
            users = json.load(f)
    else:
        users = {}

    # add/override this user and password
    if username and password:
        print('Adding user: {}'.format(username))
        users[username] = {
            "password": _hash_password(password)
        }
        # write it back
        with open(users_location, 'w+') as f:
            json.dump(users, f, indent=4, separators=(',', ': '))
        _set_permissions(project_name, username, replace)
    else:
        print('Username cannot be empty')


def _set_permissions(project_name, username, replace):
    # Add new user with admin level permission
    permission_location = '{}/etc/permissions.json'.format(project_name)
    if os.path.isfile(permission_location) and not replace:
        with open(permission_location, 'r') as f:
            permissions = json.load(f)
    else:
        permissions = {}

    print('Adding permissions for user: {}'.format(username))
    permissions[username] = {
        ".*": "rwx"
    }
    # write it back
    with open(permission_location, 'w+') as f:
        json.dump(permissions, f, indent=4, separators=(',', ': '))


def _hash_password(s, encoding='ISO-8859-1'):
    """Return the native string bcrypt hashed (as a native string)."""
    if isinstance(s, str):
        pwd = s.encode(encoding)
    else:
        pwd = s
    hashed = hashpw(pwd, gensalt())
    return hashed.decode(encoding)
