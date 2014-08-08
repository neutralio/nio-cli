""" Utility functions, argument formatters, and imports.

"""
import re
from .config_property import ConfigProperty
from .execution import Execution
from .nio_api import NIOClient


def try_int(arg):
    result = arg
    try:
        result = int(arg)
    except:
        pass
    return result

def try_bool(arg):
    result = arg
    if re.match(r'[fF]', arg):
        result = False
    elif re.match(r'[tT]', arg):
        result = True
    return result

def argument(s):
    try:
        terms = s.split('=', 1)
        terms[1] = try_int(terms[1])
        
        # # there's no boolean command param right now
        # terms[1] = try_bool(terms[1])
    except:
        raise ArgumentTypeError(
            "Command arguments must be of the form 'foo=bar'"
        )
    return terms

def creds(s):
    try:
        uname, password = s.split(':')
        if isinstance(uname, str) and isinstance(password, str):
            return (uname, password)
        else:
            raise Exception
    except:
        raise ArgumentTypeError(
            "Credentials must be of the form 'username:password'"
        )
