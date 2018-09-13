
def get_boolean(message, default=True):
    """ Get a yes/no input from the user, prompting them with a message.

    Returns:
        input (boolean): True or False depending on the user's input
    """
    if not isinstance(default, bool):
        raise TypeError("Default must be a boolean")
    result = input('{} ({}): '.format(message, 'no' if not default else 'yes'))
    if not result:
        return default

    result = result.strip().lower()
    return result in ('yes', 'y')


def get_file(message, default=None):
    """ Get a reference to a file and make sure it exists

    Returns:
        path: The path to the file, if it exists

    Raises:
        ValueError: If the provided file does not exist
    """
    if default:
        path = input('{} ({}): '.format(message, default))
    else:
        path = input('{}: '.format(message))
    return path


def get_string(message, default=None):
    """ Get a string input from the user """
    if default:
        result = input('{} ({}): '.format(message, default))
        if not result:
            result = default
    else:
        result = input('{}: '.format(message))
    return result
