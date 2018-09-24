import requests
from os.path import expanduser, join


class Base(object):

    def __init__(self, options, *args, **kwargs):
        self.options = options
        self.args = args
        self.kwargs = kwargs
        self._host = self._get_host()
        self._ssl_ca_path = expanduser(
            self.options.get('ssl_ca_path', join('~', '.nio', 'ca.crt')))
        # If they want to use the system CA, we'll use True for the requests
        # parameter
        if self._ssl_ca_path == 'system':
            self._ssl_ca_path = True
        # e.g., https://localhost:8181/{}
        self._base_url = "{}/{{}}".format(self._host)
        # default to Admin/Admin
        self._auth = ('Admin', 'Admin')

    def run(self):
        raise NotImplementedError('Implement run() in the command.')

    def get(self, *args, **kwargs):
        return self._execute_request(
            requests.get,
            *args,
            auth=self._get_credentials(),
            verify=self._ssl_ca_path,
            **kwargs,
        )

    def post(self, *args, **kwargs):
        return self._execute_request(
            requests.post,
            *args,
            auth=self._get_credentials(),
            verify=self._ssl_ca_path,
            **kwargs,
        )

    @staticmethod
    def _execute_request(fn, *args, **kwargs):
        response = fn(*args, **kwargs)
        # use response.text rather than response.reason to be able
        # to see actual exception message along with reason
        if response.status_code == 401:
            msg = "Client error, status: {}, message: {} "\
                  ", Try running again with '--username' and '--password' options".\
                  format(response.status_code, response.text)
            print(msg)
            raise RuntimeError(msg)
        elif response.status_code >= 400:
            msg = "Client error, status: {}, message: {}".format(
                response.status_code, response.text)
            print(msg)
            raise RuntimeError(msg)

        return response

    def _get_credentials(self):
        # allow to override last credentials set
        (username, password) = self._auth

        new_username = self.options.get('--username', username)
        if new_username != username:
            username = new_username

        new_password = self.options.get('--password', password)
        if new_password != password:
            password = new_password

        # cache last credentials
        self._auth = (username, password)
        return self._auth

    @staticmethod
    def _gather_input(message, default=""):
        user_input = input(message)
        if user_input:
            return user_input
        else:
            return default

    def _get_host(self):
        """ Figure out what host the instance is at based on parameters """
        param_host = self.options.get('--instance-host', None)
        param_ip = self.options.get('--ip', None)
        param_port = self.options.get('--port', None)

        # See if they used --ip or --port on an instance access command
        from .new import New
        from .config import Config
        if (param_ip or param_port) and not \
                (isinstance(self, New) or isinstance(self, Config)):
            print("Note: The --ip and --port flags have been deprecated, "
                  "please use --instance-host to configure your instance host")
            # If they didn't also specify the full host, use the ip/port
            # for backwards compat
            if not param_host:
                param_host = 'http://{}:{}'.format(
                    param_ip or '127.0.0.1',
                    param_port or '8181')
                print("Using host {} with deprecated settings".format(
                    param_host))

        if param_host is None:
            param_host = "https://localhost:8181"
        return self._cleanup_host(param_host)

    @staticmethod
    def _cleanup_host(host):
        """ Cleans up the provided host string for a nio instance """
        # Make sure the http/https protocol is specified
        if not host.lower().startswith('http'):
            host = 'https://{}'.format(host)
        # Make sure no trailing slash exists
        if host.endswith('/'):
            host = host[:-1]
        return host
