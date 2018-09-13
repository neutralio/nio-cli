import requests


class Base(object):

    def __init__(self, options, *args, **kwargs):
        self.options = options
        self.args = args
        self.kwargs = kwargs
        self._ip = self.options['--ip']\
            if self.options['--ip'] is not None\
            else '127.0.0.1'
        self._port = self.options['--port']\
            if self.options['--port'] is not None\
            else '8181'
        self._base_url = "http://{}:{}/{{}}".format(self._ip, self._port)
        # default to Admin/Admin
        self._auth = ('Admin', 'Admin')

    def run(self):
        raise NotImplementedError('Implement run() in the command.')

    def get(self, *args, **kwargs):
        return self._execute_request(
            requests.get, *args, auth=self._get_credentials(), **kwargs)

    def post(self, *args, **kwargs):
        return self._execute_request(
            requests.post, *args, auth=self._get_credentials(), **kwargs)

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
