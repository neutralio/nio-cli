import requests
import json
import sys

class NIOClient(object):

    host = 'localhost'
    port = 8181
    auth = ('username', 'password')

    @classmethod
    def initialize(cls, host, port, auth):
        cls.host = host or cls.host
        cls.port = port or cls.port
        cls.auth = auth or cls.auth
        cls.base_url = "http://{0}:{1}/{2}".format(host, port, '{0}')

    ## Methods for interacting with the NIO API

    @classmethod
    def build(cls, name, data):
        return cls.config('services', name, data)

    @classmethod
    def config(cls, resource, name, data):
        request = {
            'resource': resource,
            'name': name
        }
        data = json.dumps(data)
        return cls._request('PUT', request, data)

    @classmethod
    def command(cls, cmd, service, block='', data=None):
        request = {
            'resource': 'services',
            'name': service,
            'sub_name': block,
            'cmd': cmd
        }
        if data is not None:
            data = json.dumps(data)
        return cls._request('POST', request, data)

    @classmethod
    def list(cls, resource, name='', cmd_ls=False, _filter=[]):
        request = {
            'resource': resource,
            'name': name,
            'cmd': 'commands' if cmd_ls else None,
            'params': _filter
        }
        return cls._request('GET', request)

    @classmethod
    def shutdown(cls):
        request = {
            'resource': 'shutdown'
        }
        cls._request('GET', request)

    @classmethod
    def update(cls, block_type):
        cls.config('blocks_types', block_type, {}) 

    @classmethod
    def _request(cls, method, req_info, data=None):
        endpoint = cls._construct_endpoint(**req_info)
        url = cls.base_url.format(endpoint)
        rsp = requests.request(method, url, data=data, auth=cls.auth)
        status = rsp.status_code

        if status == 401:
            print("NIOCLient: Insufficient Permissions "
                  "(username: {0})".format(cls.auth[0]),
                  file=sys.stderr)
        elif status >= 300:
            print("NIOClient: NIO returned status {0}".format(status), 
                  file=sys.stderr)
            return None
        elif not rsp.text:
            print('`%s`' % rsp.request.url, 
                  "was processed successfully")
        return rsp

    @classmethod
    def _construct_endpoint(cls, **kwargs):
        ''' Build the endpoint for a NIO api call. In general, NIO endpoints
        take the form <resource>/<name>/<sub_name>.
        
        '''
        
        result = '{0}/{1}/'.format(kwargs.get('resource'), kwargs.get('name'))

        sub_name = kwargs.get('sub_name')
        if sub_name:
            result += '{0}/'.format(sub_name)

        cmd = kwargs.get('cmd')
        if cmd:
            result += '{0}/'.format(cmd)

        result = result.rstrip('/')
        result += cls._param_string(kwargs.get('params') or [])
 
        return result

    @classmethod
    def _param_string(cls, params):
        result = '?'
        for p in params:
            result += "{0}&".format(p)
        return result.rstrip('&').rstrip('?')
        
