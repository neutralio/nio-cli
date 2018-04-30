from .base import Base
import requests
import os
import re
import tempfile


def config_project(name='.', pubkeeper_hostname=None, pubkeeper_token=None):
    conf_location = '{}/nio.conf'.format(name)
    if not os.path.isfile(conf_location):
        print("Command must be run from project root.")
        return

    pk_host = input('Enter Pubkeeper hostname (optional): ') \
        if pubkeeper_hostname is None else pubkeeper_hostname
    pk_token = input('Enter Pubkeeper token (optional): ') \
        if pubkeeper_token is None else pubkeeper_token
    ws_host = pk_host.replace('pubkeeper', 'websocket')

    with open(conf_location, 'r') as nconf,\
            tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        for line in nconf:
            if re.search('^PK_HOST=', line) and pk_host:
                tmp.write('PK_HOST={}\n'.format(pk_host))
            elif re.search('^WS_HOST=', line) and pk_host:
                tmp.write('WS_HOST={}\n'.format(ws_host))
            elif re.search('^PK_TOKEN=', line) and pk_token:
                tmp.write('PK_TOKEN={}\n'.format(pk_token))
            else:
                tmp.write(line)
    os.remove(conf_location)
    os.rename(tmp.name, conf_location)

    secure = input('Optional secure instance configuration [Y/N]: ')
    if secure.lower() == 'y':
        config_ssl(name, conf_location)


def config_ssl(name, conf_location):

    ssl_cert = ''
    ssl_key = ''
    cwd = os.getcwd()

    new_certs = input('Generate a self-signed certificate/key [Y/N]: ')

    if (new_certs.lower() == 'y'):
        try:
            from OpenSSL import crypto
        except Exception as e:
            print('No pyOpenSSL installation detected. Your instance has still been configured but no certs were installed. To install certificates install pyOpenSSL and re-run "nio config" from inside the project directory.')
            return

        # Create a key pair
        kp = crypto.PKey()
        kp.generate_key(crypto.TYPE_RSA, 2048)

        # Create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = input('Enter two-letter country code: ')
        cert.get_subject().ST = input('Enter state: ')
        cert.get_subject().L = input('Enter city: ')
        cert.get_subject().O = input('Enter company/owner: ')
        cert.get_subject().OU = input('Enter user: ')
        cert.get_subject().CN = 'localhost'
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(kp)
        cert.sign(kp, 'sha1')

        open('{}/certificate.pem'.format(name), "wt").write(
            str(crypto.dump_certificate(crypto.FILETYPE_PEM, cert)))
        open('{}/private_key.pem'.format(name), "wt").write(
            str(crypto.dump_privatekey(crypto.FILETYPE_PEM, kp)))

        ssl_cert = '{}/{}/certificate.pem'.format(cwd, name)
        ssl_key = '{}/{}/private_key.pem'.format(cwd, name)

    else:
        ssl_cert = input('Enter SSL certificate file location: ')
        ssl_key = input('Enter SSL private key file location: ')

    with open(conf_location, 'r') as nconf,\
            tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        for line in nconf:
            if re.search('^ssl_certificate:', line) and ssl_cert:
                tmp.write('ssl_certificate: {}\n'.format(ssl_cert))
            elif re.search('^ssl_private_key:', line) and ssl_key:
                tmp.write('ssl_private_key: {}\n'.format(ssl_key))
            else:
                tmp.write(line)
    os.remove(conf_location)
    os.rename(tmp.name, conf_location)


class Config(Base):
    """ Get basic nio info """

    def __init__(self, options, *args, **kwargs):
        super().__init__(options, *args, **kwargs)
        self._resource = 'services' if self.options.get('services') else \
            'blocks' if self.options.get('blocks') else \
            'project'
        self._resource_name = \
            self.options.get('<service-name>') if self.options.get('services') else \
            self.options.get('<block-name>') if self.options.get('blocks') else \
            ""

    def config_block_or_service(self):
        response = requests.get(
            self._base_url.format(
                '{}/{}'.format(self._resource, self._resource_name)),
            auth=self._auth)
        try:
            config = response.json()
            print(config)
        except Exception as e:
            print(e)

    def run(self):
        if self._resource == 'project':
            config_project()
        else:
            self.config_block_or_service()
