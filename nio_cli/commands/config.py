from .base import Base
import requests
import os
import re
import sys
import tempfile
import subprocess


def config_project(name='.'):
    os.system('cls' if os.name == 'nt' else 'clear')
    conf_location = '{}/nio.conf'.format(name)
    pkconf_location = '{}/pk_server.conf'.format(name)

    if not os.path.isfile(conf_location):
        print("Command must be run from project root.")
        return

    print('')
    print('\033[92m' + 'Configure your local nio instance:' + '\033[0m')

    niohost = get_niohost()
    nioport = get_nioport()

    print('')
    print('\033[92m' + 'Configure Pubkeeper for instance communications:' + '\033[0m')
    standalone_pubkeeper = input('Are you running a standalone Pubkeeper Server? [y/N, default = N]: ') or 'n'

    if (standalone_pubkeeper.lower() == 'n'):
        pk_host = get_pkhost()
        pk_token = get_pktoken()
        ws_host = pk_host.replace('.pubkeeper.', '.websocket.')
        ws_host = ws_host.replace('pk.demo.', 'ws.demo.')

        with open(conf_location, 'r') as nconf,\
                tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            for line in nconf:
                if re.search('^NIOHOST=', line) and niohost:
                    tmp.write('NIOHOST={}\n'.format(niohost))
                elif re.search('^NIOPORT=', line) and nioport:
                    tmp.write('NIOPORT={}\n'.format(nioport))
                elif re.search('^PK_HOST=', line) and pk_host:
                    tmp.write('PK_HOST={}\n'.format(pk_host))
                elif re.search('^WS_HOST=', line) and pk_host:
                    tmp.write('WS_HOST={}\n'.format(ws_host))
                elif re.search('^PK_TOKEN=', line) and pk_token:
                    tmp.write('PK_TOKEN={}\n'.format(pk_token))
                else:
                    tmp.write(line)
        os.remove(conf_location)
        os.rename(tmp.name, conf_location)

    else:
        if not os.path.isfile(pkconf_location):
            print("Could not locate pk_server.conf file.")
            return
        pk_token = get_standalone_pktoken()
        with open(pkconf_location, 'r') as nconf,\
                tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
            for line in nconf:
                if re.search('^PK_TOKEN=', line) and pk_token:
                    tmp.write('PK_TOKEN={}\n'.format(pk_token))
                else:
                    tmp.write(line)
        os.remove(pkconf_location)
        os.rename(tmp.name, pkconf_location)

    print('')
    print('\033[92m' + 'Configure instance encryption:' + '\033[0m')
    secure = input('Secure instance with SSL? [y/N, default = N]: ')

    if (secure.lower() == 'y'):
        config_ssl(name, conf_location, niohost, nioport, standalone_pubkeeper.lower() != 'n')

    else:
        success_message(name, False, False, niohost, nioport, standalone_pubkeeper.lower() != 'n')

def config_ssl(name, conf_location, niohost, nioport, standalone_pubkeeper):

    ssl_cert = ''
    ssl_key = ''
    cwd = os.getcwd()

    new_certs = input('Generate a self-signed certificate/key [y/N, default = N]: ')

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
        cert.get_subject().CN = niohost
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(kp)
        cert.sign(kp, 'sha1')

        open('{}/certificate.pem'.format(name), "wt").write(
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
            )
        open('{}/private_key.pem'.format(name), "wt").write(
            crypto.dump_privatekey(crypto.FILETYPE_PEM, kp).decode('utf-8')
            )

        ssl_cert = '{}/{}/certificate.pem'.format(cwd, name)
        ssl_key = '{}/{}/private_key.pem'.format(cwd, name)

    else:
        ssl_cert = get_ssl_cert()
        ssl_key = get_ssl_key()

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

    success_message(name, True, new_certs.lower() == 'y', niohost, nioport, standalone_pubkeeper)

def success_message(name, ssl, self_signed, niohost, nioport, standalone_pubkeeper):

    print('')
    print('\033[92m' + 'Success!' + '\033[0m')
    print('')
    print('First, start your instance:')
    print('- Enter your project directory: ' + '\033[94m' + 'cd ' + name + '\033[0m')

    if (standalone_pubkeeper and nioport <= 1024):
        print('- Start the nio daemon: '  + '\033[94m' + 'sudo niod -s nio.conf -s pk_server.conf' + '\033[0m')
        print('- Start the nio daemon inn the background: '  + '\033[94m' + 'sudo nohup niod -s nio.conf -s pk_server.conf 2>&1 > /dev/null &' + '\033[0m')

    elif (standalone_pubkeeper):
        print('- Start the nio daemon: '  + '\033[94m' + 'niod -s nio.conf -s pk_server.conf' + '\033[0m')
        print('- Start the nio daemon in the background: '  + '\033[94m' + 'nohup niod -s nio.conf -s pk_server.conf 2>&1 > /dev/null &' + '\033[0m')

    elif (nioport <= 1024):
        print('- Start the nio daemon: '  + '\033[94m' + 'sudo niod' + '\033[0m')
        print('- Start the nio daemon in the background: '  + '\033[94m' + 'sudo nohup niod 2>&1 > /dev/null &' + '\033[0m')

    else:
        print('- Start the nio daemon: '  + '\033[94m' + 'niod' + '\033[0m')
        print('- Start the nio daemon in the background: '  + '\033[94m' + 'nohup niod 2>&1 > /dev/null &' + '\033[0m')

    if (self_signed == True):
        print('')
        print('Next, accept your self-signed certificate by visiting ' + '\033[94m' + 'https://' + niohost + ':' + str(nioport) + '\033[0m' + ' and clicking "Advanced > Proceed to Site Anyway".' + '\033[0m')

    if (ssl == True):
        print('')
        print('Then, proceed to ' + '\033[94m' + 'https://app.n.io/design' + '\033[0m' + ' and add your local instance to the designer: ')
        print('- hostname:' + '\033[94m' + ' https://' + niohost + '\033[0m')

    else:
        print('')
        print('Then, proceed to ' + '\033[94m' + 'http://app.n.io/design' + '\033[0m' + ' and add your local instance to the designer: ')
        print('- hostname:' + '\033[94m' + ' http://' + niohost + '\033[0m')

    print('- port: ' + '\033[94m' + str(nioport) + '\033[0m')
    print('')


def get_niohost():

    niohost = False

    niohost = input('Enter instance hostname or IP [default: localhost]: ') or 'localhost'

    return niohost


def get_nioport(error = False):

    nioport = False

    while True:
        try:
            if error:
                nioport = int(input('\033[91m' +'Enter instance port [number, below 1024 requires "sudo", default: 8181]: ' + '\033[0m') or "8181")
            else:
                nioport = int(input('Enter instance port [number, below 1024 requires "sudo", default: 8181]: ') or "8181")
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return nioport

def get_pkhost(error = False):

    pk_host = False

    while True:
        try:
            if error:
                pk_host = input('\033[91m' +'Enter Pubkeeper hostname [required]: ' + '\033[0m')
            else:
                pk_host = input('Enter Pubkeeper hostname [required]: ')
            if not pk_host:
                raise ValueError
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return pk_host

def get_pktoken(error = False):

    pk_token = False

    while True:
        try:
            if error:
                pk_token = input('\033[91m' +'Enter Pubkeeper token [required]: ' + '\033[0m')
            else:
                pk_token = input('Enter Pubkeeper token [required]: ')
            if not pk_token:
                raise ValueError
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return pk_token

def get_ssl_cert(error = False):

    ssl_cert = False

    while True:
        try:
            if error:
                ssl_cert = input('\033[91m' +'Enter SSL certificate file location [required]: ' + '\033[0m')
            else:
                ssl_cert = input('Enter SSL certificate file location [required]: ')
            if not ssl_cert:
                raise ValueError
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return ssl_cert

def get_ssl_key(error = False):

    ssl_key = False

    while True:
        try:
            if error:
                ssl_key = input('\033[91m' +'Enter SSL private key file location [required]: ' + '\033[0m')
            else:
                ssl_key = input('Enter SSL private key file location [required]: ')
            if not ssl_key:
                raise ValueError
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return ssl_key

def get_standalone_pktoken(error = False):

    pk_token = False

    while True:
        try:
            if error:
                pk_token = input('\033[91m' +'Enter a complex, random string Pubkeeper will use to secure intra-service communication [required]: ' + '\033[0m')
            else:
                pk_token = input('Enter a complex, random string Pubkeeper will use to secure intra-instance communication [required]: ')
            if not pk_token:
                raise ValueError
        except ValueError:
            sys.stdout.write("\033[F\033[K")
            error = True
            continue
        else:
            break

    return pk_token


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
