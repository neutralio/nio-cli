import os
import re
import tempfile

from .ssl import config_ssl


def config_project(name='.', pubkeeper_hostname=None, pubkeeper_token=None,
                   ssl=False, niohost=None, nioport=None):
    conf_location = '{}/nio.conf'.format(name)
    if not os.path.isfile(conf_location):
        print("Command must be run from project root.")
        return

    if pubkeeper_hostname:
        websocket_hostname = pubkeeper_hostname.replace('pubkeeper',
                                                        'websocket')

    ssl_cert_path = ssl_key_path = None
    if ssl:
        ssl_cert_path, ssl_key_path = config_ssl(name)

    with open(conf_location, 'r') as nconf,\
            tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        for line in nconf:
            if re.search('^PK_HOST=', line) and pubkeeper_hostname:
                tmp.write('PK_HOST={}\n'.format(pubkeeper_hostname))
            elif re.search('^WS_HOST=', line) and pubkeeper_hostname:
                tmp.write('WS_HOST={}\n'.format(websocket_hostname))
            elif re.search('^PK_TOKEN=', line) and pubkeeper_token:
                tmp.write('PK_TOKEN={}\n'.format(pubkeeper_token))
            elif re.search('^NIOHOST=', line) and niohost:
                tmp.write('NIOHOST={}\n'.format(niohost))
            elif re.search('^NIOPORT=', line) and nioport:
                tmp.write('NIOPORT={}\n'.format(nioport))
            elif re.search('^ssl_certificate=', line) and ssl_cert_path:
                tmp.write('ssl_certificate={}\n'.format(ssl_cert_path))
            elif re.search('^ssl_private_key=', line) and ssl_key_path:
                tmp.write('ssl_private_key={}\n'.format(ssl_key_path))
            else:
                tmp.write(line)
    os.remove(conf_location)
    os.rename(tmp.name, conf_location)
