from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from ipaddress import ip_address
from os import makedirs, getcwd
from os.path import join
from platform import system
from subprocess import run
from .inputs import get_boolean, get_string


def config_ssl(root):
    makedirs(join(root, 'etc/ssl'), exist_ok=True)
    host = get_string(
        "Enter the host where you will access your instance",
        default="localhost")
    cert_crt, cert_key = _create_cert(host)
    cert_path = 'etc/ssl/cert.crt'
    key_path = 'etc/ssl/cert.key'
    _save_key(root, key_path, cert_key)
    _save_cert(root, cert_path, cert_crt)

    if system() == 'Darwin':
        _trust_cert_mac(join(root, cert_path))
    else:
        print("Couldn't detect OS type, you may need to trust your "
              "newly created certificate")

    cwd = getcwd()
    return join(cwd, root, cert_path), join(cwd, root, key_path)


def _save_cert(root, filename, cert):
    with open(join(root, filename), 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _save_key(root, filename, key):
    with open(join(root, filename), 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _create_cert(host):
    """ Creates a new certificate signed with a key

    If no signing key is specified a new key will be created.

    Args:
        host: The host for the certificate

    Returns:
        cert, key: The certificate and private key it was signed with
    """

    # Create a key pair
    pk = rsa.generate_private_key(
        public_exponent=2**16 + 1,
        key_size=2048,
        backend=default_backend(),
    )

    # Figure out if the host is an IP address or a DNS name and create the
    # proper x509 resource for the SAN extension here
    try:
        host_resource = x509.IPAddress(ip_address(host))
    except ValueError:
        host_resource = x509.DNSName(host)

    # Create a self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CO"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Broomfield"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "niolabs"),
        x509.NameAttribute(NameOID.COMMON_NAME, "nio local instance"),
    ])
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(pk.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))\
        .add_extension(
            x509.SubjectAlternativeName([host_resource]),
            critical=False,
        )\
        .sign(pk, hashes.SHA256(), default_backend())

    return cert, pk


def _trust_cert_mac(path_to_cert):
    """Prompt the user if they want to automatically trust the new cert"""
    msg = """
We detected that you are on a Mac. Would you like to add the newly
created certificate to your local Mac Keychain and trust it? If yes, you
will be prompted for your password"""
    execute = get_boolean(msg, default=True)
    if not execute:
        return
    trust_root = "$HOME/Library/Keychains/login.keychain"
    run("security add-trusted-cert -r trustRoot -k {} {}".format(
        trust_root, path_to_cert), shell=True, check=True)
