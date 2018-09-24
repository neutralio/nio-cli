from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
from ipaddress import ip_address
from os.path import join, isfile, dirname
from platform import system
from subprocess import run
from .inputs import get_boolean, get_string
from .files import ensure_dir_exists, DEFAULT_ROOT


def config_ssl(root):
    # See if they want to specify a custom CA to sign with
    ca_cert_path = get_string(
        "Enter the path to your CA certificate. If the CA does not exist "
        "one will be created there for you",
        default=join(DEFAULT_ROOT, 'ca.crt'))
    ca_key_path = get_string(
        "Enter the path to your CA private key. If the key does not exist "
        "one will be created there for you",
        default=join(DEFAULT_ROOT, 'ca.key'))
    if not isfile(ca_cert_path):
        print("No CA certificate found, creating one...")
        ca_crt, ca_key = _create_ca()
        ensure_dir_exists(dirname(ca_cert_path))
        ensure_dir_exists(dirname(ca_key_path))
        _save_cert(ca_cert_path, ca_crt)
        _save_key(ca_key_path, ca_key)
        _trust_cert(ca_cert_path)
    else:
        ca_crt = _read_cert(ca_cert_path)
        ca_key = _read_key(ca_key_path)

    host = get_string(
        "Enter the host where you will access your instance",
        default="localhost")

    cert_crt, cert_key = _create_instance_cert(host, ca_crt, ca_key)
    cert_path = join('etc', 'ssl', 'cert.crt')
    key_path = join('etc', 'ssl', 'cert.key')
    ensure_dir_exists(join(root, 'etc', 'ssl'))
    _save_key(join(root, key_path), cert_key)
    _save_cert(join(root, cert_path), cert_crt)

    return cert_path, key_path


def _trust_cert(cert_path):
    if system() == 'Darwin':
        _trust_cert_mac(cert_path)
    else:
        print("Couldn't detect OS type, you may need to trust your "
              "newly created certificate")


def _read_cert(filename):
    with open(filename, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert


def _read_key(filename):
    with open(filename, 'rb') as f:
        key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend(),
        )
    return key


def _save_cert(filename, cert):
    with open(filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _save_key(filename, key):
    with open(filename, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def _create_ca():
    return _create_cert(
        host=None,
        signing_cert=None,
        signing_key=None,
        common_name="nio local instance CA",
    )


def _create_instance_cert(host, signing_cert, signing_key):
    return _create_cert(
        host=host,
        signing_cert=signing_cert,
        signing_key=signing_key,
        common_name=host,
    )


def _create_cert(host, signing_cert, signing_key, common_name):
    """ Creates a new certificate signed with a key

    If no signing key is specified the cert's private key will be used

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

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CO"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Broomfield"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "niolabs"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    if signing_key is None:
        # No signing key specified, sign with the private key instead
        signing_key = pk

    if signing_cert is None:
        issuer = subject
    else:
        issuer = signing_cert.subject

    builder = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(pk.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.utcnow())\
        .not_valid_after(datetime.utcnow() + timedelta(days=365))

    if host:
        # This is a local certificate
        try:
            # Figure out if the host is an IP address or a DNS name and
            # create the proper x509 resource for the SAN extension here
            host_resource = x509.IPAddress(ip_address(host))
        except ValueError:
            host_resource = x509.DNSName(host)
        builder = builder.add_extension(
            x509.SubjectAlternativeName([host_resource]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pk.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                signing_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier)
            ),
            critical=False,
        )
    else:
        # This is a CA certificate
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pk.public_key()),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                pk.public_key()),
            critical=False,
        )

    cert = builder.sign(signing_key, hashes.SHA256(), default_backend())

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
