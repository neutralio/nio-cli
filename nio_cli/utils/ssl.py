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
    ca_crt, ca_key = _create_ca()
    ca_cert_path = 'etc/ssl/ca.crt'
    ca_key_path = 'etc/ssl/ca.key'
    _save_key(root, ca_key_path, ca_key)
    _save_cert(root, ca_cert_path, ca_crt)

    cert_crt, cert_key = _create_instance_cert(host, ca_crt, ca_key)
    cert_path = 'etc/ssl/cert.crt'
    key_path = 'etc/ssl/cert.key'
    _save_key(root, key_path, cert_key)
    _save_cert(root, cert_path, cert_crt)

    if system() == 'Darwin':
        _trust_cert_mac(join(root, ca_cert_path))
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
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ), critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
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
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ), critical=False,
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
