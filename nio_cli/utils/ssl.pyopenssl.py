from OpenSSL import crypto
from os.path import join


def config_ssl(root, conf_location):
    ca_crt, ca_key = _create_cert('niolabs CA')
    _save_key(root, 'ssl/ca.key', ca_key)
    _save_cert(root, 'ssl/ca.crt', ca_crt)

    cert_crt, cert_key = _create_cert(
        'localhost', 
        issuer=ca_crt.get_subject(),
        signing_key=ca_key)
    _save_key(root, 'ssl/cert.key', cert_key)
    _save_cert(root, 'ssl/cert.crt', cert_crt)


def _save_cert(root, filename, cert):
    with open(join(root, filename), 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


def _save_key(root, filename, key):
    with open(join(root, filename), 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))


def _create_cert(host, issuing_cert=None, issuing_key=None):
    """ Creates a new certificate signed with a key

    If no signing key is specified a new key will be created.

    Args:
        host: The host for the certificate
        signing_key: Private key for signing the certificate. If omitted a
            new key will be created

    Returns:
        cert, key: The certificate and private key it was signed with
    """

    # Create a key pair
    pk = crypto.PKey()
    pk.generate_key(crypto.TYPE_RSA, 2048)

    # Create a self-signed cert
    cert = crypto.X509()
    cert_subj = cert.get_subject()
    cert_subj.C = 'US'
    cert_subj.ST = 'CO'
    cert_subj.L = 'Broomfield'
    cert_subj.O = 'niolabs'  # noqa
    cert_subj.OU = 'niolabs'
    cert_subj.CN = host
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    if issuing_cert is None:
        cert.set_issuer(cert.get_subject())
        # Extensions for the CA cert
        cert.add_extensions([
            crypto.X509Extension(
                b"subjectKeyIdentifier", False, b"hash", subject=cert),
            crypto.X509Extension(
                b"authorityKeyIdentifier", False, b"keyid:always", issuer=cert),
            crypto.X509Extension(
                b"basicConstraints", False, b"CA:TRUE"),
            crypto.X509Extension(
                b"keyUsage", False, b"keyCertSign, cRLSign"),
        ])
    else:
        cert.set_issuer(issuing_cert.get_subject())
        # Extensions for the client cert
        cert.add_extensions([
            crypto.X509Extension(
                b"keyUsage", False,
                b"Digital Signature, Non Repudiation, Key Encipherment"),
            crypto.X509Extension(
                b"basicConstraints", False, b"CA:FALSE"),
            crypto.X509Extension(
                b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
            crypto.X509Extension(
                b"subjectAltName", False, b"localhost")
        ])

    if issuing_key is None:
        issuing_key = pk

    cert.set_pubkey(pk)
    cert.sign(issuing_key, 'sha256')

    return cert, pk


def check_pyopenssl():
    try:
        from OpenSSL import crypto  # noqa
        return True
    except Exception:
        print('No pyOpenSSL installation detected. Your instance has still '
              'been configured but no certs were installed. To install '
              'certificates install pyOpenSSL and re-run "nio config" from '
              'inside the project directory.')
        return False
