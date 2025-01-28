import pathlib
import socket
import ssl

import certifi
import cryptography.x509
import pki_tools
import pytest


@pytest.fixture
def unsafe_cert_download():
    def _unsafe_cert_download(hostname: str, out_path: pathlib.Path, port: int = 443):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(certifi.where())
        # Allows us to connect to servers with self-signed certificates and hostname mismatches
        context.check_hostname = False
        # Setting verify_mode to CERT_NONE turns off most certificate verification behaviors
        # so that we can actually retrieve the certificate material without erroring out during
        # the handshake. This is fine for testing purposes where we deliberately want to validate
        # against known bad certificates, but should _never_ be set in application code.
        context.verify_mode = ssl.CERT_NONE

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssock.connect((hostname, port))
                verified_chain_bytes = ssock.get_verified_chain()
                if not verified_chain_bytes:
                    raise RuntimeError(f"Failed to get verified chain for {hostname}")
                x509_chain_verified = [
                    cryptography.x509.load_der_x509_certificate(b)
                    for b in verified_chain_bytes
                ]
        certs = pki_tools.Chain.from_cryptography(x509_chain_verified).certificates
        cert_files = []
        for idx, cert in enumerate(certs):
            cert_file = out_path.joinpath(f"cert-{idx}.pem")
            cert.to_file(str(cert_file))
            cert_files.append(cert_file)
        return cert_files

    return _unsafe_cert_download
