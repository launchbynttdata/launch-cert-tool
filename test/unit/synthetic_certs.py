"""Helpers to build small certificate chains for unit tests."""

from datetime import UTC, datetime, timedelta

import pki_tools
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _ca_extensions() -> list[x509.ExtensionType]:
    return [
        x509.BasicConstraints(ca=True, path_length=None),
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
    ]


def _ee_extensions() -> list[x509.ExtensionType]:
    return [
        x509.BasicConstraints(ca=False, path_length=None),
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    ]


def _sign(
    subject: x509.Name,
    issuer: x509.Name,
    public_key,
    signing_key,
    *,
    not_before: datetime,
    not_after: datetime,
    extensions: list[x509.ExtensionType],
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    for extension in extensions:
        builder = builder.add_extension(extension, critical=True)
    return builder.sign(signing_key, hashes.SHA256())


def build_chain(
    *,
    root_not_after: datetime | None = None,
    unrelated_ca_not_after: datetime | None = None,
    include_unrelated_ca: bool = False,
) -> pki_tools.Chain:
    """Build leaf <- intermediate <- root, optionally plus an unrelated expired CA."""
    now = datetime.now(UTC)
    default_validity = now + timedelta(days=365)
    root_not_after = root_not_after or default_validity
    unrelated_ca_not_after = unrelated_ca_not_after or (now - timedelta(days=1))

    root_key = _rsa_key()
    intermediate_key = _rsa_key()
    leaf_key = _rsa_key()
    unrelated_key = _rsa_key()

    root_name = _name("Test Root CA")
    intermediate_name = _name("Test Intermediate CA")
    leaf_name = _name("Test Leaf")
    unrelated_name = _name("Unrelated CA")

    root_cert = _sign(
        root_name,
        root_name,
        root_key.public_key(),
        root_key,
        not_before=now - timedelta(days=30),
        not_after=root_not_after,
        extensions=_ca_extensions(),
    )
    intermediate_cert = _sign(
        intermediate_name,
        root_name,
        intermediate_key.public_key(),
        root_key,
        not_before=now - timedelta(days=30),
        not_after=default_validity,
        extensions=_ca_extensions(),
    )
    leaf_cert = _sign(
        leaf_name,
        intermediate_name,
        leaf_key.public_key(),
        intermediate_key,
        not_before=now - timedelta(days=30),
        not_after=default_validity,
        extensions=_ee_extensions(),
    )

    crypto_certs = [leaf_cert, intermediate_cert, root_cert]
    if include_unrelated_ca:
        unrelated_cert = _sign(
            unrelated_name,
            unrelated_name,
            unrelated_key.public_key(),
            unrelated_key,
            not_before=now - timedelta(days=400),
            not_after=unrelated_ca_not_after,
            extensions=_ca_extensions(),
        )
        crypto_certs.append(unrelated_cert)

    return pki_tools.Chain.from_cryptography(crypto_certs=crypto_certs)


def build_ca_cycle_chain() -> pki_tools.Chain:
    """Build a leaf and two CAs that cross-sign with no self-signed trust anchor."""
    now = datetime.now(UTC)
    validity = now + timedelta(days=365)

    ca_a_key = _rsa_key()
    ca_b_key = _rsa_key()
    leaf_key = _rsa_key()

    ca_a_name = _name("Cycle CA A")
    ca_b_name = _name("Cycle CA B")
    leaf_name = _name("Cycle Leaf")

    ca_a_cert = _sign(
        ca_a_name,
        ca_b_name,
        ca_a_key.public_key(),
        ca_b_key,
        not_before=now - timedelta(days=30),
        not_after=validity,
        extensions=_ca_extensions(),
    )
    ca_b_cert = _sign(
        ca_b_name,
        ca_a_name,
        ca_b_key.public_key(),
        ca_a_key,
        not_before=now - timedelta(days=30),
        not_after=validity,
        extensions=_ca_extensions(),
    )
    leaf_cert = _sign(
        leaf_name,
        ca_a_name,
        leaf_key.public_key(),
        ca_a_key,
        not_before=now - timedelta(days=30),
        not_after=validity,
        extensions=_ee_extensions(),
    )

    return pki_tools.Chain.from_cryptography(
        crypto_certs=[leaf_cert, ca_a_cert, ca_b_cert]
    )
