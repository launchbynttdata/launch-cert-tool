import itertools
import pathlib
import socket
import ssl

import certifi
import cryptography
import cryptography.x509
import pki_tools
import typer
from arn import Arn
from boto3 import Session
from pydantic import HttpUrl
from rich.console import Console

console = Console(stderr=False)
err_console = Console(stderr=True)

FAILURE_MESSAGE_COMMON = (
    "[bold red]Failure: your certificate chain could not be validated![/bold red]\n"
)

# Set up our SSL context and flags for all remote verifications.
# Uses the default CA bundle included with certifi, and enables CRL checking.
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(certifi.where())
context.verify_flags &= ssl.VERIFY_CRL_CHECK_CHAIN


class CertificateRevoked(Exception):
    pass


def get_acm_chain(arn: Arn) -> pki_tools.Chain:
    """Retrieves a certificate chain from AWS ACM. The environment running this
    script must be logged into AWS and have the necessary permissions to access
    the ACM service.

    Args:
        arn (Arn): ACM certificate ARN

    Raises:
        RuntimeError: Raised if the certificate chain cannot be retrieved from ACM.

    Returns:
        pki_tools.Chain: Chain of retrieved certificates.
    """
    try:
        boto_session = Session()
        acm_client = boto_session.client("acm", region_name=arn.region)
        response = acm_client.get_certificate(CertificateArn=str(arn))

        certificate = pki_tools.Certificate.from_pem_string(response["Certificate"])
        chain = pki_tools.Chain.from_pem_string(response["CertificateChain"])
        return pki_tools.Chain(certificates=[certificate] + chain.certificates)
    except Exception as e:
        raise RuntimeError(
            f"Failed to retrieve certificate chain from ACM for {arn}: {e}"
        ) from e


def get_remote_chain(hostname: str, port: int = 443) -> pki_tools.Chain:
    """Initiates an SSL connection to a remote host and retrieves the certificate chain.

    Args:
        hostname (str): Remote host
        port (int, optional): Remote port. Defaults to 443.

    Raises:
        RuntimeError: Raised if no verified chain can be retrieved from the URL.

    Returns:
        pki_tools.Chain: Chain of certificates from the remote server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        console.print(f"Opening socket to {hostname}:{port}...")
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            ssock.connect((hostname, port))
            console.print(f"Connected to {hostname}:{port} in an SSL session context!")
            verified_chain_bytes = ssock.get_verified_chain()
            if not verified_chain_bytes:
                raise RuntimeError(f"Failed to get verified chain for {hostname}")
            x509_chain_verified = [
                cryptography.x509.load_der_x509_certificate(b)
                for b in verified_chain_bytes
            ]
    return pki_tools.Chain.from_cryptography(crypto_certs=x509_chain_verified)


def get_local_chain(paths: list[pathlib.Path]) -> pki_tools.Chain:
    """Reads a list of local files and builds a certificate chain from them.

    Args:
        paths (list[pathlib.Path]): List of file paths containing certificates.

    Returns:
        pki_tools.Chain: Chain of certificates from the local files.
    """
    certs = list(
        itertools.chain.from_iterable(
            [pki_tools.Chain.from_file(str(p)).certificates for p in paths]
        )
    )
    if len(certs) <= 1:
        raise pki_tools.NotCompleteChain(
            "This certificate chain is not complete! Ensure your files contain the root and all intermediate keys."
        )
    return pki_tools.Chain(certificates=certs)


def validate_chain_crl(chain: pki_tools.Chain):
    for cert in chain.certificates:
        console.print(f"Checking CRL for {cert.subject}")
        if cert.issuer != cert.subject and pki_tools.is_revoked(cert, chain=chain):
            raise CertificateRevoked(f"Certificate {cert.subject} is revoked!")


def check_local_chains(paths: list[pathlib.Path], verbose: bool = False) -> None:
    """Take a list of local file paths, combine them into a single chain, and validate the chain.

    Args:
        paths (list[pathlib.Path]): List of files containing certificates.
        verbose (bool, optional): Write the combined chain's details to stdout. Defaults to False.
    """
    console.print("Composing a certificate chain from the following files:")
    for p in paths:
        console.print(f"  - {p}")
    chain = get_local_chain(paths)
    chain.check_chain()
    validate_chain_crl(chain=chain)
    if verbose:
        console.print(chain)
    console.print(
        f"[bold green]Local chain constructed from {', '.join([str(p) for p in paths])} is valid![/bold green]"
    )


def check_remote_chain(url: HttpUrl, verbose: bool = False):
    """Take a remote URL, retrieve the certificate chain, and validate it.

    Args:
        url (RemoteUrl): URL to retrieve
        verbose (bool, optional): Write the chain's details to stdout. Defaults to False.
    """
    chain = get_remote_chain(url.host, url.port if url.port is not None else 443)
    chain.check_chain()
    validate_chain_crl(chain=chain)
    if verbose:
        console.print(chain)
    console.print(f"[bold green]Remote chain for URL {url} is valid![/bold green]")


def check_acm_chain(arn: Arn, verbose: bool = False):
    chain = get_acm_chain(arn=arn)
    chain.check_chain()
    validate_chain_crl(chain=chain)
    if verbose:
        console.print(chain)
    console.print(
        f"[bold green]ACM chain constructed from {arn} is valid![/bold green]"
    )


def analyze_certificate_chain(
    values: list[pathlib.Path] | HttpUrl | Arn, verbose: bool = False
):
    """Entrypoint for the CLI. Analyze a certificate chain, either local, remote via HTTPS, or from ACM.

    Args:
        values (list[pathlib.Path] | HttpUrl | Arn): List of files to build into a single chain, or a URL to retrieve.
        verbose (bool, optional): Write the chain's details to stdout. Defaults to False.
    """
    try:
        if isinstance(values, HttpUrl):
            check_remote_chain(url=values, verbose=verbose)
        elif isinstance(values, Arn):
            check_acm_chain(arn=values, verbose=verbose)
        else:
            check_local_chains(paths=values, verbose=verbose)
    except pki_tools.NotCompleteChain:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain is not complete! Ensure your file has the root and all intermediate keys."
        )
        raise typer.Exit(code=1)
    except pki_tools.CertExpired:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain contains one or more expired certificates."
        )
        raise typer.Exit(code=2)
    except pki_tools.InvalidSignedType:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain contains an issuer with a non-supported type."
        )
        raise typer.Exit(code=3)
    except pki_tools.SignatureVerificationFailed:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain contains a certificate with an invalid signature."
        )
        raise typer.Exit(code=4)
    except pki_tools.CertIssuerMissingInChain:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain is missing an issuer."
        )
        raise typer.Exit(code=5)
    except CertificateRevoked as cr:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}This certificate chain contains a revoked certificate: {cr}"
        )
        raise typer.Exit(code=8)
    except pki_tools.RevokeCheckFailed:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}Failed to check the revocation status of a certificate in the chain."
        )
        raise typer.Exit(code=9)
    except socket.gaierror:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}Failed to resolve the hostname: {values}"
        )
        raise typer.Exit(code=10)
    except socket.timeout:
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}Timeout while connecting to hostname: {values}"
        )
        raise typer.Exit(code=11)
    except Exception as e:
        if type(e) is ssl.SSLCertVerificationError:
            if "certificate has expired" in str(e):
                err_console.print(
                    f"{FAILURE_MESSAGE_COMMON}This certificate chain contains one or more expired certificates."
                )
                raise typer.Exit(code=2)
            if "self-signed certificate in certificate chain" in str(e):
                err_console.print(
                    f"{FAILURE_MESSAGE_COMMON}This certificate chain contains a self-signed certificate."
                )
                raise typer.Exit(code=6)
            if "Hostname mismatch" in str(e):
                err_console.print(
                    f"{FAILURE_MESSAGE_COMMON}The hostname in the certificate does not match the requested URL. {e}"
                )
                raise typer.Exit(code=7)
            if "self-signed certificate" in str(e):
                err_console.print(
                    f"{FAILURE_MESSAGE_COMMON}This certificate chain contains a self-signed certificate."
                )
                raise typer.Exit(code=6)
        err_console.print(
            f"{FAILURE_MESSAGE_COMMON}An unexpected error occurred: {type(e)} {e}"
        )
        raise typer.Exit(code=-1)
