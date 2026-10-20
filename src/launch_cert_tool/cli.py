from typing import Annotated

import arn
import loguru
import typer
from pydantic import HttpUrl
from rich.console import Console

from launch_cert_tool.parser import parse_arn, parse_filename, parse_url
from launch_cert_tool.validate import analyze_certificate_chain

app = typer.Typer(invoke_without_command=True)
validate_app = typer.Typer(invoke_without_command=True)
app.add_typer(validate_app, name="validate")


def _show_help_when_no_subcommand(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


@app.callback()
def _root(ctx: typer.Context) -> None:
    _show_help_when_no_subcommand(ctx)


@validate_app.callback()
def _validate_root(ctx: typer.Context) -> None:
    _show_help_when_no_subcommand(ctx)


console = Console(stderr=False)
err_console = Console(stderr=True)

# Suppress logs from pki_tools directly, we'll log what we need to stdout.
loguru.logger.disable("pki_tools")


def _verbose() -> typer.Option:
    return typer.Option(
        "--verbose",
        help="Print the certificate chain to the console.",
    )


def _check_trust_anchor_expiry() -> typer.Option:
    return typer.Option(
        "--check-trust-anchor-expiry/--no-check-trust-anchor-expiry",
        help="Validate notBefore/notAfter on self-signed trust anchors in the chain.",
    )


def _check_crl_option() -> typer.Option:
    return typer.Option(
        "--check-crl/--no-check-crl",
        help="Check certificate revocation using CRL distribution points.",
    )


@validate_app.command()
def local(
    paths: Annotated[
        list[str],
        typer.Argument(
            parser=parse_filename,
            help="Path to local files containing keys to validate. If multiple files are specified, they will be combined into a single chain and validated together, allowing users to have a leaf certificate and the intermediate chain in separate files.",
        ),
    ],
    verbose: Annotated[bool, _verbose()] = False,
    check_trust_anchor_expiry: Annotated[bool, _check_trust_anchor_expiry()] = True,
    check_crl: Annotated[bool, _check_crl_option()] = True,
):
    """Verify a certificate chain from local file(s). If multiple files are provided, they will be combined into a single chain and validated together."""
    analyze_certificate_chain(
        values=paths,
        verbose=verbose,
        check_trust_anchor_expiry=check_trust_anchor_expiry,
        check_crl=check_crl,
    )


@validate_app.command()
def remote(
    url: Annotated[
        HttpUrl,
        typer.Argument(
            parser=parse_url,
            help="URL to validate certificate chain. If the URL scheme is included, it must be https://",
        ),
    ],
    verbose: Annotated[bool, _verbose()] = False,
    check_trust_anchor_expiry: Annotated[bool, _check_trust_anchor_expiry()] = True,
    check_crl: Annotated[bool, _check_crl_option()] = True,
):
    """Verify a certificate chain from a remote URL."""
    analyze_certificate_chain(
        values=url,
        verbose=verbose,
        check_trust_anchor_expiry=check_trust_anchor_expiry,
        check_crl=check_crl,
    )


@validate_app.command()
def acm(
    arn: Annotated[
        arn.Arn,
        typer.Argument(
            parser=parse_arn,
            help="ARN of the ACM certificate to validate.",
        ),
    ],
    verbose: Annotated[bool, _verbose()] = False,
    check_trust_anchor_expiry: Annotated[bool, _check_trust_anchor_expiry()] = True,
    check_crl: Annotated[bool, _check_crl_option()] = True,
):
    """Verify a certificate chain from AWS ACM."""
    analyze_certificate_chain(
        values=arn,
        verbose=verbose,
        check_trust_anchor_expiry=check_trust_anchor_expiry,
        check_crl=check_crl,
    )


if __name__ == "__main__":  # pragma: no cover
    app()
