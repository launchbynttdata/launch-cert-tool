from typing import Annotated

import arn
import loguru
import typer
from pydantic import HttpUrl
from rich.console import Console

from launch_cert_tool.parser import parse_arn, parse_filename, parse_url
from launch_cert_tool.validate import analyze_certificate_chain

app = typer.Typer(no_args_is_help=True)
validate_app = typer.Typer(no_args_is_help=True)
app.add_typer(validate_app, name="validate")

console = Console(stderr=False)
err_console = Console(stderr=True)

# Suppress logs from pki_tools directly, we'll log what we need to stdout.
loguru.logger.disable("pki_tools")


@validate_app.command()
def local(
    paths: Annotated[
        list[str],
        typer.Argument(
            parser=parse_filename,
            help="Path to local files containing keys to validate. If multiple files are specified, they will be combined into a single chain and validated together, allowing users to have a leaf certificate and the intermediate chain in separate files.",
        ),
    ],
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Print the certificate chain to the console.",
        ),
    ] = False,
):
    """Verify a certificate chain from local file(s). If multiple files are provided, they will be combined into a single chain and validated together."""
    analyze_certificate_chain(values=paths, verbose=verbose)


@validate_app.command()
def remote(
    url: Annotated[
        HttpUrl,
        typer.Argument(
            parser=parse_url,
            help="URL to validate certificate chain. If the URL scheme is included, it must be https://",
        ),
    ],
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Print the certificate chain to the console.",
        ),
    ] = False,
):
    """Verify a certificate chain from a remote URL."""
    analyze_certificate_chain(values=url, verbose=verbose)


@validate_app.command()
def acm(
    arn: Annotated[
        arn.Arn,
        typer.Argument(
            parser=parse_arn,
            help="ARN of the ACM certificate to validate.",
        ),
    ],
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            help="Print the certificate chain to the console.",
        ),
    ] = False,
):
    """Verify a certificate chain from AWS ACM."""
    analyze_certificate_chain(values=arn, verbose=verbose)


if __name__ == "__main__":  # pragma: no cover
    app()
