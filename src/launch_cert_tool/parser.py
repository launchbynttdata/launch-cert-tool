import pathlib

import arn
from pydantic import HttpUrl


def parse_url(value: str) -> HttpUrl:
    """Typer helper function to parse a URL and ensure it is HTTPS.

    Args:
        value (str): URL-ish input

    Raises:
        ValueError: Raised if the URL scheme was supplied and wasn't https.

    Returns:
        HttpUrl: Parsed URL object.
    """
    if "://" not in value:
        value = f"https://{value}"
    remote = HttpUrl(url=value)
    if remote.scheme == "https":
        return remote
    raise ValueError("Invalid target: if URL scheme is specified, it must be https://")


def parse_filename(value: str) -> pathlib.Path:
    """Typer helper function to parse a filename and ensure it exists.

    Args:
        value (str): Path-ish input

    Raises:
        FileNotFoundError: Raised if the file path provided does not exist.

    Returns:
        pathlib.Path: Parsed Path object.
    """
    p = pathlib.Path(value)
    if p.exists():
        return p
    else:
        raise FileNotFoundError(f"File {value} does not exist")


def parse_arn(value: str) -> arn.Arn:
    """Typer helper function to parse an ARN.

    Args:
        value (str): ARN-ish input

    Returns:
        arn.Arn: Parsed ARN object.
    """
    return arn.Arn(input_arn=value)
