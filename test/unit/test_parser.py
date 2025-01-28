from contextlib import ExitStack as does_not_raise

import pytest
from arn import InvalidArnException

from launch_cert_tool import parser


@pytest.mark.parametrize(
    "url_value, raises",
    [
        ("https://launch.nttdata.com", does_not_raise()),
        ("launch.nttdata.com", does_not_raise()),
        ("http://launch.nttdata.com", pytest.raises(ValueError)),
    ],
)
def test_parse_url(url_value, raises):
    with raises:
        parser.parse_url(url_value)


def test_parse_filename(tmp_path):
    existing_file = tmp_path.joinpath("exists.txt")
    nonexistent_file = tmp_path.joinpath("nonexistent.txt")
    existing_file.touch()

    with does_not_raise():
        parser.parse_filename(value=str(existing_file))
    with pytest.raises(FileNotFoundError):
        parser.parse_filename(value=str(nonexistent_file))


@pytest.mark.parametrize(
    "arn, raises",
    [
        (
            "arn:aws:acm:us-east-1:123456789012:certificate/12345678-1234-1234-1234-123456789012",
            does_not_raise(),
        ),
        ("NOT_AN_ARN", pytest.raises(InvalidArnException)),
    ],
)
def test_parse_arn(arn, raises):
    with raises:
        parser.parse_arn(arn)
