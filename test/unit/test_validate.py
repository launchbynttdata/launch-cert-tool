import pathlib
import socket
import ssl

import pki_tools
import pytest
from arn import Arn
from typer.testing import CliRunner

from launch_cert_tool import validate
from launch_cert_tool.cli import app

runner = CliRunner()


def test_unhandled_exception_exits_1(mocker):
    mocker.patch("launch_cert_tool.validate.check_local_chains", side_effect=Exception)
    mocker.patch(
        "launch_cert_tool.parser.parse_filename", return_value=[pathlib.Path(".")]
    )
    result = runner.invoke(app, args=["validate", "local", "."])
    assert result.exit_code == -1


@pytest.mark.parametrize(
    "exception_type, expected_code, expected_text",
    [
        (pki_tools.NotCompleteChain, 1, "This certificate chain is not complete"),
        (
            pki_tools.CertExpired,
            2,
            "This certificate chain contains one or more expired certificates",
        ),
        (
            pki_tools.InvalidSignedType,
            3,
            "This certificate chain contains an issuer with a non-supported type",
        ),
        (
            pki_tools.SignatureVerificationFailed,
            4,
            "This certificate chain contains a certificate with an invalid signature",
        ),
        (
            pki_tools.CertIssuerMissingInChain,
            5,
            "This certificate chain is missing an issuer",
        ),
        (
            validate.CertificateRevoked,
            8,
            "This certificate chain contains a revoked certificate",
        ),
        (
            pki_tools.RevokeCheckFailed,
            9,
            "Failed to check the revocation status of a certificate in the chain",
        ),
        (
            ssl.SSLCertVerificationError("certificate has expired"),
            2,
            "This certificate chain contains one or more expired certificates",
        ),
        (
            ssl.SSLCertVerificationError(
                "self-signed certificate in certificate chain"
            ),
            6,
            "This certificate chain contains a self-signed certificate",
        ),
        (
            ssl.SSLCertVerificationError("Hostname mismatch"),
            7,
            "The hostname in the certificate does not match the requested URL",
        ),
        (
            ssl.SSLCertVerificationError("self-signed certificate"),
            6,
            "This certificate chain contains a self-signed certificate",
        ),
        (
            socket.gaierror,
            10,
            "Failed to resolve the hostname: ",
        ),
        (
            socket.timeout,
            11,
            "Timeout while connecting to hostname: ",
        ),
    ],
)
def test_handled_exceptions(
    exception_type: type, expected_code: int, expected_text: str, mocker
):

    mocker.patch(
        "launch_cert_tool.validate.check_local_chains", side_effect=exception_type
    )
    mocker.patch(
        "launch_cert_tool.parser.parse_filename", return_value=[pathlib.Path(".")]
    )
    result = runner.invoke(app, args=["validate", "local", "LICENSE"])
    assert result.exit_code == expected_code
    assert expected_text in result.stdout


def test_acm_respects_region_from_arn(mocker):
    session_mock = mocker.patch.object(validate, "Session")
    mocked_boto_session = mocker.MagicMock()
    session_mock.return_value = mocked_boto_session
    arn = Arn(
        "arn:aws:acm:foo:123456789012:certificate/12345678-1234-1234-1234-123456789012"
    )

    # pki_tools doesn't play nice with a MagicMock so we expect this failure to be raised in a mock scenario.
    with pytest.raises(
        RuntimeError, match=f"Failed to retrieve certificate chain from ACM for {arn}"
    ):
        validate.get_acm_chain(arn=arn)
    mocked_boto_session.client.assert_called_with("acm", region_name="foo")
