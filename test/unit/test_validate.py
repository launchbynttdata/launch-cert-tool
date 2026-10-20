import pathlib
import socket
import ssl
from datetime import UTC, datetime, timedelta

import pki_tools
import pytest
from arn import Arn
from typer.testing import CliRunner

from launch_cert_tool import validate
from launch_cert_tool.cli import app
from test.unit.synthetic_certs import build_chain

runner = CliRunner()


def test_find_end_entity_certificates_ignores_unrelated_expired_ca():
    chain = build_chain(include_unrelated_ca=True)
    end_entities = validate.find_end_entity_certificates(chain)
    assert len(end_entities) == 1
    assert "Test Leaf" in str(end_entities[0].subject)


def test_validate_certificate_chain_rejects_expired_trust_anchor():
    expired_root = datetime.now(UTC) - timedelta(days=1)
    chain = build_chain(root_not_after=expired_root)
    with pytest.raises(pki_tools.CertExpired):
        validate.validate_certificate_chain(chain, check_trust_anchor_expiry=True)


def test_check_local_chains_skips_trust_anchor_expiry_when_disabled(mocker):
    chain = build_chain(root_not_after=datetime.now(UTC) - timedelta(days=1))
    mocker.patch.object(validate, "get_local_chain", return_value=chain)
    mocker.patch.object(validate, "validate_chain_crl")
    validate.check_local_chains(
        paths=[pathlib.Path("a.pem"), pathlib.Path("b.pem")],
        check_trust_anchor_expiry=False,
    )


def test_check_local_chains_skips_crl_when_disabled(mocker):
    chain = build_chain()
    mocker.patch.object(validate, "get_local_chain", return_value=chain)
    crl_mock = mocker.patch.object(validate, "validate_chain_crl")
    validate.check_local_chains(
        paths=[pathlib.Path("a.pem"), pathlib.Path("b.pem")],
        check_crl=False,
    )
    crl_mock.assert_not_called()


def test_validate_certificate_chain_allows_unrelated_expired_ca():
    chain = build_chain(include_unrelated_ca=True)
    validate.validate_certificate_chain(chain, check_trust_anchor_expiry=True)


def test_assert_certificate_valid_rejects_not_yet_valid(mocker):
    cert = mocker.MagicMock()
    cert.subject = "test"
    cert.validity.not_after = datetime.now(UTC) + timedelta(days=1)
    cert.validity.not_before = datetime.now(UTC) + timedelta(days=1)
    with pytest.raises(pki_tools.CertExpired, match="not yet valid"):
        validate.assert_certificate_valid(cert)


def test_validate_certificate_chain_checks_end_entity_and_trust_path(mocker):
    chain = mocker.MagicMock()
    end_entity = mocker.MagicMock()
    mocker.patch.object(
        validate, "find_end_entity_certificates", return_value=[end_entity]
    )
    mocker.patch.object(validate, "assert_certificate_valid")

    validate.validate_certificate_chain(chain)

    validate.assert_certificate_valid.assert_called_once_with(end_entity)
    chain.validate_trust_path.assert_called_once_with(end_entity)


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
    assert expected_text in result.output


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
