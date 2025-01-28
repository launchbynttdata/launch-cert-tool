import pytest
from typer.testing import CliRunner

from launch_cert_tool.cli import app

runner = CliRunner()


class TestRemoteBadSSL:
    def test_remote_badssl_ok(self):
        result = runner.invoke(app, ["validate", "remote", "https://badssl.com"])
        assert result.exit_code == 0

    def test_remote_badssl_expired(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://expired.badssl.com"]
        )
        assert result.exit_code == 2

    def test_remote_badssl_wrong_host(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://wrong.host.badssl.com"]
        )
        assert result.exit_code == 7

    def test_remote_badssl_self_signed(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://self-signed.badssl.com"]
        )
        assert result.exit_code == 6

    def test_remote_badssl_untrusted_root(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://untrusted-root.badssl.com"]
        )
        assert result.exit_code == 6

    def test_remote_badssl_revoked(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://revoked.badssl.com"]
        )
        assert result.exit_code == 8

    @pytest.mark.skip(reason="HPKP is deprecated and not supported by modern browsers")
    def test_remote_badssl_pinning_test(self):
        result = runner.invoke(
            app, ["validate", "remote", "https://pinning-test.badssl.com"]
        )
        assert result.exit_code != 0


class TestLocalBadSSL:
    def test_local_badssl_ok(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        print(result.stdout)

        assert result.exit_code == 0

    def test_local_badssl_expired(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("expired.badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        assert result.exit_code == 2

    @pytest.mark.skip(
        reason="Hostname mismatch is not detected by the current implementation since the certs are locally downloaded"
    )
    def test_local_badssl_wrong_host(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("wrong.host.badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        assert result.exit_code == 7

    def test_local_badssl_self_signed(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("self-signed.badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        assert result.exit_code == 1

    def test_local_badssl_untrusted_root(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("untrusted-root.badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        assert result.exit_code == 9

    def test_local_badssl_revoked(self, tmp_path, unsafe_cert_download):
        cert_files = unsafe_cert_download("revoked.badssl.com", tmp_path)
        result = runner.invoke(
            app, ["validate", "local", *[f.as_posix() for f in cert_files]]
        )
        assert result.exit_code == 8
