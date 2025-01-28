from typer.testing import CliRunner

from launch_cert_tool.cli import app

runner = CliRunner()


def test_app_no_options_displays_usage():
    result = runner.invoke(app)
    assert result.exit_code == 0
    assert "Usage:" in result.stdout
