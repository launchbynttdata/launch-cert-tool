import pytest

from hello import hello


class TestHello:
    def test_hello_main_no_arguments(self, capsys):
        """Test the happy path of the main function, where no arguments are passed."""
        hello.main()
        captured = capsys.readouterr()
        assert captured.out == "Hello lcaf-skeleton-python-module!\n"

    @pytest.mark.parametrize("name", ["Alice", "Bob", "Charlie"])
    def test_hello_main_name(self, name, capsys):
        """Test the happy path of the main function, where a person is greeted.

        Args:
            name (_type_): Name of the person to greet.
        """
        hello.main(name)
        captured = capsys.readouterr()
        assert captured.out == f"Hello {name}!\n"

    @pytest.mark.parametrize("not_a_string", [None, False, -1, list(), dict(), set()])
    def test_greet_failure(self, not_a_string):
        """Tests the greet function with a non-string argument expecting a failure.

        Args:
            not_a_string (_type_): Any non-string value.
        """
        with pytest.raises(NotImplementedError):
            hello.greet(not_a_string)
