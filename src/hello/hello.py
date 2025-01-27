import sys


def greet(name: str) -> str:
    """Greets a person by name.

    Args:
        name (str): Name of the person to greet.

    Returns:
        str: A greeting message.
    """
    if not isinstance(name, str):
        raise NotImplementedError("Only strings are supported.")
    return f"Hello {name}!"


def main(name: str = "lcaf-skeleton-python-module") -> None:
    """Entrypoint for calling this module directly from the CLI

    Args:
        name (str): Name of the person to greet.
    """
    print(greet(name))


if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        main()
