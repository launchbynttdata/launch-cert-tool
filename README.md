# lcaf-skeleton-python-module

## Overview

This repository contains a reference Python module. Use this skeleton when you want to create a standalone publishable package for reuse with other Python code.

### Features

- Modern package and environment management with `uv`
- Automatic release drafting based on merged pull requests
- Automatic version bumps, tags, and publish to PyPI on release -- simply set your draft to published
- Integrated testing with `pytest`:
    - Sensible default `pytest` configurations
    - Pre-commit hooks to trigger tests before pushing
    - Code coverage checking
    - GitHub workflow
- Recommended plugins file for VSCode

## How to use this repository

### Prerequisites

- [asdf](https://github.com/asdf-vm/asdf) or [mise](https://mise.jdx.dev/) to manage dependencies
- [make](https://www.gnu.org/software/make/)

> NOTE: The workflows in this repository are designed around the target repository being publicly visible. These workflows will require adjustments to work with a private or internal repository.

### Applying the Template

The easiest way to get started is to click the **Use this template** button from the GitHub code page and select **Create a new repository**. Choose the owner of the new repository and give it a name and description. 

Alternately, you can consume this template by starting the New Repository workflow and selecting this repository from the **Repository template** dropdown.

Either method will result in GitHub copying the contents of this repository into a new repository for you. Newly-templated repositories receive all the default configurations you'd expect with a new repository, so you may need to set up collaborators and group permissions, enable or disable certain merge types, or tweak other repository settings as needed.

### Post-Template Setup

1. Clone this repository to a machine that meets the [prerequisites](#prerequisites).

2. Run `asdf install` (or `mise install`) to install any needed dependencies on your system.

3. Run `make configure` to download the Launch platform components and initialize the pre-commit hooks.

4. Run `uv sync` to synchronize dependencies declared in `pyproject.toml` to your local machine.

5. Rename the existing folder at `src/hello` to the name of your choosing. You should pay attention to PEP-8's [package and module naming guidelines](https://peps.python.org/pep-0008/#package-and-module-names) as well as the [broader guidelines found in PEP-423](https://peps.python.org/pep-0423/#overview).

6. Update the contents of `CODEOWNERS` with the individuals or team that will be responsible for providing approvals. 

7. Update the contents of `pyproject.toml` with the appropriate values for your project. At a minimum, you should be updating the following fields:

- project.name (be sure you adhere to [PEP-423](https://peps.python.org/pep-0423/)'s naming standards)
- project.description
- tool.setuptools.package-dir (replace `hello` with your module name/path from step #2)

8. Replace README.md contents with your desired verbiage. README.md is published to PyPI and should reflect your module's information rather than this template information.

### Running your code

Using `uv run` to launch your code ensures that your code runs in an isolated environment. For more inforamtion about using `uv run`, see the [official documentation](https://docs.astral.sh/uv/concepts/projects/run/).  

Modules can be directly executed by issuing `uv run path/to/file.py`, which will set \_\_name\_\_ to "\_\_main\_\_" as per Python's usual calling semantics. 

Setting up a runnable script is not in scope for this repository as it is concerned with reusable modules, but further information about setting entrypoints can be found [here](https://docs.astral.sh/uv/concepts/projects/config/#entry-points).

As a fallback, you may also activate the virtual environment directly and use the `python3` command, but the use of `uv run` is highly recommended as it will ensure your runtime environment is isolated and your project dependencies are up-to-date when run.

### Running tests

This repository comes with a default configuration for pytest.

To execute tests with the project's dependencies, issue the `uv run pytest` command. You may use the `pytest` command directly only if you activate a virtual environment.

After you have run `make configure` during the initial setup, two targets are available as shortcuts:

- `make test` will run `uvx run pytest`
- `make coverage` will run `make test`, generate coverage reports, and then open the HTML version of the coverage report in a browser for ease of use.

## Further reading

- [Set up VSCode](./docs/ide-vscode.md) for an improved development experience
- [Set up PyPI](./docs/pypi-configuration.md) for package distribution
- Learn how the [release workflows](./docs/release-workflow.md) operate

