# launch-cert-tool

## Overview

This CLI tool allows a consistent method of certificate validation, intended for use by Launch engineers when swapping out certificates for our various services.

Eventually we'd like to get to the point where we issue and renew certificates directly from ACM, but until that happens, we need to use fully-chained certificates in order to have our services play nicely with certain build systems (e.g. Azure DevOps). This tool can help you verify that you have everything you need before rotating certificates in ACM/CloudFront.

## Installation

### pip

Installing this tool to the virtual environment of your choice can be accomplished with the following:

```sh
pip install launch-cert-tool
```

### uv

`uv` handles setting up a virtual environment, you can add this tool to an existing project with:

```sh
uv add launch-cert-tool
```

### uvx / run-standalone (recommended)

`uvx` allows you to download the tool and execute it in an isolated throwaway environment without having to install
any dependencies to your system. Run this tool using the following:

```sh
uvx --with launch-cert-tool launch-cert-tool [COMMAND] [OPTIONS]
```

You can utilize this technique to run a particular version of the tool if required:

```sh
uvx --with launch-cert-tool@1.0.0 launch-cert-tool [COMMAND] [OPTIONS]
```

## Usage

Once installed to a virtual environment, `launch-cert-tool` should be added to your PATH. You may invoke the command without any arguments (or use the --help option) to view the usage page.

### Validating local certificate files

To validate certificate files prior to import to ACM, you'll need to have the certificates saved to your local machine. Local certificate verification allows you to specify any number of local files to include into a single chain for validation. This means that you could have your leaf certificate for the service separate from the intermediate certificates that make up the chain of trust. The syntax for local validation is demonstrated below:

```sh
launch-cert-tool validate local /path/to/leaf.crt /other/path/to/intermediate.crt
```

### Validating a chain stored in ACM

ACM allows us to pull down an imported certificate and the associated chain to perform the same validation. This ensures that what you uploaded to ACM matches what you tested locally:

```sh
launch-cert-tool validate acm arn:aws:acm:<region>:<account id>:certificate/<certificate id>
```

### Validating certificates served by a remote host

As a followup test after switching CloudFront over to your newly-imported ACM certificates, you may also validate the chain of certificates for a certain host, as shown here:

```sh
launch-cert-tool validate remote example.com
```

## Contributing

### Prerequisites

- [asdf](https://github.com/asdf-vm/asdf) or [mise](https://mise.jdx.dev/) to manage dependencies
- [make](https://www.gnu.org/software/make/)

### Development Environment

To configure your local development environment, perform the following steps:

1. Clone this repository to your local machine
2. `asdf install` (or `mise install`) to set up tool dependencies
3. `make configure` to pull in platform targets and set up hooks
4. `uv sync` to synchronize Python dependencies

Run tests with `make test` and review the test coverage report locally using `make coverage`.

### Running a dev version locally

Using `uv run` to launch your code ensures that your code runs in an isolated environment. For more inforamtion about using `uv run`, see the [official documentation](https://docs.astral.sh/uv/concepts/projects/run/).

To set up the proper script and environment to be able to run your dev version of `launch-cert-tool` from the command line, you will need to perform an editable installation:

```sh
uv pip install -e .
```

## Further reading

- [Set up VSCode](./docs/ide-vscode.md) for an improved development experience
- [Set up PyPI](./docs/pypi-configuration.md) for package distribution
- Learn how the [release workflows](./docs/release-workflow.md) operate
