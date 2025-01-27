# Release Workflow

This repository includes a simple release workflow that handles publishing a single package to PyPI once a release has been moved from draft status to published.

This document separates release concerns into three parts: 

- pre-release, where changes are made to the repository and bundled together,
- release, the act of publishing the packages to the package repository, and
- post-release, where you can verify your release was published successfully.

## Pre-release

Pre-release is the phase where changes are being made to the repository but a new version has not yet been published to the package repository.

Changes to the repository must occur through the Pull Requests functionality, which will initiate the following workflows:

- [Validate Branch Name](.github/workflows/validate-branch-name.yaml), to ensure that the branch name meets our naming conventions.
- [Python Tests](.github/workflows/python-tests.yaml), to execute tests for your code
- [Label Pull Request](.github/workflows/label-pull-request.yaml), which applies a label to the PR indicating the type of change (patch, minor, or major)

Once all workflows are passing and the change has been reviewed, you can merge the pull request.

When a pull request is merged, the [Draft Release](.github/workflows/draft-release.yaml) workflow will run. This evaluates the merged pull requests and creates a release in draft status. The label attached to each pull request (patch, minor, major) will drive the drafted tag version and the body of the release will be updated according to the type of release.

Multiple pull requests can be merged to main and the draft release will keep track of all outstanding unreleased changes. Once you are ready to release a new version all the way to PyPI, you can perform a release.

If you push a change directly to the `main` branch without using a pull request, a draft release will be created, but since there is no PR to associate, it will not contain any release notes. You will need to manually supply release information.

## Release

To release all outstanding changes, navigate to the Release page, select the drafted release, and click the edit button (pencil icon). You may make adjustments to the release body at this time to better document the contents of the release or provide any additional relevant information. The initial release of a given repository defaults to tag `0.1.0` and you may adjust this tag from the edit page if desired. Once you are satisfied with the contents of your release and the tag to be created, click **Publish release**. 

Upon publishing the release, a new tag will be created in the repository at the head of the main branch, and the [Release to PyPI](.github/workflows/release.yaml) workflow will begin. 

## Post-release

Successful completion of the Release workflow will log the published package name and version in the "Publish Package Distributions with PyPI" stage when viewing the action logs.

You may also navigate to the module's PyPI page and confirm that the version number has been updated as expected.
