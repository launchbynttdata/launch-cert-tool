# Configuring PyPI Distribution

This document requires you have an account on pypi.org and assumes that you are logged in.

1. Navigate to the [Publishing section of your User Settings](https://pypi.org/manage/account/publishing/).

2. Underneath any existing publishers you will find the **Add a new pending publisher** section. Fill in the fields as follows:

- PyPI Project Name: This should match the value of project.name from your pyproject.py file.
- Owner: This is the user or organization that owns the repository needing to publish.
- Repository name: Match this to the name of the repository in GitHub
- Workflow name: release.yaml
- Environment name: Unless you have specified an environment in GitHub settings, leave this blank.

3. Click Add.

Once these steps are completed, runs of the release.yaml workflow will be able to publish new versions of your package to PyPI.