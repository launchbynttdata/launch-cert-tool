# IDE Setup - VSCode

Currently, only configurations for VSCode are provided. If you would like to contribute configurations for PyCharm or another IDE, please open a pull request.

#### Recommended Extensions

This repository ships with a [recommended extensions file for VSCode](../.vscode/extensions.json). You may customize this file with additional extensions after you create your repository from this template to meet your needs. 

#### VSCode Format-on-save

By default, VSCode doesn't perform any format-on-save operations, so we highly recommend performing the following steps after installing the recommended extensions:

1. Using the command pallette (⌘+⇧+P), locate "Preferences: Open User Settings (JSON)" and select it.
2. In the settings.json file that was opened, configure the following items and save:

```json
{
    <your existing configuration>,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.fixAll": "explicit",
        "source.organizeImports": "explicit"
    },
    "editor.defaultFormatter": "charliermarsh.ruff"
}
```