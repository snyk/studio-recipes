# Contributing to Snyk Studio Recipes

Thank you for your interest in contributing to Snyk Studio Recipes! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Submitting Changes](#submitting-changes)
- [Style Guidelines](#style-guidelines)
- [Community](#community)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to [oss@snyk.io](mailto:oss@snyk.io).

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:

   ```bash
   git clone https://github.com/YOUR-USERNAME/studio-recipes.git
   cd studio-recipes
   ```

3. **Add the upstream remote**:

   ```bash
   git remote add upstream https://github.com/snyk/studio-recipes.git
   ```

## How to Contribute

### Reporting Bugs

- Check if the bug has already been reported in [GitHub Issues](https://github.com/snyk/studio-recipes/issues)
- If not, create a new issue with:
  - Clear, descriptive title
  - Steps to reproduce
  - Expected vs actual behavior
  - Platform/environment details

### Suggesting Features

- Open a [GitHub Issue](https://github.com/snyk/studio-recipes/issues/new) describing:
  - The use case and problem you're solving
  - Your proposed solution
  - Any alternatives you've considered

### Contributing Code

1. Look for issues labeled `good first issue` or `help wanted`
2. Comment on the issue to let others know you're working on it
3. Follow the [development setup](#development-setup) instructions
4. Make your changes following our [style guidelines](#style-guidelines)
5. Submit a pull request

## Development Setup

### Prerequisites

- Git
- [Snyk CLI](https://docs.snyk.io/snyk-cli/install-or-update-the-snyk-cli) (for testing recipes)
- A supported AI coding assistant (Cursor, Claude Code) for testing

### Local Development

1. Create a new branch for your changes:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes
3. Test your recipes locally with the target AI assistant
4. Ensure all files pass validation (YAML, JSON, Markdown)

## Submitting Changes

### Pull Request Process

1. **Update documentation** if you're changing functionality
2. **Follow the PR template** when creating your pull request
3. **Link related issues** using keywords like "Fixes #123"
4. **Wait for review** - maintainers will review your PR and may request changes

### Commit Messages

Write clear, concise commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters
- Reference issues and PRs in the body when relevant

Example:

```text
Add Snyk IaC scanning recipe for Cursor

- Add hooks.json configuration for IaC scanning
- Add shell script for running scans
- Update README with usage instructions

Fixes #42
```

### Review Process

- All PRs require at least one approval from a maintainer
- CI checks must pass before merging
- Maintainers may request changes or ask questions

## Style Guidelines

### File Organization

- Place recipes in the appropriate directory structure
- Include a README.md for each recipe explaining its purpose and usage
- Use consistent naming conventions

### Markdown

- Use ATX-style headers (`#`, `##`, etc.)
- Include language identifiers in fenced code blocks
- Keep lines reasonably short for readability

### YAML/JSON

- Use consistent indentation (2 spaces for YAML, 2 spaces for JSON)
- Include comments where helpful
- Validate files before committing

### Shell Scripts

- Include shebang line (`#!/bin/bash` or `#!/bin/sh`)
- Add comments explaining complex logic
- Use `set -e` to exit on errors
- Quote variables to prevent word splitting

## Community

- **Questions?** Open a [GitHub Discussion](https://github.com/snyk/studio-recipes/discussions)
- **Found a security issue?** See our [Security Policy](SECURITY.md)
- **General Snyk questions?** Visit the [Snyk Community](https://community.snyk.io)

## Recognition

Contributors will be recognized in our release notes. Thank you for helping make Snyk Studio Recipes better!

---

_This contributing guide is adapted from open source best practices and the Contributor Covenant._
