# Contributing to PortVex

Thank you for your interest in contributing to **PortVex**.

PortVex is an open-source Python port-scanning tool. Contributions of all kinds are welcome, including bug fixes, performance improvements, documentation, testing, and new features.

This document explains how to contribute effectively and keep the project maintainable.

## Getting Started

Before making changes, make sure you have:

- Python installed.
- Git installed.
- A GitHub account.
- Basic familiarity with Python and Git.

### 1. Fork the Repository

Fork the PortVex repository to your GitHub account.

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/PortVex.git
cd PortVex
```

### 3. Create a Branch

Create a separate branch for your contribution.

```bash
git checkout -b feature/your-feature-name
```

For bug fixes:

```bash
git checkout -b fix/bug-description
```

### 4. Make Your Changes

Keep your changes focused and avoid modifying unrelated parts of the project.

### 5. Verify Your Changes

At minimum, check that the Python source compiles:

```bash
python3 -m py_compile portvex.py
```

Run PortVex's help command:

```bash
python3 portvex.py --help
```

If your changes affect scanning functionality, test them against localhost or another system you own or have explicit permission to scan.

### 6. Commit Your Changes

Use clear and descriptive commit messages.

```bash
git add .
git commit -m "Fix HTML report generation"
```

### 7. Push Your Branch

```bash
git push origin feature/your-feature-name
```

### 8. Open a Pull Request

Open a pull request against the main PortVex repository.

Explain what you changed, why it was necessary, and how you tested it.

---

## Types of Contributions

You can contribute in several ways.

### Bug Fixes

- Fix incorrect scan results.
- Resolve crashes and runtime errors.
- Improve error handling.
- Fix report generation issues.
- Address compatibility problems.

### New Features

- Add scanning capabilities.
- Improve TCP or UDP scanning.
- Introduce additional output formats.
- Improve HTML reports.
- Add useful command-line options.

### Performance Improvements

- Optimize asynchronous operations.
- Improve resource management.
- Reduce unnecessary network overhead.
- Improve scanning efficiency.

### Documentation

- Improve the README.
- Add examples and usage instructions.
- Clarify command-line options.
- Improve installation instructions.
- Document internal functionality.

### Testing

- Identify edge cases.
- Test different operating systems.
- Verify TCP and UDP behavior.
- Report unexpected results.

---

## Development Guidelines

To keep PortVex consistent and maintainable, please follow these guidelines.

### Python Code

- Follow standard Python naming conventions.
- Use meaningful variable and function names.
- Keep functions focused on a single responsibility.
- Avoid unnecessary dependencies.
- Handle exceptions appropriately.
- Avoid unnecessary global variables.
- Add comments when they clarify non-obvious behavior.
- Keep the code readable and maintainable.

### Project Structure

- Keep changes organized.
- Avoid introducing unnecessary files.
- Do not commit generated reports, temporary files, or local environment directories.
- Update documentation when changing existing functionality.

### Scanning Behavior

PortVex is a network scanning tool. Changes to scanning functionality should consider:

- Connection timeouts.
- Resource usage.
- Asynchronous task management.
- TCP and UDP protocol differences.
- Accurate result classification.
- Error handling and interrupted scans.

Never introduce behavior that performs unauthorized scanning or hides scanning activity from the system owner.

### Dependencies

Before adding a dependency:

1. Check whether the functionality can be implemented using Python's standard library.
2. Explain why the dependency is necessary.
3. Consider its maintenance status and compatibility.
4. Update the project's dependency documentation when applicable.

---

## Reporting Bugs

Found a bug? Please open an issue in the GitHub repository.

Before submitting, check whether the issue has already been reported.

Include the following information:

- **PortVex version:** Which version are you using?
- **Operating system:** Windows, Linux, macOS, or another platform.
- **Python version:** Your installed Python version.
- **Command:** The command that caused the problem.
- **Expected behavior:** What should have happened?
- **Actual behavior:** What happened instead?
- **Error output:** Include the relevant traceback or terminal output.
- **Additional information:** Any details that could help reproduce the issue.

### Bug Report Example

```text
Title: HTML report generation fails

PortVex Version: 2.2.0
Operating System: Ubuntu Linux
Python Version: 3.x

Command:
python3 portvex.py -i 127.0.0.1 --profile fast --html report.html

Expected Behavior:
The scanner should generate an HTML report.

Actual Behavior:
The application exits with a Python exception.

Error Output:
Paste the traceback here.
```

Please remove sensitive information before sharing logs or configuration details.

---

## Suggesting Features

Feature requests are welcome.

Before opening a feature request:

1. Check whether the feature already exists.
2. Check existing issues and discussions.
3. Explain the problem the feature would solve.
4. Describe how you expect the feature to work.
5. Include examples where possible.

Large features should be discussed before implementation so that the proposed changes align with PortVex's direction.

---

## Submitting Pull Requests

Before submitting a pull request, make sure that:

- Your changes have a clear purpose.
- Your code follows the project's development guidelines.
- The application compiles successfully.
- You have tested the affected functionality.
- Documentation has been updated where necessary.
- No unrelated changes are included.
- You have not committed credentials, private information, or generated files.

### Pull Request Description

A good pull request should explain:

**What changed?**

Describe the implementation.

**Why was it changed?**

Explain the problem or motivation.

**How was it tested?**

List the commands and tests you performed.

**Related issues:**

Reference any related GitHub issues.

### Pull Request Example

```text
Title: Improve HTML report generation

Changes:
- Fixed HTML report formatting.
- Improved report metadata.
- Added handling for missing scan information.

Testing:
- Verified Python syntax.
- Generated a report using a localhost scan.

Related Issues:
Closes #12
```

Keep pull requests focused. If you are introducing multiple unrelated features, consider submitting separate pull requests.

---

## Code Review

Pull requests are reviewed before being merged.

During the review process:

- Maintainers may request changes.
- Contributors should respond to review feedback.
- Changes may be tested before acceptance.
- Pull requests that do not follow project guidelines may be rejected.

Please be patient during reviews. Review time depends on project activity and the complexity of the contribution.

Submitting a pull request does not guarantee that it will be merged.

---

## Security Issues

**Do not publicly disclose security vulnerabilities through regular GitHub issues.**

If you discover a vulnerability affecting PortVex, report it privately through the repository's available GitHub security reporting mechanism.

Include:

- A description of the vulnerability.
- The affected version.
- Steps to reproduce the issue.
- Potential impact.
- Any suggested mitigation.

Do not publish exploit details before the vulnerability has been reviewed and responsibly addressed.

---

## Community Guidelines

All contributors are expected to:

- Be respectful and professional.
- Communicate clearly.
- Accept constructive criticism.
- Help newcomers when possible.
- Keep discussions focused on the project.
- Respect different backgrounds and experience levels.

Harassment, discrimination, and abusive behavior are not acceptable.

---

## Final Notes

Every contribution matters, whether it is a one-line bug fix or a major improvement.

Thank you for helping improve PortVex and making it a better tool for the community.

**Happy contributing!**
