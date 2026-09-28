---
name: Bug report
about: Report a bug in alethech
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the bug

A clear description of what the bug is.

## To reproduce

```bash
# Steps to reproduce
alethech init
alethech commit --content example.json
alethech verify
```

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened (error message, unexpected output, etc.).

## Environment

- alethech version: `alethech --version`
- Python version: `python --version`
- OS: [e.g., Ubuntu 22.04, macOS 14, Windows 11]
- Cryptography backend: `python -c "import cryptography; print(cryptography.__version__)"`

## Additional context

Any other context (logs, screenshots, store export if safe to share).
