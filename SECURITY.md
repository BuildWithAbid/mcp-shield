# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in mcp-shield, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@example.com** (or open a [private security advisory](https://github.com/BuildWithAbid/mcp-shield/security/advisories/new) on GitHub).

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Scope

mcp-shield is a **static analysis tool** — it reads source code and npm metadata. It does not execute scanned code. However, it does run `npm audit` and `npm install --package-lock-only` in scanned directories, which invokes npm.

If you find a way to exploit mcp-shield's scanning process itself (e.g., via crafted filenames, malicious package.json, or npm audit output injection), that is in scope.
