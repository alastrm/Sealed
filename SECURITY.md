# Security scope

Sealed is a local portfolio project. It is not an independently audited or production-supported whistleblowing service. Do not use it for sensitive real-world reports on the strength of a demonstration or passing test suite.

The current security model, confirmed findings and accepted limitations are documented in [MILESTONE_4_SECURITY_AUDIT.md](MILESTONE_4_SECURITY_AUDIT.md). The [verification report](MILESTONE_4_REPORT.md) distinguishes completed tests from unverified environments. Earlier milestone documents are retained as historical context; M4 supersedes older Reporter bearer-authentication and audit descriptions.

## Reporting a problem

Use synthetic reports and disposable identities to reproduce an issue. If this repository offers GitHub's **Report a vulnerability** option, use it for sensitive details. Otherwise, open an issue containing only a sanitized description and ask how to share the reproduction privately.

Never post recovery phrases, workspace access keys, passwords, private keys, encrypted identity exports, databases, attachment storage or environment files in an issue, pull request or screenshot. Do not test against another person's reports or reset an existing workspace to demonstrate a defect.

There is no guaranteed response time, supported release matrix or bug-bounty program. Fixes are maintained in the current branch. Pinning, endpoint security, backend authorization and the limited server history check remain separate trust boundaries; encryption alone does not provide anonymity or malicious-server protection.
