# Security Policy

## Supported versions

Security fixes are released for the latest minor release of the current
major version.

| Version | Supported |
| ------- | --------- |
| 2.0.x   | Yes       |
| < 2.0   | No        |

Version 1.x is no longer maintained. Upgrade to the latest 2.x release; the
[README](README.md#installation) describes the installation methods.

## Reporting a vulnerability

Do not open a public issue for a vulnerability in CodexSentinel itself.

Report it privately through
[GitHub Security Advisories](https://github.com/Voskan/codexsentinel/security/advisories/new),
or by email to `voskan1989@gmail.com` with the subject
`[SECURITY] CodexSentinel`. Please include:

- the affected version (`codex-cli version`) and platform;
- a description of the problem and its impact;
- steps or a minimal module that reproduce it;
- any suggested fix.

Examples of security issues in CodexSentinel:

- running `codex-cli` on a module, or one of its commands, executes code or
  writes files outside what the command documents;
- the language server or the Model Context Protocol server can be made to
  read or change files outside the workspace it serves;
- a release binary, the install script or the GitHub Action can be made to
  run something other than the published, checksummed release;
- a suppression can bypass `--forbid-new-suppressions` without the approval
  variable.

A finding that CodexSentinel misses or reports wrongly in the analyzed code
(a false negative or false positive) is not a vulnerability in CodexSentinel;
report it as a regular issue with a minimal example.

## What to expect

- An acknowledgement within 5 business days.
- An assessment, and a fix plan for confirmed issues, as soon as the problem
  is understood.
- A patch release and a published advisory, crediting the reporter unless
  they prefer otherwise. Please keep the issue private until the advisory is
  published.

## Verifying releases

Release binaries are built by the SLSA3 Go builder, which publishes signed
provenance for each binary, and are listed with their SHA-256 hashes in
`checksums.txt`. Verify a download with
[slsa-verifier](https://github.com/slsa-framework/slsa-verifier) and against
`checksums.txt`; the install script and the GitHub Action check the
checksum automatically.
