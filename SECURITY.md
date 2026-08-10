# Security policy

## Reporting a vulnerability

Please do not open a public issue for an unpatched vulnerability. Use a
[private GitHub security advisory](https://github.com/dravengarden/skydriver/security/advisories/new)
when possible. If that channel is unavailable, contact the repository owners
through the private contact method configured for the hosting organization.

Include a concise description, affected revision or release, reproduction
steps, impact, and a suggested mitigation when available. Redact credentials,
tokens, personal data, private URLs, and provider object names from the report.

The maintainers will acknowledge receipt, reproduce the issue, coordinate a
fix, and publish a coordinated advisory when disclosure is appropriate.

## Secret exposure

If a credential may have entered Git, logs, or an artifact, revoke or rotate it
immediately through its owning provider, then report the exposure privately.
Removing a file from the working tree does not remove it from Git history.

## Security-sensitive areas

Reviewers should pay particular attention to key derivation and framing,
provider readback and deletion, token attenuation and revocation, migration
fences, deployment configuration, and secret handling in scripts and tests.
