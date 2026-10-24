# Security and credentials

This repository is public. Keep passwords, tokens, SSH keys, runtime environment files, application profiles, browser state, media libraries and production database exports out of it.

- GitHub Actions should publish with a job-scoped `GITHUB_TOKEN`, not a human OAuth token copied into repository secrets.
- Never expose registry publishing credentials to untrusted pull-request code.
- Do not put credentials in Docker `ARG`, `ENV`, image layers, build logs or example configuration.
- Build/test against disposable state. This repo must not contain production deployment credentials.
- Exclude private material before building; `.gitignore` alone is not a Docker build-context policy. Each enabled target needs a reviewed build context and `.dockerignore`.
- If a secret is exposed, revoke or rotate it immediately. Deleting the current file does not remove it from Git history or published layers.
- Do not post secrets in public issues. Use upstream security-reporting channels for upstream vulnerabilities and an appropriate private channel for any credential exposure.

See [override policy](docs/override-policy.md) for dependency provenance, exceptions and verification requirements.
