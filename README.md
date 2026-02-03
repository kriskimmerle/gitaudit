# gitaudit

**Git Repository Health & Security Auditor** — Zero-dependency tool that audits Git repositories for security issues, health problems, and best practice violations. Catches secrets, sensitive files, large files, merge conflicts, stale branches, and more.

## Why?

Existing tools are specialized and fragmented:
- **gitleaks/truffleHog**: Secrets only (Go/Python with deps)
- **git-sizer**: Repo size only (Go)
- **repo-security-scanner**: Basic secrets only (Go)

**gitaudit** is a single zero-dependency Python file that covers **15 rules** across security, hygiene, and best practices.

## Installation

```bash
curl -O https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py
chmod +x gitaudit.py
```

## Quick Start

```bash
# Audit current repo
python gitaudit.py

# Audit specific repo
python gitaudit.py /path/to/repo

# CI mode
python gitaudit.py --check --min-score 80 .

# JSON output
python gitaudit.py --json .

# Only errors (secrets + conflicts)
python gitaudit.py --severity error .
```

## Rules (15)

### Errors (security)

| Rule | Name | Description |
|------|------|-------------|
| GIT001 | sensitive-file-tracked | Sensitive file tracked (.env, *.pem, *.key, id_rsa, etc.) |
| GIT002 | secret-in-file | Secret/credential detected in tracked file (20+ patterns) |
| GIT005 | merge-conflict-marker | Unresolved merge conflict markers in file |

### Warnings (hygiene)

| Rule | Name | Description |
|------|------|-------------|
| GIT003 | large-file | Large file tracked (>1MB, consider Git LFS) |
| GIT006 | missing-gitignore | No .gitignore file found |
| GIT011 | submodule-http | Git submodule uses HTTP instead of HTTPS |

### Info (best practices)

| Rule | Name | Description |
|------|------|-------------|
| GIT004 | binary-file | Large binary file tracked |
| GIT007 | gitignore-gap | Common pattern missing from .gitignore |
| GIT008 | stale-branch | Branch with no commits in 90+ days |
| GIT009 | mixed-line-endings | Mixed CRLF + LF line endings |
| GIT010 | empty-commit-message | Trivial/empty commit message |
| GIT012 | no-gitattributes | No .gitattributes (line ending normalization) |
| GIT013 | tracked-generated-file | Build artifact tracked (node_modules, __pycache__, etc.) |
| GIT014 | symlink-in-repo | Symlink tracked (cross-platform issue) |
| GIT015 | deep-nesting | Path deeper than 8 levels (Windows path length issues) |

## Secret Detection (20+ patterns)

gitaudit scans tracked files for:
- GitHub tokens (PAT, OAuth, fine-grained)
- AWS access keys
- OpenAI / Anthropic API keys
- Slack tokens
- Stripe keys
- SendGrid API keys
- Google API keys and OAuth tokens
- JWTs
- Private keys (PEM/PKCS)
- Hardcoded passwords, API keys, and secrets

## Sensitive File Detection (24 patterns)

Flags tracked files matching:
`.env`, `id_rsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `credentials.json`, `secrets.yml`, `.npmrc`, `.pypirc`, `master.key`, and more.

## Example Output

```
$ python gitaudit.py --verbose

gitaudit v0.1.0 — Git Repository Health & Security Auditor

  Tracked files: 342
  Files scanned: 298
  Branches: 12

    ERROR  GIT001  .env
           Sensitive file tracked in repository
           .env file (environment variables/secrets)
    ERROR  GIT002  config/settings.py:45
           Potential secret/credential detected in tracked file
           Hardcoded Password
  WARNING  GIT003  data/model.h5
           Large file tracked (consider Git LFS)
           Size: 15.2 MB
     INFO  GIT008
           Stale branch (no commits in 90+ days)
           Branch 'feature/old-experiment' — last commit 142 days ago

────────────────────────────────────────────────────────────
  Grade: F  Score: 54/100
  2 errors, 1 warnings, 3 info
────────────────────────────────────────────────────────────
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Audit repository
  run: python gitaudit.py --check --min-score 90 .
```

## Options

```
-h, --help              Show help
-v, --version           Show version
--check                 Exit 1 if score below threshold
--min-score N           Minimum score (default: 80)
--json                  JSON output
--severity LEVEL        Filter: error, warning, info
--ignore RULES          Ignore specific rules
--large-threshold N     Large file size in bytes (default: 1000000)
--verbose               Show fix suggestions
--no-color              Disable colors
--list-rules            List all rules
```

## Requirements

- Python 3.9+
- Git (for `git ls-files`, `git ls-tree`, `git log`, etc.)
- Zero Python dependencies

## License

MIT
