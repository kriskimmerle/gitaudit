# gitaudit

**Git Repository Health Checker** — Audit repos for large files, potential secrets, stale branches, missing .gitignore patterns, merge conflict markers, TODO tracking, and more. A linter for your git repo itself.

Zero dependencies. Pure Python stdlib. Single file.

## Why?

Git repos accumulate problems over time:
- **Large files** bloat clone times and storage
- **Secrets** (API keys, tokens) get committed accidentally
- **Stale branches** clutter the repo
- **Missing .gitignore** leads to committing unwanted files
- **Merge conflict markers** get left in code
- **TODOs** pile up and are forgotten

Existing tools are specialized: git-sizer (size only), trufflehog/gitleaks (secrets only, heavy). No single lightweight tool covers all repo health checks with grading.

**gitaudit** runs 8 checks in seconds and gives you a health grade.

## Install

```bash
curl -O https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py
chmod +x gitaudit.py
```

No dependencies beyond Python 3.7+ and git.

## Usage

### Full Audit

```bash
gitaudit                    # Audit current repo
gitaudit /path/to/repo      # Audit specific repo
```

```
gitaudit v1.0.0 — Git Repository Health Checker

  Repo: /path/to/myproject
  Health: B (85/100)

  🚨 [GA003] Potential AWS Access Key in config.py:12
  ⚠ [GA001] Large file: data/dump.sql (15.2 MB)
  ⚠ [GA005] Missing .gitignore pattern: .env

  3 info item(s) (use --verbose to show)

Summary: 1 critical, 0 errors, 2 warnings, 3 info
```

### Specific Checks

```bash
gitaudit --check secrets           # Only scan for secrets
gitaudit --check size,history      # Large files + history
gitaudit --check secrets,conflicts # Secrets + conflict markers
```

### Verbose Mode

```bash
gitaudit --verbose    # Show all findings including INFO items
```

### JSON Output

```bash
gitaudit --json
```

### CI Mode

```bash
gitaudit --ci    # Exit 1 if any CRITICAL or ERROR findings
```

## Checks

| Check | Rule | What it finds |
|-------|------|---------------|
| `size` | GA001 | Files >500KB in working tree |
| `history` | GA002 | Blobs >1MB in git history |
| `secrets` | GA003 | API keys, tokens, passwords, private keys |
| `gitignore` | GA004-05 | Missing .gitignore or patterns |
| `branches` | GA006 | Branches with no commits in 90+ days |
| `conflicts` | GA007 | Merge conflict markers (`<<<<<<<`) left in code |
| `todos` | GA008 | TODO/FIXME/HACK/XXX comments |
| `basics` | GA009-11 | Missing README, LICENSE, uncommitted changes |

### Secret Patterns Detected

- AWS Access Keys (`AKIA...`)
- GitHub Tokens (`ghp_...`, `github_pat_...`)
- Slack Tokens (`xox[bpors]-...`)
- Stripe Keys (`sk_live_...`, `sk_test_...`)
- Private Keys (`-----BEGIN PRIVATE KEY-----`)
- Generic API keys, passwords, database URLs
- JWTs

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Healthy repo |
| B | 80-89 | Minor issues |
| C | 70-79 | Notable problems |
| D | 60-69 | Significant issues |
| F | 0-59 | Critical problems |

Scoring: CRITICAL -15, ERROR -10, WARNING -3, INFO ±0.

## CI/CD Integration

```yaml
# .github/workflows/repo-health.yml
name: Repo Health
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Audit repo
        run: |
          curl -sO https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py
          python3 gitaudit.py --ci
```

## CLI Reference

```
gitaudit [OPTIONS] [REPO]

Arguments:
  REPO                Repository path (default: current directory)

Options:
  -c, --check CHECKS  Specific checks (comma-separated)
  -v, --verbose        Show all findings including INFO
  --json               JSON output
  --ci                 Exit 1 on CRITICAL/ERROR findings
  --list-checks        List available checks
  --version            Show version
  -h, --help           Show help
```

## License

MIT
