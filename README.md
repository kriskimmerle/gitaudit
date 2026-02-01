# gitaudit

A zero-dependency git repository hygiene auditor. Audit your repo's health and get an A-F grade.

## Why?

Git repositories accumulate cruft over time: large files, stale branches, missing documentation, inconsistent commit messages. `gitaudit` runs 12 comprehensive checks to identify hygiene issues and assigns an overall grade.

**Zero dependencies** — Uses only Python standard library + git CLI commands (available everywhere git is installed).

## Installation

```bash
# Clone and run directly
git clone https://github.com/kriskimmerle/gitaudit.git
cd gitaudit
python3 gitaudit.py /path/to/your/repo

# Or copy the single file anywhere
curl -O https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py
chmod +x gitaudit.py
./gitaudit.py
```

## Quick Start

```bash
# Audit current repository
python3 gitaudit.py

# Audit another repository
python3 gitaudit.py ~/projects/myapp

# JSON output for CI/CD
python3 gitaudit.py --format json

# Fail CI build if grade below B
python3 gitaudit.py --check --min-grade B

# Only show warnings and errors
python3 gitaudit.py --severity warning

# Ignore specific checks
python3 gitaudit.py --ignore GA001 --ignore GA006
```

## Checks

`gitaudit` runs 12 health checks:

| ID | Severity | Check | Description |
|----|----------|-------|-------------|
| **GA001** | WARNING | Large files in history | Files over 5MB anywhere in git history |
| **GA002** | INFO | Large repo size | Total .git directory size over 100MB |
| **GA003** | WARNING | Stale branches | Remote-tracking branches with no commits in 90+ days |
| **GA004** | INFO | Orphan tags | Tags pointing to unreachable commits |
| **GA005** | WARNING | Missing .gitignore | No .gitignore or missing common patterns for detected languages |
| **GA006** | INFO | Unsigned commits | Percentage of commits without GPG/SSH signatures |
| **GA007** | INFO | Inconsistent commit messages | Mix of conventional commits and freeform, very short messages, WIP commits |
| **GA008** | INFO | Unmerged branches | Local branches significantly diverged from main/master |
| **GA009** | WARNING | Missing LICENSE | No LICENSE or COPYING file |
| **GA010** | ERROR | Sensitive files committed | Files like .env, *.pem, *.key in working tree or history |
| **GA011** | INFO | Shallow clone detected | Repository is a shallow clone with limited history |
| **GA012** | WARNING | Submodule health | Submodules with detached HEAD, missing remotes, or dirty state |

## Usage

```
gitaudit [OPTIONS] [REPO_PATH]

Options:
  REPO_PATH                     Path to git repository (default: current directory)
  
  --format text|json            Output format (default: text)
  --severity info|warning|error Minimum severity to show (default: info)
  --ignore CHECK_ID             Ignore specific checks (repeatable)
  
  --check                       CI mode: exit 1 if grade below threshold
  --min-grade A|B|C|D           Minimum passing grade (default: C, used with --check)
  
  --list-checks                 Show all available checks and exit
  --max-file-size MB            Large file threshold in MB (default: 5)
  --stale-days N                Days before branch is stale (default: 90)
  
  -q, --quiet                   Only show summary grade
  -h, --help                    Show this help message
```

## Grading

Grades are calculated based on findings:
- **ERROR** findings: -20 points each
- **WARNING** findings: -10 points each
- **INFO** findings: -3 points each

| Grade | Score Range | Meaning |
|-------|-------------|---------|
| **A** | 90-100 | Excellent hygiene |
| **B** | 80-89 | Good hygiene |
| **C** | 70-79 | Acceptable hygiene |
| **D** | 60-69 | Poor hygiene |
| **F** | <60 | Critical issues |

## Example Output

```
======================================================================
Git Repository Audit: /Users/kris/projects/myapp
======================================================================

⚠️  [GA001] Large files in history
   Severity: WARNING
   Found 2 file(s) over 5MB in git history
   files:
      • {'file': 'docs/video.mp4', 'size_mb': 12.5, 'sha': 'a1b2c3d4'}
      • {'file': 'data/dump.sql', 'size_mb': 8.3, 'sha': 'e5f6g7h8'}

⚠️  [GA003] Stale branches detected
   Severity: WARNING
   Found 3 branch(es) with no commits in 90+ days
   branches:
      • {'branch': 'origin/feature/old-experiment', 'days_old': 245}
      • {'branch': 'origin/hotfix/2022-bug', 'days_old': 180}

======================================================================
SUMMARY
======================================================================
Overall Grade: 🟡 C
Total Findings: 5
  Errors:   0
  Warnings: 3
  Info:     2
======================================================================
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Repository Health
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Full history for accurate audit
      
      - name: Run gitaudit
        run: |
          curl -sSL https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py -o gitaudit.py
          python3 gitaudit.py --check --min-grade C
```

### GitLab CI

```yaml
repo-audit:
  stage: test
  script:
    - curl -sSL https://raw.githubusercontent.com/kriskimmerle/gitaudit/main/gitaudit.py -o gitaudit.py
    - python3 gitaudit.py --check --min-grade B --format json > audit-report.json
  artifacts:
    reports:
      junit: audit-report.json
```

## How It Works

`gitaudit` shells out to standard git commands and parses the output:

- `git rev-list --objects --all` — Find all objects in history
- `git cat-file` — Check object sizes
- `git branch -r` — List remote branches with dates
- `git log --format=%G?` — Check commit signatures
- `git submodule status` — Check submodule health
- And more...

No git library dependencies means it works anywhere git CLI is installed.

## Requirements

- Python 3.7+
- git CLI tool

## License

MIT License - see [LICENSE](LICENSE)

## Contributing

Issues and pull requests welcome! This is a single-file tool, so contributions should maintain that simplicity.

## Acknowledgments

Inspired by:
- [repo-health](https://github.com/dogweather/repo-health)
- [git-sizer](https://github.com/github/git-sizer)
- [gitleaks](https://github.com/gitleaks/gitleaks)

Built by [Kris Kimmerle](https://github.com/kriskimmerle)
