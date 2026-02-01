#!/usr/bin/env python3
"""gitaudit - Git Repository Health Checker

Audit a git repo for common issues: large files in history, potential secrets
in commits, stale branches, missing .gitignore patterns, merge conflict
markers, TODO/FIXME tracking, and more. Like a linter for your repo itself.

Usage:
    gitaudit                        Audit current repo
    gitaudit /path/to/repo          Audit specific repo
    gitaudit --check secrets        Only check for secrets
    gitaudit --json                 JSON output
    gitaudit --check size           Only check large files
    gitaudit --verbose              Show all findings with details

Author: github.com/kriskimmerle
License: MIT
"""

__version__ = "1.0.0"

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap

# ── ANSI colors ────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

NO_COLOR = os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty()
if NO_COLOR:
    for attr in ("RED", "GREEN", "YELLOW", "BLUE", "CYAN", "BOLD", "DIM", "RESET"):
        setattr(C, attr, "")


# ── Git helpers ────────────────────────────────────────────────────────────

def git(*args, cwd=None):
    """Run a git command and return stdout."""
    try:
        result = subprocess.run(
            ["git"] + list(args),
            cwd=cwd, capture_output=True, text=True, timeout=30,
        )
        return result.stdout.strip(), result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", 1


def is_git_repo(path):
    """Check if path is inside a git repo."""
    _, code = git("rev-parse", "--git-dir", cwd=path)
    return code == 0


# ── Audit Checks ──────────────────────────────────────────────────────────

def check_large_files(repo_path, threshold_kb=500):
    """Find large files in the working tree."""
    findings = []
    for root, dirs, files in os.walk(repo_path):
        # Skip .git directory
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                size = os.path.getsize(fpath)
                if size > threshold_kb * 1024:
                    rel = os.path.relpath(fpath, repo_path)
                    findings.append({
                        "rule": "GA001",
                        "severity": "WARNING",
                        "message": f"Large file: {rel} ({_fmt_size(size)})",
                        "file": rel,
                        "detail": f"Files over {threshold_kb}KB should use Git LFS or be gitignored",
                    })
            except OSError:
                pass
    return findings


def check_large_blobs_history(repo_path, threshold_kb=1000, limit=20):
    """Find large blobs in git history."""
    findings = []
    # Get all blobs with sizes
    out, code = git("rev-list", "--objects", "--all", cwd=repo_path)
    if code != 0 or not out:
        return findings

    # Use verify-pack on pack files for efficient size checking
    git_dir, _ = git("rev-parse", "--git-dir", cwd=repo_path)
    if not git_dir:
        return findings

    pack_dir = os.path.join(repo_path, git_dir, "objects", "pack")
    if not os.path.isdir(pack_dir):
        return findings

    large_blobs = []
    for pf in os.listdir(pack_dir):
        if pf.endswith(".idx"):
            pack_path = os.path.join(pack_dir, pf)
            vp_out, vp_code = git("verify-pack", "-v", pack_path, cwd=repo_path)
            if vp_code != 0:
                continue
            for line in vp_out.split("\n"):
                parts = line.split()
                if len(parts) >= 4 and parts[1] == "blob":
                    try:
                        size = int(parts[2])
                        if size > threshold_kb * 1024:
                            large_blobs.append((parts[0], size))
                    except (ValueError, IndexError):
                        pass

    # Map blob hashes to file paths
    if large_blobs:
        obj_map = {}
        for line in out.split("\n"):
            parts = line.split(None, 1)
            if len(parts) == 2:
                obj_map[parts[0]] = parts[1]

        large_blobs.sort(key=lambda x: -x[1])
        for blob_hash, size in large_blobs[:limit]:
            path = obj_map.get(blob_hash, blob_hash[:12])
            findings.append({
                "rule": "GA002",
                "severity": "WARNING",
                "message": f"Large blob in history: {path} ({_fmt_size(size)})",
                "file": path,
                "detail": f"Consider using `git filter-branch` or BFG to clean history",
            })

    return findings


def check_secrets(repo_path):
    """Scan tracked files for potential secrets."""
    findings = []
    patterns = [
        ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
        ("AWS Secret Key", r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]"),
        ("GitHub Token", r"ghp_[a-zA-Z0-9]{36}"),
        ("GitHub PAT", r"github_pat_[a-zA-Z0-9_]{22,}"),
        ("Generic API Key", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{20,}['\"]"),
        ("Generic Secret", r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"][^\s'\"]{8,}['\"]"),
        ("Private Key", r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ("Slack Token", r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}"),
        ("Stripe Key", r"sk_(live|test)_[a-zA-Z0-9]{24,}"),
        ("JWT", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
        ("Database URL", r"(?i)(postgres|mysql|mongodb|redis)://[^\s\"']+:[^\s\"']+@"),
    ]

    # Get tracked files
    out, code = git("ls-files", cwd=repo_path)
    if code != 0:
        return findings

    binary_exts = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2",
                   ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".bin",
                   ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".class"}

    for fpath in out.split("\n"):
        if not fpath.strip():
            continue
        _, ext = os.path.splitext(fpath.lower())
        if ext in binary_exts:
            continue

        full_path = os.path.join(repo_path, fpath)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, "r", errors="ignore") as f:
                content = f.read(100000)  # Cap at 100KB per file
        except (OSError, UnicodeDecodeError):
            continue

        for name, pattern in patterns:
            for match in re.finditer(pattern, content):
                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                snippet = match.group(0)[:60]
                # Mask the middle
                if len(snippet) > 20:
                    snippet = snippet[:10] + "..." + snippet[-6:]

                findings.append({
                    "rule": "GA003",
                    "severity": "CRITICAL",
                    "message": f"Potential {name} in {fpath}:{line_num}",
                    "file": fpath,
                    "line": line_num,
                    "detail": f"Pattern: {snippet}",
                })

    return findings


def check_gitignore(repo_path):
    """Check for missing common .gitignore patterns."""
    findings = []
    gitignore_path = os.path.join(repo_path, ".gitignore")

    if not os.path.exists(gitignore_path):
        findings.append({
            "rule": "GA004",
            "severity": "WARNING",
            "message": "No .gitignore file found",
            "file": ".gitignore",
            "detail": "Create a .gitignore to prevent committing unwanted files",
        })
        return findings

    try:
        with open(gitignore_path) as f:
            content = f.read()
    except OSError:
        return findings

    # Detect project type and check for expected patterns
    tracked, _ = git("ls-files", cwd=repo_path)
    tracked_files = set(tracked.split("\n")) if tracked else set()

    checks = []

    # Python
    if any(f.endswith(".py") for f in tracked_files):
        checks.extend([
            ("__pycache__", "Python bytecode cache"),
            ("*.pyc", "Python compiled files"),
            (".venv", "Python virtual environment"),
            ("*.egg-info", "Python egg metadata"),
        ])

    # Node
    if "package.json" in tracked_files:
        checks.extend([
            ("node_modules", "Node.js dependencies (can be huge)"),
        ])

    # General
    checks.extend([
        (".env", "Environment files (may contain secrets)"),
        (".DS_Store", "macOS metadata files"),
    ])

    for pattern, reason in checks:
        # Simple check: is the pattern (or similar) in .gitignore?
        pattern_variants = [pattern, pattern.replace("*", ""), pattern.lstrip(".")]
        if not any(v in content for v in pattern_variants if v):
            # Check if the file actually exists in repo
            if pattern.startswith("*."):
                ext = pattern[1:]
                has_files = any(f.endswith(ext) for f in tracked_files)
            elif pattern == "node_modules":
                has_files = any(f.startswith("node_modules/") for f in tracked_files)
            else:
                has_files = any(pattern.strip(".*") in f for f in tracked_files)

            severity = "WARNING" if has_files else "INFO"
            findings.append({
                "rule": "GA005",
                "severity": severity,
                "message": f"Missing .gitignore pattern: {pattern}",
                "file": ".gitignore",
                "detail": reason,
            })

    return findings


def check_branches(repo_path, stale_days=90):
    """Check for stale branches."""
    findings = []

    out, code = git("for-each-ref", "--sort=-committerdate",
                     "--format=%(refname:short) %(committerdate:unix) %(committerdate:relative)",
                     "refs/heads/", cwd=repo_path)
    if code != 0 or not out:
        return findings

    import time
    now = time.time()
    stale_threshold = now - (stale_days * 86400)

    for line in out.split("\n"):
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        branch = parts[0]
        try:
            commit_time = int(parts[1])
        except ValueError:
            continue
        relative = parts[2]

        if commit_time < stale_threshold and branch not in ("main", "master", "develop", "dev"):
            findings.append({
                "rule": "GA006",
                "severity": "INFO",
                "message": f"Stale branch: {branch} (last commit {relative})",
                "file": branch,
                "detail": f"Consider deleting branches with no recent activity",
            })

    return findings


def check_conflict_markers(repo_path):
    """Check for merge conflict markers left in tracked files."""
    findings = []
    out, _ = git("ls-files", cwd=repo_path)
    if not out:
        return findings

    text_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
                 ".c", ".cpp", ".h", ".rb", ".php", ".sh", ".yml", ".yaml",
                 ".json", ".toml", ".md", ".txt", ".cfg", ".ini", ".html",
                 ".css", ".scss", ".sql", ".xml", ".env", ".conf"}

    for fpath in out.split("\n"):
        if not fpath.strip():
            continue
        _, ext = os.path.splitext(fpath.lower())
        if ext not in text_exts:
            continue

        full_path = os.path.join(repo_path, fpath)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    if line.startswith("<<<<<<< ") or line.startswith(">>>>>>> ") or line.startswith("======= "):
                        # Avoid false positive on markdown horizontal rules
                        if line.strip() == "=======" or line.startswith("<<<<<<< ") or line.startswith(">>>>>>> "):
                            findings.append({
                                "rule": "GA007",
                                "severity": "ERROR",
                                "message": f"Merge conflict marker in {fpath}:{line_num}",
                                "file": fpath,
                                "line": line_num,
                                "detail": line.strip()[:80],
                            })
                            break  # One finding per file is enough
        except (OSError, UnicodeDecodeError):
            pass

    return findings


def check_todos(repo_path):
    """Track TODO/FIXME/HACK/XXX comments."""
    findings = []
    out, _ = git("ls-files", cwd=repo_path)
    if not out:
        return findings

    text_exts = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs",
                 ".c", ".cpp", ".h", ".rb", ".php", ".sh", ".yml", ".yaml",
                 ".md", ".txt", ".sql", ".html", ".css"}

    pattern = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG)\b\s*:?\s*(.*)", re.IGNORECASE)
    count = 0
    MAX_FINDINGS = 50

    for fpath in out.split("\n"):
        if not fpath.strip() or count >= MAX_FINDINGS:
            break
        _, ext = os.path.splitext(fpath.lower())
        if ext not in text_exts:
            continue

        full_path = os.path.join(repo_path, fpath)
        if not os.path.isfile(full_path):
            continue

        try:
            with open(full_path, "r", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    match = pattern.search(line)
                    if match:
                        tag = match.group(1).upper()
                        msg = match.group(2).strip()[:80]
                        findings.append({
                            "rule": "GA008",
                            "severity": "INFO",
                            "message": f"{tag} in {fpath}:{line_num}: {msg}",
                            "file": fpath,
                            "line": line_num,
                            "detail": f"{tag}: {msg}",
                        })
                        count += 1
                        if count >= MAX_FINDINGS:
                            break
        except (OSError, UnicodeDecodeError):
            pass

    return findings


def check_repo_basics(repo_path):
    """Check basic repo health: README, LICENSE, etc."""
    findings = []

    # Check for README
    readme_found = False
    for name in ["README.md", "README.rst", "README.txt", "README"]:
        if os.path.exists(os.path.join(repo_path, name)):
            readme_found = True
            break
    if not readme_found:
        findings.append({
            "rule": "GA009",
            "severity": "WARNING",
            "message": "No README file found",
            "file": "",
            "detail": "Add a README.md with project description, installation, and usage",
        })

    # Check for LICENSE
    license_found = False
    for name in ["LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"]:
        if os.path.exists(os.path.join(repo_path, name)):
            license_found = True
            break
    if not license_found:
        findings.append({
            "rule": "GA010",
            "severity": "WARNING",
            "message": "No LICENSE file found",
            "file": "",
            "detail": "Add a LICENSE file to clarify usage terms",
        })

    # Check for uncommitted changes
    status, code = git("status", "--porcelain", cwd=repo_path)
    if status:
        lines = [l for l in status.split("\n") if l.strip()]
        findings.append({
            "rule": "GA011",
            "severity": "INFO",
            "message": f"Uncommitted changes: {len(lines)} file(s)",
            "file": "",
            "detail": "Consider committing or stashing changes",
        })

    return findings


# ── Grading ────────────────────────────────────────────────────────────────

def grade_findings(findings):
    """Compute a health score from findings."""
    score = 100
    for f in findings:
        sev = f["severity"]
        if sev == "CRITICAL":
            score -= 15
        elif sev == "ERROR":
            score -= 10
        elif sev == "WARNING":
            score -= 3
        # INFO doesn't reduce score

    score = max(0, min(100, score))

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return grade, score


# ── Formatting helpers ────────────────────────────────────────────────────

def _fmt_size(nbytes):
    if nbytes >= 1024 * 1024:
        return f"{nbytes / (1024*1024):.1f} MB"
    elif nbytes >= 1024:
        return f"{nbytes / 1024:.1f} KB"
    return f"{nbytes} B"


SEVERITY_ICON = {
    "CRITICAL": f"{C.RED}🚨",
    "ERROR": f"{C.RED}✗",
    "WARNING": f"{C.YELLOW}⚠",
    "INFO": f"{C.BLUE}ℹ",
}

SEVERITY_ORDER = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}


# ── Output Formatters ─────────────────────────────────────────────────────

def format_text(repo_path, findings, grade, score, verbose=False):
    lines = []
    lines.append(f"\n{C.BOLD}gitaudit v{__version__}{C.RESET} — Git Repository Health Checker\n")
    lines.append(f"  Repo: {C.BOLD}{repo_path}{C.RESET}")

    grade_color = C.GREEN if grade in ("A", "B") else (C.YELLOW if grade == "C" else C.RED)
    lines.append(f"  Health: {grade_color}{C.BOLD}{grade}{C.RESET} ({score}/100)\n")

    if not findings:
        lines.append(f"  {C.GREEN}✓ No issues found — clean repo!{C.RESET}\n")
        return "\n".join(lines)

    # Group by rule
    by_severity = {"CRITICAL": [], "ERROR": [], "WARNING": [], "INFO": []}
    for f in findings:
        by_severity.get(f["severity"], by_severity["INFO"]).append(f)

    for sev in ["CRITICAL", "ERROR", "WARNING", "INFO"]:
        group = by_severity[sev]
        if not group:
            continue
        if sev == "INFO" and not verbose:
            lines.append(f"\n  {C.DIM}{len(group)} info item(s) (use --verbose to show){C.RESET}")
            continue

        icon = SEVERITY_ICON.get(sev, "")
        for f in group:
            lines.append(f"  {icon}{C.RESET} [{f['rule']}] {f['message']}")
            if verbose and f.get("detail"):
                lines.append(f"    {C.DIM}→ {f['detail']}{C.RESET}")

    # Summary
    counts = {s: len(by_severity[s]) for s in by_severity}
    lines.append(f"\n{C.BOLD}Summary:{C.RESET} "
                 f"{counts['CRITICAL']} critical, {counts['ERROR']} errors, "
                 f"{counts['WARNING']} warnings, {counts['INFO']} info\n")

    return "\n".join(lines)


def format_json(repo_path, findings, grade, score):
    output = {
        "version": __version__,
        "repo": repo_path,
        "grade": grade,
        "score": score,
        "total_findings": len(findings),
        "counts": {
            "critical": len([f for f in findings if f["severity"] == "CRITICAL"]),
            "error": len([f for f in findings if f["severity"] == "ERROR"]),
            "warning": len([f for f in findings if f["severity"] == "WARNING"]),
            "info": len([f for f in findings if f["severity"] == "INFO"]),
        },
        "findings": findings,
    }
    return json.dumps(output, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────

ALL_CHECKS = {
    "size": ("Large files in working tree", check_large_files),
    "history": ("Large blobs in git history", check_large_blobs_history),
    "secrets": ("Potential secrets in code", check_secrets),
    "gitignore": ("Missing .gitignore patterns", check_gitignore),
    "branches": ("Stale branches", check_branches),
    "conflicts": ("Merge conflict markers", check_conflict_markers),
    "todos": ("TODO/FIXME tracking", check_todos),
    "basics": ("Repo basics (README, LICENSE)", check_repo_basics),
}


def main():
    parser = argparse.ArgumentParser(
        prog="gitaudit",
        description="Git Repository Health Checker — audit repos for large files, secrets, stale branches, and more.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              gitaudit                         Audit current repo (all checks)
              gitaudit /path/to/repo           Audit specific repo
              gitaudit --check secrets         Only check for secrets
              gitaudit --check size,secrets    Run specific checks
              gitaudit --json                  JSON output
              gitaudit --verbose               Show all findings including INFO
              gitaudit --ci                    CI mode: exit 1 on errors/criticals

            checks:
              size       Large files in working tree (>500KB)
              history    Large blobs in git history (>1MB)
              secrets    Potential secrets (API keys, tokens, passwords)
              gitignore  Missing .gitignore patterns
              branches   Stale branches (>90 days)
              conflicts  Merge conflict markers left in code
              todos      TODO/FIXME/HACK tracking
              basics     README, LICENSE, uncommitted changes
        """),
    )

    parser.add_argument("repo", nargs="?", default=".", help="Repository path (default: current directory)")
    parser.add_argument("--check", "-c", metavar="CHECKS",
                        help="Run specific checks (comma-separated: size,secrets,branches,...)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all findings including INFO")
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output")
    parser.add_argument("--ci", action="store_true", help="CI mode: exit 1 if any CRITICAL or ERROR findings")
    parser.add_argument("--list-checks", action="store_true", help="List all available checks")
    parser.add_argument("--version", action="version", version=f"gitaudit {__version__}")

    args = parser.parse_args()

    if args.list_checks:
        print(f"\n{C.BOLD}Available checks:{C.RESET}\n")
        for name, (desc, _) in ALL_CHECKS.items():
            print(f"  {C.CYAN}{name:12s}{C.RESET} {desc}")
        print()
        sys.exit(0)

    repo_path = os.path.abspath(args.repo)

    if not is_git_repo(repo_path):
        print(f"Error: {repo_path} is not a git repository.", file=sys.stderr)
        sys.exit(1)

    # Determine which checks to run
    if args.check:
        check_names = [c.strip() for c in args.check.split(",")]
        for cn in check_names:
            if cn not in ALL_CHECKS:
                print(f"Error: Unknown check '{cn}'. Use --list-checks to see available checks.", file=sys.stderr)
                sys.exit(1)
    else:
        check_names = list(ALL_CHECKS.keys())

    # Run checks
    all_findings = []
    if not args.json_output:
        print(f"\n{C.BOLD}gitaudit v{__version__}{C.RESET} — Scanning...\n")

    for check_name in check_names:
        desc, check_fn = ALL_CHECKS[check_name]
        if not args.json_output:
            print(f"  {C.DIM}⏳ {desc}...{C.RESET}", flush=True)
        findings = check_fn(repo_path)
        all_findings.extend(findings)

    # Sort by severity
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    # Grade
    grade, score = grade_findings(all_findings)

    # Output
    if args.json_output:
        print(format_json(repo_path, all_findings, grade, score))
    else:
        print(format_text(repo_path, all_findings, grade, score, verbose=args.verbose))

    # CI mode
    if args.ci:
        has_critical = any(f["severity"] in ("CRITICAL", "ERROR") for f in all_findings)
        sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
