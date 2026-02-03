#!/usr/bin/env python3
"""gitaudit - Git Repository Health & Security Auditor.

Zero-dependency tool that audits a Git repository for security issues,
health problems, and best practice violations. Covers secrets, large files,
binary files, merge conflicts, .gitignore gaps, stale branches, and more.

Usage:
    gitaudit [path]
    gitaudit --check --min-score 80 .
    gitaudit --json .
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__version__ = "0.1.0"

SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"
SEVERITY_INFO = "info"

RULES: dict[str, dict[str, str]] = {
    "GIT001": {
        "name": "sensitive-file-tracked",
        "severity": SEVERITY_ERROR,
        "message": "Sensitive file tracked in repository",
        "fix": "Remove the file from tracking: git rm --cached {path} && add to .gitignore",
    },
    "GIT002": {
        "name": "secret-in-file",
        "severity": SEVERITY_ERROR,
        "message": "Potential secret/credential detected in tracked file",
        "fix": "Remove the secret, rotate the credential, and use environment variables instead",
    },
    "GIT003": {
        "name": "large-file",
        "severity": SEVERITY_WARNING,
        "message": "Large file tracked (consider Git LFS)",
        "fix": "Use git lfs track '{pattern}' for large files",
    },
    "GIT004": {
        "name": "binary-file",
        "severity": SEVERITY_INFO,
        "message": "Binary file tracked in repository",
        "fix": "Consider using Git LFS for binary files, or add to .gitignore if generated",
    },
    "GIT005": {
        "name": "merge-conflict-marker",
        "severity": SEVERITY_ERROR,
        "message": "Merge conflict marker found in file",
        "fix": "Resolve the merge conflict and remove the conflict markers",
    },
    "GIT006": {
        "name": "missing-gitignore",
        "severity": SEVERITY_WARNING,
        "message": "No .gitignore file found",
        "fix": "Create a .gitignore — see github.com/github/gitignore for templates",
    },
    "GIT007": {
        "name": "gitignore-gap",
        "severity": SEVERITY_INFO,
        "message": "Common pattern missing from .gitignore",
        "fix": "Add '{pattern}' to .gitignore",
    },
    "GIT008": {
        "name": "stale-branch",
        "severity": SEVERITY_INFO,
        "message": "Stale branch (no commits in 90+ days)",
        "fix": "Delete stale branches: git branch -d {branch} or git push origin --delete {branch}",
    },
    "GIT009": {
        "name": "mixed-line-endings",
        "severity": SEVERITY_INFO,
        "message": "Mixed line endings detected (CRLF + LF)",
        "fix": "Normalize line endings: add '* text=auto' to .gitattributes",
    },
    "GIT010": {
        "name": "empty-commit-message",
        "severity": SEVERITY_INFO,
        "message": "Commit with empty or trivial message",
        "fix": "Write meaningful commit messages describing what changed and why",
    },
    "GIT011": {
        "name": "submodule-http",
        "severity": SEVERITY_WARNING,
        "message": "Git submodule uses HTTP (not HTTPS)",
        "fix": "Update submodule URL to use HTTPS for secure transport",
    },
    "GIT012": {
        "name": "no-gitattributes",
        "severity": SEVERITY_INFO,
        "message": "No .gitattributes file — line ending normalization not configured",
        "fix": "Create .gitattributes with '* text=auto' for consistent line endings",
    },
    "GIT013": {
        "name": "tracked-generated-file",
        "severity": SEVERITY_INFO,
        "message": "Generated/build artifact tracked in repository",
        "fix": "Add '{path}' to .gitignore and remove from tracking: git rm --cached {path}",
    },
    "GIT014": {
        "name": "symlink-in-repo",
        "severity": SEVERITY_INFO,
        "message": "Symlink tracked in repository (may not work cross-platform)",
        "fix": "Consider replacing symlinks with copies or relative paths for portability",
    },
    "GIT015": {
        "name": "deep-nesting",
        "severity": SEVERITY_INFO,
        "message": "Deeply nested file path (>8 levels) — may cause issues on Windows",
        "fix": "Consider flattening directory structure for cross-platform compatibility",
    },
}

# ── Sensitive file patterns ──────────────────────────────────────────────────

SENSITIVE_FILE_PATTERNS: list[tuple[str, str]] = [
    (r"\.env$", ".env file (environment variables/secrets)"),
    (r"\.env\.\w+$", ".env variant file"),
    (r"id_rsa$", "SSH private key"),
    (r"id_dsa$", "DSA private key"),
    (r"id_ecdsa$", "ECDSA private key"),
    (r"id_ed25519$", "Ed25519 private key"),
    (r"\.pem$", "PEM certificate/key"),
    (r"\.key$", "Private key file"),
    (r"\.p12$", "PKCS12 keystore"),
    (r"\.pfx$", "PFX certificate"),
    (r"\.jks$", "Java keystore"),
    (r"\.keystore$", "Keystore file"),
    (r"\.kdbx?$", "KeePass database"),
    (r"htpasswd$", "Apache htpasswd"),
    (r"\.netrc$", ".netrc credentials"),
    (r"credentials\.json$", "Credentials file"),
    (r"secrets\.ya?ml$", "Secrets file"),
    (r"secrets\.json$", "Secrets file"),
    (r"\.secret$", "Secret file"),
    (r"master\.key$", "Rails master key"),
    (r"\.npmrc$", "npm credentials"),
    (r"\.pypirc$", "PyPI credentials"),
    (r"\.gem/credentials$", "RubyGems credentials"),
    (r"token\.json$", "Token file"),
]

SENSITIVE_FILE_RES = [(re.compile(p, re.IGNORECASE), desc) for p, desc in SENSITIVE_FILE_PATTERNS]

# ── Secret patterns ──────────────────────────────────────────────────────────

SECRET_PATTERNS: list[tuple[str, str]] = [
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"gho_[a-zA-Z0-9]{36}", "GitHub OAuth Token"),
    (r"github_pat_[a-zA-Z0-9_]{22,}", "GitHub PAT (fine-grained)"),
    (r"sk-[a-zA-Z0-9]{48}", "OpenAI API Key"),
    (r"sk-proj-[a-zA-Z0-9_-]+", "OpenAI Project API Key"),
    (r"sk-ant-[a-zA-Z0-9_-]+", "Anthropic API Key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"xoxb-[0-9]{11,}-[0-9]{11,}-[a-zA-Z0-9]{24}", "Slack Bot Token"),
    (r"xoxp-[0-9]{11,}-[0-9]{11,}-[0-9]{11,}-[a-f0-9]{32}", "Slack User Token"),
    (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key"),
    (r"sk_live_[a-zA-Z0-9]{24,}", "Stripe Live Key"),
    (r"rk_live_[a-zA-Z0-9]{24,}", "Stripe Restricted Key"),
    (r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----", "Private Key"),
    (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth Client ID"),
    (r"ya29\.[0-9A-Za-z_-]+", "Google OAuth Token"),
    (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+", "JWT Token"),
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", "Hardcoded Password"),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "Hardcoded API Key"),
    (r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", "Hardcoded Secret"),
]

SECRET_RES = [(re.compile(p), desc) for p, desc in SECRET_PATTERNS]

# ── Binary file extensions ───────────────────────────────────────────────────

BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".a", ".lib", ".o", ".obj",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".jar", ".war", ".ear", ".class",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".pyc", ".pyo", ".whl", ".egg",
    ".db", ".sqlite", ".sqlite3",
}

# ── Generated/build patterns ─────────────────────────────────────────────────

GENERATED_PATTERNS: list[tuple[str, str]] = [
    (r"node_modules/", "node_modules directory"),
    (r"__pycache__/", "__pycache__ directory"),
    (r"\.pyc$", "Compiled Python file"),
    (r"dist/", "Distribution directory"),
    (r"build/", "Build directory"),
    (r"\.egg-info/", "Egg info directory"),
    (r"coverage\.xml$", "Coverage report"),
    (r"\.coverage$", "Coverage data"),
    (r"htmlcov/", "HTML coverage report"),
    (r"\.tox/", "Tox directory"),
    (r"\.pytest_cache/", "Pytest cache"),
    (r"\.mypy_cache/", "Mypy cache"),
    (r"package-lock\.json$", "npm lock file (optional to track)"),
]

GENERATED_RES = [(re.compile(p), desc) for p, desc in GENERATED_PATTERNS]

# ── Gitignore recommended patterns ──────────────────────────────────────────

GITIGNORE_PATTERNS: dict[str, list[str]] = {
    "Python": ["__pycache__/", "*.pyc", "*.pyo", "dist/", "build/", "*.egg-info/",
               ".eggs/", ".venv/", "venv/", ".env", ".mypy_cache/", ".pytest_cache/"],
    "Node.js": ["node_modules/", ".env", "dist/"],
    "General": [".DS_Store", "Thumbs.db", "*.swp", "*.swo", "*~", ".idea/", ".vscode/"],
}

# ── Merge conflict markers ───────────────────────────────────────────────────

CONFLICT_MARKER_RE = re.compile(r"^(<{7}\s|={7}$|>{7}\s)", re.MULTILINE)

# ── Trivial commit messages ──────────────────────────────────────────────────

TRIVIAL_MESSAGES = re.compile(
    r"^(fix|update|changes?|wip|tmp|test|asdf|aaa|xxx|yyy|todo|stuff|"
    r"\.\.\.|---|\?\?\?|!!!)$",
    re.IGNORECASE,
)


# ── Finding ──────────────────────────────────────────────────────────────────


@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    file: str = ""
    line: int = 0
    context: str = ""
    fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"rule": self.rule, "severity": self.severity, "message": self.message}
        if self.file:
            d["file"] = self.file
        if self.line:
            d["line"] = self.line
        if self.context:
            d["context"] = self.context
        if self.fix:
            d["fix"] = self.fix
        return d


# ── Git helpers ──────────────────────────────────────────────────────────────


def _git(args: list[str], cwd: str) -> str:
    """Run a git command and return stdout."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _git_ls_files(cwd: str) -> list[str]:
    """Get list of tracked files."""
    out = _git(["ls-files"], cwd)
    return out.splitlines() if out else []


def _git_file_sizes(cwd: str) -> dict[str, int]:
    """Get sizes of tracked files via ls-tree."""
    out = _git(["ls-tree", "-r", "-l", "HEAD"], cwd)
    sizes: dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5:
            try:
                size = int(parts[3])
                path = " ".join(parts[4:])
                sizes[path] = size
            except (ValueError, IndexError):
                pass
    return sizes


def _git_branches(cwd: str) -> list[tuple[str, str]]:
    """Get branches with last commit date. Returns [(branch, iso_date), ...]."""
    out = _git(["for-each-ref", "--sort=-committerdate",
                "--format=%(refname:short) %(committerdate:iso8601)", "refs/heads/"], cwd)
    branches: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            branches.append((parts[0], parts[1].strip()))
    return branches


def _git_recent_commits(cwd: str, n: int = 50) -> list[tuple[str, str]]:
    """Get recent commit hashes and messages."""
    out = _git(["log", f"-{n}", "--format=%H %s"], cwd)
    commits: list[tuple[str, str]] = []
    for line in out.splitlines():
        parts = line.split(" ", 1)
        if len(parts) == 2:
            commits.append((parts[0], parts[1]))
    return commits


def _file_content(path: str, max_bytes: int = 100_000) -> str | None:
    """Read file content, returning None for binary files."""
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        if b"\x00" in raw[:8192]:
            return None  # Binary
        return raw.decode("utf-8", errors="replace")
    except (OSError, IOError):
        return None


# ── Auditor ──────────────────────────────────────────────────────────────────


def audit_repo(repo_path: str,
               ignore_rules: set[str] | None = None,
               severity_filter: str | None = None,
               large_file_threshold: int = 1_000_000) -> tuple[list[Finding], dict[str, Any]]:
    """Audit a git repository."""
    ignore_rules = ignore_rules or set()
    findings: list[Finding] = []
    repo = str(Path(repo_path).resolve())

    # Verify it's a git repo
    git_dir = _git(["rev-parse", "--git-dir"], repo)
    if not git_dir:
        return [], {"error": "Not a git repository"}

    tracked_files = _git_ls_files(repo)
    file_sizes = _git_file_sizes(repo)
    branches = _git_branches(repo)
    commits = _git_recent_commits(repo)

    def _add(rule: str, **kwargs: Any) -> None:
        if rule in ignore_rules:
            return
        rule_def = RULES[rule]
        sev = rule_def["severity"]
        if severity_filter:
            order = {SEVERITY_ERROR: 3, SEVERITY_WARNING: 2, SEVERITY_INFO: 1}
            if order.get(sev, 0) < order.get(severity_filter, 0):
                return
        fix = kwargs.pop("fix", rule_def.get("fix", ""))
        for k, v in list(kwargs.items()):
            if isinstance(v, str):
                fix = fix.replace(f"{{{k}}}", v)
        findings.append(Finding(rule=rule, severity=sev, message=rule_def["message"],
                                fix=fix, **kwargs))

    # GIT006: Missing .gitignore
    gitignore_path = os.path.join(repo, ".gitignore")
    has_gitignore = os.path.isfile(gitignore_path)
    if not has_gitignore:
        _add("GIT006")

    # GIT012: Missing .gitattributes
    gitattributes_path = os.path.join(repo, ".gitattributes")
    if not os.path.isfile(gitattributes_path):
        _add("GIT012")

    # GIT011: Submodule HTTP
    gitmodules_path = os.path.join(repo, ".gitmodules")
    if os.path.isfile(gitmodules_path):
        content = _file_content(gitmodules_path)
        if content:
            for line in content.splitlines():
                if "url" in line.lower() and "http://" in line:
                    _add("GIT011", file=".gitmodules",
                         context=line.strip())

    # Read .gitignore content for gap analysis
    gitignore_content = ""
    if has_gitignore:
        try:
            with open(gitignore_path, "r", encoding="utf-8", errors="replace") as f:
                gitignore_content = f.read()
        except (OSError, IOError):
            pass

    # GIT007: .gitignore gaps — check for Python project patterns
    if has_gitignore:
        # Detect project type
        has_python = any(f.endswith(".py") for f in tracked_files)
        has_node = any(f == "package.json" for f in tracked_files)

        check_patterns: list[str] = list(GITIGNORE_PATTERNS.get("General", []))
        if has_python:
            check_patterns.extend(GITIGNORE_PATTERNS.get("Python", []))
        if has_node:
            check_patterns.extend(GITIGNORE_PATTERNS.get("Node.js", []))

        for pattern in check_patterns:
            # Simple check: is the pattern (or close variant) in .gitignore?
            base = pattern.rstrip("/").replace("*.", "").replace(".", r"\.")
            if not re.search(re.escape(pattern.rstrip("/")), gitignore_content, re.IGNORECASE):
                # Only flag if such files actually exist in tracked files
                if any(pattern.rstrip("/").replace("*", "") in f for f in tracked_files):
                    _add("GIT007", context=f"Pattern: {pattern}",
                         pattern=pattern)

    files_scanned = 0
    secrets_found = 0
    binary_count = 0
    large_count = 0

    for filepath in tracked_files:
        full_path = os.path.join(repo, filepath)

        # GIT001: Sensitive files
        for pat, desc in SENSITIVE_FILE_RES:
            if pat.search(filepath):
                _add("GIT001", file=filepath, context=desc, path=filepath)
                break

        # GIT013: Generated/build files
        for pat, desc in GENERATED_RES:
            if pat.search(filepath):
                _add("GIT013", file=filepath, context=desc, path=filepath)
                break

        # GIT003: Large files
        size = file_sizes.get(filepath, 0)
        if size > large_file_threshold:
            size_mb = size / 1_000_000
            _add("GIT003", file=filepath,
                 context=f"Size: {size_mb:.1f} MB",
                 pattern=f"*{Path(filepath).suffix}" if Path(filepath).suffix else filepath)
            large_count += 1

        # GIT004: Binary files
        ext = Path(filepath).suffix.lower()
        if ext in BINARY_EXTENSIONS:
            binary_count += 1
            # Only flag if there are many or they're large
            if size > 100_000:
                _add("GIT004", file=filepath,
                     context=f"Binary file ({ext}, {size / 1000:.0f} KB)")

        # GIT014: Symlinks
        if os.path.islink(full_path):
            _add("GIT014", file=filepath)

        # GIT015: Deep nesting
        depth = len(Path(filepath).parts)
        if depth > 8:
            _add("GIT015", file=filepath,
                 context=f"Nesting depth: {depth} levels")

        # Content-based checks (skip binary, skip very large)
        if ext not in BINARY_EXTENSIONS and size < 500_000:
            content = _file_content(full_path)
            if content is not None:
                files_scanned += 1

                # GIT002: Secrets in files
                for pat, desc in SECRET_RES:
                    match = pat.search(content)
                    if match:
                        # Find line number
                        line_num = content[:match.start()].count("\n") + 1
                        _add("GIT002", file=filepath, line=line_num,
                             context=desc)
                        secrets_found += 1
                        break  # One secret per file is enough

                # GIT005: Merge conflict markers
                if CONFLICT_MARKER_RE.search(content):
                    for i, line in enumerate(content.splitlines(), 1):
                        if re.match(r"^<{7}\s", line):
                            _add("GIT005", file=filepath, line=i)
                            break

                # GIT009: Mixed line endings
                has_crlf = "\r\n" in content
                has_lf = "\n" in content.replace("\r\n", "")
                if has_crlf and has_lf:
                    _add("GIT009", file=filepath)

    # GIT010: Trivial commit messages
    trivial_count = 0
    for commit_hash, message in commits:
        if TRIVIAL_MESSAGES.match(message.strip()):
            trivial_count += 1
            if trivial_count <= 3:  # Cap to avoid noise
                _add("GIT010", context=f"Commit {commit_hash[:8]}: \"{message}\"")

    # GIT008: Stale branches
    import time
    now = time.time()
    for branch, date_str in branches:
        if branch in ("main", "master"):
            continue
        try:
            # Parse ISO date roughly
            date_part = date_str[:10]
            parts = date_part.split("-")
            if len(parts) == 3:
                from datetime import datetime
                dt = datetime(int(parts[0]), int(parts[1]), int(parts[2]))
                age_days = (now - dt.timestamp()) / 86400
                if age_days > 90:
                    _add("GIT008", context=f"Branch '{branch}' — last commit {int(age_days)} days ago",
                         branch=branch)
        except (ValueError, OSError):
            pass

    stats = {
        "tracked_files": len(tracked_files),
        "files_scanned": files_scanned,
        "branches": len(branches),
        "recent_commits": len(commits),
        "binary_files": binary_count,
        "large_files": large_count,
        "secrets_found": secrets_found,
    }

    return findings, stats


# ── Scoring ──────────────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {SEVERITY_ERROR: 15, SEVERITY_WARNING: 7, SEVERITY_INFO: 2}


def compute_score(findings: list[Finding]) -> int:
    if not findings:
        return 100
    total = sum(SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings)
    return max(0, 100 - total)


def grade_from_score(score: int) -> str:
    if score >= 98:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


# ── Output ───────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {SEVERITY_ERROR: "\033[91m", SEVERITY_WARNING: "\033[93m", SEVERITY_INFO: "\033[96m"}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
GRADE_COLORS = {"A+": "\033[92m", "A": "\033[92m", "B": "\033[93m", "C": "\033[93m", "D": "\033[91m", "F": "\033[91m"}


def format_output(findings: list[Finding], stats: dict[str, Any],
                  use_color: bool = True, verbose: bool = False) -> str:
    lines: list[str] = []

    if use_color:
        lines.append(f"{BOLD}gitaudit v{__version__}{RESET} — Git Repository Health & Security Auditor\n")
        lines.append(f"  {DIM}Tracked files: {stats.get('tracked_files', 0)}{RESET}")
        lines.append(f"  {DIM}Files scanned: {stats.get('files_scanned', 0)}{RESET}")
        lines.append(f"  {DIM}Branches: {stats.get('branches', 0)}{RESET}")
        if stats.get("binary_files"):
            lines.append(f"  {DIM}Binary files: {stats['binary_files']}{RESET}")
    else:
        lines.append(f"gitaudit v{__version__} — Git Repository Health & Security Auditor\n")
        lines.append(f"  Tracked files: {stats.get('tracked_files', 0)}")
        lines.append(f"  Files scanned: {stats.get('files_scanned', 0)}")
        lines.append(f"  Branches: {stats.get('branches', 0)}")
        if stats.get("binary_files"):
            lines.append(f"  Binary files: {stats['binary_files']}")

    lines.append("")

    for f in findings:
        loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file if f.file else "")
        if use_color:
            color = SEVERITY_COLORS.get(f.severity, "")
            lines.append(f"  {color}{f.severity.upper():>7}{RESET}  {BOLD}{f.rule}{RESET}  {loc}")
            lines.append(f"           {f.message}")
            if f.context:
                lines.append(f"           {DIM}{f.context}{RESET}")
        else:
            lines.append(f"  {f.severity.upper():>7}  {f.rule}  {loc}")
            lines.append(f"           {f.message}")
            if f.context:
                lines.append(f"           {f.context}")

    score = compute_score(findings)
    grade = grade_from_score(score)
    err = sum(1 for f in findings if f.severity == SEVERITY_ERROR)
    warn = sum(1 for f in findings if f.severity == SEVERITY_WARNING)
    info = sum(1 for f in findings if f.severity == SEVERITY_INFO)

    if use_color:
        gc = GRADE_COLORS.get(grade, "")
        lines.append(f"\n{BOLD}{'─' * 60}{RESET}")
        lines.append(f"  {BOLD}Grade: {gc}{grade}{RESET}  {BOLD}Score: {gc}{score}/100{RESET}")
        parts = []
        if err:
            parts.append(f"\033[91m{err} errors{RESET}")
        if warn:
            parts.append(f"\033[93m{warn} warnings{RESET}")
        if info:
            parts.append(f"\033[96m{info} info{RESET}")
        if parts:
            lines.append(f"  {', '.join(parts)}")
        else:
            lines.append(f"  \033[92mRepository is clean ✓{RESET}")
        lines.append(f"{BOLD}{'─' * 60}{RESET}")
    else:
        lines.append(f"\n{'─' * 60}")
        lines.append(f"  Grade: {grade}  Score: {score}/100")
        parts = []
        if err:
            parts.append(f"{err} errors")
        if warn:
            parts.append(f"{warn} warnings")
        if info:
            parts.append(f"{info} info")
        lines.append(f"  {', '.join(parts)}" if parts else "  Repository is clean ✓")
        lines.append(f"{'─' * 60}")

    if verbose and findings:
        lines.append("")
        lines.append(f"  {BOLD}Fix suggestions:{RESET}" if use_color else "  Fix suggestions:")
        seen: set[str] = set()
        for f in findings:
            if f.rule not in seen and f.fix:
                seen.add(f.rule)
                lines.append(f"  • {f.fix}")

    return "\n".join(lines)


def format_json(findings: list[Finding], stats: dict[str, Any]) -> str:
    score = compute_score(findings)
    grade = grade_from_score(score)
    return json.dumps({
        "grade": grade, "score": score, "stats": stats,
        "total_findings": len(findings),
        "errors": sum(1 for f in findings if f.severity == SEVERITY_ERROR),
        "warnings": sum(1 for f in findings if f.severity == SEVERITY_WARNING),
        "info": sum(1 for f in findings if f.severity == SEVERITY_INFO),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


# ── CLI ──────────────────────────────────────────────────────────────────────


def print_help() -> None:
    print(f"""gitaudit v{__version__} — Git Repository Health & Security Auditor

Usage:
    gitaudit [options] [path]

Options:
    -h, --help              Show this help
    -v, --version           Show version
    --check                 Exit 1 if score below threshold (CI mode)
    --min-score N           Minimum score for --check (default: 80)
    --json                  Output as JSON
    --severity LEVEL        Minimum severity: error, warning, info
    --ignore RULES          Comma-separated rules to ignore
    --large-threshold N     Large file threshold in bytes (default: 1000000)
    --verbose               Show fix suggestions
    --no-color              Disable colored output
    --list-rules            List all rules

Examples:
    gitaudit                Audit current repo
    gitaudit /path/to/repo  Audit specific repo
    gitaudit --check .      CI mode
    gitaudit --severity error .  Only show errors
""")


def print_rules() -> None:
    print(f"gitaudit v{__version__} — Rules\n")
    for rule_id, rule_def in sorted(RULES.items()):
        sev = rule_def["severity"].upper()
        name = rule_def["name"]
        msg = rule_def["message"]
        print(f"  {rule_id}  [{sev:>7}]  {name}")
        print(f"           {msg}")
        print()


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    path = "."
    check_mode = False
    min_score = 80
    json_mode = False
    severity_filter: str | None = None
    ignore_rules: set[str] = set()
    large_threshold = 1_000_000
    verbose = False
    no_color = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print_help()
            return 0
        elif arg in ("-v", "--version"):
            print(f"gitaudit {__version__}")
            return 0
        elif arg == "--list-rules":
            print_rules()
            return 0
        elif arg == "--check":
            check_mode = True
        elif arg == "--min-score":
            i += 1
            if i < len(args):
                try:
                    min_score = int(args[i])
                except ValueError:
                    print("Error: --min-score requires integer", file=sys.stderr)
                    return 2
        elif arg == "--json":
            json_mode = True
        elif arg == "--severity":
            i += 1
            if i < len(args):
                severity_filter = args[i].lower()
        elif arg == "--ignore":
            i += 1
            if i < len(args):
                ignore_rules = {r.strip().upper() for r in args[i].split(",")}
        elif arg == "--large-threshold":
            i += 1
            if i < len(args):
                try:
                    large_threshold = int(args[i])
                except ValueError:
                    print("Error: --large-threshold requires integer", file=sys.stderr)
                    return 2
        elif arg == "--verbose":
            verbose = True
        elif arg == "--no-color":
            no_color = True
        elif not arg.startswith("-"):
            path = arg
        else:
            print(f"Unknown option: {arg}", file=sys.stderr)
            return 2
        i += 1

    use_color = not no_color and not json_mode and sys.stdout.isatty()

    findings, stats = audit_repo(
        path,
        ignore_rules=ignore_rules,
        severity_filter=severity_filter,
        large_file_threshold=large_threshold,
    )

    if "error" in stats:
        if json_mode:
            print(json.dumps({"error": stats["error"]}))
        else:
            print(f"Error: {stats['error']}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: (f.severity != SEVERITY_ERROR,
                                  f.severity != SEVERITY_WARNING,
                                  f.file, f.line))

    if json_mode:
        print(format_json(findings, stats))
    else:
        print(format_output(findings, stats, use_color=use_color, verbose=verbose))

    if check_mode:
        score = compute_score(findings)
        if score < min_score:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
