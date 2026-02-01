#!/usr/bin/env python3
"""
gitaudit - Git Repository Hygiene Auditor

A zero-dependency tool for auditing git repository health and hygiene.
Uses only Python stdlib and git CLI commands.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


class Severity:
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class Finding:
    """Represents a single audit finding."""
    
    def __init__(self, check_id: str, severity: str, title: str, 
                 description: str, details: Any = None):
        self.check_id = check_id
        self.severity = severity
        self.title = title
        self.description = description
        self.details = details or {}
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "details": self.details
        }


class GitAuditor:
    """Main auditor class that runs all checks."""
    
    def __init__(self, repo_path: str, max_file_size_mb: int = 5, 
                 stale_days: int = 90, ignored_checks: List[str] = None):
        self.repo_path = Path(repo_path).resolve()
        self.max_file_size_mb = max_file_size_mb
        self.stale_days = stale_days
        self.ignored_checks = ignored_checks or []
        self.findings: List[Finding] = []
        
        if not self._is_git_repo():
            raise ValueError(f"Not a git repository: {self.repo_path}")
    
    def _is_git_repo(self) -> bool:
        """Check if path is a git repository."""
        try:
            self._run_git("rev-parse", "--git-dir")
            return True
        except subprocess.CalledProcessError:
            return False
    
    def _run_git(self, *args, **kwargs) -> str:
        """Run a git command and return stdout."""
        cmd = ["git"] + list(args)
        kwargs.setdefault("cwd", self.repo_path)
        kwargs.setdefault("capture_output", True)
        kwargs.setdefault("text", True)
        kwargs.setdefault("check", True)
        
        result = subprocess.run(cmd, **kwargs)
        return result.stdout.strip()
    
    def _get_git_dir(self) -> Path:
        """Get the .git directory path."""
        git_dir = self._run_git("rev-parse", "--git-dir")
        return (self.repo_path / git_dir).resolve()
    
    def _get_dir_size(self, path: Path) -> int:
        """Calculate directory size in bytes."""
        total = 0
        try:
            for entry in path.rglob("*"):
                if entry.is_file():
                    total += entry.stat().st_size
        except (OSError, PermissionError):
            pass
        return total
    
    def run_all_checks(self) -> None:
        """Run all audit checks."""
        checks = [
            ("GA001", self.check_large_files),
            ("GA002", self.check_repo_size),
            ("GA003", self.check_stale_branches),
            ("GA004", self.check_orphan_tags),
            ("GA005", self.check_gitignore),
            ("GA006", self.check_unsigned_commits),
            ("GA007", self.check_commit_messages),
            ("GA008", self.check_unmerged_branches),
            ("GA009", self.check_missing_license),
            ("GA010", self.check_sensitive_files),
            ("GA011", self.check_shallow_clone),
            ("GA012", self.check_submodule_health),
        ]
        
        for check_id, check_func in checks:
            if check_id not in self.ignored_checks:
                try:
                    check_func()
                except Exception as e:
                    # Log errors but continue with other checks
                    print(f"Warning: Check {check_id} failed: {e}", file=sys.stderr)
    
    def check_large_files(self) -> None:
        """GA001: Find large files in git history."""
        threshold_bytes = self.max_file_size_mb * 1024 * 1024
        
        try:
            # Get all objects with their sizes
            objects = self._run_git("rev-list", "--objects", "--all")
            if not objects:
                return
            
            large_files = []
            
            # Process in batches for efficiency
            object_lines = objects.split('\n')
            for line in object_lines:
                if not line.strip():
                    continue
                    
                parts = line.split(None, 1)
                sha = parts[0]
                filename = parts[1] if len(parts) > 1 else ""
                
                if not filename:  # Skip commits and trees
                    continue
                
                try:
                    # Get object size
                    info = self._run_git("cat-file", "-s", sha)
                    size = int(info)
                    
                    if size > threshold_bytes:
                        large_files.append({
                            "file": filename,
                            "size_mb": round(size / (1024 * 1024), 2),
                            "sha": sha[:8]
                        })
                except (subprocess.CalledProcessError, ValueError):
                    continue
            
            if large_files:
                # Sort by size
                large_files.sort(key=lambda x: x["size_mb"], reverse=True)
                self.findings.append(Finding(
                    "GA001",
                    Severity.WARNING,
                    "Large files in history",
                    f"Found {len(large_files)} file(s) over {self.max_file_size_mb}MB in git history",
                    {"files": large_files[:10]}  # Limit to top 10
                ))
        except subprocess.CalledProcessError:
            pass
    
    def check_repo_size(self) -> None:
        """GA002: Check total repository size."""
        git_dir = self._get_git_dir()
        size_bytes = self._get_dir_size(git_dir)
        size_mb = size_bytes / (1024 * 1024)
        
        # Info threshold: 100MB
        if size_mb > 100:
            self.findings.append(Finding(
                "GA002",
                Severity.INFO,
                "Large repository size",
                f"Repository .git directory is {size_mb:.1f}MB",
                {"size_mb": round(size_mb, 1)}
            ))
    
    def check_stale_branches(self) -> None:
        """GA003: Find stale remote-tracking branches."""
        try:
            branches = self._run_git("branch", "-r", "--format=%(refname:short)|%(committerdate:iso-strict)")
            if not branches:
                return
            
            now = datetime.now(timezone.utc)
            stale_branches = []
            
            for line in branches.split('\n'):
                if not line.strip() or "->" in line:  # Skip HEAD references
                    continue
                
                parts = line.split('|')
                if len(parts) != 2:
                    continue
                
                branch_name, date_str = parts
                try:
                    commit_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    days_old = (now - commit_date).days
                    
                    if days_old > self.stale_days:
                        stale_branches.append({
                            "branch": branch_name,
                            "days_old": days_old
                        })
                except (ValueError, AttributeError):
                    continue
            
            if stale_branches:
                stale_branches.sort(key=lambda x: x["days_old"], reverse=True)
                self.findings.append(Finding(
                    "GA003",
                    Severity.WARNING,
                    "Stale branches detected",
                    f"Found {len(stale_branches)} branch(es) with no commits in {self.stale_days}+ days",
                    {"branches": stale_branches[:10]}
                ))
        except subprocess.CalledProcessError:
            pass
    
    def check_orphan_tags(self) -> None:
        """GA004: Find tags pointing to unreachable commits."""
        try:
            # Get all tags
            tags = self._run_git("tag")
            if not tags:
                return
            
            # Get all commits reachable from branches
            reachable = self._run_git("rev-list", "--all")
            reachable_commits = set(reachable.split('\n'))
            
            orphan_tags = []
            for tag in tags.split('\n'):
                if not tag.strip():
                    continue
                
                try:
                    # Get commit that tag points to
                    commit = self._run_git("rev-list", "-n", "1", tag)
                    if commit not in reachable_commits:
                        orphan_tags.append(tag)
                except subprocess.CalledProcessError:
                    continue
            
            if orphan_tags:
                self.findings.append(Finding(
                    "GA004",
                    Severity.INFO,
                    "Orphan tags detected",
                    f"Found {len(orphan_tags)} tag(s) pointing to unreachable commits",
                    {"tags": orphan_tags}
                ))
        except subprocess.CalledProcessError:
            pass
    
    def check_gitignore(self) -> None:
        """GA005: Check for missing or incomplete .gitignore."""
        gitignore_path = self.repo_path / ".gitignore"
        
        if not gitignore_path.exists():
            self.findings.append(Finding(
                "GA005",
                Severity.WARNING,
                "Missing .gitignore",
                "No .gitignore file found in repository root",
                {}
            ))
            return
        
        # Detect languages and check for common patterns
        try:
            files = self._run_git("ls-files")
            extensions = defaultdict(int)
            
            for file in files.split('\n'):
                if '.' in file:
                    ext = file.rsplit('.', 1)[1].lower()
                    extensions[ext] += 1
            
            # Read .gitignore
            gitignore_content = gitignore_path.read_text().lower()
            
            missing_patterns = []
            
            # Python
            if extensions.get('py', 0) > 0:
                if '__pycache__' not in gitignore_content:
                    missing_patterns.append('__pycache__/')
                if '.pyc' not in gitignore_content:
                    missing_patterns.append('*.pyc')
                if '.egg-info' not in gitignore_content:
                    missing_patterns.append('*.egg-info/')
            
            # Node.js
            if extensions.get('js', 0) > 0 or (self.repo_path / "package.json").exists():
                if 'node_modules' not in gitignore_content:
                    missing_patterns.append('node_modules/')
            
            # Go
            if extensions.get('go', 0) > 0:
                if not any(p in gitignore_content for p in ['*.exe', '*.test']):
                    missing_patterns.append('*.exe, *.test')
            
            # Rust
            if (self.repo_path / "Cargo.toml").exists():
                if 'target/' not in gitignore_content:
                    missing_patterns.append('target/')
            
            if missing_patterns:
                self.findings.append(Finding(
                    "GA005",
                    Severity.WARNING,
                    "Incomplete .gitignore",
                    f"Missing {len(missing_patterns)} common pattern(s) for detected languages",
                    {"missing_patterns": missing_patterns}
                ))
        except (subprocess.CalledProcessError, OSError):
            pass
    
    def check_unsigned_commits(self) -> None:
        """GA006: Check for unsigned commits."""
        try:
            # Get all commits with signature info
            log = self._run_git("log", "--format=%H|%G?", "--all")
            if not log:
                return
            
            total_commits = 0
            unsigned_commits = 0
            
            for line in log.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split('|')
                if len(parts) != 2:
                    continue
                
                total_commits += 1
                sig_status = parts[1]
                
                # G = good, B = bad, U = good but unknown validity, N = no signature
                if sig_status in ['N', 'E']:  # No signature or error
                    unsigned_commits += 1
            
            if total_commits > 0:
                unsigned_pct = (unsigned_commits / total_commits) * 100
                
                if unsigned_pct > 50:
                    self.findings.append(Finding(
                        "GA006",
                        Severity.INFO,
                        "Many unsigned commits",
                        f"{unsigned_pct:.1f}% of commits are unsigned ({unsigned_commits}/{total_commits})",
                        {
                            "unsigned_count": unsigned_commits,
                            "total_count": total_commits,
                            "unsigned_percentage": round(unsigned_pct, 1)
                        }
                    ))
        except subprocess.CalledProcessError:
            pass
    
    def check_commit_messages(self) -> None:
        """GA007: Check for inconsistent commit messages."""
        try:
            # Get commit messages from main/master branch
            default_branch = self._get_default_branch()
            if not default_branch:
                return
            
            messages = self._run_git("log", default_branch, "--format=%s", "-100")
            if not messages:
                return
            
            message_list = messages.split('\n')
            total = len(message_list)
            
            short_messages = 0
            wip_messages = 0
            conventional = 0
            
            conventional_pattern = re.compile(r'^(feat|fix|docs|style|refactor|test|chore|perf|ci|build|revert)(\(.+\))?:.+')
            
            for msg in message_list:
                if len(msg) < 10:
                    short_messages += 1
                
                if re.match(r'^\s*(wip|WIP|fixup|squash)', msg, re.IGNORECASE):
                    wip_messages += 1
                
                if conventional_pattern.match(msg):
                    conventional += 1
            
            issues = []
            
            if short_messages > total * 0.2:
                issues.append(f"{short_messages} very short messages (<10 chars)")
            
            if wip_messages > 0:
                issues.append(f"{wip_messages} WIP/fixup commits")
            
            # Mixed style: some conventional, some not
            if 0 < conventional < total * 0.8:
                issues.append(f"Inconsistent commit style ({conventional}/{total} conventional)")
            
            if issues:
                self.findings.append(Finding(
                    "GA007",
                    Severity.INFO,
                    "Inconsistent commit messages",
                    f"Found {len(issues)} commit message issue(s)",
                    {"issues": issues}
                ))
        except subprocess.CalledProcessError:
            pass
    
    def _get_default_branch(self) -> Optional[str]:
        """Get the default branch name (main/master)."""
        try:
            # Try symbolic ref
            branch = self._run_git("symbolic-ref", "refs/remotes/origin/HEAD")
            return branch.replace('refs/remotes/origin/', '')
        except subprocess.CalledProcessError:
            # Fallback: check for main or master
            try:
                branches = self._run_git("branch", "--format=%(refname:short)")
                for branch in branches.split('\n'):
                    if branch in ['main', 'master']:
                        return branch
                # Return first branch
                return branches.split('\n')[0] if branches else None
            except subprocess.CalledProcessError:
                return None
    
    def check_unmerged_branches(self) -> None:
        """GA008: Find local branches that diverged from main."""
        try:
            default_branch = self._get_default_branch()
            if not default_branch:
                return
            
            # Get local branches
            branches = self._run_git("branch", "--format=%(refname:short)")
            if not branches:
                return
            
            diverged = []
            
            for branch in branches.split('\n'):
                if not branch or branch == default_branch:
                    continue
                
                try:
                    # Count commits not in default branch
                    ahead = self._run_git("rev-list", "--count", f"{default_branch}..{branch}")
                    behind = self._run_git("rev-list", "--count", f"{branch}..{default_branch}")
                    
                    ahead_count = int(ahead) if ahead else 0
                    behind_count = int(behind) if behind else 0
                    
                    # Significantly diverged: more than 10 commits behind
                    if behind_count > 10:
                        diverged.append({
                            "branch": branch,
                            "ahead": ahead_count,
                            "behind": behind_count
                        })
                except (subprocess.CalledProcessError, ValueError):
                    continue
            
            if diverged:
                self.findings.append(Finding(
                    "GA008",
                    Severity.INFO,
                    "Diverged branches detected",
                    f"Found {len(diverged)} branch(es) significantly behind {default_branch}",
                    {"branches": diverged}
                ))
        except subprocess.CalledProcessError:
            pass
    
    def check_missing_license(self) -> None:
        """GA009: Check for missing LICENSE file."""
        license_patterns = ["LICENSE", "COPYING", "LICENSE.md", "LICENSE.txt", "LICENCE"]
        
        for pattern in license_patterns:
            if (self.repo_path / pattern).exists():
                return
            # Case-insensitive check
            for file in self.repo_path.iterdir():
                if file.name.upper() == pattern.upper():
                    return
        
        self.findings.append(Finding(
            "GA009",
            Severity.WARNING,
            "Missing LICENSE file",
            "No LICENSE or COPYING file found in repository root",
            {}
        ))
    
    def check_sensitive_files(self) -> None:
        """GA010: Check for sensitive files in working tree or history."""
        sensitive_patterns = [
            r'\.env$',
            r'\.pem$',
            r'\.key$',
            r'\.pfx$',
            r'\.p12$',
            r'id_rsa$',
            r'id_dsa$',
            r'credentials\.json$',
            r'secret.*\.json$',
            r'\.aws/credentials$',
            r'\.ssh/id_',
            r'password.*\.txt$',
            r'private.*\.key$',
        ]
        
        found_files = set()
        
        # Check working tree
        try:
            files = self._run_git("ls-files")
            for file in files.split('\n'):
                for pattern in sensitive_patterns:
                    if re.search(pattern, file, re.IGNORECASE):
                        found_files.add(file)
        except subprocess.CalledProcessError:
            pass
        
        # Check history (limit to recent commits for performance)
        try:
            objects = self._run_git("rev-list", "--objects", "--all", "--max-count=1000")
            for line in objects.split('\n'):
                if not line.strip():
                    continue
                
                parts = line.split(None, 1)
                if len(parts) < 2:
                    continue
                
                filename = parts[1]
                for pattern in sensitive_patterns:
                    if re.search(pattern, filename, re.IGNORECASE):
                        found_files.add(filename + " (history)")
        except subprocess.CalledProcessError:
            pass
        
        if found_files:
            self.findings.append(Finding(
                "GA010",
                Severity.ERROR,
                "Sensitive files detected",
                f"Found {len(found_files)} potential sensitive file(s)",
                {"files": sorted(list(found_files))[:20]}
            ))
    
    def check_shallow_clone(self) -> None:
        """GA011: Check if repository is a shallow clone."""
        git_dir = self._get_git_dir()
        shallow_file = git_dir / "shallow"
        
        if shallow_file.exists():
            self.findings.append(Finding(
                "GA011",
                Severity.INFO,
                "Shallow clone detected",
                "Repository is a shallow clone with limited history",
                {}
            ))
    
    def check_submodule_health(self) -> None:
        """GA012: Check submodule health."""
        try:
            # Check if there are submodules
            submodules = self._run_git("submodule", "status")
            if not submodules:
                return
            
            issues = []
            
            for line in submodules.split('\n'):
                if not line.strip():
                    continue
                
                # Status prefix: '-' = not initialized, '+' = different commit, 'U' = conflicts
                if line.startswith('-'):
                    issues.append(f"Not initialized: {line[1:].split()[1]}")
                elif line.startswith('+'):
                    issues.append(f"Different commit: {line[1:].split()[1]}")
                elif line.startswith('U'):
                    issues.append(f"Merge conflicts: {line[1:].split()[1]}")
            
            # Check for detached HEAD in submodules
            try:
                foreach_out = self._run_git("submodule", "foreach", "--quiet", 
                                           "git symbolic-ref -q HEAD || echo DETACHED")
                if "DETACHED" in foreach_out:
                    detached_count = foreach_out.count("DETACHED")
                    issues.append(f"{detached_count} submodule(s) with detached HEAD")
            except subprocess.CalledProcessError:
                pass
            
            if issues:
                self.findings.append(Finding(
                    "GA012",
                    Severity.WARNING,
                    "Submodule issues detected",
                    f"Found {len(issues)} submodule issue(s)",
                    {"issues": issues}
                ))
        except subprocess.CalledProcessError:
            pass
    
    def calculate_grade(self) -> str:
        """Calculate overall repository grade (A-F)."""
        # Scoring: start at 100, deduct points for findings
        score = 100
        
        for finding in self.findings:
            if finding.severity == Severity.ERROR:
                score -= 20
            elif finding.severity == Severity.WARNING:
                score -= 10
            elif finding.severity == Severity.INFO:
                score -= 3
        
        # Convert to letter grade
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def get_results(self) -> Dict[str, Any]:
        """Get audit results as a dictionary."""
        return {
            "repository": str(self.repo_path),
            "grade": self.calculate_grade(),
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "errors": sum(1 for f in self.findings if f.severity == Severity.ERROR),
                "warnings": sum(1 for f in self.findings if f.severity == Severity.WARNING),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            }
        }


def format_text_output(results: Dict[str, Any], min_severity: str = "INFO", 
                       quiet: bool = False) -> str:
    """Format results as human-readable text."""
    output = []
    
    if not quiet:
        output.append("=" * 70)
        output.append(f"Git Repository Audit: {results['repository']}")
        output.append("=" * 70)
        output.append("")
    
    severity_order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    min_level = severity_order.get(min_severity, 2)
    
    findings = [f for f in results['findings'] 
                if severity_order.get(f['severity'], 2) <= min_level]
    
    if not quiet and findings:
        for finding in findings:
            severity_icon = {
                "ERROR": "❌",
                "WARNING": "⚠️ ",
                "INFO": "ℹ️ "
            }.get(finding['severity'], "•")
            
            output.append(f"{severity_icon} [{finding['check_id']}] {finding['title']}")
            output.append(f"   Severity: {finding['severity']}")
            output.append(f"   {finding['description']}")
            
            if finding['details']:
                # Format details nicely
                for key, value in finding['details'].items():
                    if isinstance(value, list) and value:
                        output.append(f"   {key}:")
                        for item in value[:5]:  # Limit display
                            if isinstance(item, dict):
                                output.append(f"      • {item}")
                            else:
                                output.append(f"      • {item}")
                        if len(value) > 5:
                            output.append(f"      ... and {len(value) - 5} more")
                    elif not isinstance(value, (list, dict)):
                        output.append(f"   {key}: {value}")
            
            output.append("")
    
    # Summary
    output.append("=" * 70)
    output.append("SUMMARY")
    output.append("=" * 70)
    
    grade = results['grade']
    grade_color = {
        'A': '🟢',
        'B': '🟢',
        'C': '🟡',
        'D': '🟠',
        'F': '🔴'
    }.get(grade, '⚪')
    
    output.append(f"Overall Grade: {grade_color} {grade}")
    output.append(f"Total Findings: {results['summary']['total']}")
    output.append(f"  Errors:   {results['summary']['errors']}")
    output.append(f"  Warnings: {results['summary']['warnings']}")
    output.append(f"  Info:     {results['summary']['info']}")
    output.append("=" * 70)
    
    return '\n'.join(output)


def list_checks() -> str:
    """Return a formatted list of all checks."""
    checks = [
        ("GA001", "WARNING", "Large files in history", 
         "Find files over threshold in git history"),
        ("GA002", "INFO", "Large repo size", 
         "Check total .git directory size"),
        ("GA003", "WARNING", "Stale branches", 
         "Remote-tracking branches with no recent commits"),
        ("GA004", "INFO", "Orphan tags", 
         "Tags pointing to unreachable commits"),
        ("GA005", "WARNING", "Missing .gitignore", 
         "Missing or incomplete .gitignore file"),
        ("GA006", "INFO", "Unsigned commits", 
         "Percentage of commits without GPG/SSH signatures"),
        ("GA007", "INFO", "Inconsistent commit messages", 
         "Mix of conventional commits and freeform, WIP commits"),
        ("GA008", "INFO", "Unmerged branches", 
         "Local branches significantly diverged from main"),
        ("GA009", "WARNING", "Missing LICENSE", 
         "No LICENSE or COPYING file"),
        ("GA010", "ERROR", "Sensitive files committed", 
         "Potential secrets like .env, *.pem, *.key files"),
        ("GA011", "INFO", "Shallow clone detected", 
         "Repository is a shallow clone"),
        ("GA012", "WARNING", "Submodule health", 
         "Submodules with issues (detached HEAD, dirty state)"),
    ]
    
    output = ["Available Checks:", "=" * 70]
    for check_id, severity, title, description in checks:
        output.append(f"{check_id} [{severity:7}] {title}")
        output.append(f"         {description}")
        output.append("")
    
    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description="Git Repository Hygiene Auditor - Audit your git repo health",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "repo_path",
        nargs="?",
        default=".",
        help="Path to git repository (default: current directory)"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "--severity",
        choices=["info", "warning", "error"],
        default="info",
        help="Minimum severity to show (default: info)"
    )
    
    parser.add_argument(
        "--ignore",
        action="append",
        dest="ignored_checks",
        metavar="CHECK_ID",
        help="Ignore specific checks (can be repeated)"
    )
    
    parser.add_argument(
        "--check",
        action="store_true",
        help="CI mode: exit 1 if grade below threshold"
    )
    
    parser.add_argument(
        "--min-grade",
        choices=["A", "B", "C", "D"],
        default="C",
        help="Minimum passing grade for --check mode (default: C)"
    )
    
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="Show all available checks and exit"
    )
    
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=5,
        metavar="MB",
        help="Large file threshold in MB (default: 5)"
    )
    
    parser.add_argument(
        "--stale-days",
        type=int,
        default=90,
        metavar="N",
        help="Days before branch is considered stale (default: 90)"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Only show summary grade"
    )
    
    args = parser.parse_args()
    
    if args.list_checks:
        print(list_checks())
        return 0
    
    try:
        auditor = GitAuditor(
            args.repo_path,
            max_file_size_mb=args.max_file_size,
            stale_days=args.stale_days,
            ignored_checks=args.ignored_checks or []
        )
        
        auditor.run_all_checks()
        results = auditor.get_results()
        
        if args.format == "json":
            print(json.dumps(results, indent=2))
        else:
            print(format_text_output(
                results, 
                min_severity=args.severity.upper(),
                quiet=args.quiet
            ))
        
        # CI mode check
        if args.check:
            grade_order = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}
            actual_grade = results['grade']
            min_grade = args.min_grade
            
            if grade_order[actual_grade] < grade_order[min_grade]:
                return 1
        
        return 0
        
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAudit interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
