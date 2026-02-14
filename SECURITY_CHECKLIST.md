# Git Security Checklist

Comprehensive guide to securing your Git repository and workflow.

## Quick Audit

Run gitaudit to check your repo:
```bash
gitaudit /path/to/repo
```

## Pre-Commit Security

### 1. Prevent Secret Commits

**Install pre-commit hook:**
```bash
#!/bin/bash
# .git/hooks/pre-commit

# Check for common secret patterns
if git diff --cached | grep -E '(api[_-]?key|password|secret|token|bearer|jwt).*[=:]\s*["\047][^"\047]{8,}' ; then
    echo "❌ Possible secret detected in staged changes"
    exit 1
fi

# Run gitaudit
gitaudit --check-staged || exit 1
```

**Or use dedicated tools:**
```bash
# git-secrets (AWS)
git secrets --install
git secrets --register-aws

# gitleaks
gitleaks protect --staged

# truffleHog
trufflehog git file://. --since-commit HEAD
```

### 2. Verify Commit Signatures

**Sign commits with GPG:**
```bash
# Generate key
gpg --gen-key

# Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true

# Verify signatures
gitaudit --check-signatures
```

**Require signed commits (GitHub):**
- Settings → Branches → Branch protection rules
- Enable "Require signed commits"

### 3. Protected Branches

**Configure protection:**
```bash
# GitHub CLI
gh api repos/OWNER/REPO/branches/main/protection \
  -X PUT \
  -F required_status_checks[strict]=true \
  -F required_pull_request_reviews[required_approving_review_count]=1 \
  -F enforce_admins=true
```

**Rules to enable:**
- Require pull request reviews
- Require status checks to pass
- Require signed commits
- Include administrators
- Restrict who can push

## Repository Audit

### 1. Check for Leaked Secrets

**Scan entire history:**
```bash
# gitaudit
gitaudit --deep-scan --secrets

# gitleaks
gitleaks detect --source . --verbose

# truffleHog
trufflehog git file://. --only-verified
```

**If secrets found:**
```bash
# 1. Revoke the compromised secret immediately
# 2. Remove from history (use BFG or git-filter-repo)

# BFG Repo-Cleaner
bfg --replace-text passwords.txt repo.git

# git-filter-repo (recommended)
git filter-repo --path-glob '**/*.env' --invert-paths
```

### 2. Verify File Permissions

**Check for executable bits on sensitive files:**
```bash
gitaudit --check-permissions

# Manually check
git ls-files -s | grep '^100755' | grep -E '\.(key|pem|env|config)$'
```

**Fix:**
```bash
# Remove execute permission
git update-index --chmod=-x file.key
git commit -m "fix: remove execute bit from key file"
```

### 3. Audit .gitignore

**Ensure sensitive files are ignored:**
```bash
cat > .gitignore << 'EOF'
# Credentials
.env
.env.local
*.pem
*.key
id_rsa
id_dsa
credentials.json
secrets.yaml

# OS files
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp

# Build artifacts
dist/
build/
*.pyc
__pycache__/
node_modules/
EOF
```

**Verify:**
```bash
gitaudit --check-gitignore
```

### 4. Check Submodules

**Security risks:**
- Submodules can point to arbitrary repos
- May contain outdated/vulnerable code

**Audit:**
```bash
gitaudit --check-submodules

# List submodules
git submodule status

# Check each one
git submodule foreach 'gitaudit .'
```

## Access Control

### 1. SSH Keys

**Use SSH over HTTPS:**
```bash
# Check current remote
git remote -v

# Switch to SSH
git remote set-url origin git@github.com:user/repo.git
```

**Rotate SSH keys regularly:**
```bash
# Generate new key
ssh-keygen -t ed25519 -C "your_email@example.com"

# Add to GitHub
cat ~/.ssh/id_ed25519.pub
# Add to GitHub Settings → SSH Keys
```

### 2. Deploy Keys

**Read-only access for CI/CD:**
```bash
# Generate deploy key
ssh-keygen -t ed25519 -f deploy_key -N ""

# Add public key to GitHub
# Settings → Deploy keys → Add deploy key
# ✓ Allow read access (no write unless needed)
```

**Use in CI:**
```yaml
# .github/workflows/deploy.yml
- name: Setup SSH
  run: |
    mkdir -p ~/.ssh
    echo "${{ secrets.DEPLOY_KEY }}" > ~/.ssh/id_ed25519
    chmod 600 ~/.ssh/id_ed25519
```

### 3. Personal Access Tokens (PATs)

**Scope tokens narrowly:**
```bash
# GitHub: Settings → Developer settings → Personal access tokens
# Select minimal scopes needed (e.g., repo:read for read-only)
```

**Rotate regularly:**
- Set expiration dates
- Audit token usage monthly
- Revoke unused tokens

## Workflow Security

### 1. Pull Request Reviews

**Require reviews before merge:**
```yaml
# .github/CODEOWNERS
# Require security team review for sensitive paths
/src/auth/ @security-team
/src/payments/ @security-team
*.pem @security-team
```

**Review checklist:**
- [ ] No hardcoded secrets
- [ ] Dependencies are trusted
- [ ] Tests pass
- [ ] No obvious vulnerabilities

### 2. Dependency Scanning

**Automated checks:**
```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run gitaudit
        run: |
          pip install gitaudit
          gitaudit --check
      
      - name: Dependency check
        run: |
          pip install safety
          safety check
      
      - name: SAST
        uses: github/codeql-action/analyze@v2
```

### 3. Branch Naming

**Use descriptive names:**
```bash
# ✅ Good
git checkout -b security/fix-xss-in-profile
git checkout -b feat/add-2fa

# ❌ Bad
git checkout -b test
git checkout -b fix
```

## Incident Response

### 1. Secret Leaked in Commit

**Immediate actions:**
```bash
# 1. Revoke the secret (API key, password, token)
# 2. Notify security team
# 3. Remove from history

# Remove file from history
git filter-repo --path secret.key --invert-paths

# Force push (coordinate with team!)
git push origin --force --all

# 4. Document incident
# 5. Review access logs for unauthorized use
```

### 2. Unauthorized Commit

**Investigate:**
```bash
# Check commit details
git log --show-signature --oneline

# Verify author
git log --format="%H %an %ae %GK" -1 COMMIT_HASH

# Check if GPG signed
git verify-commit COMMIT_HASH
```

**Remediate:**
```bash
# Revert if malicious
git revert COMMIT_HASH
git push origin main

# Or remove from history if not yet pulled
git rebase -i COMMIT_HASH~1
# Mark as 'drop'
git push origin +main
```

### 3. Compromised Repository

**Lock down:**
1. Revoke all deploy keys and tokens
2. Enable GitHub Advanced Security (if available)
3. Audit commit history
4. Rotate all secrets referenced in code
5. Notify users/customers if data exposed

## Best Practices Summary

### ✅ DO

- Use signed commits (GPG)
- Enable branch protection
- Scan for secrets before commit
- Use .gitignore for sensitive files
- Rotate SSH keys and tokens regularly
- Review all PRs
- Run security scans in CI
- Use deploy keys (not personal tokens) for automation
- Keep dependencies updated
- Document security incidents

### ❌ DON'T

- Commit .env files
- Push directly to main/protected branches
- Share SSH keys or tokens
- Ignore security warnings
- Use HTTP remotes (use SSH or HTTPS)
- Reuse tokens across projects
- Skip code reviews for "small" changes
- Commit large binary files (use Git LFS)
- Force push to shared branches without coordination

## Compliance

### GDPR / Data Protection

```bash
# Check for PII in commits
gitaudit --check-pii

# Common patterns to avoid:
# - Email addresses (except in git config)
# - Phone numbers
# - Social security numbers
# - Credit card numbers
# - Names in test data
```

### Industry Standards

- **PCI-DSS**: No credit card data in repos
- **HIPAA**: No PHI in repos
- **SOC 2**: Access control, audit logs, encryption
- **ISO 27001**: Security policies, regular audits

## Tools

| Tool | Purpose | Command |
|------|---------|---------|
| **gitaudit** | Comprehensive Git security audit | `gitaudit .` |
| **gitleaks** | Secret scanning | `gitleaks detect` |
| **truffleHog** | Secret scanning (verified) | `trufflehog git file://.` |
| **git-secrets** | AWS secret prevention | `git secrets --scan` |
| **BFG Repo-Cleaner** | Remove sensitive files from history | `bfg --delete-files secrets.txt` |
| **git-filter-repo** | Advanced history rewriting | `git filter-repo --path file --invert-paths` |
| **safety** | Python dependency vulnerability scan | `safety check` |
| **npm audit** | Node dependency scan | `npm audit` |
| **Snyk** | Dependency and container scanning | `snyk test` |

## Resources

- [GitHub Security Best Practices](https://docs.github.com/en/code-security)
- [Git Security Vulnerabilities](https://git-scm.com/docs/security)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [gitaudit GitHub repo](https://github.com/kriskimmerle/gitaudit)

## Automation

```bash
# Daily security scan (cron)
0 2 * * * cd /path/to/repo && gitaudit --check || mail -s "Git Security Alert" admin@example.com < /tmp/gitaudit.log

# Pre-commit hook template
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e

echo "Running security checks..."

# Check for secrets
gitaudit --check-staged || exit 1

# Check for large files
for file in $(git diff --cached --name-only); do
    size=$(wc -c < "$file" 2>/dev/null || echo 0)
    if [ $size -gt 10485760 ]; then  # 10MB
        echo "❌ File too large: $file (${size} bytes)"
        exit 1
    fi
done

echo "✓ Security checks passed"
EOF

chmod +x .git/hooks/pre-commit
```

---

**Remember:** Security is a practice, not a feature. Audit regularly, stay informed, and respond quickly to incidents.
