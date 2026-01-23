# SkillShepard

![SkillShepard logo](logo/logo_skillshepard.png)

A security scanner for Claude Code Skills. Detects malware and vulnerable code to help you safely install Skills.

Compatible with [Agent Skills](https://agentskills.io) standard - works with any AI agent that supports Skills.

> [!WARNING]
> SkillShepard is a supplementary tool designed to assist in the safe use of Skills. It uses pattern-based detection to identify known security risks, but **cannot guarantee complete protection** against all threats.
>
> - **New attack techniques** may not be detected
> - **Obfuscated or encoded malicious code** may evade detection
> - **Context-dependent vulnerabilities** require human judgment
> - **False positives** may occur in legitimate code
>
> **Always review the source code yourself before installing any Skill.** This tool reduces risk but does not eliminate it. You are ultimately responsible for the security of your environment.

## Overview

SkillShepard scans Skill definition files (SKILL.md, scripts, etc.) and detects the following security risks:

- **Prompt injection** (instruction override, role manipulation)
- **Command injection** (`eval`, `exec`, `shell=True`, etc.)
- **Supply chain attacks** (`curl | bash`, dynamic imports)
- **Path manipulation** (root access, wildcards, path traversal)
- **Secret exposure** (hardcoded API keys, tokens, etc.)
- **External data fetch** (fetching content that may contain malicious instructions)
- **Privilege escalation** (excessive `allowed-tools` settings)
- **Dangerous commands** (`sudo`, `rm -rf`, etc.)
- **Insecure defaults** (`verify=False`, etc.)

## Installation

### 1. Place in Skills directory

```bash
# Install as Personal Skills (example paths)
cp -r skillshepard ~/.claude/skills/          # Claude Code
cp -r skillshepard ~/.agent/skills/           # Other agents

# Or install as Project Skills
cp -r skillshepard .claude/skills/
```

### 2. Requirements

- Python 3.10+

```bash
python3 --version  # Verify 3.10 or higher
```

## Usage

### Installing a Skill from GitHub

To install a Skill from a GitHub repository (e.g., [anthropics/skills/frontend-design](https://github.com/anthropics/skills/tree/main/skills/frontend-design)):

```
/skillshepard install https://github.com/anthropics/skills/tree/main/skills/frontend-design
```

SkillShepard will:
1. Fetch the Skill files from GitHub to a temporary directory (`/tmp/`)
2. Run security checks on the fetched files
3. Install the Skill to your skills directory if no blocking issues are found
4. The temporary files in `/tmp/` are automatically cleaned up by the system

### Basic Commands

```bash
# Install from GitHub URL
/skillshepard install https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Install from local path
/skillshepard install /path/to/new-skill/

# Scan only (don't install)
/skillshepard install --scan-only https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Japanese output
/skillshepard install --lang ja https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Batch scan all installed Skills
/skillshepard scan

# Show directory info
/skillshepard info
```

## Commands

| Command | Description | Output Format |
|---------|-------------|---------------|
| `install <path>` | Security check and install Skill | Markdown |
| `scan [directory]` | Batch scan existing Skills | JSON |
| `ignore add <skill>` | Add a Skill to ignore list | Text |
| `ignore remove <skill>` | Remove a Skill from ignore list | Text |
| `ignore list` | Show ignored Skills | Text |
| `info` | Show detected directory paths | Text |

## Options

| Option | Description |
|--------|-------------|
| `--scan-only` | Only scan, do not install (for `install` command) |
| `-y, --yes` | Skip confirmation prompt when overwriting existing Skill |
| `--skill-dir <path>` | Override auto-detected skills root directory |
| `-o, --output <file>` | Write output to file instead of stdout |
| `--lang, -l` | Output language (`en`: English, `ja`: Japanese) |
| `--global, -g` | Use global ignore list (for `ignore` command) |
| `--local, -L` | Use local ignore list (for `ignore` command, default) |
| `--directory, -d` | Target directory for local ignore list |

## Output Examples

### install (Markdown)

```markdown
# SkillShepard Security Report

## Summary
- Skill: example-skill
- Status: BLOCKED
- Issues Found: 2

## Issues
### [HIGH] Command Injection Risk
- File: scripts/run.py:42
- Code: `subprocess.Popen(cmd, shell=True)`
...
```

### scan (JSON)

```json
{
  "scan_date": "2026-01-15T10:30:00Z",
  "skills_scanned": 5,
  "issues_found": 3,
  "results": [
    {
      "skill_name": "example-skill",
      "path": "/path/to/skills/example-skill",
      "status": "warning",
      "issues": [...]
    }
  ]
}
```

### info (Text)

```
SkillShepard Directory Info
========================================
Script location:     /path/to/skills/skillshepard/scripts
Skill directory:     /path/to/skills/skillshepard
Skills root:         /path/to/skills
```

### ignore (Text)

```bash
# Add a Skill to ignore list (won't be scanned)
/skillshepard ignore add trusted-skill --global

# List ignored Skills
/skillshepard ignore list
# Output:
# Global ignore list:
#   - trusted-skill
#
# Local ignore list (/path/to/project):
#   (empty)

# Remove from ignore list
/skillshepard ignore remove trusted-skill --global
```

**Ignore List Locations:**
- **Global**: `skillshepard/scan-ignore.txt` (applies to all scans)
- **Local**: `<target-directory>/.claude/scan-ignore` (project-specific)

### Japanese Output (`--lang ja`)

```markdown
# SkillShepard セキュリティレポート

## 概要
- **Skill**: `example-skill`
- **ステータス**: 🚫 ブロック
- **検出された問題**: 2

## 検出された問題
### 1. [🔴 高] コマンドインジェクション
**ファイル**: `scripts/run.py` (行 42)
**推奨事項**: subprocess.run()をshell=Falseで使用し、引数をリストとして渡してください
```

## Security Checks

SkillShepard detects the following vulnerability categories, designed with reference to:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Agent Skills in the Wild (arXiv:2601.10338)](https://arxiv.org/abs/2601.10338) - Large-scale empirical study analyzing 42,447 Skills
- [Anthropic Agent Skills Documentation](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)

### High Severity (Blocks Import)

| Category | Description | Patterns |
|----------|-------------|----------|
| **Prompt Injection** | Agent behavior manipulation | `ignore previous instructions`, role override, delimiter attacks |
| **Command Injection** | Arbitrary code/command execution | `eval()`, `exec()`, `shell=True`, `os.system()` |
| **Supply Chain Risk** | Remote code execution | `curl \| bash`, dynamic imports, remote script execution |
| **Insecure Deserialization** | Arbitrary code execution via untrusted data | `pickle.load()`, `yaml.load()`, `marshal.load()` |
| **Secret Exposure** | Hardcoded credentials and API keys | OpenAI, Anthropic, AWS, GitHub, Stripe, etc. (30+ patterns) |
| **Path Manipulation** | Unauthorized file system access | Root access (`/`), wildcards (`**`), path traversal (`..`) |
| **Dangerous Commands** | System-level destructive operations | `sudo`, `rm -rf`, `chmod 777`, `mkfs` |

### Medium Severity (Warning)

| Category | Description | Patterns |
|----------|-------------|----------|
| **External Data Fetch** | Indirect prompt injection vector | `fetch()`, `requests.get().text`, dynamic URLs |
| **External Communication** | Data exfiltration risk | `http://`, `requests`, `curl`, `wget` |
| **Privilege Escalation** | Excessive permissions in SKILL.md | `allowed-tools: *`, `Bash(*)` |
| **Information Disclosure** | Sensitive data in logs | `print(password)`, `logging.*(secret)` |

### Low Severity (Informational)

| Category | Description | Patterns |
|----------|-------------|----------|
| **Insecure Defaults** | Security features disabled | `verify=False`, `debug=True` |
| **Dependency Risk** | Untrusted package sources | `pip install https://...`, `npm install git+...` |

For detailed patterns and recommendations, see [reference.md](skillshepard/reference.md).

## Workflow

### Example: Installing frontend-design Skill

```bash
# 1. Find a Skill you want to install (e.g., from Agent Skills directory)
#    https://github.com/anthropics/skills/tree/main/skills/frontend-design

# 2. Run skillshepard install with the GitHub URL
/skillshepard install https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Output:
# No security issues found.
# Installed: /Users/you/.claude/skills/frontend-design

# 3. The Skill is now ready to use!
/frontend-design
```

### Installing New Skills

1. Find a Skill (GitHub, Agent Skills directory, etc.)
2. Run `/skillshepard install <url-or-path>`
3. Review the security report if issues are found
4. Skill is installed automatically if no HIGH severity issues

### Auditing Installed Skills

Run `/skillshepard scan` periodically to check all installed Skills for vulnerabilities.

## License

MIT License

## Contributing

Issues and Pull Requests are welcome.

## Credits

- Logo generated by [Google Gemini](https://gemini.google.com/)
