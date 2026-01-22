# SkillShepard

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

```
/skillshepard install /path/to/new-skill/
/skillshepard install --scan-only /path/to/new-skill/
/skillshepard scan
/skillshepard info
```

## Commands

| Command | Description | Output Format |
|---------|-------------|---------------|
| `install <path>` | Security check and install Skill | Markdown |
| `scan [directory]` | Batch scan existing Skills | JSON |
| `info` | Show detected directory paths | Text |

## Options

| Option | Description |
|--------|-------------|
| `--scan-only` | Only scan, do not install (for `install` command) |
| `-y, --yes` | Skip confirmation prompt when overwriting existing Skill |
| `--skill-dir <path>` | Override auto-detected skills root directory |
| `-o, --output <file>` | Write output to file instead of stdout |

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

1. Find a new Skill
2. Run `skillshepard install` to check and install
3. If HIGH severity issues found, installation is blocked with a report
4. If no blocking issues, Skill is installed automatically
5. Periodically run `skillshepard scan` to audit installed Skills

## License

MIT License

## Contributing

Issues and Pull Requests are welcome.
