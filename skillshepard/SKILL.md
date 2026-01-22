---
name: skillshepard
description: Security scanner for Skills. Use before importing new Skills or for batch auditing existing Skills.
allowed-tools: Read, Glob, Grep, Bash(python:*)
---

# SkillShepard - Skill Security Scanner

SkillShepard scans Skill definition files (SKILL.md, scripts, etc.) to detect security risks and quality issues.

## Usage

### 1. install - Security check and install (Primary)

Checks a new Skill for security issues and installs it if no blocking issues are found.

**Examples:**
```bash
# Install from GitHub URL (recommended)
/skillshepard install https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Install from local path
/skillshepard install /path/to/new-skill/

# Scan only (don't install)
/skillshepard install --scan-only https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Skip overwrite confirmation
/skillshepard install -y https://github.com/anthropics/skills/tree/main/skills/frontend-design

# Japanese output
/skillshepard install --lang ja https://github.com/anthropics/skills/tree/main/skills/frontend-design
```

**Options:**
- `--scan-only`: Only perform security scan, do not install
- `-y, --yes`: Skip confirmation prompt when overwriting existing Skill
- `-o, --output`: Save report to file
- `--lang, -l`: Output language (`en`: English, `ja`: Japanese)

**Process flow:**
1. Retrieve target Skill files
2. Run security checks
3. If HIGH severity issues found, generate Markdown report and abort installation
4. If no blocking issues, install Skill to skills directory
5. If Skill with same name exists, prompt for confirmation (skip with `-y`)

### 2. scan - Batch scan existing Skills

Scans an entire Skills directory and outputs results in JSON format.

**Examples:**
```
/skillshepard scan
/skillshepard scan /path/to/skills/
/skillshepard scan --lang ja  # Japanese output
```

**Process flow:**
1. Detect all Skills under the specified directory (or auto-detect)
2. Run security checks on each Skill
3. Output results in JSON format

### 3. info - Show directory info

Shows detected skill directory paths for debugging.

**Example:**
```
/skillshepard info
```

## Running Scans

Use the following script to run scans:

```bash
python ./scripts/scanner.py $ARGUMENTS
```

The scanner automatically detects its location and the skills root directory.

### Directory Auto-Detection

- `scan` command without arguments will auto-detect the skills root directory
- Use `--skill-dir` option to override the detected directory
- Use `info` command to see detected paths

## Check Items

See [reference.md](reference.md) for detailed check items.

### Main Check Categories

| Category | Description | Severity |
|----------|-------------|----------|
| Command Injection | Detection of `eval`, `exec`, `shell=True`, etc. | High |
| Path Manipulation | Overly broad file paths, path traversal | High |
| Secret Exposure | Hardcoded API keys, etc. | High |
| External Communication | Communication to suspicious domains | Medium |
| Privilege Escalation | Wildcard permissions, excessive privilege requests | Medium |
| Insecure Defaults | Dangerous default settings | Low |

## Output Formats

### install command (Markdown)

When blocking issues are detected, generates a report in the following format:

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
- Recommendation: Use subprocess.run() with shell=False and pass arguments as a list

...
```

### scan command (JSON)

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
      "issues": [
        {
          "severity": "high",
          "type": "command_injection",
          "file": "scripts/run.py",
          "line": 42,
          "message": "subprocess.Popen with shell=True detected",
          "code_snippet": "subprocess.Popen(cmd, shell=True)"
        }
      ]
    }
  ]
}
```
