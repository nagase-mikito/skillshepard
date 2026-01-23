# SkillShepard Check Items Reference

References:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Agent Skills in the Wild (arXiv:2601.10338)](https://arxiv.org/abs/2601.10338)
- [Anthropic Agent Skills Documentation](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)

---

## High Severity

### Command Injection

| Pattern | Description |
|---------|-------------|
| `eval(`, `exec(` | Dynamic code execution |
| `shell=True` | Shell execution in subprocess |
| `os.system(`, `os.popen(` | Direct shell commands |

```python
# Bad
subprocess.Popen(f"ls {user_input}", shell=True)

# Good
subprocess.run(["ls", user_input], shell=False)
```

### Path Manipulation

| Pattern | Risk |
|---------|------|
| `"/"`, `"/*"` | Root directory access |
| `"**"`, `"**/*"` | Recursive wildcard |
| `../` | Path traversal |

### Secret Exposure

Detects hardcoded credentials: `api_key = "..."`, `password = "..."`, `token = "..."`, etc.

Provider-specific patterns: OpenAI (`sk-`), Anthropic (`sk-ant-`), AWS (`AKIA`), GitHub (`ghp_`), Stripe (`sk_live_`), and 20+ more.

### Insecure Deserialization

`pickle.load()`, `yaml.load()`, `marshal.load()` - Use `json.load()` or `yaml.safe_load()` instead.

### Dangerous Commands

`sudo`, `rm -rf /`, `chmod 777`, `mkfs`, `> /dev/`

### Prompt Injection

Detects attempts to manipulate agent behavior:
- `ignore previous instructions`, `disregard all previous`
- `you are now a`, `act as if`, `pretend to be`
- Delimiter attacks: `<system>`, `[INST]`, `### Human:`

This is one of the most critical risks in Agent Skills per [arXiv:2601.10338](https://arxiv.org/abs/2601.10338).

### Supply Chain

Remote code execution patterns:
- `curl ... | bash`, `wget ... | sh`
- `source <(curl ...)`
- Dynamic imports: `__import__(var)`

---

## Medium Severity

### External Communication

`http://`, `requests.get/post`, `curl`, `wget` - Verify endpoints and use HTTPS.

### External Data Fetch

Patterns that fetch content which may contain malicious instructions:
- `requests.get(...).text`, `requests.get(...).json()`
- Dynamic URL construction: `f"https://...{var}"`

Even trustworthy Skills can be compromised if external dependencies change.

### Privilege Escalation

SKILL.md frontmatter patterns:
- `allowed-tools: *`
- `allowed-tools: Bash(*)`
- `allowed-tools: Edit(*)`, `Write(*)`

### Information Disclosure

`print(password`, `logging.*(secret`, `console.log(token` - Remove sensitive data from output.

---

## Low Severity

### Insecure Defaults

`verify=False`, `debug=True`, `CORS(*)`, `Access-Control-Allow-Origin: *`

### Dependency Risk

`pip install https://...`, `npm install git+...` - Use official registries with pinned versions.

---

## Scan Targets

| File | Checks |
|------|--------|
| `SKILL.md` | Frontmatter permissions, prompt injection |
| `*.py` | All Python patterns |
| `*.js`, `*.ts` | Command injection, external fetch |
| `*.sh` | Dangerous commands, supply chain |
| `*.yaml`, `*.json` | Secrets, insecure defaults |

---

## Ignore List

You can exclude trusted Skills from scanning using the ignore list feature.

### Commands

```bash
# Add to ignore list
skillshepard ignore add <skill-name> [--global | --local]

# Remove from ignore list
skillshepard ignore remove <skill-name> [--global | --local]

# List ignored Skills
skillshepard ignore list [--global | --local]
```

### Ignore List Locations

| Scope | Location | Description |
|-------|----------|-------------|
| Global | `skillshepard/scan-ignore.txt` | Applies to all scans |
| Local | `<target>/.claude/scan-ignore` | Project-specific |

Both lists are merged when scanning. Skills matching either list are excluded.

### File Format

One Skill name per line. Lines starting with `#` are comments.

```
# Trusted internal Skills
my-trusted-skill
another-safe-skill
```
