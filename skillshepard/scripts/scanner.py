#!/usr/bin/env python3
"""SkillShepard - Security scanner for Agent Skills"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from reporter import MarkdownReporter, JsonReporter
from i18n import I18n


def get_script_dir() -> Path:
    return Path(__file__).parent.resolve()


def get_skill_dir() -> Path:
    return get_script_dir().parent


def detect_skills_root() -> Optional[Path]:
    skills_root = get_skill_dir().parent
    return skills_root if skills_root.exists() else None


# ============ Ignore List Management ============

def get_global_ignore_path() -> Path:
    """Get the path to the global scan-ignore file (in skillshepard directory)."""
    return get_skill_dir() / 'scan-ignore.txt'


def get_local_ignore_path(directory: Path) -> Path:
    """Get the path to the local scan-ignore file (in target .claude directory)."""
    return directory / '.claude' / 'scan-ignore'


def load_ignore_list(directory: Optional[Path] = None) -> set[str]:
    """Load and merge global and local ignore lists."""
    ignored = set()

    # Load global ignore list
    global_path = get_global_ignore_path()
    if global_path.exists():
        for line in global_path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                ignored.add(line)

    # Load local ignore list
    if directory:
        local_path = get_local_ignore_path(directory)
        if local_path.exists():
            for line in local_path.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if line and not line.startswith('#'):
                    ignored.add(line)

    return ignored


def add_to_ignore(skill_name: str, is_global: bool, directory: Optional[Path] = None) -> bool:
    """Add a skill to the ignore list. Returns True if added, False if already exists."""
    if is_global:
        path = get_global_ignore_path()
    else:
        if directory is None:
            raise ValueError("directory is required for local ignore")
        path = get_local_ignore_path(directory)

    # Load existing entries
    existing = set()
    if path.exists():
        for line in path.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                existing.add(line)

    if skill_name in existing:
        return False

    # Ensure parent directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Check if file needs newline before appending
    needs_newline = False
    if path.exists() and path.stat().st_size > 0:
        content = path.read_text(encoding='utf-8')
        needs_newline = not content.endswith('\n')

    # Append to file
    with path.open('a', encoding='utf-8') as f:
        if needs_newline:
            f.write('\n')
        f.write(f'{skill_name}\n')

    return True


def remove_from_ignore(skill_name: str, is_global: bool, directory: Optional[Path] = None) -> bool:
    """Remove a skill from the ignore list. Returns True if removed, False if not found."""
    if is_global:
        path = get_global_ignore_path()
    else:
        if directory is None:
            raise ValueError("directory is required for local ignore")
        path = get_local_ignore_path(directory)

    if not path.exists():
        return False

    lines = path.read_text(encoding='utf-8').splitlines()
    new_lines = []
    found = False

    for line in lines:
        stripped = line.strip()
        if stripped == skill_name:
            found = True
        else:
            new_lines.append(line)

    if not found:
        return False

    path.write_text('\n'.join(new_lines) + ('\n' if new_lines else ''), encoding='utf-8')
    return True


def list_ignore(is_global: bool, directory: Optional[Path] = None) -> list[str]:
    """List skills in the ignore list."""
    if is_global:
        path = get_global_ignore_path()
    else:
        if directory is None:
            raise ValueError("directory is required for local ignore")
        path = get_local_ignore_path(directory)

    if not path.exists():
        return []

    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            result.append(line)
    return result


@dataclass
class Issue:
    severity: str
    type: str
    file: str
    line: Optional[int]
    message: str
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None


@dataclass
class ScanResult:
    skill_name: str
    path: str
    status: str
    issues: list[Issue] = field(default_factory=list)


@dataclass
class ScanReport:
    scan_date: str
    skills_scanned: int
    issues_found: int
    results: list[ScanResult] = field(default_factory=list)


class SecurityPatterns:
    # Command Injection
    COMMAND_INJECTION = [
        (r'\beval\s*\(', 'Dynamic code execution via eval()'),
        (r'\bexec\s*\(', 'Dynamic code execution via exec()'),
        (r'shell\s*=\s*True', 'Shell execution with shell=True'),
        (r'os\.system\s*\(', 'Command execution via os.system()'),
        (r'os\.popen\s*\(', 'Command execution via os.popen()'),
        (r'subprocess\.call\s*\([^)]*shell\s*=\s*True', 'subprocess.call() with shell=True'),
        (r'subprocess\.Popen\s*\([^)]*shell\s*=\s*True', 'subprocess.Popen() with shell=True'),
        (r'subprocess\.run\s*\([^)]*shell\s*=\s*True', 'subprocess.run() with shell=True'),
    ]

    # Path Manipulation
    PATH_MANIPULATION = [
        (r'["\']\/["\']', 'Root directory access'),
        (r'["\']\/\*["\']', 'Access to entire root directory'),
        (r'["\']\*\*["\']', 'Recursive wildcard'),
        (r'["\']\*\*\/\*["\']', 'Recursive wildcard'),
        (r'\.\./', 'Path traversal'),
        (r'\.\.\\', 'Path traversal (Windows)'),
    ]

    # Secrets
    SECRETS = [
        (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded API key'),
        (r'password\s*=\s*["\'][^"\']+["\']', 'Hardcoded password'),
        (r'secret\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded secret'),
        (r'token\s*=\s*["\'][^"\']{10,}["\']', 'Hardcoded token'),
        (r'Bearer\s+[A-Za-z0-9\-_]{20,}', 'Inline Bearer token'),
        # OpenAI
        (r'sk-[A-Za-z0-9]{20,}', 'OpenAI API key'),
        (r'sk-proj-[A-Za-z0-9]{20,}', 'OpenAI project API key'),
        # AWS
        (r'AKIA[A-Z0-9]{16}', 'AWS access key'),
        (r'ASIA[A-Z0-9]{16}', 'AWS temporary access key'),
        # GitHub
        (r'ghp_[A-Za-z0-9]{36,}', 'GitHub Personal Access Token'),
        (r'gho_[A-Za-z0-9]{36,}', 'GitHub OAuth token'),
        (r'ghu_[A-Za-z0-9]{36,}', 'GitHub user-to-server token'),
        (r'ghs_[A-Za-z0-9]{36,}', 'GitHub server-to-server token'),
        (r'ghr_[A-Za-z0-9]{36,}', 'GitHub refresh token'),
        # Slack
        (r'xox[baprs]-[A-Za-z0-9\-]{10,}', 'Slack token'),
        # Anthropic
        (r'sk-ant-[A-Za-z0-9\-]{20,}', 'Anthropic API key'),
        # Google
        (r'AIza[A-Za-z0-9\-_]{35}', 'Google API key'),
        # Stripe
        (r'sk_live_[A-Za-z0-9]{24,}', 'Stripe live secret key'),
        (r'sk_test_[A-Za-z0-9]{24,}', 'Stripe test secret key'),
        (r'pk_live_[A-Za-z0-9]{24,}', 'Stripe live publishable key'),
        (r'pk_test_[A-Za-z0-9]{24,}', 'Stripe test publishable key'),
        # Twilio
        (r'SK[a-f0-9]{32}', 'Twilio API key'),
        # SendGrid
        (r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}', 'SendGrid API key'),
        # Discord
        (r'[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}', 'Discord bot token'),
        # Private keys
        (r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----', 'Private key in file'),
        (r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----', 'OpenSSH private key'),
    ]

    # External Communication
    EXTERNAL_COMMUNICATION = [
        (r'http:\/\/(?!localhost|127\.0\.0\.1)', 'Unencrypted HTTP communication'),
        (r'requests\.(get|post|put|delete|patch)\s*\(', 'HTTP request'),
        (r'urllib\.request', 'Request via urllib'),
        (r'httpx\.(get|post|put|delete|patch)', 'httpx request'),
        (r'\bcurl\s+', 'curl command'),
        (r'\bwget\s+', 'wget command'),
    ]

    # Privilege Escalation (SKILL.md frontmatter)
    PRIVILEGE_ESCALATION = [
        (r'allowed-tools:\s*\*', 'Access to all tools allowed'),
        (r'allowed-tools:.*Bash\s*\(\s*\*\s*\)', 'Arbitrary Bash commands allowed'),
        (r'allowed-tools:.*Edit\s*\(\s*\*\s*\)', 'Arbitrary file editing allowed'),
        (r'allowed-tools:.*Write\s*\(\s*\*\s*\)', 'Arbitrary file writing allowed'),
    ]

    # Dangerous System Commands
    DANGEROUS_COMMANDS = [
        (r'\bsudo\s+', 'sudo command'),
        (r'\bsu\s+', 'su command'),
        (r'chmod\s+777', 'chmod 777 (full permissions)'),
        (r'rm\s+-rf\s+/', 'rm -rf / (dangerous deletion)'),
        (r'rm\s+-rf\s+\*', 'rm -rf * (dangerous deletion)'),
        (r'\bmkfs\b', 'mkfs (format)'),
        (r'>\s*/dev/', 'Write to /dev/'),
    ]

    # Insecure Defaults
    INSECURE_DEFAULTS = [
        (r'verify\s*=\s*False', 'SSL certificate verification disabled'),
        (r'disable[_-]?ssl', 'SSL disabled'),
        (r'debug\s*=\s*True', 'Debug mode enabled'),
        (r'CORS\s*\(\s*\*\s*\)', 'CORS allows all origins'),
        (r'Access-Control-Allow-Origin:\s*\*', 'Access allowed from all origins'),
    ]

    # Insecure Deserialization
    DESERIALIZATION = [
        (r'pickle\.load\s*\(', 'Insecure deserialization via pickle.load()'),
        (r'pickle\.loads\s*\(', 'Insecure deserialization via pickle.loads()'),
        (r'cPickle\.load', 'Insecure deserialization via cPickle'),
        (r'yaml\.load\s*\([^)]*\)', 'Potentially unsafe yaml.load() - use yaml.safe_load()'),
        (r'yaml\.unsafe_load', 'Unsafe YAML loading'),
        (r'marshal\.load', 'Insecure deserialization via marshal'),
        (r'shelve\.open', 'Insecure deserialization via shelve'),
        (r'jsonpickle\.decode', 'Insecure deserialization via jsonpickle'),
    ]

    # Information Disclosure
    INFORMATION_DISCLOSURE = [
        (r'print\s*\(\s*["\']?password', 'Potential password disclosure in print'),
        (r'print\s*\(\s*["\']?secret', 'Potential secret disclosure in print'),
        (r'print\s*\(\s*["\']?token', 'Potential token disclosure in print'),
        (r'print\s*\(\s*["\']?api[_-]?key', 'Potential API key disclosure in print'),
        (r'logging\.\w+\s*\([^)]*password', 'Potential password in log'),
        (r'logging\.\w+\s*\([^)]*secret', 'Potential secret in log'),
        (r'logging\.\w+\s*\([^)]*token', 'Potential token in log'),
        (r'console\.log\s*\([^)]*password', 'Potential password in console.log'),
        (r'console\.log\s*\([^)]*secret', 'Potential secret in console.log'),
        (r'console\.log\s*\([^)]*token', 'Potential token in console.log'),
    ]

    # Dependency Risk (Low)
    DEPENDENCY_RISK = [
        (r'pip\s+install\s+.*https?://', 'Installing package from URL'),
        (r'pip\s+install\s+.*git\+', 'Installing package from git URL'),
        (r'npm\s+install\s+.*https?://', 'Installing npm package from URL'),
        (r'npm\s+install\s+.*git\+', 'Installing npm package from git'),
    ]

    # Prompt Injection
    PROMPT_INJECTION = [
        # Instruction override attempts
        (r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)', 'Prompt injection: instruction override'),
        (r'disregard\s+(all\s+)?(previous|prior|above)', 'Prompt injection: disregard previous'),
        (r'forget\s+(everything|all)\s+(you|about)', 'Prompt injection: forget instructions'),
        (r'new\s+instructions?:', 'Prompt injection: new instruction marker'),
        (r'system\s*:\s*you\s+are', 'Prompt injection: system role override'),
        # Role manipulation
        (r'you\s+are\s+now\s+(a|an)\s+', 'Prompt injection: role reassignment'),
        (r'act\s+as\s+(if\s+)?(a|an)\s+', 'Prompt injection: role manipulation'),
        (r'pretend\s+(to\s+be|you\s+are)', 'Prompt injection: role pretending'),
        # Delimiter/boundary attacks
        (r'<\/?system>', 'Prompt injection: system tag'),
        (r'\[INST\]|\[\/INST\]', 'Prompt injection: instruction delimiter'),
        (r'###\s*(Human|Assistant|System):', 'Prompt injection: role delimiter'),
        # Output manipulation
        (r'respond\s+with\s+only', 'Prompt injection: output constraint'),
        (r'output\s+(only|exactly)', 'Prompt injection: output manipulation'),
    ]

    # External Data Fetch
    EXTERNAL_DATA_FETCH = [
        # URL fetching that could contain malicious instructions
        (r'fetch\s*\(\s*["\']https?://', 'External fetch from URL (potential prompt injection vector)'),
        (r'requests\.get\s*\(\s*[^)]*\)\s*\.text', 'Fetching external text content'),
        (r'requests\.get\s*\(\s*[^)]*\)\s*\.json', 'Fetching external JSON content'),
        (r'urllib\.request\.urlopen', 'URL open (external content fetch)'),
        (r'httpx\.(get|post)\s*\([^)]*\)\.text', 'httpx fetching external text'),
        # Dynamic URL construction
        (r'f["\']https?://.*\{', 'Dynamic URL construction'),
        (r'["\']https?://.*\'\s*\+', 'URL string concatenation'),
        (r'["\']https?://.*"\s*\+', 'URL string concatenation'),
        # WebFetch tool usage patterns
        (r'WebFetch\s*\(', 'WebFetch tool usage (external content)'),
    ]

    # Supply Chain
    SUPPLY_CHAIN = [
        # External script execution
        (r'curl\s+[^|]*\|\s*(bash|sh|python)', 'Pipe curl to shell (supply chain risk)'),
        (r'wget\s+[^|]*\|\s*(bash|sh|python)', 'Pipe wget to shell (supply chain risk)'),
        (r'curl\s+-s\s+.*\|\s*', 'Silent curl piped to command'),
        # Remote script sourcing
        (r'source\s+<\(curl', 'Sourcing remote script via curl'),
        (r'eval\s*\(\s*\$\(curl', 'Eval remote content via curl'),
        (r'python\s+-c\s+.*requests\.get', 'Python executing fetched content'),
        # Dynamic imports
        (r'__import__\s*\(\s*[^"\']+\)', 'Dynamic import with variable'),
        (r'importlib\.import_module\s*\([^"\']+\)', 'Dynamic module import'),
    ]


class SkillScanner:
    SCAN_EXTENSIONS = {'.py', '.js', '.ts', '.sh', '.bash', '.yaml', '.yml', '.json', '.md'}

    def __init__(self):
        self.patterns = SecurityPatterns()

    def scan_directory(self, directory: str, ignore_list: Optional[set[str]] = None) -> ScanReport:
        directory = Path(directory).expanduser().resolve()
        if not directory.exists():
            raise FileNotFoundError(f"Directory not found: {directory}")

        # Load ignore list if not provided
        if ignore_list is None:
            ignore_list = load_ignore_list(directory)

        results = [self._scan_skill(skill_dir) for skill_dir in self._find_skills(directory, ignore_list)]
        return ScanReport(
            scan_date=datetime.now().isoformat(),
            skills_scanned=len(results),
            issues_found=sum(len(r.issues) for r in results),
            results=results
        )

    def check_skill(self, path: str) -> ScanResult:
        path = Path(path).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")
        if path.is_file():
            path = path.parent
        return self._scan_skill(path)

    def _find_skills(self, directory: Path, ignore_list: Optional[set[str]] = None) -> list[Path]:
        skills = [skill_md.parent for skill_md in directory.rglob("SKILL.md")]
        if ignore_list:
            skills = [s for s in skills if s.name not in ignore_list]
        return skills

    def _scan_skill(self, skill_dir: Path) -> ScanResult:
        issues = []
        for ext in self.SCAN_EXTENSIONS:
            for file_path in skill_dir.rglob(f"*{ext}"):
                issues.extend(self._scan_file(file_path, skill_dir))

        high_count = sum(1 for i in issues if i.severity == 'high')
        medium_count = sum(1 for i in issues if i.severity == 'medium')
        status = 'blocked' if high_count else ('warning' if medium_count else 'ok')

        return ScanResult(skill_name=skill_dir.name, path=str(skill_dir), status=status, issues=issues)

    def _scan_file(self, file_path: Path, skill_dir: Path) -> list[Issue]:
        issues = []
        relative_path = str(file_path.relative_to(skill_dir))

        try:
            content = file_path.read_text(encoding='utf-8')
        except Exception:
            return issues

        lines = content.split('\n')

        # Check based on file type
        is_skill_md = file_path.name == 'SKILL.md'
        is_python = file_path.suffix == '.py'
        is_shell = file_path.suffix in {'.sh', '.bash'}
        is_js = file_path.suffix in {'.js', '.ts'}

        # Command Injection
        if is_python or is_shell or is_js:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.COMMAND_INJECTION,
                'command_injection', 'high',
                'Use subprocess.run() with shell=False and pass arguments as a list'
            ))

        # Path Manipulation
        issues.extend(self._check_patterns(
            lines, relative_path,
            self.patterns.PATH_MANIPULATION,
            'path_manipulation', 'high',
            'Limit path scope'
        ))

        # Secrets
        issues.extend(self._check_patterns(
            lines, relative_path,
            self.patterns.SECRETS,
            'secret_exposure', 'high',
            'Use environment variables (os.environ.get())'
        ))

        # External Communication
        if is_python or is_shell or is_js:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.EXTERNAL_COMMUNICATION,
                'external_communication', 'medium',
                'Verify external endpoints and use HTTPS'
            ))

        # Privilege Escalation (SKILL.md only)
        if is_skill_md:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.PRIVILEGE_ESCALATION,
                'privilege_escalation', 'medium',
                'Limit allowed-tools scope'
            ))

        # Dangerous System Commands
        if is_shell or is_python:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.DANGEROUS_COMMANDS,
                'dangerous_command', 'high',
                'Avoid dangerous system commands'
            ))

        # Insecure Defaults
        issues.extend(self._check_patterns(
            lines, relative_path,
            self.patterns.INSECURE_DEFAULTS,
            'insecure_default', 'low',
            'Enable security settings'
        ))

        # Insecure Deserialization (Python only)
        if is_python:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.DESERIALIZATION,
                'insecure_deserialization', 'high',
                'Use safe alternatives (e.g., yaml.safe_load(), json instead of pickle)'
            ))

        # Information Disclosure
        if is_python or is_js:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.INFORMATION_DISCLOSURE,
                'information_disclosure', 'medium',
                'Remove sensitive data from logs and output'
            ))

        # Dependency Risk
        if is_shell or is_python:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.DEPENDENCY_RISK,
                'dependency_risk', 'low',
                'Install packages from official registries with pinned versions'
            ))

        # Prompt Injection (all text files, especially SKILL.md and instructions)
        issues.extend(self._check_patterns(
            lines, relative_path,
            self.patterns.PROMPT_INJECTION,
            'prompt_injection', 'high',
            'Remove prompt injection patterns - these could manipulate agent behavior'
        ))

        # External Data Fetch (scripts that fetch external content)
        if is_python or is_js:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.EXTERNAL_DATA_FETCH,
                'external_data_fetch', 'medium',
                'External content may contain malicious instructions - validate and sanitize fetched data'
            ))

        # Supply Chain Risk
        if is_shell or is_python:
            issues.extend(self._check_patterns(
                lines, relative_path,
                self.patterns.SUPPLY_CHAIN,
                'supply_chain', 'high',
                'Avoid executing remote scripts - download, review, then execute locally'
            ))

        return issues

    def _check_patterns(self, lines, file_path, patterns, issue_type, severity, recommendation):
        issues = []
        for line_num, line in enumerate(lines, 1):
            for pattern, message in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(Issue(
                        severity=severity, type=issue_type, file=file_path, line=line_num,
                        message=message, code_snippet=line.strip()[:100], recommendation=recommendation
                    ))
        return issues


def main():
    parser = argparse.ArgumentParser(
        description='SkillShepard - Skill Security Scanner'
    )

    # Global options
    parser.add_argument(
        '--skill-dir',
        help='Skills root directory (auto-detected if not specified)',
        default=None
    )
    parser.add_argument(
        '--lang', '-l',
        choices=['en', 'ja'],
        default='en',
        help='Output language (en: English, ja: Japanese)'
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # install command (primary)
    install_parser = subparsers.add_parser('install', help='Security check and install Skill')
    install_parser.add_argument('path', help='Skill path to install')
    install_parser.add_argument('--scan-only', action='store_true', help='Only scan, do not install')
    install_parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    install_parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation for overwrite')

    # scan command
    scan_parser = subparsers.add_parser('scan', help='Batch scan existing Skills')
    scan_parser.add_argument(
        'directory',
        nargs='?',
        default=None,
        help='Target directory to scan (default: auto-detected skills root)'
    )
    scan_parser.add_argument('-o', '--output', help='Output file (default: stdout)')

    # info command
    info_parser = subparsers.add_parser('info', help='Show skill directory info')

    # ignore command
    ignore_parser = subparsers.add_parser('ignore', help='Manage scan ignore list')
    ignore_subparsers = ignore_parser.add_subparsers(dest='ignore_command', help='Ignore commands')

    # ignore add
    ignore_add_parser = ignore_subparsers.add_parser('add', help='Add a skill to ignore list')
    ignore_add_parser.add_argument('skill_name', help='Skill name to ignore')
    ignore_add_group = ignore_add_parser.add_mutually_exclusive_group()
    ignore_add_group.add_argument('--global', '-g', dest='is_global', action='store_true', help='Add to global ignore list')
    ignore_add_group.add_argument('--local', '-L', dest='is_local', action='store_true', help='Add to local ignore list (default)')
    ignore_add_parser.add_argument('--directory', '-d', help='Target directory for local ignore (default: current directory)')

    # ignore remove
    ignore_remove_parser = ignore_subparsers.add_parser('remove', help='Remove a skill from ignore list')
    ignore_remove_parser.add_argument('skill_name', help='Skill name to remove from ignore')
    ignore_remove_group = ignore_remove_parser.add_mutually_exclusive_group()
    ignore_remove_group.add_argument('--global', '-g', dest='is_global', action='store_true', help='Remove from global ignore list')
    ignore_remove_group.add_argument('--local', '-L', dest='is_local', action='store_true', help='Remove from local ignore list (default)')
    ignore_remove_parser.add_argument('--directory', '-d', help='Target directory for local ignore (default: current directory)')

    # ignore list
    ignore_list_parser = ignore_subparsers.add_parser('list', help='List ignored skills')
    ignore_list_group = ignore_list_parser.add_mutually_exclusive_group()
    ignore_list_group.add_argument('--global', '-g', dest='is_global', action='store_true', help='Show only global ignore list')
    ignore_list_group.add_argument('--local', '-L', dest='is_local', action='store_true', help='Show only local ignore list')
    ignore_list_parser.add_argument('--directory', '-d', help='Target directory for local ignore (default: current directory)')

    args = parser.parse_args()

    # Initialize i18n
    i18n = I18n(args.lang)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Handle info command
    if args.command == 'info':
        print(i18n.t('info_title'))
        print("=" * 40)
        print(f"{i18n.t('info_script_location')}:     {get_script_dir()}")
        print(f"{i18n.t('info_skill_directory')}:     {get_skill_dir()}")
        skills_root = detect_skills_root()
        if skills_root:
            print(f"{i18n.t('info_skills_root')}:         {skills_root}")
        else:
            print(f"{i18n.t('info_skills_root')}:         {i18n.t('info_not_detected')}")
        sys.exit(0)

    # Handle ignore command
    if args.command == 'ignore':
        if not args.ignore_command:
            ignore_parser.print_help()
            sys.exit(1)

        # Determine directory for local operations
        local_dir = Path(args.directory).resolve() if hasattr(args, 'directory') and args.directory else Path.cwd()

        if args.ignore_command == 'add':
            is_global = args.is_global
            if add_to_ignore(args.skill_name, is_global, local_dir):
                scope = i18n.t('ignore_scope_global') if is_global else i18n.t('ignore_scope_local')
                print(i18n.t('ignore_added', name=args.skill_name, scope=scope))
            else:
                print(i18n.t('ignore_already_exists', name=args.skill_name))
            sys.exit(0)

        elif args.ignore_command == 'remove':
            is_global = args.is_global
            if remove_from_ignore(args.skill_name, is_global, local_dir):
                scope = i18n.t('ignore_scope_global') if is_global else i18n.t('ignore_scope_local')
                print(i18n.t('ignore_removed', name=args.skill_name, scope=scope))
            else:
                print(i18n.t('ignore_not_found', name=args.skill_name))
            sys.exit(0)

        elif args.ignore_command == 'list':
            show_global = args.is_global or not args.is_local
            show_local = args.is_local or not args.is_global

            if show_global:
                print(i18n.t('ignore_list_global_header'))
                global_list = list_ignore(is_global=True)
                if global_list:
                    for skill in global_list:
                        print(f"  - {skill}")
                else:
                    print(f"  ({i18n.t('ignore_list_empty')})")
                print()

            if show_local:
                print(i18n.t('ignore_list_local_header', path=local_dir))
                local_list = list_ignore(is_global=False, directory=local_dir)
                if local_list:
                    for skill in local_list:
                        print(f"  - {skill}")
                else:
                    print(f"  ({i18n.t('ignore_list_empty')})")

            sys.exit(0)

    scanner = SkillScanner()

    try:
        if args.command == 'install':
            result = scanner.check_skill(args.path)
            reporter = MarkdownReporter(i18n)
            output = reporter.generate(result)

            # If issues found, output report and abort
            if result.status == 'blocked':
                if args.output:
                    Path(args.output).write_text(output, encoding='utf-8')
                    print(i18n.t('security_issues_found', path=args.output))
                else:
                    print(output)
                print(f"\n{i18n.t('installation_aborted')}")
                sys.exit(1)

            # If scan-only mode, just output result and exit
            if args.scan_only:
                if result.issues:
                    print(output)
                else:
                    print(i18n.t('no_issues_in', name=result.skill_name))
                sys.exit(0)

            # Proceed with installation
            skills_root = args.skill_dir or detect_skills_root()
            if skills_root is None:
                print(i18n.t('error_skills_dir_not_detected'), file=sys.stderr)
                sys.exit(1)

            skills_root = Path(skills_root)
            dest_path = skills_root / result.skill_name

            # Check if skill already exists
            if dest_path.exists():
                if not args.yes:
                    print(i18n.t('skill_exists', name=result.skill_name, path=dest_path))
                    response = input(i18n.t('overwrite_prompt')).strip().lower()
                    if response != 'y':
                        print(i18n.t('installation_cancelled'))
                        sys.exit(0)
                import shutil
                shutil.rmtree(dest_path)

            # Install skill
            import shutil
            source_path = Path(args.path).expanduser().resolve()
            if source_path.is_file():
                source_path = source_path.parent
            shutil.copytree(source_path, dest_path)

            # Output result
            if result.issues:
                print(output)
                print(f"\n{i18n.t('installed_with_warnings', path=dest_path)}")
            else:
                print(i18n.t('no_security_issues'))
                print(i18n.t('installed', path=dest_path))

            sys.exit(0)

        elif args.command == 'scan':
            # Use provided directory, --skill-dir, or auto-detect
            directory = args.directory
            if directory is None:
                directory = args.skill_dir or detect_skills_root()
            if directory is None:
                print(i18n.t('error_skills_dir_specify'), file=sys.stderr)
                sys.exit(1)

            report = scanner.scan_directory(str(directory))
            reporter = JsonReporter(i18n)
            output = reporter.generate(report)

        if args.output:
            Path(args.output).write_text(output, encoding='utf-8')
            print(i18n.t('report_saved', path=args.output))
        else:
            print(output)

    except FileNotFoundError as e:
        print(i18n.t('error_prefix', message=str(e)), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(i18n.t('error_prefix', message=str(e)), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
