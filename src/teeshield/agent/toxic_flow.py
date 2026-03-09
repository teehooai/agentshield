"""Toxic Flow detection -- dangerous tool capability combinations.

Two engines:
  v1 (keyword): Regex on SKILL.md text.  Fast, always available.
  v2 (AST):     Python ``ast`` analysis of source code.  Traces actual
                 function calls (open/requests.post/os.remove) inside each
                 function body and flags source→sink or source→destructive
                 combinations at the function level.

Classifies capabilities by role (data_source, public_sink, destructive)
and flags dangerous combinations indicating exfiltration or destructive flows.

Inspired by MCPhound TF analysis and Snyk ToxicSkills research.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

# --- Capability classification keywords ---

# Words/phrases indicating data access capabilities
DATA_SOURCE_KEYWORDS: list[tuple[str, str]] = [
    (r"\bread\s+file", "read file"),
    (r"\bfile\s+read", "file read"),
    (r"\blist\s+files", "list files"),
    (r"\blist\s+director", "list directory"),
    (r"\bfile\s+system", "filesystem"),
    (r"\bdatabase\b", "database"),
    (r"\bquery\b.*\b(table|sql|select|from)\b", "database query"),
    (r"\bsql\b", "SQL"),
    (r"\bget\s+env", "get env"),
    (r"\benviron", "environment variables"),
    (r"\bcredential", "credentials"),
    (r"\bsecret", "secrets"),
    (r"\bpassword", "password"),
    (r"\btoken\b", "token"),
    (r"\bapi.?key", "API key"),
    (r"\bssh\b.*\bkey", "SSH key"),
    (r"\bconfig\s+file", "config file"),
    (r"\b\.env\b", ".env file"),
    (r"\bkeychain", "keychain"),
    (r"\bclipboard", "clipboard"),
    (r"\bscreenshot", "screenshot"),
    (r"\bscrape\b", "scrape"),
    (r"\bcrawl\b", "crawl"),
]

# Words/phrases indicating external send capabilities
PUBLIC_SINK_KEYWORDS: list[tuple[str, str]] = [
    (r"\bsend\s+(email|mail|message|http|request|data)", "send data"),
    (r"\bpost\s+(to|data|message|request)", "post data"),
    (r"\bhttp\s*(post|put|patch)", "HTTP write"),
    (r"\bupload\b", "upload"),
    (r"\bwebhook", "webhook"),
    (r"\b(slack|discord)\b.*\b(send|post|message)", "messaging"),
    (r"\b(send|post)\b.*\b(slack|discord)\b", "messaging"),
    (r"\bemail\b.*\bsend", "email send"),
    (r"\bsend\b.*\bemail", "send email"),
    (r"\btweet\b", "tweet"),
    (r"\bpublish\b", "publish"),
    (r"\bforward\b.*\bto", "forward to"),
    (r"\bexport\b.*\b(to|external)", "export"),
    (r"\btransfer\b", "transfer"),
    (r"\bpaste\b.*\b(bin|service)", "paste service"),
    (r"\bpastebin", "pastebin"),
]

# Words/phrases indicating destructive capabilities
DESTRUCTIVE_KEYWORDS: list[tuple[str, str]] = [
    (r"\bdelete\s+file", "delete file"),
    (r"\bremove\s+file", "remove file"),
    (r"\brm\s+-", "rm command"),
    (r"\bdrop\s+(table|database|collection)", "drop table/db"),
    (r"\btruncate\s+(table|log)", "truncate"),
    (r"\boverwrite\b", "overwrite"),
    (r"\bformat\s+disk", "format disk"),
    (r"\bkill\s+(process|pid)", "kill process"),
    (r"\bshutdown\b", "shutdown"),
    (r"\breboot\b", "reboot"),
    (r"\bexec\b.*\bcommand", "exec command"),
    (r"\bshell\b.*\bexecut", "shell execute"),
    (r"\brun\s+command", "run command"),
    (r"\bmodify\s+(system|config|registry)", "modify system"),
    (r"\bchmod\b", "chmod"),
    (r"\bchown\b", "chown"),
    (r"\bwrite\s+file", "write file"),
]


@dataclass
class FlowClassification:
    """Result of classifying a skill's capabilities."""

    data_sources: list[str] = field(default_factory=list)
    public_sinks: list[str] = field(default_factory=list)
    destructive: list[str] = field(default_factory=list)

    @property
    def has_data_source(self) -> bool:
        return len(self.data_sources) > 0

    @property
    def has_public_sink(self) -> bool:
        return len(self.public_sinks) > 0

    @property
    def has_destructive(self) -> bool:
        return len(self.destructive) > 0


@dataclass
class ToxicFlow:
    """A detected dangerous capability combination."""

    flow_type: str  # "exfiltration" or "destructive"
    description: str
    sources: list[str]
    sinks: list[str]


def classify_capabilities(content: str) -> FlowClassification:
    """Classify a skill's capabilities from its SKILL.md content.

    Returns a FlowClassification with matched capability keywords.
    """
    result = FlowClassification()

    for pattern, label in DATA_SOURCE_KEYWORDS:
        if re.search(pattern, content, re.IGNORECASE):
            if label not in result.data_sources:
                result.data_sources.append(label)

    for pattern, label in PUBLIC_SINK_KEYWORDS:
        if re.search(pattern, content, re.IGNORECASE):
            if label not in result.public_sinks:
                result.public_sinks.append(label)

    for pattern, label in DESTRUCTIVE_KEYWORDS:
        if re.search(pattern, content, re.IGNORECASE):
            if label not in result.destructive:
                result.destructive.append(label)

    return result


def detect_toxic_flows(content: str) -> list[ToxicFlow]:
    """Detect dangerous capability combinations in skill content.

    Returns list of ToxicFlow findings (may be empty if safe).
    """
    classification = classify_capabilities(content)
    flows: list[ToxicFlow] = []

    # Flow 1: data_source → public_sink = exfiltration
    if classification.has_data_source and classification.has_public_sink:
        flows.append(ToxicFlow(
            flow_type="exfiltration",
            description=(
                f"Skill can read sensitive data ({', '.join(classification.data_sources[:3])}) "
                f"AND send externally ({', '.join(classification.public_sinks[:3])}). "
                f"Potential data exfiltration flow."
            ),
            sources=classification.data_sources,
            sinks=classification.public_sinks,
        ))

    # Flow 2: data_source → destructive = ransom/wipe
    if classification.has_data_source and classification.has_destructive:
        flows.append(ToxicFlow(
            flow_type="destructive",
            description=(
                f"Skill can access data ({', '.join(classification.data_sources[:3])}) "
                f"AND perform destructive actions ({', '.join(classification.destructive[:3])}). "
                f"Potential ransomware or data destruction flow."
            ),
            sources=classification.data_sources,
            sinks=classification.destructive,
        ))

    return flows


# ---------------------------------------------------------------------------
# v2: AST-level toxic flow detection for Python source code
# ---------------------------------------------------------------------------

# Qualified call patterns → (role, label)
# Matches are checked against `module.func` or `func` strings built from AST.
_AST_DATA_SOURCES: list[tuple[str, str]] = [
    ("open", "open()"),
    ("builtins.open", "open()"),
    ("Path.read_text", "Path.read_text()"),
    ("Path.read_bytes", "Path.read_bytes()"),
    ("pathlib.Path.read_text", "Path.read_text()"),
    ("pathlib.Path.read_bytes", "Path.read_bytes()"),
    ("os.environ.get", "os.environ.get()"),
    ("os.environ", "os.environ"),
    ("os.getenv", "os.getenv()"),
    ("dotenv.load_dotenv", "dotenv.load_dotenv()"),
    ("sqlite3.connect", "sqlite3.connect()"),
    ("cursor.execute", "cursor.execute()"),
    ("cursor.fetchall", "cursor.fetchall()"),
    ("cursor.fetchone", "cursor.fetchone()"),
    ("subprocess.run", "subprocess.run()"),
    ("subprocess.check_output", "subprocess.check_output()"),
    ("subprocess.Popen", "subprocess.Popen()"),
    ("json.load", "json.load()"),
    ("json.loads", "json.loads()"),
    ("yaml.safe_load", "yaml.safe_load()"),
    ("yaml.load", "yaml.load()"),
    ("configparser.ConfigParser", "ConfigParser()"),
    ("glob.glob", "glob.glob()"),
    ("os.listdir", "os.listdir()"),
    ("os.walk", "os.walk()"),
    ("Path.iterdir", "Path.iterdir()"),
    ("Path.glob", "Path.glob()"),
    ("Path.rglob", "Path.rglob()"),
    ("keyring.get_password", "keyring.get_password()"),
    ("getpass.getpass", "getpass.getpass()"),
]

_AST_PUBLIC_SINKS: list[tuple[str, str]] = [
    ("requests.post", "requests.post()"),
    ("requests.put", "requests.put()"),
    ("requests.patch", "requests.patch()"),
    ("httpx.post", "httpx.post()"),
    ("httpx.put", "httpx.put()"),
    ("httpx.AsyncClient.post", "httpx.post()"),
    ("urllib.request.urlopen", "urllib.urlopen()"),
    ("urllib.request.Request", "urllib.Request()"),
    ("aiohttp.ClientSession.post", "aiohttp.post()"),
    ("smtplib.SMTP", "smtplib.SMTP()"),
    ("smtplib.SMTP.sendmail", "smtplib.sendmail()"),
    ("socket.socket", "socket.socket()"),
    ("paramiko.SSHClient", "paramiko.SSHClient()"),
    ("slack_sdk.WebClient.chat_postMessage", "slack.post_message()"),
    ("boto3.client", "boto3.client()"),
    ("uploadfile", "upload_file()"),
]

_AST_DESTRUCTIVE: list[tuple[str, str]] = [
    ("os.remove", "os.remove()"),
    ("os.unlink", "os.unlink()"),
    ("os.rmdir", "os.rmdir()"),
    ("os.system", "os.system()"),
    ("shutil.rmtree", "shutil.rmtree()"),
    ("shutil.move", "shutil.move()"),
    ("Path.unlink", "Path.unlink()"),
    ("Path.rmdir", "Path.rmdir()"),
    ("Path.write_text", "Path.write_text()"),
    ("Path.write_bytes", "Path.write_bytes()"),
    ("subprocess.run", "subprocess.run()"),
    ("subprocess.call", "subprocess.call()"),
    ("os.chmod", "os.chmod()"),
    ("os.chown", "os.chown()"),
    ("os.kill", "os.kill()"),
    ("os.truncate", "os.truncate()"),
]


def _resolve_call(node: ast.Call) -> str:
    """Resolve an ast.Call node to a dotted name string (best-effort).

    Handles: ``os.remove()``, ``Path("x").read_text()``, ``open()``.
    For chained calls like ``Path("x").unlink()``, resolves to ``Path.unlink``.
    """
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts: list[str] = [func.attr]
        val = func.value
        while isinstance(val, ast.Attribute):
            parts.append(val.attr)
            val = val.value
        if isinstance(val, ast.Name):
            parts.append(val.id)
        elif isinstance(val, ast.Call):
            # Handle chained calls: Path("x").read_text() → Path.read_text
            inner = _resolve_call(val)
            if inner:
                # Take only the final name (e.g. "Path" from "pathlib.Path")
                parts.append(inner.rsplit(".", 1)[-1])
        return ".".join(reversed(parts))
    return ""


class _FlowVisitor(ast.NodeVisitor):
    """Walk a function body and collect classified call sites."""

    def __init__(self) -> None:
        self.sources: list[str] = []
        self.sinks: list[str] = []
        self.destructive: list[str] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        name = _resolve_call(node)
        if not name:
            self.generic_visit(node)
            return

        for pattern, label in _AST_DATA_SOURCES:
            if name == pattern or name.endswith("." + pattern):
                if label not in self.sources:
                    self.sources.append(label)
                break

        for pattern, label in _AST_PUBLIC_SINKS:
            if name == pattern or name.endswith("." + pattern):
                if label not in self.sinks:
                    self.sinks.append(label)
                break

        for pattern, label in _AST_DESTRUCTIVE:
            if name == pattern or name.endswith("." + pattern):
                if label not in self.destructive:
                    self.destructive.append(label)
                break

        self.generic_visit(node)

    # Also catch os.environ["KEY"] (subscript access, not a call)
    def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
        if isinstance(node.value, ast.Attribute):
            if (
                isinstance(node.value.value, ast.Name)
                and node.value.value.id == "os"
                and node.value.attr == "environ"
            ):
                label = "os.environ[]"
                if label not in self.sources:
                    self.sources.append(label)
        self.generic_visit(node)


def detect_toxic_flows_ast(source: str | Path) -> list[ToxicFlow]:
    """Detect toxic flows by parsing Python source code with AST.

    Analyses each function/method body independently.  If a single function
    contains both data-source calls and public-sink (or destructive) calls,
    it is flagged as a toxic flow.

    Args:
        source: Python source code string, or Path to a .py file.

    Returns:
        List of ToxicFlow findings (may be empty if safe).
    """
    if isinstance(source, Path):
        try:
            source = source.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    flows: list[ToxicFlow] = []

    # Collect functions and methods (top-level + nested in classes)
    func_nodes: list[tuple[str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_nodes.append((node.name, node))

    # Also analyse module-level code (statements outside functions)
    module_body = [
        n for n in tree.body
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    ]
    if module_body:
        # Create a synthetic module from top-level statements
        mod = ast.Module(body=module_body, type_ignores=[])
        func_nodes.append(("<module>", mod))

    for func_name, func_node in func_nodes:
        visitor = _FlowVisitor()
        visitor.visit(func_node)

        if visitor.sources and visitor.sinks:
            flows.append(ToxicFlow(
                flow_type="exfiltration",
                description=(
                    f"Function '{func_name}' reads data "
                    f"({', '.join(visitor.sources[:3])}) AND sends externally "
                    f"({', '.join(visitor.sinks[:3])}). "
                    f"Potential data exfiltration flow (AST analysis)."
                ),
                sources=visitor.sources,
                sinks=visitor.sinks,
            ))

        if visitor.sources and visitor.destructive:
            # Exclude self-contained patterns: subprocess.run is both
            # source and destructive, only flag when there is a DIFFERENT
            # data source beyond subprocess itself.
            non_subprocess_sources = [
                s for s in visitor.sources
                if "subprocess" not in s.lower()
            ]
            if non_subprocess_sources:
                flows.append(ToxicFlow(
                    flow_type="destructive",
                    description=(
                        f"Function '{func_name}' accesses data "
                        f"({', '.join(non_subprocess_sources[:3])}) AND performs "
                        f"destructive actions ({', '.join(visitor.destructive[:3])}). "
                        f"Potential data destruction flow (AST analysis)."
                    ),
                    sources=non_subprocess_sources,
                    sinks=visitor.destructive,
                ))

    return flows


def detect_toxic_flows_in_dir(directory: Path) -> list[ToxicFlow]:
    """Scan all Python files in a directory for AST-level toxic flows.

    Skips test files, __pycache__, .venv, node_modules, etc.
    """
    skip_dirs = {
        "node_modules", "__pycache__", ".venv", "venv", ".git",
        "dist", "build", ".tox", ".mypy_cache",
    }
    skip_file_re = re.compile(r"^test_|_test\.py$", re.IGNORECASE)

    flows: list[ToxicFlow] = []
    for py_file in directory.rglob("*.py"):
        if any(part in skip_dirs for part in py_file.parts):
            continue
        if skip_file_re.search(py_file.name):
            continue
        flows.extend(detect_toxic_flows_ast(py_file))
    return flows
