"""Edge case tests for security scanner pattern detection.

Each DANGEROUS_PATTERNS and TS_DANGEROUS_PATTERNS entry has:
- True positive (TP): code that SHOULD be flagged
- False positive (FP): code that should NOT be flagged

NOTE: When Semgrep is installed, it replaces regex for certain categories
(sql_injection, command_injection, dangerous_eval, child_process_injection,
ts_unsafe_eval, ts_sql_injection). Tests for those categories use regex-only
mode (monkeypatch SEMGREP_AVAILABLE=False) to test the regex patterns
independently of Semgrep availability.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from spidershield.scanner.security_scan import scan_security


def _scan_snippet(tmp_path: Path, code: str, filename: str = "server.py",
                  *, force_regex: bool = False) -> list[str]:
    """Write code to a file, scan it, return list of matched categories.

    If force_regex=True, disable Semgrep to test regex patterns directly.
    """
    (tmp_path / filename).write_text(code)
    if force_regex:
        with patch("spidershield.scanner.security_scan.SEMGREP_AVAILABLE", False):
            _, issues = scan_security(tmp_path)
    else:
        _, issues = scan_security(tmp_path)
    return [i.category for i in issues]


# ---------------------------------------------------------------------------
# Python patterns
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_tp_os_path_join_dotdot(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import os\nf = os.path.join(base, "..")')
        assert "path_traversal" in cats

    def test_tp_open_concat(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'open(base + user_input)')
        assert "path_traversal" in cats

    def test_fp_open_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'open("config.json")')
        assert "path_traversal" not in cats

    def test_fp_path_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'from pathlib import Path\nPath("/etc/hosts")')
        assert "path_traversal" not in cats


class TestCommandInjection:
    def test_tp_os_system_fstring(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import os\nos.system(f"echo {user}")',
                             force_regex=True)
        assert "command_injection" in cats

    def test_tp_subprocess_shell_true(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import subprocess\nsubprocess.run(cmd, shell=True)',
                             force_regex=True)
        assert "command_injection" in cats

    def test_fp_os_system_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import os\nos.system("echo hello")')
        assert "command_injection" not in cats

    def test_fp_subprocess_no_shell(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import subprocess\nsubprocess.run(["ls", "-la"])')
        assert "command_injection" not in cats


class TestDangerousEval:
    def test_tp_eval_variable(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'result = eval(user_input)',
                             force_regex=True)
        assert "dangerous_eval" in cats

    def test_tp_exec_variable(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'exec(code_string)',
                             force_regex=True)
        assert "dangerous_eval" in cats

    def test_fp_eval_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, "result = eval('1 + 2')")
        assert "dangerous_eval" not in cats

    def test_fp_method_execute(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'cursor.execute("SELECT 1")')
        assert "dangerous_eval" not in cats

    def test_fp_run_eval_function(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'def run_eval():\n    pass')
        assert "dangerous_eval" not in cats


class TestSqlInjection:
    def test_tp_fstring_select(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'q = f"SELECT * FROM users WHERE id={uid}"', force_regex=True)
        assert "sql_injection" in cats

    def test_tp_execute_fstring(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'cursor.execute(f"DELETE FROM logs WHERE id={x}")',
                             force_regex=True)
        assert "sql_injection" in cats

    def test_tp_execute_percent(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'cursor.execute("SELECT * FROM t WHERE id=%s" % uid)',
                             force_regex=True)
        assert "sql_injection" in cats

    def test_fp_parameterized_query(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'cursor.execute("SELECT * FROM t WHERE id=?", (uid,))')
        assert "sql_injection" not in cats

    def test_fp_string_with_sql_keyword(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'msg = "Please SELECT a valid option FROM the menu"')
        assert "sql_injection" not in cats


class TestHardcodedCredential:
    def test_tp_real_secret(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'api_key = "sk-abc123realkey789xyz"')
        assert "hardcoded_credential" in cats

    def test_fp_placeholder(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'api_key = "your_api_key_here"')
        assert "hardcoded_credential" not in cats

    def test_fp_example_value(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'token = "example-token-for-docs"')
        assert "hardcoded_credential" not in cats

    def test_fp_comment_line(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, '# api_key = "sk-abc123realkey789xyz"')
        assert "hardcoded_credential" not in cats

    def test_fp_short_value(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'password = "short"')
        assert "hardcoded_credential" not in cats


class TestUnsafeDeserialization:
    def test_tp_pickle_loads(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import pickle\npickle.loads(data)')
        assert "unsafe_deserialization" in cats

    def test_tp_yaml_unsafe(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import yaml\nyaml.unsafe_load(data)')
        assert "unsafe_deserialization" in cats

    def test_fp_yaml_safe_load(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import yaml\nyaml.safe_load(data)')
        assert "unsafe_deserialization" not in cats

    def test_fp_json_loads(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import json\njson.loads(data)')
        assert "unsafe_deserialization" not in cats


class TestSsrf:
    def test_tp_requests_get_url_var(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import requests\nrequests.get(url)')
        assert "ssrf" in cats

    def test_tp_httpx_post_endpoint(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import httpx\nhttpx.post(endpoint)')
        assert "ssrf" in cats

    def test_fp_requests_literal_url(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import requests\nrequests.get("https://api.example.com")')
        assert "ssrf" not in cats


class TestNoInputValidation:
    def test_tp_raw_str_param(self, tmp_path: Path) -> None:
        code = '@server.tool()\nasync def read(path: str):\n    return path'
        cats = _scan_snippet(tmp_path, code)
        assert "no_input_validation" in cats

    def test_fp_with_validation(self, tmp_path: Path) -> None:
        code = (
            '@server.tool()\nasync def read(path: str):\n'
            '    if not path or len(path) > 100:\n'
            '        return "error"\n    return path'
        )
        cats = _scan_snippet(tmp_path, code)
        assert "no_input_validation" not in cats


# ---------------------------------------------------------------------------
# New patterns (P4-1)
# ---------------------------------------------------------------------------


class TestUnsafePathResolution:
    def test_tp_path_read_text(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'from pathlib import Path\nPath(user_input).read_text()')
        assert "unsafe_path_resolution" in cats

    def test_tp_open_fstring(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'open(f"/data/{filename}")')
        assert "unsafe_path_resolution" in cats

    def test_fp_path_literal_read(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'from pathlib import Path\nPath("/etc/config").read_text()')
        assert "unsafe_path_resolution" not in cats

    def test_fp_path_string_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'from pathlib import Path\nPath("config.yaml").read_text()')
        assert "unsafe_path_resolution" not in cats


class TestAsyncShellInjection:
    def test_tp_create_subprocess_shell_fstring(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import asyncio\nawait asyncio.create_subprocess_shell(f"ls {path}")')
        assert "async_shell_injection" in cats

    def test_tp_create_subprocess_shell_variable(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import asyncio\nawait asyncio.create_subprocess_shell(cmd)')
        assert "async_shell_injection" in cats

    def test_fp_create_subprocess_exec(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import asyncio\nawait asyncio.create_subprocess_exec("ls", "-la")')
        assert "async_shell_injection" not in cats


class TestBasicAuthInUrl:
    def test_tp_http_auth_url(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'url = "http://admin:secret123@db.example.com/api"')
        assert "basic_auth_in_url" in cats

    def test_tp_https_auth_url(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'conn = "https://user:p4ssw0rd@host.com:5432/db"')
        assert "basic_auth_in_url" in cats

    def test_fp_comment_line(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, '# url = "http://user:pass@host.com"')
        assert "basic_auth_in_url" not in cats

    def test_fp_normal_url(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'url = "https://api.example.com/v1"')
        assert "basic_auth_in_url" not in cats


class TestTimingAttackComparison:
    def test_tp_password_equals(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'if password == user_password:\n    grant()')
        assert "timing_attack_comparison" in cats

    def test_tp_token_equals(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'if token == stored_token:\n    return True')
        assert "timing_attack_comparison" in cats

    def test_fp_password_is_none(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'if password == None:\n    return')
        assert "timing_attack_comparison" not in cats

    def test_fp_hmac_compare(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'import hmac\nhmac.compare_digest(token, stored)')
        assert "timing_attack_comparison" not in cats


# ---------------------------------------------------------------------------
# TS/JS patterns
# ---------------------------------------------------------------------------


class TestTsChildProcessInjection:
    def test_tp_exec_template(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'child_process.exec(`ls ${dir}`)', "server.ts",
                             force_regex=True)
        assert "child_process_injection" in cats

    def test_tp_execsync_variable(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'child_process.execSync(cmd)', "server.ts",
                             force_regex=True)
        assert "child_process_injection" in cats

    def test_fp_exec_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'child_process.exec("echo hello")', "server.ts")
        assert "child_process_injection" not in cats


class TestTsSqlInjection:
    def test_tp_query_template(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'db.query(`SELECT * FROM users WHERE id=${id}`)', "server.ts",
                             force_regex=True)
        assert "ts_sql_injection" in cats

    def test_fp_tagged_template(self, tmp_path: Path) -> None:
        # Tagged template literals (sql`...`) are safe parameterized queries
        cats = _scan_snippet(tmp_path, 'const q = sql`SELECT * FROM users`', "server.ts")
        assert "ts_sql_injection" not in cats


class TestTsPathTraversal:
    def test_tp_path_join_req_params(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'const p = path.join(base, req.params.file)', "server.ts")
        assert "ts_path_traversal" in cats

    def test_fp_path_join_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'const p = path.join(__dirname, "config")', "server.ts")
        assert "ts_path_traversal" not in cats


class TestTsAsyncInjection:
    def test_tp_spawn_shell_true(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'spawn("cmd", args, {shell: true})', "server.ts")
        assert "ts_async_injection" in cats

    def test_fp_spawn_no_shell(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'spawn("ls", ["-la"])', "server.ts")
        assert "ts_async_injection" not in cats


class TestTsUnsafeEval:
    def test_tp_new_function(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'const fn = new Function(code)', "server.ts",
                             force_regex=True)
        assert "ts_unsafe_eval" in cats

    def test_tp_eval_variable(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'const r = eval(userInput)', "server.ts",
                             force_regex=True)
        assert "ts_unsafe_eval" in cats

    def test_tp_vm_run(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'vm.runInNewContext(code, sandbox)', "server.ts",
                             force_regex=True)
        assert "ts_unsafe_eval" in cats

    def test_fp_eval_literal(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, "const r = eval('1+1')", "server.ts")
        assert "ts_unsafe_eval" not in cats

    def test_fp_method_with_eval_in_name(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'this.evaluateResult(data)', "server.ts")
        assert "ts_unsafe_eval" not in cats


class TestPrototypePollution:
    def test_tp_lodash_merge(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, '_.merge(config, req.body)', "server.ts")
        assert "prototype_pollution" in cats

    def test_tp_dynamic_property(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'obj[params[key]] = value', "server.ts")
        assert "prototype_pollution" in cats

    def test_fp_static_property(self, tmp_path: Path) -> None:
        cats = _scan_snippet(tmp_path, 'obj["name"] = "test"', "server.ts")
        assert "prototype_pollution" not in cats


class TestMultiLineDetection:
    """Regression tests for re.MULTILINE fix (FIX-1)."""

    def test_hardcoded_cred_not_on_line_1(self, tmp_path: Path) -> None:
        code = 'import os\n\napi_key = "sk-realSecretKeyThatIsLongEnough123"'
        cats = _scan_snippet(tmp_path, code)
        assert "hardcoded_credential" in cats

    def test_basic_auth_not_on_line_1(self, tmp_path: Path) -> None:
        code = 'import requests\nurl = "https://admin:s3cretP4ss@db.example.com/api"'
        cats = _scan_snippet(tmp_path, code)
        assert "basic_auth_in_url" in cats
