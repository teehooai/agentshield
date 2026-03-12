"""Tests for the scanner module."""

from pathlib import Path

from spidershield.scanner.architecture_check import check_architecture
from spidershield.scanner.description_quality import score_descriptions
from spidershield.scanner.license_check import check_license
from spidershield.scanner.security_scan import scan_security


def test_license_check_mit(tmp_path: Path):
    """Test MIT license detection."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("MIT License\n\nPermission is hereby granted, free of charge...")
    name, ok = check_license(tmp_path)
    assert name == "MIT"
    assert ok is True


def test_license_check_gpl(tmp_path: Path):
    """Test GPL license detection (should not be fork-safe)."""
    license_file = tmp_path / "LICENSE"
    license_file.write_text("GNU General Public License version 3")
    name, ok = check_license(tmp_path)
    assert name == "GPL"
    assert ok is False


def test_license_check_missing(tmp_path: Path):
    """Test missing license."""
    name, ok = check_license(tmp_path)
    assert name is None
    assert ok is False


def test_security_scan_clean(tmp_path: Path):
    """Test scanning a clean file."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, issues = scan_security(tmp_path)
    assert score >= 8.0
    assert len(issues) == 0


def test_security_scan_sql_injection(tmp_path: Path):
    """Test detection of SQL injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def query(sql):\n    db.execute(f"SELECT * FROM {sql}")\n')
    score, issues = scan_security(tmp_path)
    assert score < 8.0
    assert any(i.category == "sql_injection" for i in issues)


def test_security_scan_command_injection(tmp_path: Path):
    """Test detection of command injection."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import os\ndef run(cmd):\n    os.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "command_injection" for i in issues)
    assert any(i.severity == "critical" for i in issues)


def test_security_scan_no_false_positive_environ(tmp_path: Path):
    """os.environ.get for secrets should NOT be flagged (it's the standard pattern)."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import os\napi_key = os.environ.get("API_KEY", "")\n')
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "hardcoded_credential" for i in issues)


def test_security_scan_hardcoded_secret(tmp_path: Path):
    """Hardcoded secret string SHOULD be flagged."""
    py_file = tmp_path / "server.py"
    py_file.write_text('api_key = "sk-1234567890abcdef"\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "hardcoded_credential" for i in issues)


def test_security_scan_unsafe_deserialization(tmp_path: Path):
    """pickle.load and yaml.load without SafeLoader should be flagged."""
    py_file = tmp_path / "server.py"
    py_file.write_text('import pickle\ndata = pickle.load(f)\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "unsafe_deserialization" for i in issues)


def test_security_scan_no_false_positive_str_param(tmp_path: Path):
    """Regular function with str param should NOT be flagged (only MCP tools)."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def helper(name: str):\n    return name.upper()\n')
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "no_input_validation" for i in issues)


def test_description_quality_good(tmp_path: Path):
    """Test scoring of a well-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def list_tables():
    """List all tables in the database.

    Use when the user wants to see available tables.
    Accepts `schema` parameter to filter by schema name.
    Example: Returns ['users', 'orders', 'products'].
    If the connection fails, check your database URL.
    """
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert len(names) == 1
    assert names[0] == "list_tables"
    assert tool_scores[0].has_action_verb is True
    assert tool_scores[0].has_scenario_trigger is True
    assert tool_scores[0].has_param_examples is True
    assert tool_scores[0].has_error_guidance is True
    assert tool_scores[0].has_param_docs is True
    assert tool_scores[0].overall_score >= 8.0


def test_description_quality_poor(tmp_path: Path):
    """Test scoring of a poorly-described tool."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def query(sql):
    """Execute a query."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert tool_scores[0].has_scenario_trigger is False
    assert tool_scores[0].has_param_examples is False
    assert tool_scores[0].overall_score < 4.0


def test_description_quality_minimal(tmp_path: Path):
    """Test that a bare-minimum description scores very low."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def do_thing():
    """Does a thing."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    # No verb start, no scenario, no examples, no error guidance, no param docs
    # Should score near 1.0-2.0, NOT 3.5
    assert tool_scores[0].overall_score < 2.5


def test_architecture_check(tmp_path: Path):
    """Test architecture quality checks."""
    # No tests, no error handling
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score, has_tests, has_error = check_architecture(tmp_path)
    assert has_tests is False
    assert has_error is False

    # Add a test file
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_server.py").write_text("def test_hello(): pass")
    score2, has_tests2, _ = check_architecture(tmp_path)
    assert has_tests2 is True
    assert score2 > score


def test_architecture_gradual_scoring(tmp_path: Path):
    """Architecture scoring should be gradual, not binary."""
    # Minimal server: no tests, no error handling, no README
    py_file = tmp_path / "server.py"
    py_file.write_text('def hello():\n    return "world"\n')
    score_bare, _, _ = check_architecture(tmp_path)

    # Add README (short)
    (tmp_path / "README.md").write_text("# Server\nA simple server.")
    score_readme, _, _ = check_architecture(tmp_path)
    assert score_readme > score_bare

    # Add 1 test file -> 1.0 for tests
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_a.py").write_text("def test_a(): pass")
    score_1test, _, _ = check_architecture(tmp_path)
    assert score_1test > score_readme

    # Add 5+ test files -> 3.0 for tests
    for i in range(5):
        (test_dir / f"test_{i}.py").write_text(f"def test_{i}(): pass")
    score_many_tests, _, _ = check_architecture(tmp_path)
    assert score_many_tests > score_1test


def test_security_ts_child_process(tmp_path: Path):
    """TypeScript child_process.exec should be flagged."""
    ts_file = tmp_path / "server.ts"
    ts_file.write_text('import { exec } from "child_process";\nexecSync(`ls ${dir}`);\n')
    score, issues = scan_security(tmp_path)
    assert any(i.category == "child_process_injection" for i in issues)


def test_security_ts_sql_template_literal(tmp_path: Path):
    """Template literal interpolation in SQL queries should be flagged."""
    ts_file = tmp_path / "db.ts"
    ts_file.write_text(
        "async function q(table: string) {\n"
        "  await pool.query(`SELECT * FROM ${table}`);\n}\n"
    )
    score, issues = scan_security(tmp_path)
    assert any(i.category == "ts_sql_injection" for i in issues)


def test_security_examples_excluded(tmp_path: Path):
    """Files in examples/ directory should not be scanned."""
    examples_dir = tmp_path / "examples"
    examples_dir.mkdir()
    py_file = examples_dir / "demo.py"
    py_file.write_text('import os\nos.system("ls")\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_no_false_positive_eval_in_name(tmp_path: Path):
    """Function names containing 'eval' (run_eval, do_evaluate) should NOT trigger."""
    py_file = tmp_path / "server.py"
    py_file.write_text('def run_eval(original, improved):\n    return True\n')
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "dangerous_eval" for i in issues)


def test_security_no_false_positive_sql_in_message(tmp_path: Path):
    """SQL keywords in f-string messages (not queries) should NOT trigger."""
    py_file = tmp_path / "server.py"
    py_file.write_text(
        'def warn():\n'
        '    msg = f"Block INSERT/UPDATE/DELETE/DROP by default"\n'
    )
    score, issues = scan_security(tmp_path)
    assert not any(i.category == "sql_injection" for i in issues)


def test_security_real_sql_injection_still_detected(tmp_path: Path):
    """Real SQL injection with full statement (SELECT...FROM) must still be caught."""
    py_file = tmp_path / "server.py"
    py_file.write_text(
        'def query(table):\n'
        '    db.execute(f"SELECT * FROM {table} WHERE id=1")\n'
    )
    score, issues = scan_security(tmp_path)
    assert any(i.category == "sql_injection" for i in issues)


# --- S1: Go tool extraction tests ---

def test_extract_go_newtool(tmp_path: Path):
    """Go MCP SDK: mcp.NewTool("name", mcp.WithDescription("..."))."""
    go_file = tmp_path / "server.go"
    go_file.write_text('''package main

import "github.com/mark3labs/mcp-go/mcp"

func main() {
    tool := mcp.NewTool("list_repos",
        mcp.WithDescription("List all repositories for the authenticated user"),
    )
    tool2 := mcp.NewTool("get_file",
        mcp.WithDescription("Get file contents from a repository"),
    )
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "list_repos" in names
    assert "get_file" in names
    assert len(names) == 2


def test_extract_go_tool_struct(tmp_path: Path):
    """Go: mcp.Tool{Name: "...", Description: "..."}."""
    go_file = tmp_path / "tools.go"
    go_file.write_text('''package tools

import "github.com/mark3labs/mcp-go/mcp"

var tools = []mcp.Tool{
    mcp.Tool{Name: "search_issues", Description: "Search for issues across repositories"},
    mcp.Tool{Name: "create_pr", Description: "Create a pull request in a repository"},
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "search_issues" in names
    assert "create_pr" in names


def test_extract_go_addtool(tmp_path: Path):
    """Go: server.AddTool("name", "description", handler)."""
    go_file = tmp_path / "main.go"
    go_file.write_text('''package main

func main() {
    s := server.NewMCPServer("grafana", "1.0")
    s.AddTool("query_dashboard", "Query a Grafana dashboard by UID", handleQuery)
    s.AddTool("list_alerts", "List all alert rules in Grafana", handleAlerts)
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "query_dashboard" in names
    assert "list_alerts" in names


def test_extract_go_tool_with_t_wrapper(tmp_path: Path):
    """Go: mcp.Tool{Name: "...", Description: t("KEY", "desc")} — github-mcp-server style."""
    go_file = tmp_path / "pkg" / "github" / "issues.go"
    go_file.parent.mkdir(parents=True)
    go_file.write_text('''package github

func IssueRead() {
    return NewTool(
        ToolsetMetadataIssues,
        mcp.Tool{
            Name:        "issue_read",
            Description: t("TOOL_ISSUE_READ_DESCRIPTION", "Get information about a specific issue in a GitHub repository."),
        },
        handler,
    )
}

func AddComment() {
    return NewTool(
        ToolsetMetadataIssues,
        mcp.Tool{
            Name:        "add_issue_comment",
            Description: t("TOOL_ADD_ISSUE_COMMENT_DESCRIPTION", `Add a comment to a specific issue
in a GitHub repository. Use this tool to add comments.`),
        },
        handler,
    )
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "issue_read" in names
    assert "add_issue_comment" in names
    assert len(names) == 2


def test_extract_go_test_files_excluded(tmp_path: Path):
    """Go test files (*_test.go) should NOT have tools extracted."""
    # Real tool in source file
    src_file = tmp_path / "server.go"
    src_file.write_text('''package main
func init() {
    s.AddTool("real_tool", "A real tool", handler)
}
''')
    # Fake tool in test file
    test_file = tmp_path / "server_test.go"
    test_file.write_text('''package main
func TestTool() {
    s.AddTool("test_tool", "A test fixture tool", handler)
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "real_tool" in names
    assert "test_tool" not in names


def test_extract_ts_test_files_excluded(tmp_path: Path):
    """TS test files (*.test.ts) should NOT have tools extracted."""
    src_file = tmp_path / "server.ts"
    src_file.write_text('''
server.tool("real_tool", "A real tool", {}, handler);
''')
    test_file = tmp_path / "server.test.ts"
    test_file.write_text('''
server.tool("test_tool", "A test fixture", {}, handler);
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "real_tool" in names
    assert "test_tool" not in names


def test_extract_py_test_files_excluded(tmp_path: Path):
    """Python test files (test_*.py) should NOT have tools extracted."""
    src_file = tmp_path / "server.py"
    src_file.write_text('''
@server.tool()
def real_tool():
    """A real tool."""
    pass
''')
    test_file = tmp_path / "test_server.py"
    test_file.write_text('''
@server.tool()
def fake_tool():
    """A test fixture tool."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "real_tool" in names
    assert "fake_tool" not in names


def test_extract_test_dir_excluded(tmp_path: Path):
    """Tools in tests/ directory should NOT be extracted."""
    src_file = tmp_path / "server.py"
    src_file.write_text('''
@server.tool()
def real_tool():
    """A real tool."""
    pass
''')
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "conftest.py"
    test_file.write_text('''
@server.tool()
def fixture_tool():
    """A test fixture."""
    pass
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "real_tool" in names
    assert "fixture_tool" not in names


# --- S1: Rust tool extraction tests ---

def test_extract_rust_tool_new(tmp_path: Path):
    """Rust: Tool::new("name", "description")."""
    rs_file = tmp_path / "tools.rs"
    rs_file.write_text('''
use mcp_sdk::Tool;

fn register_tools() {
    let tool1 = Tool::new("read_file", "Read the contents of a file at the given path");
    let tool2 = Tool::new("write_file", "Write content to a file at the given path");
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "read_file" in names
    assert "write_file" in names


def test_extract_rust_tool_attribute(tmp_path: Path):
    """Rust: #[tool(description = "...")] fn name(...)."""
    rs_file = tmp_path / "server.rs"
    rs_file.write_text('''
use mcp_derive::tool;

#[tool(description = "List all files in a directory")]
async fn list_files(path: &str) -> Result<Vec<String>> {
    Ok(vec![])
}

#[tool(description = "Delete a file at the given path")]
pub async fn delete_file(path: &str) -> Result<()> {
    Ok(())
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "list_files" in names
    assert "delete_file" in names


def test_extract_rust_tool_builder(tmp_path: Path):
    """Rust: ToolBuilder::new("name").description("...")."""
    rs_file = tmp_path / "main.rs"
    rs_file.write_text('''
fn register() {
    let tool = ToolBuilder::new("search_code")
        .description("Search for code patterns across the repository")
        .build();
}
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "search_code" in names


# --- S1: Improved TS extraction tests ---

def test_extract_ts_tool_with_string_description(tmp_path: Path):
    """TS: server.tool("name", "description", ...)."""
    ts_file = tmp_path / "server.ts"
    ts_file.write_text('''
const server = new McpServer("test");

server.tool("search_repos", "Search GitHub repositories by query", {
    query: z.string(),
}, async (args) => {
    return { content: [] };
});

server.tool("get_repo", "Get details of a specific GitHub repository", {
    owner: z.string(),
    repo: z.string(),
}, async (args) => {
    return { content: [] };
});
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "search_repos" in names
    assert "get_repo" in names


def test_extract_ts_zod_tool_definitions(tmp_path: Path):
    """TS: Zod-style tool definitions with name/description/parameters."""
    ts_file = tmp_path / "tools.ts"
    ts_file.write_text('''
const tools = [
    {
        name: "execute_query",
        description: "Execute a SQL query against the connected database",
        parameters: z.object({
            query: z.string(),
        }),
    },
    {
        name: "list_tables",
        description: "List all tables in the current database schema",
        parameters: z.object({}),
    },
];
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "execute_query" in names
    assert "list_tables" in names


# --- S1: README fallback extraction tests ---

def test_extract_tools_from_readme_list(tmp_path: Path):
    """Fallback: extract tools from README bullet list when code parsing fails."""
    readme = tmp_path / "README.md"
    readme.write_text('''# MCP Server

## Tools

- `search_files` - Search for files matching a pattern
- `read_file` - Read the contents of a file
- `write_file` - Write content to a file
- `list_directory` - List contents of a directory
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "search_files" in names
    assert "read_file" in names
    assert "write_file" in names
    assert "list_directory" in names


def test_extract_tools_from_readme_table(tmp_path: Path):
    """Fallback: extract tools from README markdown table."""
    readme = tmp_path / "README.md"
    readme.write_text('''# Terraform MCP Server

## Tools

| Tool | Description |
|------|-------------|
| plan | Run terraform plan on the current configuration |
| apply | Apply terraform changes to infrastructure |
| validate | Validate terraform configuration files |
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "plan" in names
    assert "apply" in names
    assert "validate" in names


def test_extract_tools_readme_not_used_when_code_found(tmp_path: Path):
    """README fallback should NOT be used when code extraction succeeds."""
    py_file = tmp_path / "server.py"
    py_file.write_text('''
@server.tool()
def real_tool():
    """The real tool from code."""
    pass
''')
    readme = tmp_path / "README.md"
    readme.write_text('''# Server
## Tools
- `fake_tool` - This should not appear
''')
    score, tool_scores, names = score_descriptions(tmp_path)
    assert "real_tool" in names
    assert "fake_tool" not in names


# --- S3: Scope limiting tests ---

def test_security_benchmarks_excluded(tmp_path: Path):
    """Files in benchmarks/ directory should not be scanned."""
    bench_dir = tmp_path / "benchmarks"
    bench_dir.mkdir()
    py_file = bench_dir / "bench_eval.py"
    py_file.write_text('import os\nos.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_fixtures_excluded(tmp_path: Path):
    """Files in fixtures/ directory should not be scanned."""
    fix_dir = tmp_path / "fixtures"
    fix_dir.mkdir()
    py_file = fix_dir / "vulnerable.py"
    py_file.write_text('import os\nos.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_vendor_excluded(tmp_path: Path):
    """Files in vendor/ directory should not be scanned."""
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    py_file = vendor_dir / "lib.py"
    py_file.write_text('import os\nos.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_dts_excluded(tmp_path: Path):
    """TypeScript .d.ts type definition files should not be scanned."""
    ts_file = tmp_path / "types.d.ts"
    ts_file.write_text('declare function eval(code: string): any;\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_go_test_excluded(tmp_path: Path):
    """Go test files (*_test.go) should not be scanned."""
    go_dir = tmp_path / "src"
    go_dir.mkdir()
    # _test.go files should be excluded by the filename filter
    test_file = go_dir / "handler_test.go"
    test_file.write_text('package main\n// os.system(cmd)\n')
    # test_ prefix files are excluded
    py_test = tmp_path / "test_handler.py"
    py_test.write_text('import os\nos.system(cmd)\n')
    score, issues = scan_security(tmp_path)
    assert len(issues) == 0


def test_security_monorepo_scoping(tmp_path: Path):
    """Monorepo: vulnerabilities in non-MCP code should be excluded when MCP dir exists."""
    # Create a large non-MCP SDK directory
    sdk_dir = tmp_path / "sdk"
    sdk_dir.mkdir()
    for i in range(60):
        (sdk_dir / f"module_{i}.py").write_text(
            f'def func_{i}():\n    return "safe"\n'
        )
    # Add a vulnerability in the SDK
    (sdk_dir / "dangerous.py").write_text('import os\nos.system(cmd)\n')

    # Create MCP server directory
    mcp_dir = tmp_path / "mcp-server"
    mcp_dir.mkdir()
    (mcp_dir / "server.py").write_text('def handle():\n    return "ok"\n')

    score, issues = scan_security(tmp_path)
    # The vulnerability in sdk/ should be scoped out since mcp-server/ exists
    assert not any(i.file.startswith("sdk") for i in issues)
