# SecureIOMCP Design Document

**Date:** 2026-02-26
**Status:** Draft (Revised)
**Author:** Grant Mooney + Claude
**Revision:** 2 — addresses security review findings

> **Note:** The repository is currently named `SecureSearchMCP`. It should be renamed to `SecureIOMCP` to reflect the expanded scope (secure read-write I/O, not just search).

## Overview

SecureIOMCP is a TypeScript MCP server that provides AI agents with secure, token-efficient, read-write access to codebases. It sits between any MCP-compatible agent (Claude Code, Cursor, Copilot) and the filesystem, enforcing redaction, access control, and result sizing on every operation.

**Target audience:** Development teams using AI coding agents in security-conscious environments.

**Core goals (equal priority):**
- Prevent AI agents from seeing or exposing secrets (API keys, tokens, credentials, PII)
- Reduce token waste by returning only relevant, right-sized content
- Work with any MCP-compatible agent on Windows and Linux
- Provide audit trails and compliance tooling for government security teams

**Key constraints:**
- Pure JavaScript — zero external binary dependencies (no ripgrep)
- Security layer is not opt-in — every operation passes through it
- Denylist is extend-only — built-in protections cannot be disabled
- Default preset is `strict` — entropy detection enabled out of the box

## Threat Model

This section defines who and what SecureIOMCP defends against. The tool exists because AI agents are not trusted — they can be manipulated through prompt injection, make mistakes, and have no inherent concept of confidentiality.

### Threat Actors

1. **The AI agent itself** — Agents read files, follow instructions found in code comments, and may be manipulated by prompt injection embedded in source files. The agent is the primary consumer of every tool and the primary vector for data exposure.

2. **Malicious content in the codebase** — Source files, comments, README files, and configuration may contain instructions designed to manipulate the AI agent into exfiltrating secrets or performing unintended actions.

3. **Misconfigured projects** — Developers may commit secrets to repos, place credentials in non-standard locations, or configure `.gitignore` incorrectly.

4. **Compromised dependencies** — A malicious npm postinstall script could modify `.secureiorc` to weaken protections. The config system must be resilient to this.

### Attack Scenarios and Mitigations

| Scenario | Attack | Mitigation |
|---|---|---|
| Direct secret access | Agent calls `secure_read` on `.env` | Denylist blocks the file entirely |
| Indirect exfiltration via search | A code comment instructs the agent to `secure_search` for `DB_PASSWORD` to find secrets referenced in other files | Redaction engine catches secret values in search results. Search patterns themselves are not restricted — the defense is on the output, not the query. |
| Path traversal | Agent requests `../../etc/passwd` | Path resolver canonicalizes + jails to project root |
| Symlink escape | Symlink inside project points outside project root | `fs.realpath()` resolves before bounds check. On Windows, junction points are resolved via the same mechanism. |
| Config tampering | Malicious postinstall script modifies `.secureiorc` | System-level policy file (`~/.secureio/policy.json`) overrides project config and cannot be modified by the project |
| Audit log tampering | Agent calls `secure_write` on `.secureio/audit.log` | Audit log path is on the immutable denylist |
| Secret in write content | Agent hardcodes an API key in generated code | Write tools scan content with the same redaction engine and reject if secrets detected |
| Error message probing | Agent systematically triggers path errors to map filesystem | Error responses never expose resolved paths or project root — details logged server-side only |
| Encoded secrets | Secret is base64-encoded in a Kubernetes manifest | Entropy detection (strict preset, default) flags high-entropy strings regardless of encoding |
| Non-UTF-8 secret hiding | Secret stored in a UTF-16 file bypasses UTF-8 regex | Encoding detection + transcoding to UTF-8 before redaction (see Encoding Handling) |

### What This Tool Does NOT Defend Against

- **Agent memory/context** — Once content passes through the redaction layer, the agent has it in context. SecureIOMCP cannot prevent the agent from including redacted-but-memorized patterns in its responses to the user. The tool reduces exposure surface, it does not eliminate it.
- **Agent native file access** — If the agent also has direct filesystem tools (e.g., Claude Code's built-in Read tool), those bypass SecureIOMCP entirely. The tool is effective only when agents are configured to use it as their primary I/O interface.
- **Secrets in formats the redaction engine doesn't recognize** — The pattern library is finite. See the Limitations section.

## Limitations of the Redaction Engine

The redaction engine uses pattern matching and entropy detection. It is not omniscient. This section documents known gaps so security teams can make informed risk assessments.

### What It Catches (high confidence)
- Secrets with well-known prefixes: AWS keys (`AKIA...`), GitHub tokens (`ghp_...`, `ghs_...`), Stripe keys (`sk_live_...`), etc.
- Secrets assigned to obviously-named variables: `password = "..."`, `api_key = "..."`
- PEM private key blocks
- Connection strings with embedded credentials
- High-entropy strings (strict preset): catches unknown secret formats with Shannon entropy > 4.5

### What It May Miss (known gaps)
- Secrets assigned to non-obvious variable names (`config.db_conn = "..."`, `auth_header = "..."`)
- Base64-encoded secrets where the encoded form has lower entropy than the threshold
- Secrets split across multiple lines
- Secrets in binary or non-text formats (binary files are blocked entirely, which is the correct mitigation)
- Custom/proprietary secret formats not in the pattern library (mitigated by custom patterns in `.secureiorc` and entropy detection)
- Secrets embedded in URLs without a recognized scheme prefix

### Mitigation Strategy
The design uses defense in depth — no single layer is sufficient:
1. **File-level blocking** (denylist) — prevents access to known secret files entirely
2. **Pattern matching** — catches secrets with recognizable formats in allowed files
3. **Entropy detection** (strict, default) — catches unknown formats with high randomness
4. **Custom patterns** — allows security teams to add organization-specific detections
5. **Audit logging** — enables post-hoc detection of what was exposed

The false negative rate is nonzero and unknowable. This tool reduces secret exposure significantly but cannot eliminate it. Security teams should treat it as one layer in a defense-in-depth strategy, not a complete solution.

## Architecture

```
Agent (Claude Code / Cursor / Copilot)
  | MCP protocol (stdio transport)
SecureIOMCP Server
  +-- Tool Router (maps MCP tool calls to handlers)
  +-- Security Layer (middleware, wraps every operation)
  |   +-- Path Resolver (canonicalize, jail to project root)
  |   +-- Encoding Detector (BOM detection, transcode to UTF-8)
  |   +-- Access Control (gitignore-aware file filtering)
  |   +-- Redaction Engine (pattern + entropy-based secret detection)
  |   +-- Audit Logger (structured JSON, configurable output, tamper-protected)
  +-- Read Layer
  |   +-- Content Search (regex search across files)
  |   +-- File Glob (pattern-based file discovery)
  |   +-- Safe Read (file reading with redaction)
  |   +-- Directory Tree (structure overview)
  |   +-- Git Diff (redacted diffs)
  +-- Write Layer
  |   +-- Safe Write (file creation/overwrite with secret scanning)
  |   +-- Safe Patch (partial edit with secret scanning + optimistic locking)
  +-- Meta Layer
      +-- Audit Report (what would be redacted in this repo)
      +-- Project Overview (single-call project summary)
      +-- Self Test (validation suite for security teams)
```

**Data flow — reads:** Tool Router -> Security Layer (validate path, detect encoding, check access) -> Read Layer (execute operation) -> Security Layer (transcode if needed, redact output) -> Audit Logger -> Agent

**Data flow — writes:** Tool Router -> Security Layer (validate path, check access, scan content for secrets) -> reject if secrets found OR Write Layer (execute operation) -> Audit Logger -> Agent

## MCP Tools

### Read Tools

**1. `secure_search` — Content search across files**
- Params: `pattern` (regex), `path` (optional scope), `file_pattern` (glob filter), `context_lines` (default 2), `max_results` (default 50), `offset`
- Returns matching lines with surrounding context, file paths, line numbers
- Pagination: response includes `total_matches` and `has_more`
- Lines containing redacted content include `redacted: true` flag

**2. `secure_read` — Read a file with redaction**
- Params: `path`, `start_line`, `end_line` (optional range)
- Returns file content with secrets replaced by `[REDACTED:CATEGORY]`
- Hard cap at `maxFileReadLines` (default 500)
- Detects encoding via BOM; transcodes UTF-16LE/UTF-16BE to UTF-8 before redaction

**3. `secure_glob` — Find files by pattern**
- Params: `pattern` (glob), `path` (optional scope), `max_results`, `offset`
- Returns file paths + sizes only — no content
- Respects access control (never returns denied files)

**4. `secure_tree` — Directory structure overview**
- Params: `path`, `max_depth` (default 3)
- Returns compact tree with file counts per directory
- Skips `node_modules`, `.git`, `dist`, `build`, `vendor` by default

**5. `secure_diff` — Git diff with redaction**
- Params: `ref` (optional, defaults to working changes), `path` (optional scope)
- Returns redacted diffs scoped to specific paths
- Diff redaction algorithm:
  - Both `+` and `-` lines pass through the full redaction engine
  - If a diff hunk references a file on the denylist (e.g., diff shows `.env` was modified), the entire hunk is replaced with `[DIFF BLOCKED: denylist file]`
  - Diff headers showing denied file paths are replaced with `[REDACTED PATH]`

### Write Tools

**6. `secure_write` — Write file with secret scanning**
- Params: `path`, `content`
- Rejects if content contains detected secrets (returns pattern category + line number, not the secret itself)
- Blocks writing to protected paths (`.env`, `*.pem`, `.secureio/`, `.secureiorc`, etc.)
- Size limit: rejects content exceeding `maxWriteBytes` (default 256KB)
- Atomic write strategy:
  - Write to temp file in same directory (`.<name>.secureio.tmp`)
  - `fs.rename()` to target path
  - On Windows: retry rename up to 3 times with 100ms backoff if target is locked (handles Windows file locking semantics where `rename` fails if target is open)
- Returns success/failure + path only — no content echo

**7. `secure_patch` — Partial edit with validation**
- Params: `path`, `old_content`, `new_content`, `expected_hash` (optional optimistic lock)
- Scans `new_content` for secrets before applying
- Rejects if file changed since last read (hash mismatch) — returns current hash so agent can re-read without an extra round trip
- Size limit: `new_content` cannot exceed `maxWriteBytes`
- Returns the changed line range + new file hash after successful edit

### Meta Tools

**8. `secure_audit` — Security scan report**
- Params: `path` (optional scope), `verbose` (boolean)
- Reports: files that would be blocked, secrets that would be redacted, denylist rules in effect, active preset, custom patterns loaded
- Summary mode (default): counts by category (e.g., "3 files blocked, 7 secrets detected across 4 files")
- Verbose mode: file-by-file details with line numbers and pattern categories (but never the secret values themselves)
- Essential for security team sign-off

**9. `secure_overview` — Project summary in one call**
- Params: `path` (optional), `verbose` (boolean, default false)
- Default response: project name, framework, language, package manager, entry points, scripts, directory structure summary, config files detected, dependency counts (e.g., "12 dependencies, 8 devDependencies")
- Verbose mode: includes full dependency names and versions
- Dependency details are summarized by default because full dependency trees reveal attack surface information

Example response (default):
```json
{
  "project": {
    "name": "my-agency-app",
    "framework": "express",
    "language": "typescript",
    "packageManager": "npm",
    "entryPoints": ["src/index.ts"],
    "scripts": {
      "build": "tsc",
      "test": "jest",
      "start": "node dist/index.js"
    },
    "dependencyCount": 12,
    "devDependencyCount": 8,
    "structure": "src/ (42 files), tests/ (18 files), config/ (3 files)",
    "configFiles": ["tsconfig.json", ".eslintrc", "jest.config.ts"]
  }
}
```

**10. `secure_self_test` — Validation suite for security teams**
- Params: none
- Runs the redaction engine against a built-in corpus of known test secrets and verifies each is caught
- Tests path resolver against traversal attempts
- Tests denylist against known sensitive file patterns
- Tests encoding detection against UTF-8/UTF-16 fixtures
- Returns pass/fail per test category with details on any failures
- Allows security teams to verify the tool works before approving deployment
- Can be run via CLI: `npx secureio-mcp --self-test`

## Security Layer

### Path Resolver (anti-traversal)

The most security-critical component. A single bypass compromises everything.

- Canonicalizes all paths via `path.resolve()` + `fs.realpath()` (resolves symlinks and Windows junction points)
- Order of operations: resolve symlinks/junctions first, then apply denylist check, then apply bounds check. This prevents symlinks that point to denied paths from bypassing the denylist.
- Rejects any resolved path outside the project root — hard stop, no exceptions
- Blocks access to `.git/` internals (objects, refs — protects commit history secrets)
- Normalizes Windows backslashes and drive letters for cross-platform consistency
- Handles circular symlinks gracefully: `fs.realpath()` throws `ELOOP`, which is caught and returned as a path violation error

### Encoding Detection

- Before any redaction, files are checked for encoding via BOM (Byte Order Mark):
  - `0xFEFF` → UTF-16BE
  - `0xFFFE` → UTF-16LE
  - `0xEFBBBF` → UTF-8 (explicit BOM)
  - No BOM → assume UTF-8
- Non-UTF-8 files are transcoded to UTF-8 before redaction patterns are applied
- This prevents secrets in UTF-16 files from bypassing regex-based detection

### Access Control (file filtering)

- Parses `.gitignore` at project root + nested directories (uses `ignore` npm package)
- Explicitly does NOT parse `.git/info/exclude` or global gitignore (`core.excludesFile`) — only project-scoped ignore rules are used. Rationale: the tool's security posture should be deterministic from the project contents alone, not dependent on per-machine git configuration.
- Built-in immutable denylist (applies even without `.gitignore`, cannot be removed or overridden):
  - `.env`, `.env.*` — environment files
  - `*.pem`, `*.key`, `*.p12`, `*.pfx` — certificates and private keys
  - `credentials.json`, `secrets.yaml`, `*secret*` — common secret files
  - `.aws/`, `.ssh/`, `.gnupg/` — credential directories
  - `.secureio/` — audit logs and internal state (tamper protection)
  - `.secureiorc` — configuration file (prevent agent from reading/modifying security config)
- Denylist is extend-only — users add patterns in `.secureiorc` or system policy, never remove built-ins
- Write operations: blocks writing to any path on the denylist

### Redaction Engine (content filtering)

Runs on all text leaving the server (reads) and all text entering via writes. Applied after encoding detection and transcoding.

**Pattern library — organized by confidence level:**

High confidence (distinct prefixes, very low false positive rate):

| Pattern Name | Regex | Example |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| GitHub Token | `gh[ps]_[A-Za-z0-9_]{36,}` | `ghp_xxxx...` |
| GitHub Fine-Grained Token | `github_pat_[A-Za-z0-9_]{82,}` | `github_pat_xxxx...` |
| Stripe Live Key | `sk_live_[A-Za-z0-9]{24,}` | `sk_live_xxxx...` |
| Stripe Publishable Key | `pk_live_[A-Za-z0-9]{24,}` | `pk_live_xxxx...` |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | Slack incoming webhook URL |
| SendGrid Key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | `SG.xxxx.xxxx` |
| Twilio Auth Token | `SK[0-9a-f]{32}` | Twilio API key SID |
| Private Key Block | `-----BEGIN [A-Z ]+ PRIVATE KEY-----` | PEM headers |
| JWT | `eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+` | Full JWT with signature |

Medium confidence (context-dependent, may require anchoring):

| Pattern Name | Regex | Context Requirement | Example |
|---|---|---|---|
| AWS Secret Key | `(?<=aws_secret_access_key\s*[=:]\s*['"]?)[A-Za-z0-9/+=]{40}` | Must be in an assignment to a variable containing `aws_secret` | 40-char key after `aws_secret_access_key=` |
| Azure Storage Key | `(?<=AccountKey=)[A-Za-z0-9+/]{86}==` | Must follow `AccountKey=` literal | Azure connection string key portion |
| Connection String | `(mongodb\|postgres\|mysql\|redis\|amqp)://[^\s'"]+@[^\s'"]+` | Must contain `@` (credentials embedded) | `postgres://user:pass@host/db` |
| Generic API Key | `(?i)(api[_-]?key\|apikey\|secret[_-]?key\|auth[_-]?token)\s*[:=]\s*['"][^\s'"]{8,}['"]` | Must be assigned to a recognized variable name | `api_key = "abc123..."` |
| Generic Secret | `(?i)(password\|passwd\|token\|secret\|credential)\s*[:=]\s*['"][^\s'"]{8,}['"]` | Must be assigned to a recognized variable name | `password = "hunter2..."` |

Entropy-based detection (strict preset, enabled by default):

| Detection | Threshold | Conditions |
|---|---|---|
| High entropy string | Shannon entropy > 4.5 | String is 20+ chars, alphanumeric + special, not a known-safe pattern (UUIDs, hashes in comments, import paths) |

**Known-safe allowlist** (exempt from entropy detection to reduce false positives):
- UUID format: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
- Git commit SHAs: `[0-9a-f]{40}` when on a line with `commit`, `ref`, `sha`, or `hash`
- Import paths and URLs with recognized domain prefixes
- Hex-encoded hashes in lockfiles (package-lock.json, yarn.lock)

**Output format:** Matches are replaced with `[REDACTED:CATEGORY]` — e.g., `export AWS_KEY=[REDACTED:AWS_ACCESS_KEY]`

**Custom pattern precedence:** Custom patterns in `.secureiorc` always supplement built-in patterns. If a custom pattern has the same name as a built-in, the custom pattern is added alongside it (both run). Built-in patterns cannot be overridden or disabled.

### Audit Logger

Every tool invocation produces a structured JSON log entry:

```json
{
  "timestamp": "2026-02-26T10:30:00Z",
  "tool": "secure_read",
  "params": { "path": "src/config.ts" },
  "redactions": [
    { "line": 12, "category": "AWS_ACCESS_KEY", "confidence": "high" },
    { "line": 15, "category": "GENERIC_SECRET", "confidence": "medium" }
  ],
  "access_denied": false,
  "duration_ms": 23
}
```

- Default output: `.secureio/audit.log` (append-only)
- **Tamper protection:** `.secureio/` directory is on the immutable denylist — agents cannot read, write, or modify audit logs through any tool
- Configurable output: file path, stdout, or callback for SIEM integration
- Write operation params logged as content hashes, not plaintext
- Security events (path violations, access denials, secret-in-write rejections) are flagged with `"severity": "security"` for SIEM filtering
- **Log rotation:** configurable `maxAuditLogSizeMB` (default 50MB). When exceeded, current log is renamed with timestamp suffix and a new log is started. Old logs are retained (deletion is the responsibility of external log management).

## Configuration

### Layered Configuration (precedence, highest to lowest)

1. **CLI flags** — per-invocation overrides
2. **System policy** — `~/.secureio/policy.json` — security team controls, cannot be weakened by project config
3. **Project config** — `.secureiorc` in project root — developer customization
4. **Built-in defaults** — strict preset, immutable denylist

The system policy file is critical for enterprise deployment. It allows a security team to enforce organization-wide rules (minimum preset level, required denylist patterns, mandatory audit output) that individual projects cannot weaken. Projects can only make settings stricter than the system policy.

### System Policy (`~/.secureio/policy.json`)

```json
{
  "minimumPreset": "strict",
  "denylist": {
    "extend": ["*.tfvars", "*.tfstate", "agency-internal/**"]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "AGENCY_TOKEN",
        "pattern": "AGCY-[A-Z0-9]{32}",
        "description": "Internal agency auth token"
      }
    ]
  },
  "audit": {
    "required": true,
    "minimumOutput": "file"
  }
}
```

### Project Config (`.secureiorc`, JSON, project root, optional)

```json
{
  "preset": "strict",
  "projectRoot": ".",
  "denylist": {
    "extend": ["internal-certs/**", "deploy-keys/"]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "INTERNAL_TOKEN",
        "pattern": "PROJ-[A-Z0-9]{24}",
        "description": "Project-specific API token"
      }
    ]
  },
  "audit": {
    "output": "file",
    "path": ".secureio/audit.log"
  },
  "limits": {
    "maxResultCount": 100,
    "maxLineLength": 2000,
    "maxResponseBytes": 51200,
    "maxFileReadLines": 500,
    "maxWriteBytes": 262144,
    "maxTreeDepth": 4,
    "maxAuditLogSizeMB": 50
  }
}
```

### Presets

| | Standard | Strict (default) |
|---|---|---|
| Gitignore filtering | Yes | Yes |
| Built-in denylist | Yes | Yes |
| Pattern-based redaction | Yes | Yes |
| Entropy detection | No | Yes (Shannon > 4.5, 20+ chars) |
| Custom patterns | Optional | Optional |
| Write secret scanning | Yes | Yes |
| Write size limits | 256KB default | 128KB default |
| Response size limits | Generous defaults | Tighter defaults |
| Audit logging | File (can disable) | File (required, cannot disable) |

**Design rules:**
- No "off" preset — security layer cannot be disabled
- Denylist is extend-only — built-in rules are immutable
- `strict` is the default — `standard` is available for lower-security contexts where entropy false positives are unacceptable
- System policy `minimumPreset` prevents projects from downgrading below the organization's threshold
- Limits have floors and ceilings — `maxResponseBytes` cannot exceed 512KB, `maxWriteBytes` cannot exceed 1MB
- Config is optional — zero-config with `strict` preset works out of the box
- CLI flags override project config but cannot violate system policy

### CLI Flags

```bash
npx secureio-mcp                          # strict preset, default config
npx secureio-mcp --preset standard        # lower security (if system policy allows)
npx secureio-mcp --root /path/to/project  # custom project root
npx secureio-mcp --audit-output stdout    # pipe audit to SIEM
npx secureio-mcp --self-test              # run validation suite and exit
```

### Agent Configuration

```jsonc
// Claude Code - .claude/mcp.json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp"]
    }
  }
}

// Cursor - .cursor/mcp.json (same format)
```

## Token Efficiency

### Response Envelope

Every tool response uses a standard envelope:

```json
{
  "results": [],
  "meta": {
    "total": 234,
    "returned": 50,
    "offset": 0,
    "has_more": true,
    "truncated_lines": 3,
    "redactions": 2,
    "bytes": 12840
  }
}
```

The `meta` object costs ~50 tokens but saves thousands by telling agents exactly what they haven't seen, enabling strategic pagination.

### Response Size Limit Precedence

When multiple limits apply, the **first limit reached** stops the response:

1. `maxResultCount` — caps number of results/matches (default 50 for search, 100 for glob)
2. `maxLineLength` — truncates individual lines exceeding this length (default 2000 chars), appends `[TRUNCATED]`
3. `maxResponseBytes` — hard cap on total response payload (default 50KB). If reached mid-result, the current result is completed and `has_more` is set to true.

These limits interact independently. A search returning 10 results could hit `maxResponseBytes` before `maxResultCount` if individual matches have long context. The response always indicates which limit was the constraining factor in the `meta` object.

### Per-Tool Strategies

| Tool | Strategy | Token Savings |
|---|---|---|
| `secure_search` | Context lines default 2, max_results default 50, pagination | Focused matches, not file dumps |
| `secure_read` | Line-range support, hard cap at maxFileReadLines | Read a function, not a 3000-line file |
| `secure_glob` | Paths + sizes only, no content | ~10 tokens per result vs hundreds |
| `secure_tree` | Compact format, depth-limited, file counts | One call replaces 5+ recursive globs |
| `secure_diff` | Scoped to paths, defaults to working changes | Relevant changes only |
| `secure_write` | Returns success/failure + path only | No content echo |
| `secure_patch` | Returns changed line range + new hash | Minimal confirmation, no re-read needed |
| `secure_overview` | Single-call project summary, deps summarized by default | ~200 tokens vs ~2000 across 4 calls |
| `secure_audit` | Summary counts, detailed only on request | Overview first, drill down if needed |

### Built-in Noise Filters (always active)

- Skip binary files (detected via magic bytes in first 512 bytes)
- Skip files over 1MB (likely generated/minified)
- Skip `node_modules/`, `.git/`, `dist/`, `build/`, `vendor/` in search/glob unless explicitly targeted
- Collapse consecutive blank lines in read output
- Strip trailing whitespace

## Error Handling

### Structured Error Responses

Every failure returns actionable information **without leaking sensitive system details**:

```json
{
  "error": {
    "code": "PATH_DENIED",
    "message": "The requested path is not accessible",
    "suggestion": "Use secure_tree to discover available paths within the project."
  }
}
```

**Critical security rule:** Error responses to the agent never include:
- Resolved absolute paths
- Project root path
- Operating system details
- Internal file system structure outside the project

These details are logged server-side in the audit log (with `"severity": "security"`) for incident investigation but are never exposed to the agent.

### Error Categories

| Category | Example | Agent Response | Audit Log |
|---|---|---|---|
| Path denied | `../../etc/passwd`, symlink escape, denylist file | Generic "path not accessible" + suggestion | Full details: resolved path, denial reason, severity=security |
| Secret in write | Agent writes content containing API key | "Content rejected: secret detected on line N, category: AWS_ACCESS_KEY" (no secret value) | Content hash, matched pattern, severity=security |
| Invalid regex | `search("[invalid")` | Regex parse error with character position | Client error |
| File not found | Non-existent path | Error + fuzzy match suggestions from allowed files | Client error |
| Binary file | Reading image or compiled file | File type detected + size, suggest `secure_glob` | Not logged |
| Encoding unsupported | File with unrecognized encoding | "File encoding not supported, detected: [encoding]" | Warning |
| Size exceeded | Write content exceeds `maxWriteBytes` | "Content size N bytes exceeds limit of M bytes" | Warning |
| Hash mismatch | `secure_patch` on modified file | "File was modified since last read" + current hash | Normal |
| Response too large | 10K search matches | Truncate to limit, `has_more: true`, indicate constraining limit | Normal |

### Edge Cases

1. **Partial redaction** — When a search match contains a redacted secret, the result includes `"redacted": true` so agents know content is incomplete.

2. **Concurrent writes** — `secure_write` uses atomic write (temp file + rename, with retry on Windows). `secure_patch` uses optimistic locking via file hash — rejects with current hash if file changed since last read.

3. **Gitignore changes** — Access control re-parses `.gitignore` on every request. No caching. Costs milliseconds but ensures consistency.

4. **Empty projects** — `secure_overview` returns minimal response with directory structure and file type counts. Does not error.

5. **Massive repos (100K+ files)** — `secure_glob` and `secure_tree` use streaming enumeration with early termination at `max_results`. Never loads full directory listing into memory.

6. **Circular symlinks** — `fs.realpath()` throws `ELOOP`, caught and returned as a generic path denied error.

7. **Windows junction points** — Treated identically to symlinks: resolved via `fs.realpath()` before bounds and denylist checks.

8. **Diff of denylist files** — If `git diff` output references a file on the denylist, the entire hunk is replaced with `[DIFF BLOCKED: protected file]`. The file path in the diff header is replaced with `[REDACTED PATH]`.

## Testing Strategy

### Framework

- **Test runner:** Vitest (fast, TypeScript-native, ESM support, built-in coverage)
- **Assertion library:** Vitest built-in (`expect`)
- **Structure:** Tests mirror `src/` directory structure in `tests/`

### Test Categories

**1. Unit Tests (`tests/unit/`)**

Each security layer component is tested in isolation with comprehensive edge cases.

Path Resolver tests:
- Valid relative paths within project root resolve correctly
- `../` traversal attempts are rejected
- Deeply nested traversal (`../../../../...`) is rejected
- Symlinks pointing outside project root are rejected
- Symlinks pointing inside project root are allowed
- Circular symlinks return path denied error
- Windows junction points are resolved and checked
- Windows backslash normalization works
- Drive letter normalization (C: vs c:) works
- Null bytes in paths are rejected
- Unicode path components are handled

Access Control tests:
- `.gitignore` rules are respected
- Nested `.gitignore` files are parsed
- Immutable denylist entries cannot be bypassed
- Denylist extensions from `.secureiorc` are applied
- Denylist extensions from system policy are applied
- `.secureio/` directory is always denied
- `.secureiorc` is always denied
- Files allowed by `.gitignore` but on denylist are still denied

Redaction Engine tests:
- Each pattern in the library has at minimum 3 positive and 3 negative test cases
- Patterns are tested against the known-safe allowlist (UUIDs, git SHAs should not trigger)
- Entropy detection catches high-entropy strings
- Entropy detection does not flag known-safe patterns
- Custom patterns are applied alongside built-ins
- Multiple secrets on the same line are all redacted
- Redaction output format is correct (`[REDACTED:CATEGORY]`)
- Empty strings, single-character strings, and very long strings are handled
- UTF-8 content is redacted correctly
- Transcoded UTF-16 content is redacted correctly

Audit Logger tests:
- Log entries are valid JSON
- All required fields are present
- Security events have `"severity": "security"`
- Write params are logged as hashes, not plaintext
- Log rotation triggers at configured size threshold
- Timestamps are ISO 8601 UTC

Encoding Detector tests:
- UTF-8 with BOM detected correctly
- UTF-16LE with BOM detected correctly
- UTF-16BE with BOM detected correctly
- No BOM defaults to UTF-8
- Transcoded output matches expected UTF-8 content

**2. Integration Tests (`tests/integration/`)**

Tests that verify components work together through the full data flow pipeline.

Read pipeline tests:
- `secure_read` on a file with secrets returns redacted content
- `secure_read` on a denylist file returns path denied error
- `secure_search` across a test repo returns redacted matches with correct pagination
- `secure_glob` never returns denylist files
- `secure_tree` excludes default-skipped directories
- `secure_diff` on a diff containing secrets returns redacted diff
- `secure_diff` on a diff referencing a denylist file returns blocked hunk

Write pipeline tests:
- `secure_write` with clean content succeeds
- `secure_write` with secret content is rejected with correct error
- `secure_write` to denylist path is rejected
- `secure_write` exceeding size limit is rejected
- `secure_patch` with matching hash succeeds
- `secure_patch` with stale hash is rejected with current hash
- `secure_patch` with secret in new content is rejected
- Atomic write produces correct file content (no corruption)

Configuration tests:
- System policy overrides project config
- Project config cannot weaken system policy
- CLI flags override project config
- CLI flags cannot violate system policy
- Missing config files use defaults
- Malformed config files produce clear errors

**3. Security Tests (`tests/security/`)**

Dedicated test suite that validates security properties. These tests form the basis of the `--self-test` validation.

Secret corpus tests:
- A corpus of 100+ known secret formats (real format, fake values) is tested against the redaction engine
- Each secret format has a test case verifying it is caught
- Each test case documents which confidence level (high/medium/entropy) catches it
- False positive corpus: 100+ strings that look like secrets but aren't (UUIDs, hashes, encoded data) verified as not redacted (or correctly allowed through)

Traversal corpus tests:
- 50+ path traversal variations tested (encoded dots, null bytes, unicode normalization attacks, Windows-specific tricks like `CON`, `NUL`, `AUX` device names)

Error disclosure tests:
- Every error code is verified to not contain absolute paths
- Every error code is verified to not contain project root
- Every error code is verified to not contain OS-specific information

**4. Cross-Platform Tests (`tests/platform/`)**

Tests that verify Windows/Linux-specific behavior.

- Path separator handling (backslash vs forward slash)
- Case sensitivity (Windows is case-insensitive for paths)
- Atomic write retry logic on Windows
- Junction point resolution on Windows
- Long path handling (>260 chars on Windows)

**5. Performance Tests (`tests/performance/`)**

Not blocking for v1 but included to establish baselines.

- Search across a 10K-file synthetic repo completes within 30 seconds
- `secure_glob` on a 100K-entry directory returns within 5 seconds
- `secure_read` on a 10K-line file returns within 1 second
- Memory usage does not exceed 256MB during any single operation

### Test Fixtures (`tests/fixtures/`)

- `test-repo/` — A synthetic repository with known secrets planted in specific locations, various file types, nested directories, symlinks, and edge cases
- `secret-corpus.json` — Catalog of secret patterns with test values
- `false-positive-corpus.json` — Catalog of non-secret strings that resemble secrets
- `traversal-corpus.json` — Catalog of path traversal attack strings

### Coverage Requirements

- Minimum 90% line coverage on `src/security/` (path resolver, access control, redaction engine)
- Minimum 80% line coverage on `src/tools/` (MCP tool handlers)
- 100% coverage on the known-safe allowlist logic (false positive prevention)

### CI Pipeline

```yaml
# Runs on every PR and push to main
- npm run test:unit          # Fast, runs first
- npm run test:integration   # Medium, requires test fixtures
- npm run test:security      # The self-test corpus
- npm run test:platform      # Platform-specific (matrix: windows, linux)
- npm run test:coverage      # Fails if coverage thresholds not met
```

## Tech Stack

- **Runtime:** Node.js (TypeScript)
- **MCP SDK:** `@modelcontextprotocol/sdk` (TypeScript reference implementation)
- **Transport:** stdio (standard for local MCP servers)
- **Gitignore parsing:** `ignore` npm package
- **Search:** Pure JavaScript — `fs.createReadStream` + `readline` + regex (no ripgrep dependency)
- **Testing:** Vitest
- **Distribution:** npm (`npx secureio-mcp`)
- **No external binary dependencies** — critical for restricted environments with strict IT policies

## Decisions and Trade-offs

| Decision | Rationale |
|---|---|
| Pure JS search over ripgrep | Zero external deps. Restricted environments can't always install arbitrary binaries. Performance adequate for project-scale searches. |
| No symbol lookup in v1 | Regex-based heuristics are fragile and give wrong answers. `secure_search` with function names is more honest. |
| Extend-only denylist | Prevents misconfiguration from weakening security. Users can only make it stricter. |
| No "off" mode | If you don't want security, don't use the tool. Eliminates a class of misconfiguration. |
| stdio transport only | Simplest, most secure. No network exposure. All three target agents support it. |
| Strict as default preset | Security-conscious teams require maximum protection out of the box. Entropy detection false positives are acceptable — missed secrets are not. |
| System policy overrides project config | Security teams must be able to enforce organization-wide rules that developers cannot weaken. |
| Sanitized error responses | Preventing information disclosure (CWE-209) to agents that may be under prompt injection. Details go to audit log only. |
| Audit log on immutable denylist | Prevents agents from tampering with their own audit trail. |
| Context-anchored medium-confidence patterns | Reduces false positives on patterns like Azure keys and AWS secret keys that would otherwise match common base64 strings. |
| Vitest over Jest | Faster execution, native TypeScript/ESM support, better developer experience. Adequate ecosystem maturity. |
| Optimistic locking on patch | Prevents silent data loss from concurrent edits without requiring a lock server. |

## Future Considerations (not v1)

- Multi-root workspace support (monorepos)
- Language-aware symbol lookup (if demand warrants)
- Plugin system for custom tool extensions
- Remote MCP transport (SSE/HTTP) for centralized deployment
- Multi-line secret detection (regex patterns that span line boundaries)
- SARIF output format for `secure_audit` (integration with GitHub Advanced Security, Azure DevOps)
