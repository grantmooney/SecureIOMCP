# SecureIOMCP

[![CI](https://github.com/grantmooney/SecureIOMCP/actions/workflows/ci.yml/badge.svg)](https://github.com/grantmooney/SecureIOMCP/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/secureio-mcp.svg)](https://www.npmjs.com/package/secureio-mcp)
[![Node.js](https://img.shields.io/node/v/secureio-mcp.svg)](https://nodejs.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure, token-efficient MCP server that provides AI agents with read-write codebase access while automatically redacting secrets, enforcing access controls, and maintaining audit trails. Built for development teams using AI coding agents (Claude Code, Cursor, Copilot).

---

## Features

- **Automatic secret redaction** -- 10 high-confidence and 5 medium-confidence patterns detect AWS keys, GitHub tokens, Stripe keys, JWTs, private key blocks, connection strings, and more. Entropy-based detection (Shannon > 4.5) catches unknown secret formats.
- **Immutable denylist** -- `.env`, `*.pem`, `*.key`, `credentials.json`, `.ssh/`, `.aws/`, and other sensitive paths are blocked by default and cannot be removed via configuration.
- **Path traversal prevention** -- All paths are resolved and jailed to the project root. Symlinks, junction points, null bytes, UNC paths, and Windows device names are all handled.
- **Write-side secret scanning** -- Content is scanned by the redaction engine before being written. Writes containing detected secrets are rejected.
- **Token-efficient responses** -- Pagination, result count limits, line truncation, and response byte caps minimize token usage. A standard response envelope with metadata enables strategic pagination.
- **Tamper-proof audit logging** -- Every tool invocation is logged as structured JSON. The `.secureio/` directory is on the immutable denylist, preventing agents from accessing their own audit trail.
- **Zero external binary dependencies** -- Pure JavaScript implementation with no dependency on ripgrep or other native binaries. Suitable for restricted environments.
- **Cross-platform** -- Tested on Linux and Windows (Node.js 20+ and 22+).
- **Organization-level system policy** -- `~/.secureio/policy.json` allows security teams to enforce organization-wide rules that individual projects cannot weaken.

---

## Quick Start

### Install

```bash
npm install -g secureio-mcp
# or run directly
npx secureio-mcp
```

**Prerequisites:** Node.js >= 20.0.0, git (required for `secure_diff`)

### Configure Your AI Agent

**Claude Code** (`.claude/mcp.json`):

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp"]
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp"]
    }
  }
}
```

### Restrict Native File Access

For best results, configure your AI agent to prefer SecureIOMCP tools over native file access tools. This ensures all file operations go through the security layer.

**Claude Code** — add to your project `CLAUDE.md`:

```markdown
## File Access Rules

- ALWAYS use secure_read instead of the Read tool or cat/head/tail
- ALWAYS use secure_search instead of the Grep tool or grep/rg
- ALWAYS use secure_glob instead of the Glob tool or find/ls
- ALWAYS use secure_write instead of the Write tool
- ALWAYS use secure_patch instead of the Edit tool or sed/awk
- ALWAYS use secure_diff instead of git diff
- ALWAYS use secure_tree instead of tree or ls -R
```

**Cursor** — add to `.cursor/rules`:

```
Always prefer SecureIOMCP tools (secure_read, secure_search, secure_glob, secure_write,
secure_patch, secure_diff, secure_tree) over native file access tools (Read, Grep, Glob,
Write, Edit, cat, grep, find, sed). These tools enforce secret redaction and access control.
```

**Copilot** — native tool restriction is not currently configurable. Copilot will select SecureIOMCP tools based on tool descriptions when they are a better fit.

### Verify Installation

```bash
npx secureio-mcp --self-test
```

Runs the built-in security validation suite and exits with code 0 on success.

---

## CLI Reference

```
secureio-mcp [options]

Options:
  --preset <strict|standard>          Security preset (default: strict)
  --root <path>                       Project root directory (default: cwd)
  --audit-output <file|stderr|none>   Audit log destination (default: file)
  --self-test                         Run security validation suite and exit
  -h, --help                          Show help message
```

---

## MCP Tools

SecureIOMCP provides 10 MCP tools organized into three categories.

### Read Tools

#### `secure_read`

Read a file with automatic secret redaction.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | File path relative to project root |
| `start_line` | number | No | Starting line number (1-indexed) |
| `end_line` | number | No | Ending line number |

```json
{
  "results": {
    "path": "src/config.ts",
    "content": "export const API_KEY = [REDACTED:GENERIC_API_KEY];\n...",
    "start_line": 1,
    "end_line": 50,
    "total_lines": 120,
    "redacted_lines": [3],
    "encoding_detected": "utf-8"
  },
  "meta": { "total": 120, "returned": 50, "has_more": true, "redactions": 1 }
}
```

#### `secure_search`

Search across files with regex pattern matching and redaction.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | string | Yes | Regex pattern to search for |
| `path` | string | No | Scope search to subdirectory |
| `file_pattern` | string | No | File glob filter (e.g., `*.ts`) |
| `context_lines` | number | No | Context lines around match (default: 2) |
| `max_results` | number | No | Maximum results to return |
| `offset` | number | No | Offset for pagination |

```json
{
  "results": [
    {
      "file": "src/db.ts",
      "line": 15,
      "content": "const conn = [REDACTED:CONNECTION_STRING];",
      "context_before": ["// Database setup", ""],
      "context_after": ["const pool = createPool(conn);"],
      "redacted": true
    }
  ],
  "meta": { "total": 3, "returned": 3, "has_more": false, "redactions": 1 }
}
```

#### `secure_glob`

Find files by glob pattern, respecting access control.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | string | Yes | Glob pattern to match files |
| `path` | string | No | Scope search to subdirectory |
| `max_results` | number | No | Maximum results to return |
| `offset` | number | No | Offset for pagination |

```json
{
  "results": [
    { "path": "src/index.ts", "size": 1234 },
    { "path": "src/server.ts", "size": 2345 }
  ],
  "meta": { "total": 42, "returned": 42, "has_more": false }
}
```

#### `secure_tree`

Get directory structure with file counts.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Root directory for the tree |
| `max_depth` | number | No | Maximum depth to traverse |

```json
{
  "results": {
    "name": "project",
    "type": "directory",
    "children": [
      { "name": "src", "type": "directory", "file_count": 12, "children": [...] },
      { "name": "package.json", "type": "file" }
    ],
    "file_count": 3
  }
}
```

#### `secure_diff`

Get redacted git diff output.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ref` | string | No | Git ref to diff against |
| `path` | string | No | Scope diff to this path |

```json
{
  "results": {
    "diff": "diff --git a/src/app.ts b/src/app.ts\n...",
    "files_changed": 2,
    "redacted_hunks": 0
  }
}
```

Diffs referencing files on the denylist are replaced with `[DIFF BLOCKED: protected file]` and their paths with `[REDACTED PATH]`.

### Write Tools

#### `secure_write`

Write a file with secret scanning. Rejects content containing detected secrets.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | File path relative to project root |
| `content` | string | Yes | File content to write |

```json
{
  "results": {
    "path": "src/utils.ts",
    "success": true,
    "hash": "a1b2c3d4..."
  }
}
```

Uses atomic writes (temp file + rename) with retry logic for Windows file locking.

#### `secure_patch`

Partial file edit with optimistic locking and secret scanning.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | Yes | File path relative to project root |
| `old_content` | string | Yes | Content to find and replace |
| `new_content` | string | Yes | Replacement content |
| `expected_hash` | string | No | SHA-256 hash for optimistic locking |

```json
{
  "results": {
    "path": "src/utils.ts",
    "success": true,
    "changed_range": { "start": 10, "end": 15 },
    "hash": "e5f6g7h8..."
  }
}
```

If `expected_hash` is provided and the file has changed since last read, returns `HASH_MISMATCH` with the current hash.

### Meta Tools

#### `secure_audit`

Security scan report showing blocked files and detected secrets.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Scope audit to subdirectory |
| `verbose` | boolean | No | Include per-file details (paginated) |
| `offset` | number | No | Number of detail entries to skip (verbose mode only) |
| `max_results` | number | No | Maximum detail entries to return (verbose mode only) |

Summary counts (`files_blocked`, `secrets_detected`, `files_with_secrets`) always reflect the full scan regardless of pagination. Only the `details` array is paginated.

```json
{
  "results": {
    "preset": "strict",
    "files_blocked": 3,
    "secrets_detected": 7,
    "files_with_secrets": 4,
    "denylist_rules": 0,
    "custom_patterns": 0
  }
}
```

In verbose mode, includes `details` array with per-file breakdown of blocked status and redaction locations.

#### `secure_overview`

Project summary in a single call: framework, language, dependencies, structure.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Project root to analyze |
| `verbose` | boolean | No | Include full dependency names |

```json
{
  "results": {
    "name": "my-app",
    "framework": "express",
    "language": "typescript",
    "packageManager": "npm",
    "entryPoints": ["dist/index.js"],
    "scripts": { "build": "tsc", "test": "vitest run" },
    "dependencyCount": 12,
    "devDependencyCount": 8,
    "structure": "src/\n  (15 files)\ntests/\n  (10 files)",
    "configFiles": ["package.json", "tsconfig.json"]
  }
}
```

#### `secure_self_test`

Run the security validation suite to verify deployment integrity.

No parameters. Returns pass/fail results for four test categories:

| Category | Tests |
|----------|-------|
| `pattern_detection` | Validates known secret formats are caught |
| `traversal_prevention` | Validates path traversal attacks are blocked |
| `denylist_enforcement` | Validates sensitive file patterns are denied |
| `false_positive_prevention` | Validates safe strings are not flagged |

```bash
npx secureio-mcp --self-test
```

---

## Security Model

### Architecture

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
  |   +-- Audit Logger (structured JSON, tamper-protected)
  +-- Read Layer (secure_read, secure_search, secure_glob, secure_tree, secure_diff)
  +-- Write Layer (secure_write, secure_patch)
  +-- Meta Layer (secure_audit, secure_overview, secure_self_test)
```

**Data flow (reads):** Tool Router -> Security Layer (validate path, detect encoding, check access) -> Read Layer (execute) -> Security Layer (transcode, redact output) -> Audit Logger -> Agent

**Data flow (writes):** Tool Router -> Security Layer (validate path, check access, scan content for secrets) -> reject if secrets found OR Write Layer (execute) -> Audit Logger -> Agent

### Defense in Depth

The security layer cannot be disabled. Every request and response flows through it.

1. **File-level blocking** (denylist) -- prevents access to known sensitive files entirely
2. **Pattern matching** -- catches secrets with recognizable formats in allowed files
3. **Entropy detection** (strict preset, default) -- catches unknown formats with high randomness
4. **Custom patterns** -- organization-specific detections via `.secureiorc` or system policy
5. **Audit logging** -- enables post-hoc detection of what was exposed

### Threat Model

**Defends against:**
- AI agents reading secrets from `.env`, `*.pem`, credential files
- Indirect exfiltration via search results (redaction engine catches secrets in output)
- Path traversal attacks (`../../etc/passwd`, symlink escapes, junction points)
- Configuration tampering by compromised dependencies (system policy overrides project config)
- Audit log tampering (`.secureio/` is on the immutable denylist)
- Secrets in AI-generated write content (content scanning before writes)
- Error message probing for filesystem structure (CWE-209 prevention)
- Encoded secrets in non-UTF-8 files (encoding detection + transcoding before redaction)

**Does NOT defend against:**
- Agent memory/context -- once content passes redaction, the agent has it
- Agent native file access -- if the agent has direct filesystem tools, those bypass SecureIOMCP
- Secret formats not in the pattern library (mitigated by entropy detection and custom patterns)

---

## Redaction Engine

### Pattern Categories

**High confidence** (distinct prefixes, very low false positive rate):

| Pattern | Example Format |
|---------|---------------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `ghp_...` / `ghs_...` |
| GitHub Fine-Grained Token | `github_pat_...` |
| Stripe Live Key | `sk_live_...` |
| Stripe Publishable Key | `pk_live_...` |
| Slack Webhook | `https://hooks.slack.com/services/...` |
| SendGrid Key | `SG.xxxx.xxxx` |
| Twilio Auth Token | `SK[0-9a-f]{32}` |
| Private Key Block | `-----BEGIN ... PRIVATE KEY-----` |
| JWT | `eyJ...eyJ...` |

**Medium confidence** (context-anchored, require assignment to recognized variable names):

| Pattern | Context Requirement |
|---------|-------------------|
| AWS Secret Key | Must follow `aws_secret_access_key=` |
| Azure Storage Key | Must follow `AccountKey=` |
| Connection String | Must contain `@` (embedded credentials) |
| Generic API Key | Must be assigned to `api_key`, `secret_key`, etc. |
| Generic Secret | Must be assigned to `password`, `token`, `secret`, etc. |

**Entropy-based detection** (strict preset only, enabled by default):

Quoted strings 20+ characters with Shannon entropy > 4.5 are flagged as `[REDACTED:HIGH_ENTROPY]`. Known-safe patterns (UUIDs, git commit SHAs, SRI hashes) are exempt.

### Output Format

Detected secrets are replaced inline: `export AWS_KEY=[REDACTED:AWS_ACCESS_KEY]`

---

## Configuration

### Precedence (highest to lowest)

1. **System policy** -- `~/.secureio/policy.json` (security team controls, cannot be weakened)
2. **Project config** -- `.secureiorc` in project root (developer customization, can only make settings stricter)
3. **CLI flags** -- per-invocation overrides (cannot violate system policy)
4. **Built-in defaults** -- strict preset, immutable denylist

### Presets

| | Standard | Strict (default) |
|---|---|---|
| Gitignore filtering | Yes | Yes |
| Built-in denylist | Yes | Yes |
| Pattern-based redaction | Yes | Yes |
| Entropy detection | No | Yes |
| Write secret scanning | Yes | Yes |
| Audit logging | File (can disable) | File (required) |

### System Policy (`~/.secureio/policy.json`)

Organization-wide rules that projects cannot weaken:

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

### Project Config (`.secureiorc`)

Project-level customization (JSON, placed in project root):

```json
{
  "preset": "strict",
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
    "maxFileReadLines": 500,
    "maxWriteBytes": 262144
  }
}
```

### Limits

| Limit | Strict Default | Standard Default | Ceiling |
|-------|---------------|-----------------|---------|
| `maxResultCount` | 50 | 100 | -- |
| `maxLineLength` | 2000 | 2000 | -- |
| `maxResponseBytes` | 50 KB | 100 KB | 512 KB |
| `maxFileReadLines` | 500 | 1000 | -- |
| `maxWriteBytes` | 128 KB | 256 KB | 1 MB |
| `maxTreeDepth` | 4 | 5 | -- |
| `maxAuditLogSizeMB` | 50 | 50 | -- |

---

## Response Format

Every tool response uses a standard envelope:

```json
{
  "results": "...",
  "meta": {
    "total": 234,
    "returned": 50,
    "offset": 0,
    "has_more": true,
    "truncated_lines": 3,
    "redactions": 2,
    "bytes": 12840,
    "constrained_by": "maxResultCount"
  }
}
```

The `meta` object tells agents exactly what they haven't seen, enabling strategic pagination. The `constrained_by` field indicates which limit stopped the response.

---

## Error Handling

Error responses are structured and never expose filesystem details (CWE-209 prevention):

```json
{
  "error": {
    "code": "PATH_DENIED",
    "message": "The requested path is not accessible",
    "suggestion": "Use secure_tree to discover available paths within the project."
  }
}
```

| Error Code | Cause | Suggestion |
|------------|-------|------------|
| `PATH_DENIED` | Path traversal, denylist, or out-of-bounds | Use `secure_tree` to discover paths |
| `SECRET_IN_WRITE` | Write content contains a detected secret | Remove the secret before writing |
| `INVALID_REGEX` | Search pattern is not valid regex | Fix the regex pattern |
| `FILE_NOT_FOUND` | Requested file does not exist | Use `secure_glob` to find files |
| `BINARY_FILE` | File is binary (contains null bytes) | Use `secure_glob` to check file types |
| `SIZE_EXCEEDED` | Content exceeds `maxWriteBytes` | Reduce size or use `secure_patch` |
| `HASH_MISMATCH` | File modified since last read (optimistic lock) | Re-read with `secure_read` |
| `CONFIG_ERROR` | Malformed configuration file | Check `.secureiorc` JSON syntax |
| `INTERNAL_ERROR` | Unexpected server error | Check server logs |

Resolved paths, project root, and OS details are logged server-side only (in the audit log) and never sent to the agent.

---

## Testing

### Framework

Vitest with TypeScript-native support, globals enabled.

### Test Categories

| Category | Command | Description |
|----------|---------|-------------|
| Unit | `npm run test:unit` | Component-level tests for security layer, config, and tools |
| Integration | `npm run test:integration` | Full pipeline tests (CLI, config loading, read/write flows) |
| Security | `npm run test:security` | Secret corpus, path traversal corpus, error disclosure |
| Platform | `npm run test:platform` | Windows/Linux-specific behavior |
| All | `npm test` | Run all tests |
| Coverage | `npm run test:coverage` | Coverage report with v8 provider |

### Coverage Requirements

- 90% line coverage on `src/security/`
- 80% line coverage on `src/tools/`
- 100% coverage on known-safe allowlist logic

### Deployment Validation

```bash
npx secureio-mcp --self-test
```

Runs the built-in security corpus against the redaction engine, path resolver, and denylist to verify the deployment is functioning correctly.

---

## Development

```bash
git clone https://github.com/grantmooney/SecureIOMCP.git
cd SecureIOMCP
npm install
npm run build        # Compile TypeScript
npm test             # Run all tests
npm run dev          # Watch mode for development
npm run test:watch   # Vitest in watch mode
```

### Project Structure

```
src/
  index.ts              # CLI entry point
  server.ts             # MCP server factory and tool registration
  response.ts           # Generic response builder with pagination
  config/
    defaults.ts         # Preset limit values and default configuration
    loader.ts           # Layered config loader (system policy > project > CLI)
  security/
    middleware.ts        # Central security middleware class
    path-resolver.ts     # Path canonicalization and traversal prevention
    access-control.ts    # Denylist and gitignore-based access control
    redaction-engine.ts  # Pattern + entropy-based secret detection
    patterns.ts          # Built-in redaction pattern library
    encoding-detector.ts # BOM-based encoding detection and transcoding
    audit-logger.ts      # Structured JSON audit logging with rotation
  tools/
    read/               # secure_read, secure_search, secure_glob, secure_tree, secure_diff
    write/              # secure_write, secure_patch
    meta/               # secure_audit, secure_overview, secure_self_test
  types/
    config.ts           # Configuration interfaces
    errors.ts           # Error codes and audit types
    response.ts         # Response envelope and result types
    patterns.ts         # Compiled pattern types
tests/
  unit/                 # Component-level tests
  integration/          # Pipeline tests
  security/             # Secret corpus, traversal, error disclosure tests
  fixtures/             # Test repos and corpora
```

---

## License

[MIT](LICENSE) -- Copyright (c) 2026 Grant Mooney
