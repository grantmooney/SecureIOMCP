# API Reference

Complete reference for all 10 SecureIOMCP MCP tools, their parameters, response formats, and error codes.

## Table of Contents

- [Response Envelope](#response-envelope)
- [Error Format](#error-format)
- [Read Tools](#read-tools)
  - [secure_read](#secure_read)
  - [secure_search](#secure_search)
  - [secure_glob](#secure_glob)
  - [secure_tree](#secure_tree)
  - [secure_diff](#secure_diff)
- [Write Tools](#write-tools)
  - [secure_write](#secure_write)
  - [secure_patch](#secure_patch)
- [Meta Tools](#meta-tools)
  - [secure_audit](#secure_audit)
  - [secure_overview](#secure_overview)
  - [secure_self_test](#secure_self_test)
- [Error Codes](#error-codes)
- [Pagination](#pagination)

---

## Response Envelope

Every successful tool response is wrapped in a standard envelope:

```json
{
  "results": "<tool-specific data>",
  "meta": {
    "total": 150,
    "returned": 50,
    "offset": 0,
    "has_more": true,
    "truncated_lines": 3,
    "redactions": 2,
    "bytes": 48200,
    "constrained_by": "maxResultCount"
  }
}
```

### `meta` Fields

| Field | Type | Description |
|-------|------|-------------|
| `total` | `number` | Total matching items available (before pagination) |
| `returned` | `number` | Items returned in this response |
| `offset` | `number` | Zero-based offset into the full result set |
| `has_more` | `boolean` | Whether additional results are available |
| `truncated_lines` | `number` | Lines truncated due to `maxLineLength` |
| `redactions` | `number` | Total secret redactions applied |
| `bytes` | `number` | Response payload size in bytes |
| `constrained_by` | `string?` | Which limit caused early termination: `"maxResultCount"`, `"maxResponseBytes"`, or `"maxLineLength"` |

## Error Format

Failed operations return an error object instead of the response envelope:

```json
{
  "error": {
    "code": "PATH_DENIED",
    "message": "The requested path is not accessible",
    "suggestion": "Use secure_tree to discover available paths within the project."
  }
}
```

Error messages never expose resolved file paths, project root, or OS details (CWE-209).

---

## Read Tools

### `secure_read`

Read a file with automatic secret redaction.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | Yes | File path relative to project root |
| `start_line` | `number` | No | Starting line number (1-indexed) |
| `end_line` | `number` | No | Ending line number |

#### Response

```json
{
  "results": {
    "path": "src/config.ts",
    "content": "const api_key = [REDACTED:AWS_ACCESS_KEY]\nconst port = 3000;",
    "start_line": 1,
    "end_line": 50,
    "total_lines": 120,
    "redacted_lines": [1],
    "encoding_detected": "utf-8"
  },
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | File path as requested |
| `content` | `string` | File content with secrets redacted |
| `start_line` | `number` | Starting line of returned content (1-indexed) |
| `end_line` | `number` | Ending line of returned content |
| `total_lines` | `number` | Total lines in the file |
| `redacted_lines` | `number[]` | Line numbers where redactions were applied |
| `encoding_detected` | `string` | Detected encoding (`utf-8`, `utf-8-bom`, `utf-16le`, `utf-16be`) |

#### Errors

- `PATH_DENIED` -- File is on the denylist or outside project root
- `FILE_NOT_FOUND` -- File does not exist
- `BINARY_FILE` -- File contains binary content

---

### `secure_search`

Search across files with regex pattern matching and automatic redaction.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | `string` | Yes | Regex pattern to search for |
| `path` | `string` | No | Scope search to this subdirectory |
| `file_pattern` | `string` | No | File glob filter (e.g., `*.ts`) |
| `context_lines` | `number` | No | Number of context lines (default: 2) |
| `max_results` | `number` | No | Maximum results to return |
| `offset` | `number` | No | Offset for pagination |

#### Response

```json
{
  "results": [
    {
      "file": "src/server.ts",
      "line": 42,
      "content": "  const server = new McpServer({",
      "context_before": ["", "export function createServer(mw) {"],
      "context_after": ["    name: 'secureio-mcp',", "    version: '0.1.0',"],
      "redacted": false
    }
  ],
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `file` | `string` | File path relative to project root |
| `line` | `number` | Line number of the match (1-indexed) |
| `content` | `string` | Matching line content (redacted if applicable) |
| `context_before` | `string[]` | Lines before the match |
| `context_after` | `string[]` | Lines after the match |
| `redacted` | `boolean` | Whether any content was redacted |

#### Errors

- `INVALID_REGEX` -- Search pattern is not a valid regular expression
- `PATH_DENIED` -- Scoped path is not accessible

---

### `secure_glob`

Find files by glob pattern, respecting access control.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | `string` | Yes | Glob pattern to match files |
| `path` | `string` | No | Scope search to this subdirectory |
| `max_results` | `number` | No | Maximum results to return |
| `offset` | `number` | No | Offset for pagination |

#### Response

```json
{
  "results": [
    { "path": "src/server.ts", "size": 4823 },
    { "path": "src/index.ts", "size": 2156 }
  ],
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | File path relative to project root |
| `size` | `number` | File size in bytes |

#### Errors

- `PATH_DENIED` -- Scoped path is not accessible

---

### `secure_tree`

Get directory structure with file counts.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | No | Root directory for the tree |
| `max_depth` | `number` | No | Maximum depth to traverse |

#### Response

```json
{
  "results": [
    {
      "name": "src",
      "type": "directory",
      "file_count": 3,
      "children": [
        { "name": "index.ts", "type": "file" },
        {
          "name": "security",
          "type": "directory",
          "file_count": 8,
          "children": []
        }
      ]
    }
  ],
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | File or directory name |
| `type` | `string` | `"file"` or `"directory"` |
| `children` | `TreeEntry[]?` | Child entries (directories only, within depth limit) |
| `file_count` | `number?` | Number of direct child files |

#### Errors

- `PATH_DENIED` -- Root path is not accessible

---

### `secure_diff`

Get redacted git diff output.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ref` | `string` | No | Git ref to diff against (default: working tree changes) |
| `path` | `string` | No | Scope diff to this path |

#### Response

```json
{
  "results": [
    {
      "file": "src/config.ts",
      "diff": "@@ -10,3 +10,4 @@\n const port = 3000;\n+const host = 'localhost';\n",
      "redacted": false
    }
  ],
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `file` | `string` | File path from the diff header |
| `diff` | `string` | Unified diff content (redacted if applicable) |
| `redacted` | `boolean` | Whether any diff content was redacted |

#### Errors

- `PATH_DENIED` -- Scoped path is not accessible
- `INTERNAL_ERROR` -- Git command failed

---

## Write Tools

### `secure_write`

Write a file with secret scanning. The write is **rejected** if secrets are detected in the content.

Writes are atomic: content is written to a temporary file first, then renamed into place.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | Yes | File path relative to project root |
| `content` | `string` | Yes | File content to write |

#### Response

```json
{
  "results": {
    "path": "src/config.ts",
    "success": true,
    "hash": "a1b2c3d4e5f6..."
  },
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | File path as requested |
| `success` | `boolean` | Whether the write succeeded |
| `hash` | `string` | SHA-256 hash of the written content (for use with `secure_patch`) |

#### Errors

- `PATH_DENIED` -- File is on the denylist or outside project root
- `SECRET_IN_WRITE` -- Content contains detected secrets
- `SIZE_EXCEEDED` -- Content exceeds `maxWriteBytes` limit

---

### `secure_patch`

Partial file edit with optimistic locking and secret scanning.

Finds `old_content` in the file and replaces it with `new_content`. If `expected_hash` is provided, the operation fails if the file has been modified since the last read (optimistic locking via SHA-256).

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | Yes | File path relative to project root |
| `old_content` | `string` | Yes | Content to find and replace |
| `new_content` | `string` | Yes | Replacement content |
| `expected_hash` | `string` | No | SHA-256 hash for optimistic locking |

#### Response

```json
{
  "results": {
    "path": "src/config.ts",
    "success": true,
    "changed_range": { "start": 10, "end": 15 },
    "hash": "f6e5d4c3b2a1..."
  },
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | File path as requested |
| `success` | `boolean` | Whether the patch succeeded |
| `changed_range` | `object` | Line range affected: `{ start: number, end: number }` (1-indexed) |
| `hash` | `string` | SHA-256 hash of the file after patching |

#### Errors

- `PATH_DENIED` -- File is on the denylist or outside project root
- `FILE_NOT_FOUND` -- File does not exist
- `SECRET_IN_WRITE` -- New content contains detected secrets
- `SIZE_EXCEEDED` -- Resulting file exceeds `maxWriteBytes` limit
- `HASH_MISMATCH` -- File was modified since last read (optimistic lock failure)

---

## Meta Tools

### `secure_audit`

Security scan report showing blocked files and detected secrets across the project.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | No | Scope audit to this subdirectory |
| `verbose` | `boolean` | No | Include per-file details |

#### Response

```json
{
  "results": {
    "preset": "strict",
    "files_blocked": 5,
    "secrets_detected": 12,
    "files_with_secrets": 3,
    "denylist_rules": 0,
    "custom_patterns": 2,
    "details": [
      {
        "path": "config/database.ts",
        "blocked": false,
        "redactions": [
          { "line": 15, "category": "CONNECTION_STRING", "confidence": "high" }
        ]
      }
    ]
  },
  "meta": { "..." }
}
```

#### Summary Fields

| Field | Type | Description |
|-------|------|-------------|
| `preset` | `string` | Active security preset (`strict` or `standard`) |
| `files_blocked` | `number` | Files blocked by the denylist |
| `secrets_detected` | `number` | Total secret instances detected |
| `files_with_secrets` | `number` | Files containing at least one secret |
| `denylist_rules` | `number` | Active denylist rules |
| `custom_patterns` | `number` | Custom redaction patterns configured |
| `details` | `array?` | Per-file details (only with `verbose: true`) |

#### Per-File Detail Fields

| Field | Type | Description |
|-------|------|-------------|
| `path` | `string` | File path relative to project root |
| `blocked` | `boolean` | Whether the file is blocked by the denylist |
| `redactions` | `array` | Redactions found: `{ line, category, confidence }` |

---

### `secure_overview`

Project summary: framework, language, dependencies, structure.

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | `string` | No | Project root to analyze |
| `verbose` | `boolean` | No | Include full dependency names |

#### Response

```json
{
  "results": {
    "name": "secureio-mcp",
    "framework": "express",
    "language": "typescript",
    "packageManager": "npm",
    "entryPoints": ["dist/index.js"],
    "scripts": {
      "build": "tsc",
      "test": "vitest",
      "start": "node dist/index.js"
    },
    "dependencyCount": 3,
    "devDependencyCount": 8,
    "structure": "src/\n  security/\n  tools/\n  types/\n  (5 files)",
    "configFiles": ["package.json", "tsconfig.json", ".gitignore"]
  },
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Project name from `package.json` or directory name |
| `framework` | `string?` | Detected framework (`next`, `react`, `vue`, `angular`, `express`, `fastify`, `koa`, `hono`, `nuxt`) |
| `language` | `string?` | Detected language (`typescript`, `javascript`, `python`, `rust`, `go`) |
| `packageManager` | `string?` | Detected package manager (`npm`, `pnpm`, `yarn`, `bun`) |
| `entryPoints` | `string[]` | Entry points from `package.json` (main, module, bin) |
| `scripts` | `object` | NPM scripts from `package.json` |
| `dependencyCount` | `number` | Production dependency count |
| `devDependencyCount` | `number` | Development dependency count |
| `structure` | `string` | Text summary of top-level directory structure |
| `configFiles` | `string[]` | Configuration files found in project root |

---

### `secure_self_test`

Run the built-in security validation suite to verify deployment.

#### Parameters

None.

#### Response

```json
{
  "results": {
    "passed": true,
    "categories": [
      {
        "name": "pattern_detection",
        "passed": true,
        "total": 7,
        "failures": []
      },
      {
        "name": "traversal_prevention",
        "passed": true,
        "total": 4,
        "failures": []
      },
      {
        "name": "denylist_enforcement",
        "passed": true,
        "total": 8,
        "failures": []
      },
      {
        "name": "false_positive_prevention",
        "passed": true,
        "total": 4,
        "failures": []
      }
    ]
  },
  "meta": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `passed` | `boolean` | Whether all test categories passed |
| `categories` | `array` | Individual test category results |

#### Category Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `string` | Category name |
| `passed` | `boolean` | Whether all tests in this category passed |
| `total` | `number` | Number of test cases |
| `failures` | `string[]` | Descriptions of failed tests |

#### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| `pattern_detection` | 7 | Verifies known secret formats (AWS keys, GitHub tokens, Stripe keys, private key blocks, JWTs, connection strings, generic passwords) are detected |
| `traversal_prevention` | 4 | Confirms `../`, `..\\`, and absolute paths outside the project root are rejected |
| `denylist_enforcement` | 8 | Checks immutable denylist entries (`.env`, `*.pem`, `*.key`, `.ssh/`, `.aws/`, `.secureio/`, `.secureiorc`) are blocked |
| `false_positive_prevention` | 4 | Ensures UUIDs, simple code, imports, and URLs do not trigger false positive detections |

---

## Error Codes

| Code | Description | Common Triggers |
|------|-------------|-----------------|
| `PATH_DENIED` | Path blocked by security controls | Denylist match, gitignore match, traversal attempt, path outside project root |
| `SECRET_IN_WRITE` | Write content contains detected secrets | `secure_write` or `secure_patch` with secret patterns in content |
| `INVALID_REGEX` | Invalid regular expression | `secure_search` with malformed regex pattern |
| `FILE_NOT_FOUND` | File does not exist | `secure_read` or `secure_patch` targeting a non-existent file |
| `BINARY_FILE` | Binary file detected | `secure_read` on a file with null bytes in the first 512 bytes |
| `ENCODING_UNSUPPORTED` | Unsupported encoding | File encoding that cannot be transcoded to UTF-8 |
| `SIZE_EXCEEDED` | Content too large | Write content exceeds `maxWriteBytes` limit |
| `HASH_MISMATCH` | Optimistic lock failed | `secure_patch` with `expected_hash` that doesn't match current file |
| `CONFIG_ERROR` | Invalid configuration | Malformed `.secureiorc` or system policy |
| `INTERNAL_ERROR` | Unexpected error | Git command failure, filesystem errors |

---

## Pagination

Tools that return lists (`secure_search`, `secure_glob`) support pagination through `offset` and `max_results` parameters.

### How It Works

1. First request: omit `offset` (defaults to 0)
2. Check `meta.has_more` in the response
3. If `true`, send another request with `offset` set to the previous `offset + returned`
4. Repeat until `has_more` is `false`

### Constraint Feedback

When a response is truncated, `meta.constrained_by` indicates which limit caused it:

- `"maxResultCount"` -- Too many results. Use `offset` to paginate or narrow the search.
- `"maxResponseBytes"` -- Response too large. Reduce scope or use pagination.
- `"maxLineLength"` -- Individual lines were truncated (see `meta.truncated_lines` for count).

### Example: Paginated Search

```
# Request 1
secure_search({ pattern: "TODO", offset: 0, max_results: 25 })
# Response: { meta: { total: 73, returned: 25, offset: 0, has_more: true } }

# Request 2
secure_search({ pattern: "TODO", offset: 25, max_results: 25 })
# Response: { meta: { total: 73, returned: 25, offset: 25, has_more: true } }

# Request 3
secure_search({ pattern: "TODO", offset: 50, max_results: 25 })
# Response: { meta: { total: 73, returned: 23, offset: 50, has_more: false } }
```

### Preset Limits

| Limit | Strict | Standard | Hard Ceiling |
|-------|--------|----------|--------------|
| `maxResultCount` | 50 | 100 | -- |
| `maxResponseBytes` | 50 KB | 100 KB | 512 KB |
| `maxLineLength` | 2000 | 2000 | -- |
| `maxFileReadLines` | 500 | 1000 | -- |
| `maxWriteBytes` | 128 KB | 256 KB | 1 MB |
| `maxTreeDepth` | 4 | 5 | -- |
