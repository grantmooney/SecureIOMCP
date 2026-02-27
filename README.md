# SecureIOMCP

<!-- Badges -->
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node >= 20](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-compatible-purple.svg)](https://modelcontextprotocol.io/)

**Secure, token-efficient MCP server providing read-write codebase access for AI agents.**

---

## Overview

SecureIOMCP is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that gives AI coding agents -- Claude Code, Cursor, GitHub Copilot -- controlled access to your project files. Every request passes through a mandatory security layer that prevents path traversal, redacts secrets, enforces file access policies, and produces a tamper-proof audit trail.

### Why SecureIOMCP?

AI agents need to read and write source code. Giving them unrestricted filesystem access creates real risks: leaked API keys in tool responses, agents reading credential files, path traversal outside the project, and no visibility into what the agent actually accessed. SecureIOMCP closes those gaps with security that is always on -- not opt-in, not configurable to "off".

### Who is it for?

SecureIOMCP is designed for **GovTech development teams** and any organization that needs auditable, policy-governed AI agent access to codebases. The layered configuration system supports both organization-wide security policy enforcement and per-project customization.

---

## Features

- **10 purpose-built MCP tools** -- read, search, glob, tree, diff, write, patch, audit, overview, and self-test
- **Mandatory security middleware** -- wraps every request and response; cannot be bypassed or turned off
- **Secret detection and redaction** -- 10 high-confidence patterns, 5 medium-confidence patterns, and Shannon entropy analysis
- **Immutable denylist** -- `.env`, `*.pem`, `*.key`, credential files, and cloud provider directories are always blocked
- **Path traversal prevention** -- symlinks and junctions resolved before bounds checking; agents cannot escape the project root
- **Tamper-proof audit logging** -- every tool invocation is logged; the audit directory is on the immutable denylist so agents cannot read or modify their own trail
- **Encoding detection** -- UTF-8 and UTF-16 (via BOM) with automatic transcoding before redaction
- **Token-efficient responses** -- configurable result limits, line counts, and response size caps reduce token consumption
- **Layered configuration** -- system policy overrides project config; projects can only make settings stricter
- **Zero external binary dependencies** -- pure JavaScript implementation; no ripgrep or other native binaries required
- **Safe error messages** -- error responses never expose resolved paths, project root, or OS details (CWE-209)

---

## Quick Start

### Installation

```bash
# Run directly with npx
npx secureio-mcp

# Or install globally
npm install -g secureio-mcp

# Or add to your project
npm install secureio-mcp
```

### Basic Usage

```bash
# Start the server in the current directory (strict preset, default)
secureio-mcp

# Start with a specific project root
secureio-mcp --root /path/to/project

# Use standard preset (less restrictive)
secureio-mcp --preset standard

# Run the security self-test to validate deployment
secureio-mcp --self-test
```

### MCP Client Configuration

#### Claude Code

Add to your Claude Code MCP configuration (`~/.claude/mcp_servers.json` or project-level):

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["-y", "secureio-mcp"],
      "env": {}
    }
  }
}
```

#### Cursor

Add to your Cursor MCP settings (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["-y", "secureio-mcp"],
      "env": {}
    }
  }
}
```

#### VS Code (GitHub Copilot)

Add to your VS Code settings (`.vscode/mcp.json`):

```json
{
  "servers": {
    "secureio": {
      "type": "stdio",
      "command": "npx",
      "args": ["-y", "secureio-mcp"]
    }
  }
}
```

---

## Architecture

SecureIOMCP uses a three-layer architecture where the security layer is mandatory middleware that wraps every tool invocation:

```
                         MCP Client (Claude Code / Cursor / Copilot)
                                          |
                                     stdio transport
                                          |
                                  +-------v--------+
                                  |  Tool Router   |
                                  |  (McpServer)   |
                                  +-------+--------+
                                          |
                          +---------------v----------------+
                          |      Security Middleware       |
                          |  (mandatory -- cannot bypass)  |
                          |                                |
                          |  +----------+ +-------------+  |
                          |  | Path     | | Access      |  |
                          |  | Resolver | | Control     |  |
                          |  +----------+ +-------------+  |
                          |  +----------+ +-------------+  |
                          |  | Redaction| | Audit       |  |
                          |  | Engine   | | Logger      |  |
                          |  +----------+ +-------------+  |
                          |  +-------------------------+   |
                          |  | Encoding Detector       |   |
                          |  +-------------------------+   |
                          +---------------+----------------+
                                          |
                  +-----------+-----------+-----------+
                  |           |                       |
          +-------v---+ +----v------+          +------v-----+
          |   Read    | |   Write   |          |    Meta    |
          |  Handlers | |  Handlers |          |  Handlers  |
          +-----------+ +-----------+          +------------+
          secure_read    secure_write          secure_audit
          secure_search  secure_patch          secure_overview
          secure_glob                          secure_self_test
          secure_tree
          secure_diff
```

**Tool Router** -- The MCP server receives tool invocations over stdio transport and dispatches them to the appropriate handler. Each tool has a validated input schema (Zod).

**Security Middleware** -- Every handler receives a `SecurityMiddleware` instance that orchestrates path resolution, access control, secret redaction, encoding detection, and audit logging. There is no code path that bypasses this layer.

**Handlers** -- Read handlers return redacted content. Write handlers scan content for secrets and reject writes that would introduce credentials. Meta handlers provide audit reports, project overviews, and deployment validation.

---

## Tools Reference

### Read Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `secure_read` | Read a file with automatic secret redaction | `path` (required), `start_line`, `end_line` |
| `secure_search` | Regex search across files with redacted results | `pattern` (required), `path`, `file_pattern`, `context_lines`, `max_results`, `offset` |
| `secure_glob` | Find files by glob pattern, respecting access control | `pattern` (required), `path`, `max_results`, `offset` |
| `secure_tree` | Directory structure with file counts | `path`, `max_depth` |
| `secure_diff` | Git diff output with secret redaction | `ref`, `path` |

### Write Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `secure_write` | Write a file; rejects if secrets are detected in content | `path` (required), `content` (required) |
| `secure_patch` | Partial file edit with optimistic locking and secret scanning | `path` (required), `old_content` (required), `new_content` (required), `expected_hash` |

### Meta Tools

| Tool | Description | Key Parameters |
|------|-------------|----------------|
| `secure_audit` | Security scan report: blocked files and detected secrets | `path`, `verbose` |
| `secure_overview` | Project summary: framework, language, dependencies, structure | `path`, `verbose` |
| `secure_self_test` | Run security validation suite to verify deployment | _(none)_ |

---

## Security

SecureIOMCP's security layer is composed of five subsystems that work together on every request:

### 1. Path Resolver

Prevents path traversal attacks. Resolves symlinks and junctions **first**, then checks the denylist, then verifies the resolved path is within the project root boundary. Agents cannot escape the project directory.

### 2. Access Control

Enforces an **immutable denylist** combined with gitignore rules. The built-in denylist cannot be removed or overridden -- it can only be extended:

| Category | Patterns |
|----------|----------|
| Environment files | `.env`, `.env.*` |
| Cryptographic keys | `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| Credential files | `credentials.json`, `secrets.yaml`, `*secret*` |
| Cloud provider dirs | `.aws/**`, `.ssh/**`, `.gnupg/**` |
| SecureIOMCP files | `.secureio/**`, `.secureiorc` |

Additionally, patterns from `.gitignore` files are loaded recursively and applied as access restrictions.

### 3. Redaction Engine

Detects and masks secrets in file content before it reaches the AI agent. Three tiers of detection:

- **High-confidence patterns (10)** -- Distinct prefixes with near-zero false positives: AWS access keys (`AKIA...`), GitHub tokens (`ghp_...`, `ghs_...`, `github_pat_...`), Stripe keys (`sk_live_...`, `pk_live_...`), Slack webhooks, SendGrid keys, Twilio API keys, PEM private key headers, and JWTs.
- **Medium-confidence patterns (5)** -- Context-anchored patterns requiring a variable name or protocol prefix: AWS secret keys, Azure storage keys, database connection strings, generic API keys, and generic secrets/passwords.
- **Shannon entropy detection** -- Catches unknown secret formats by measuring string randomness. Enabled by default in `strict` preset.

**Safe patterns (3)** are exempted from entropy detection: UUIDs, git commit SHAs, and Subresource Integrity (SRI) hashes.

Detected secrets are replaced with `[REDACTED:<PATTERN_NAME>]` markers. Redaction line numbers are included in responses and audit logs.

### 4. Audit Logger

Records every tool invocation as a structured JSON Lines entry with:
- Timestamp, tool name, and parameters
- Access decisions (granted/denied)
- Redaction counts and categories
- Execution duration

The audit log directory (`.secureio/`) is on the immutable denylist -- agents cannot read, modify, or delete their own audit trail. Log rotation occurs at 50 MB.

Audit output modes: `file` (default), `stderr` (for container/sidecar log collection), or `none` (can be blocked by system policy).

### 5. Encoding Detector

Detects file encoding (UTF-8, UTF-16 LE/BE via BOM) and transcodes to UTF-8 before redaction. Binary files are detected and rejected with a safe error message.

---

## Configuration

SecureIOMCP uses a four-layer configuration system with strict precedence rules:

```
CLI Flags  (highest priority)
    |
System Policy  (~/.secureio/policy.json)
    |
Project Config  (.secureiorc)
    |
Built-in Defaults  (lowest priority)
```

**Key rules:**
- Each layer can only make settings **stricter** than the layer below it
- The denylist is **extend-only** -- no layer can remove built-in patterns
- System policy can **block** the `standard` preset, forcing all projects to use `strict`
- System policy can **require** audit logging, preventing projects from disabling it
- Hard ceilings (512 KB response, 1 MB write) cannot be exceeded by any configuration

### Presets

| Setting | `strict` (default) | `standard` |
|---------|-------------------|------------|
| Entropy detection | Enabled | Disabled |
| Max results | 50 | 100 |
| Max response size | 50 KB | 100 KB |
| Max read lines | 500 | 1,000 |
| Max write size | 128 KB | 256 KB |
| Max tree depth | 4 | 5 |
| Max line length | 2,000 chars | 2,000 chars |

**Hard ceilings** (cannot be exceeded by any configuration):
- Response payload: 512 KB
- Write content: 1 MB

### Example `.secureiorc` (Project Config)

Place this file in your project root:

```json
{
  "preset": "strict",
  "denylist": {
    "extend": ["internal/secrets/**", "*.tfstate"]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "INTERNAL_TOKEN",
        "pattern": "itk_[A-Za-z0-9]{32}",
        "description": "Internal service token",
        "confidence": "high"
      }
    ]
  },
  "audit": {
    "output": "file"
  },
  "limits": {
    "maxWriteBytes": 65536
  }
}
```

### Example `~/.secureio/policy.json` (System Policy)

System administrators can enforce organization-wide security baselines:

```json
{
  "minimumPreset": "strict",
  "denylist": {
    "extend": ["*.pfx", "*.jks", "internal/**"]
  },
  "redaction": {
    "customPatterns": []
  },
  "audit": {
    "required": true,
    "minimumOutput": "file"
  }
}
```

---

## CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--preset <strict\|standard>` | Security preset level | `strict` |
| `--root <path>` | Project root directory | Current working directory |
| `--audit-output <file\|stderr\|none>` | Audit log output mode | `file` |
| `--self-test` | Run security validation suite and exit | _(off)_ |
| `-h`, `--help` | Show help message and exit | _(off)_ |

---

## Development

### Prerequisites

- **Node.js** >= 20.0.0
- **npm** (included with Node.js)

### Setup

```bash
git clone https://github.com/grantmooney/SecureIOMCP.git
cd SecureIOMCP
npm install
```

### Build

```bash
# Compile TypeScript to JavaScript
npm run build

# Watch mode for development
npm run dev
```

### Test

SecureIOMCP uses [Vitest](https://vitest.dev/) as its test framework with multiple test categories:

```bash
# Run all tests
npm test

# Run specific test categories
npm run test:unit          # Unit tests
npm run test:integration   # Integration tests
npm run test:security      # Security corpus (secret detection validation)
npm run test:platform      # Platform-specific tests (Windows/Linux matrix)

# Run tests with coverage report
npm run test:coverage

# Watch mode
npm run test:watch
```

**Coverage requirements:**
- `src/security/` -- 90% minimum
- `src/tools/` -- 80% minimum
- Known-safe allowlist -- 100%

### Project Structure

```
src/
  index.ts                  # CLI entry point and argument parsing
  server.ts                 # MCP server setup and tool registration
  response.ts               # Response builder with pagination and limits
  config/
    defaults.ts             # Preset definitions and hard ceilings
    loader.ts               # Four-layer configuration loader
  security/
    middleware.ts            # Central security orchestration
    path-resolver.ts         # Path traversal prevention
    access-control.ts        # Immutable denylist and gitignore rules
    redaction-engine.ts      # Secret detection and masking
    patterns.ts              # Built-in detection pattern library
    audit-logger.ts          # Structured JSON Lines audit logging
    encoding-detector.ts     # UTF-8/UTF-16 detection and transcoding
  tools/
    read/                    # secure_read, secure_search, secure_glob, secure_tree, secure_diff
    write/                   # secure_write, secure_patch
    meta/                    # secure_audit, secure_overview, secure_self_test
  types/
    config.ts                # Configuration type definitions
    errors.ts                # Error type definitions
    response.ts              # Response type definitions
    patterns.ts              # Pattern type definitions
tests/
  unit/                      # Unit tests
  integration/               # Integration tests
  security/                  # Secret detection corpus
  platform/                  # Platform-specific tests
```

---

## License

MIT License. Copyright (c) 2026 Grant Mooney.

See [LICENSE](LICENSE) for the full text.
