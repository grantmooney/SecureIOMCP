# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

SecureIOMCP — a TypeScript MCP server providing secure, token-efficient, read-write codebase access for AI agents (Claude Code, Cursor, Copilot). Target audience is development teams working in security-conscious environments. See `docs/plans/2026-02-26-secureio-mcp-design.md` for the full design document.

> **Note:** Repository is named `SecureSearchMCP` but project has been renamed to `SecureIOMCP`.

## Architecture

Three-layer design: Tool Router -> Security Layer (mandatory middleware) -> Read/Write/Meta handlers. Pure JavaScript, zero external binary dependencies, stdio transport.

**10 MCP tools:** `secure_search`, `secure_read`, `secure_glob`, `secure_tree`, `secure_diff` (read), `secure_write`, `secure_patch` (write), `secure_audit`, `secure_overview`, `secure_self_test` (meta).

## Key Design Constraints

- Security layer is not opt-in — wraps every request and response, no "off" mode
- Default preset is `strict` (entropy detection enabled). `standard` available but can be blocked by system policy.
- Denylist is extend-only — built-in protections (`.env`, `*.pem`, `.secureio/`, `.secureiorc`) are immutable
- System policy (`~/.secureio/policy.json`) overrides project config (`.secureiorc`) — projects can only make settings stricter
- Error responses to agents never expose resolved paths, project root, or OS details (CWE-209 prevention)
- Audit log (`.secureio/`) is on the immutable denylist — agents cannot tamper with their own audit trail
- Path resolver: resolve symlinks/junctions first, then denylist, then bounds check
- Zero external binary dependencies (no ripgrep)
- Encoding detection (UTF-8/UTF-16 via BOM) with transcoding before redaction

## Testing

- **Framework:** Vitest
- **Test categories:** unit, integration, security (secret corpus), platform (Windows/Linux matrix), performance
- **Coverage requirements:** 90% on `src/security/`, 80% on `src/tools/`, 100% on known-safe allowlist
- `--self-test` CLI flag runs the security corpus for deployment validation
