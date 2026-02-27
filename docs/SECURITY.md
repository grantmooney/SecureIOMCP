# SecureIOMCP Security Documentation

This document describes the security architecture, threat model, and protective mechanisms of SecureIOMCP -- a TypeScript MCP server providing secure, token-efficient, read-write codebase access for AI agents in GovTech environments.

## Security Architecture

SecureIOMCP uses a three-layer architecture where every request and response passes through a mandatory security layer:

```
Agent (Claude Code / Cursor / Copilot)
  | MCP protocol (stdio transport)
Tool Router (maps MCP tool calls to handlers)
  |
Security Layer (mandatory middleware -- wraps every operation)
  |-- Path Resolver (canonicalize, jail to project root)
  |-- Encoding Detector (BOM detection, transcode to UTF-8)
  |-- Access Control (gitignore-aware file filtering)
  |-- Redaction Engine (pattern + entropy-based secret detection)
  |-- Audit Logger (structured JSON, tamper-protected)
  |
Read / Write / Meta Handlers (execute operations)
```

The security layer is NOT opt-in. It wraps every request and response with no "off" mode. There is no preset, configuration option, or CLI flag that disables it.

**Defense in depth pipeline:**

1. **Path resolution** -- Canonicalize and jail all paths to the project root, resolving symlinks before any other check.
2. **Access control** -- Apply the immutable denylist and gitignore rules to block access to sensitive files.
3. **Encoding detection** -- Detect file encoding via BOM (UTF-8, UTF-16LE, UTF-16BE) and transcode to UTF-8 before pattern matching.
4. **Redaction** -- Scan all outbound content with pattern matching and entropy detection, replacing secrets with `[REDACTED:<category>]` markers.
5. **Write scanning** -- Scan all inbound write content with the same redaction engine, rejecting writes that contain detected secrets.
6. **Audit logging** -- Log every tool invocation (success and failure) to a tamper-protected structured log.

## Threat Model

### Primary Threat

AI agents under prompt injection attempting to exfiltrate secrets or access restricted files. The agent is the primary consumer of every tool and the primary vector for data exposure. Agents read files, follow instructions found in code comments, and may be manipulated by prompt injection embedded in source files.

### Secondary Threats

- **Malicious code comments** -- Source files, comments, README files, and configuration may contain instructions designed to manipulate the AI agent into exfiltrating secrets or performing unintended actions.
- **Misconfiguration** -- Developers may commit secrets to repositories, place credentials in non-standard locations, or configure `.gitignore` incorrectly.
- **Compromised dependencies** -- A malicious npm postinstall script could modify `.secureiorc` to weaken protections. The configuration system must be resilient to this.

### Mitigations by Layer

| Scenario | Attack | Mitigation |
|---|---|---|
| Direct secret access | Agent calls `secure_read` on `.env` | Denylist blocks the file entirely |
| Indirect exfiltration via search | Code comment instructs agent to search for `DB_PASSWORD` | Redaction engine catches secret values in search results |
| Path traversal | Agent requests `../../etc/passwd` | Path resolver canonicalizes and jails to project root |
| Symlink escape | Symlink inside project points outside root | `fs.realpath()` resolves before bounds check |
| Config tampering | Malicious postinstall modifies `.secureiorc` | System policy overrides project config and cannot be modified by the project |
| Audit log tampering | Agent calls `secure_write` on `.secureio/audit.log` | Audit log path is on the immutable denylist |
| Secret in write content | Agent hardcodes an API key in generated code | Write tools scan content with the redaction engine and reject if secrets detected |
| Error message probing | Agent triggers path errors to map filesystem | Error responses never expose resolved paths or project root |
| Encoded secrets | Secret is base64-encoded in a Kubernetes manifest | Entropy detection (strict preset, default) flags high-entropy strings regardless of encoding |
| Non-UTF-8 secret hiding | Secret stored in a UTF-16 file bypasses UTF-8 regex | Encoding detection and transcoding to UTF-8 before redaction |

## Path Resolution (CWE-22 Prevention)

The path resolver is the most security-critical component. A single bypass compromises the entire security model.

**Resolution process:**

1. All paths are resolved relative to the project root using `path.resolve()` followed by `fs.realpath()`.
2. Symlinks and Windows junction points are resolved first, then the denylist is checked, then bounds checking is applied. This ordering prevents symlinks pointing to denied paths from bypassing the denylist.
3. Any resolved path outside the project root is rejected unconditionally.

**Rejected inputs:**

- **Null bytes** -- Paths containing null bytes (`\0`) are rejected immediately.
- **Absolute paths** -- Only relative paths within the project root are accepted.
- **UNC paths** -- Windows UNC paths (`\\server\share\...`) are rejected.
- **Windows drive letters** -- Paths with drive letter prefixes (`C:\...`) are rejected; drive letter normalization (`C:` vs `c:`) is handled for case-insensitive comparison.
- **Windows device names** -- Reserved device names (`CON`, `PRN`, `NUL`, `AUX`, `COM1`-`COM9`, `LPT1`-`LPT9`) are rejected to prevent device path attacks.
- **`.git` directory access** -- Access to `.git/` internals (objects, refs) is blocked to protect commit history secrets.
- **Path traversal sequences** -- `../` sequences, encoded dots, and unicode normalization attacks are all resolved and checked.

**Symlink handling:**

- `fs.realpath()` resolves all symlinks and junction points before bounds and denylist checks.
- Circular symlinks are detected via the `ELOOP` error thrown by `fs.realpath()` and returned as a generic path denied error.
- Windows junction points are treated identically to symlinks.

**Case sensitivity:**

- Case-insensitive comparison is used for denylist matching on Windows to prevent bypasses via case variation.

**Error responses (CWE-209):**

- Error responses to agents never expose resolved file paths, the project root, or OS details. Detailed information is logged server-side in the audit log for incident investigation.

## Access Control

### Immutable Denylist

The built-in denylist is extend-only. These entries cannot be removed, overridden, or disabled by any configuration:

| Pattern | Purpose |
|---|---|
| `.env`, `.env.*` | Environment variable files |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | Certificates and private keys |
| `credentials.json` | Cloud provider credentials |
| `secrets.yaml` | Kubernetes and application secrets |
| `*secret*` | Files with "secret" in the name |
| `.aws/**` | AWS credential directory |
| `.ssh/**` | SSH key directory |
| `.gnupg/**` | GPG key directory |
| `.secureio/**` | Audit logs and internal state (tamper protection) |
| `.secureiorc` | Configuration file (prevents agent from reading or modifying security config) |

### Gitignore Integration

- `.gitignore` rules are loaded recursively from the project root and nested directories using the `ignore` npm package.
- Only project-scoped ignore rules are used. `.git/info/exclude` and global gitignore (`core.excludesFile`) are explicitly not parsed, ensuring the security posture is deterministic from project contents alone.
- `.gitignore` is re-parsed on every request (no caching) to ensure consistency.

### Extension Rules

- **System policy** (`~/.secureio/policy.json`) can add denylist entries but never remove built-in entries.
- **Project config** (`.secureiorc`) can add denylist entries but never remove built-in or system policy entries.
- Custom patterns in `.secureiorc` always supplement built-in patterns. If a custom pattern has the same name as a built-in, both run -- built-in patterns cannot be overridden or disabled.

### Write Access Control

- All write operations are blocked to any path on the denylist, including extensions from system policy and project config.

## Secret Detection

### High-Confidence Patterns (10 patterns)

These patterns have distinct prefixes with a very low false positive rate:

| Pattern | Regex | Example |
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

### Medium-Confidence Patterns (5 patterns)

These patterns are context-anchored to reduce false positives:

| Pattern | Context Requirement | Example |
|---|---|---|
| AWS Secret Key | Must follow `aws_secret_access_key=` assignment | 40-char key after `aws_secret_access_key=` |
| Azure Storage Key | Must follow `AccountKey=` literal | Azure connection string key portion |
| Connection String | Must contain `@` (embedded credentials) | `postgres://user:pass@host/db` |
| Generic API Key | Must be assigned to a recognized variable name (`api_key`, `apikey`, `secret_key`, `auth_token`) | `api_key = "abc123..."` |
| Generic Secret | Must be assigned to a recognized variable name (`password`, `passwd`, `token`, `secret`, `credential`) | `password = "hunter2..."` |

### Entropy-Based Detection (strict preset only, enabled by default)

- **Algorithm:** Shannon entropy calculation on candidate strings.
- **Threshold:** Entropy greater than 4.5 bits per character.
- **Conditions:** String must be 20 or more characters, alphanumeric with special characters, and not match a known-safe pattern.
- **Purpose:** Catches unknown or proprietary secret formats with high randomness, including base64-encoded secrets.

### False Positive Prevention

The following patterns are exempt from entropy detection (known-safe allowlist):

- **UUIDs:** `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
- **Git commit SHAs:** `[0-9a-f]{40}` when on a line containing `commit`, `ref`, `sha`, or `hash`
- **SRI hashes:** Subresource integrity hashes in standard format
- **Import paths and URLs:** Paths with recognized domain prefixes
- **Hex hashes in lockfiles:** Hashes in `package-lock.json` and `yarn.lock`

### Output Format

Detected secrets are replaced with `[REDACTED:<CATEGORY>]` markers. For example:

```
export AWS_KEY=[REDACTED:AWS_ACCESS_KEY]
```

## Write Protection

### Content Scanning

All write content (`secure_write` and `secure_patch`) is scanned with the same redaction engine used for reads. If any secret pattern matches, the write is rejected. The rejection response includes the pattern category and line number but never the secret value itself.

### Atomic Writes

Write operations use a temp-file-and-rename strategy to prevent partial writes:

1. Content is written to a temporary file in the same directory (`.<name>.secureio.tmp`).
2. `fs.rename()` atomically replaces the target path.
3. On Windows, rename is retried up to 3 times with 100ms backoff to handle file locking semantics.

### Size Limits

| Preset | Default Write Limit | Maximum Override |
|---|---|---|
| Strict | 128KB | 1MB ceiling (cannot be overridden) |
| Standard | 256KB | 1MB ceiling (cannot be overridden) |

### Optimistic Locking

`secure_patch` uses SHA-256 hash-based optimistic locking:

- An `expected_hash` parameter can be provided with the patch request.
- If the file has been modified since the last read (hash mismatch), the patch is rejected.
- The rejection response includes the current hash so the agent can re-read without an extra round trip.

## Audit Logging

### Log Format

Every tool invocation produces a structured JSON log entry in JSON Lines format:

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

### What Is Logged

- Every tool invocation, including both successful operations and failures.
- For write operations, content is logged as a SHA-256 hash, not plaintext.
- Security events (path violations, access denials, secret-in-write rejections) are flagged with `"severity": "security"` for SIEM filtering.

### Severity Levels

| Level | Description |
|---|---|
| `normal` | Standard tool invocation, no security event |
| `warning` | Non-critical issue (encoding unsupported, size exceeded) |
| `security` | Security-relevant event (path denied, secret in write, access violation) |

### Tamper Protection

The `.secureio/` directory is on the immutable denylist. Agents cannot read, write, or modify audit logs through any SecureIOMCP tool. This prevents agents from tampering with their own audit trail.

### Log Rotation

- Log rotation triggers at a configurable size threshold (default 50MB, set via `maxAuditLogSizeMB`).
- When exceeded, the current log is renamed with a timestamp suffix and a new log is started.
- Old logs are retained; deletion is the responsibility of external log management.

### Output Destinations

- Default: `.secureio/audit.log` (append-only file)
- Configurable: file path, stdout, or callback for SIEM integration

## Configuration Security

### Layered Configuration Precedence

Configuration is resolved in the following order (highest to lowest precedence):

1. **CLI flags** -- Per-invocation overrides.
2. **System policy** (`~/.secureio/policy.json`) -- Security team controls. Cannot be weakened by project config.
3. **Project config** (`.secureiorc` in project root) -- Developer customization.
4. **Built-in defaults** -- Strict preset with immutable denylist.

### System Policy Overrides Project Config

The system policy file is the mechanism for GovTech security teams to enforce organization-wide rules. Projects can only make settings stricter than the system policy:

- **Presets can only be escalated** (standard to strict), never relaxed. If the system policy sets `minimumPreset: "strict"`, no project config or CLI flag can downgrade to standard.
- **Resource limits can only be lowered** by projects, never raised above the system policy threshold.
- **Hard ceilings cannot be overridden:** `maxResponseBytes` cannot exceed 512KB, `maxWriteBytes` cannot exceed 1MB. These limits are enforced regardless of configuration.
- **`audit.required: true`** in system policy prevents any project or CLI flag from disabling audit logging.

### Configuration File Protection

The `.secureiorc` file is on the immutable denylist. Agents cannot read or modify the security configuration through any SecureIOMCP tool.

## Error Handling (CWE-209)

### Information Disclosure Prevention

Error responses to agents never expose:

- Resolved absolute file paths
- The project root path
- Operating system details
- Internal file system structure outside the project

Detailed diagnostic information is logged server-side in the audit log (with `"severity": "security"`) for incident investigation but is never sent to the agent.

### Structured Error Responses

Every failure returns actionable information without leaking sensitive system details:

```json
{
  "error": {
    "code": "PATH_DENIED",
    "message": "The requested path is not accessible",
    "suggestion": "Use secure_tree to discover available paths within the project."
  }
}
```

### Standardized Error Codes

| Code | Description | Agent Sees | Audit Log Contains |
|---|---|---|---|
| `PATH_DENIED` | Path traversal, symlink escape, or denylist file | Generic "path not accessible" with suggestion | Full resolved path, denial reason, severity=security |
| `SECRET_IN_WRITE` | Agent writes content containing a detected secret | "Content rejected: secret detected on line N, category: [CATEGORY]" (no secret value) | Content hash, matched pattern, severity=security |
| `INVALID_REGEX` | Invalid regular expression in search | Regex parse error with character position | Client error |
| `FILE_NOT_FOUND` | Non-existent path | Error with fuzzy match suggestions from allowed files | Client error |
| `BINARY_FILE` | Attempt to read a binary file | File type detected and size, suggest `secure_glob` | Not logged |
| `ENCODING_UNSUPPORTED` | File with unrecognized encoding | "File encoding not supported, detected: [encoding]" | Warning |
| `SIZE_EXCEEDED` | Write content exceeds `maxWriteBytes` | "Content size N bytes exceeds limit of M bytes" | Warning |
| `HASH_MISMATCH` | `secure_patch` on a modified file | "File was modified since last read" with current hash | Normal |

## Known Limitations

SecureIOMCP reduces secret exposure significantly but cannot eliminate it. Security teams should treat it as one layer in a defense-in-depth strategy.

- **Agent memory retention** -- Once content passes through the redaction layer, the agent has it in context. SecureIOMCP cannot prevent the agent from including previously read content in its responses. The tool reduces exposure surface; it does not eliminate it.
- **Agent native file access** -- If the agent also has direct filesystem tools (e.g., Claude Code's built-in Read tool), those bypass SecureIOMCP entirely. The tool is effective only when agents are configured to use it as their primary I/O interface.
- **Finite pattern library** -- The redaction engine uses a fixed set of patterns. Some secret formats (custom, proprietary, or novel) may not be detected. This is mitigated by custom patterns in `.secureiorc` and system policy, and by entropy detection in strict mode.
- **Multi-line secrets** -- The redaction engine scans line by line. Secrets that span multiple lines (e.g., multi-line private keys without PEM headers) may not be detected. PEM-formatted keys are detected via their header line.
- **Entropy detection limits** -- Entropy detection may miss low-entropy secrets (short passwords, dictionary words) or flag high-entropy non-secrets (compressed data, encoded binary). The known-safe allowlist reduces false positives but cannot eliminate them.
- **Secrets in non-obvious variable names** -- Medium-confidence patterns are anchored to recognized variable names (`password`, `api_key`, etc.). Secrets assigned to non-obvious names (`config.db_conn`, `auth_header`) may be missed unless caught by entropy detection.

## Reporting Security Issues

If you discover a security vulnerability in SecureIOMCP, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please follow these steps:

1. **Email:** Send a detailed report to the project maintainers via the contact information in the repository. Include a description of the vulnerability, steps to reproduce, and the potential impact.
2. **Response time:** We aim to acknowledge reports within 48 hours and provide a resolution timeline within 5 business days.
3. **Disclosure:** We follow coordinated disclosure. Please allow us reasonable time to address the vulnerability before making it public.
4. **Scope:** Vulnerabilities in the security layer (path resolver, access control, redaction engine, audit logger) are considered high priority. Bypasses of the denylist, path traversal escapes, and redaction failures are critical.

We appreciate the security research community's efforts to improve SecureIOMCP and will credit reporters (with permission) in release notes.
