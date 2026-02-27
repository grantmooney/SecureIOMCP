# SecureIOMCP Configuration Guide

## Overview

SecureIOMCP uses a four-layer configuration system. Each layer can only make settings **stricter** than the layer below it -- no layer can relax protections set by a higher-priority layer.

**Precedence (highest to lowest):**

| Priority | Layer | Location | Purpose |
|----------|-------|----------|---------|
| 1 | CLI flags | Command line | Per-invocation overrides |
| 2 | System policy | `~/.secureio/policy.json` | Organization-wide enforcement by security teams |
| 3 | Project config | `.secureiorc` (project root) | Per-project customization by developers |
| 4 | Built-in defaults | Compiled into the binary | Strict preset, immutable denylist |

**Key rules:**

- System policy overrides project config -- projects can only make settings stricter.
- CLI flags override project config but cannot violate system policy.
- The built-in denylist (`.env`, `*.pem`, `.secureio/`, etc.) is immutable -- no configuration layer can remove entries.
- Zero configuration is required. SecureIOMCP works out of the box with the `strict` preset and built-in defaults.

---

## Presets

SecureIOMCP ships with two security presets. There is no "off" mode -- the security layer is always active.

### `strict` (default)

The default preset, designed for maximum protection. Recommended for GovTech environments and any context where missed secrets are less acceptable than false positives.

| Setting | Value |
|---------|-------|
| Entropy detection | **Enabled** (Shannon entropy > 4.5, strings 20+ chars) |
| `maxResultCount` | 50 |
| `maxLineLength` | 2000 |
| `maxResponseBytes` | 51200 (50 KB) |
| `maxFileReadLines` | 500 |
| `maxWriteBytes` | 131072 (128 KB) |
| `maxTreeDepth` | 4 |
| `maxAuditLogSizeMB` | 50 |
| Audit logging | Required (cannot be disabled) |

### `standard`

A more permissive preset for lower-security contexts where entropy detection false positives are unacceptable. Can be blocked by system policy via `minimumPreset`.

| Setting | Value |
|---------|-------|
| Entropy detection | **Disabled** |
| `maxResultCount` | 100 |
| `maxLineLength` | 2000 |
| `maxResponseBytes` | 102400 (100 KB) |
| `maxFileReadLines` | 1000 |
| `maxWriteBytes` | 262144 (256 KB) |
| `maxTreeDepth` | 5 |
| `maxAuditLogSizeMB` | 50 |
| Audit logging | Enabled by default (can be disabled) |

Both presets share these protections (always active, cannot be disabled):

- Gitignore-aware file filtering
- Built-in immutable denylist
- Pattern-based secret redaction (high and medium confidence)
- Write content secret scanning
- Custom pattern support

### Hard Ceilings

Regardless of preset or configuration, these absolute limits cannot be exceeded by any configuration layer:

| Setting | Hard Ceiling |
|---------|-------------|
| `maxResponseBytes` | 524288 (512 KB) |
| `maxWriteBytes` | 1048576 (1 MB) |

Any configured value above these ceilings is silently clamped down.

---

## CLI Flags

CLI flags provide per-invocation overrides. They take the highest precedence after system policy enforcement.

```bash
npx secureio-mcp [flags]
```

| Flag | Description |
|------|-------------|
| `--preset <strict\|standard>` | Set the security preset. Overrides the project config preset. Has no effect if the system policy `minimumPreset` is stricter. |
| `--root <path>` | Set the project root directory. Defaults to the current working directory. All path resolution and access control is jailed to this directory. |
| `--audit-output <file\|stderr\|none>` | Set the audit log output destination. `file` writes to `.secureio/audit.log`. `stderr` writes to stderr for container/SIEM log collection. `none` disables audit logging (blocked if system policy sets `audit.required: true`). |
| `--self-test` | Run the built-in security validation suite and exit. Tests the redaction engine against a corpus of known secrets, verifies path traversal protection, and validates denylist enforcement. Returns pass/fail results for security team review. |
| `-h, --help` | Print usage information and exit. |

**Examples:**

```bash
# Default: strict preset, current directory as root, audit to file
npx secureio-mcp

# Use standard preset (if system policy allows)
npx secureio-mcp --preset standard

# Custom project root with audit to stderr for container log collection
npx secureio-mcp --root /path/to/project --audit-output stderr

# Run security validation suite before deployment
npx secureio-mcp --self-test
```

---

## Project Configuration (`.secureiorc`)

The project configuration file is an optional JSON file placed at the project root. It allows developers to customize security settings for their specific project, within the bounds allowed by the system policy.

**Location:** `.secureiorc` in the project root directory.

**Important:** The `.secureiorc` file itself is on the immutable denylist -- AI agents cannot read or modify it through SecureIOMCP tools.

### Full Example

```json
{
  "preset": "strict",
  "projectRoot": ".",
  "denylist": {
    "extend": [
      "internal-certs/**",
      "deploy-keys/",
      "*.tfvars",
      "config/secrets/**"
    ]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "INTERNAL_TOKEN",
        "pattern": "PROJ-[A-Z0-9]{24}",
        "description": "Project-specific API token",
        "confidence": "medium"
      },
      {
        "name": "SERVICE_KEY",
        "pattern": "svc_[A-Za-z0-9]{32}",
        "description": "Internal service authentication key",
        "confidence": "medium"
      }
    ]
  },
  "audit": {
    "output": "file",
    "path": ".secureio/audit.log"
  },
  "limits": {
    "maxResultCount": 50,
    "maxLineLength": 2000,
    "maxResponseBytes": 51200,
    "maxFileReadLines": 500,
    "maxWriteBytes": 131072,
    "maxTreeDepth": 4,
    "maxAuditLogSizeMB": 50
  }
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `preset` | `"strict"` \| `"standard"` | Security preset for this project. Cannot be weaker than system policy `minimumPreset`. |
| `projectRoot` | `string` | Path to the project root. Typically `"."`. Resolved relative to the `.secureiorc` location. |
| `denylist.extend` | `string[]` | Additional gitignore-style patterns to block. **Extend-only** -- these are merged with the immutable built-in denylist. You cannot remove built-in entries. |
| `redaction.customPatterns` | `RedactionPattern[]` | Additional secret detection patterns. Each pattern has `name`, `pattern` (regex string), `description`, and `confidence`. Custom patterns defined at the project level receive **medium** confidence classification. |
| `audit.output` | `"file"` \| `"stderr"` \| `"none"` | Where audit log entries are written. Can be restricted by system policy `audit.required` and `audit.minimumOutput`. |
| `audit.path` | `string` | File path for audit output, relative to project root. Default: `.secureio/audit.log`. |
| `limits.*` | `number` | Resource limits. Projects can only set values **lower** than preset defaults. Values above preset defaults are ignored. Values above hard ceilings are clamped. |

### Key Behaviors

**Extend-only denylist:** The `denylist.extend` array adds patterns on top of the built-in immutable list. The following paths are always blocked regardless of configuration:

- `.env`, `.env.*` -- environment variable files
- `*.pem`, `*.key`, `*.p12`, `*.pfx` -- certificates and private keys
- `credentials.json`, `secrets.yaml`, `*secret*` -- common secret files
- `.aws/`, `.ssh/`, `.gnupg/` -- credential directories
- `.secureio/` -- audit logs (tamper protection)
- `.secureiorc` -- the configuration file itself

**Custom patterns:** Patterns defined in `.secureiorc` are applied alongside (not instead of) the built-in pattern library. If a custom pattern has the same name as a built-in pattern, both run. Built-in patterns cannot be overridden or disabled. Project-level custom patterns are classified at **medium** confidence.

**Limits can only be lowered:** If the `strict` preset sets `maxResponseBytes` to 51200, a project config value of 102400 is ignored. A value of 25600 is accepted.

---

## System Policy (`~/.secureio/policy.json`)

The system policy file provides organization-wide security enforcement. It is managed by security teams and takes precedence over all project-level configuration. Projects can only make settings stricter than the system policy, never relax them.

**Location:** `~/.secureio/policy.json` (user home directory).

### Full Example

```json
{
  "minimumPreset": "strict",
  "denylist": {
    "extend": [
      "*.tfvars",
      "*.tfstate",
      "agency-internal/**",
      "*.jks",
      "*.keystore"
    ]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "AGENCY_TOKEN",
        "pattern": "AGCY-[A-Z0-9]{32}",
        "description": "Internal agency auth token",
        "confidence": "high"
      },
      {
        "name": "GOV_CERT_ID",
        "pattern": "GCERT-[0-9]{4}-[A-Z0-9]{16}",
        "description": "Government certificate identifier",
        "confidence": "high"
      }
    ]
  },
  "audit": {
    "required": true,
    "minimumOutput": "file"
  }
}
```

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `minimumPreset` | `"strict"` \| `"standard"` | Minimum allowed preset. If set to `"strict"`, projects cannot use `"standard"` and CLI `--preset standard` has no effect. |
| `denylist.extend` | `string[]` | Additional denylist patterns enforced organization-wide. Merged with the built-in list and any project-level extensions. |
| `redaction.customPatterns` | `RedactionPattern[]` | Additional redaction patterns enforced organization-wide. System-level custom patterns receive **high** confidence classification. Applied alongside built-in and project-level patterns. |
| `audit.required` | `boolean` | When `true`, audit logging cannot be disabled. Projects cannot set `audit.output: "none"` and the CLI `--audit-output none` flag is rejected. |
| `audit.minimumOutput` | `"file"` \| `"stderr"` | Minimum durability for audit output. When set to `"file"`, projects cannot downgrade to `"stderr"` or `"none"`. When set to `"stderr"`, projects cannot use `"none"`. |

### Key Behaviors

**Preset enforcement:** Setting `minimumPreset: "strict"` ensures that entropy detection is enabled across all projects on the workstation. Projects requesting `"standard"` are upgraded to `"strict"` silently.

**Denylist stacking:** System policy denylist patterns, project denylist patterns, and built-in patterns are all merged. The final resolved denylist is the union of all three layers.

**Custom pattern confidence:** Custom patterns defined at the system policy level receive **high** confidence, reflecting the assumption that security teams define precise, validated patterns. Project-level custom patterns receive **medium** confidence.

**Audit enforcement:** Setting `audit.required: true` and `audit.minimumOutput: "file"` guarantees a durable, file-based audit trail exists for every tool invocation -- essential for GovTech compliance requirements.

---

## Configuration Examples

### 1. Minimal `.secureiorc`

The simplest project configuration. Uses all defaults from the `strict` preset, adding only a few project-specific paths to the denylist.

```json
{
  "preset": "strict",
  "denylist": {
    "extend": ["deploy-keys/"]
  }
}
```

This is equivalent to running with no `.secureiorc` at all, except the `deploy-keys/` directory is also blocked.

### 2. GovTech `.secureiorc` with Custom Patterns

A configuration for a government agency project that uses internal token formats and has sensitive internal directories.

```json
{
  "preset": "strict",
  "denylist": {
    "extend": [
      "internal-certs/**",
      "deploy-keys/",
      "*.tfvars",
      "*.tfstate",
      "config/agency-secrets/**",
      "docs/classified/**"
    ]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "AGENCY_API_TOKEN",
        "pattern": "AAT-[A-Z0-9]{32}",
        "description": "Agency internal API token format",
        "confidence": "medium"
      },
      {
        "name": "INTERNAL_SERVICE_KEY",
        "pattern": "ISK_[A-Za-z0-9]{48}",
        "description": "Internal microservice authentication key",
        "confidence": "medium"
      },
      {
        "name": "CLEARANCE_CODE",
        "pattern": "CLR-[0-9]{4}-[A-Z]{2}-[A-Z0-9]{12}",
        "description": "Security clearance verification code",
        "confidence": "medium"
      }
    ]
  },
  "audit": {
    "output": "file",
    "path": ".secureio/audit.log"
  },
  "limits": {
    "maxResultCount": 30,
    "maxResponseBytes": 25600,
    "maxFileReadLines": 300,
    "maxWriteBytes": 65536,
    "maxTreeDepth": 3
  }
}
```

This configuration lowers several limits below the `strict` preset defaults for an extra layer of protection and adds custom patterns specific to the agency's token formats.

### 3. System Policy Enforcing Strict + Audit

A system policy for a GovTech security team that mandates strict mode and file-based audit logging across all projects.

```json
{
  "minimumPreset": "strict",
  "denylist": {
    "extend": [
      "*.tfvars",
      "*.tfstate",
      "*.jks",
      "*.keystore",
      "agency-internal/**"
    ]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "AGENCY_TOKEN",
        "pattern": "AGCY-[A-Z0-9]{32}",
        "description": "Agency-wide auth token",
        "confidence": "high"
      }
    ]
  },
  "audit": {
    "required": true,
    "minimumOutput": "file"
  }
}
```

With this policy in place:

- `npx secureio-mcp --preset standard` silently upgrades to `strict`.
- `npx secureio-mcp --audit-output none` is rejected.
- All projects on this machine have `*.tfvars`, `*.tfstate`, `*.jks`, `*.keystore`, and `agency-internal/**` blocked in addition to the built-in denylist.
- The `AGCY-*` token pattern is detected at high confidence in every project.

### 4. System Policy + Project Config Interaction

This example shows how the layers merge at runtime.

**System policy** (`~/.secureio/policy.json`):

```json
{
  "minimumPreset": "strict",
  "denylist": {
    "extend": ["*.tfvars", "agency-internal/**"]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "AGENCY_TOKEN",
        "pattern": "AGCY-[A-Z0-9]{32}",
        "description": "Agency auth token",
        "confidence": "high"
      }
    ]
  },
  "audit": {
    "required": true,
    "minimumOutput": "file"
  }
}
```

**Project config** (`.secureiorc`):

```json
{
  "preset": "standard",
  "denylist": {
    "extend": ["deploy-keys/", "config/secrets/**"]
  },
  "redaction": {
    "customPatterns": [
      {
        "name": "PROJECT_KEY",
        "pattern": "PK_[A-Za-z0-9]{24}",
        "description": "Project service key",
        "confidence": "medium"
      }
    ]
  },
  "audit": {
    "output": "none"
  },
  "limits": {
    "maxResponseBytes": 102400,
    "maxWriteBytes": 65536
  }
}
```

**Resolved runtime configuration:**

| Setting | Resolved Value | Reason |
|---------|---------------|--------|
| `preset` | `strict` | Project requested `standard`, but system policy enforces `minimumPreset: "strict"`. |
| `denylist` | Built-in + `*.tfvars` + `agency-internal/**` + `deploy-keys/` + `config/secrets/**` | All layers merged (union). |
| `redactionPatterns` | Built-in + `AGENCY_TOKEN` (high) + `PROJECT_KEY` (medium) | All layers merged. |
| `entropyDetection` | `true` | Follows from `strict` preset. |
| `audit.output` | `file` | Project requested `none`, but system policy sets `audit.required: true` and `audit.minimumOutput: "file"`. |
| `maxResponseBytes` | `51200` (50 KB) | Project requested 102400, but `strict` preset default is 51200. Projects can only lower limits, not raise them. |
| `maxWriteBytes` | `65536` (64 KB) | Project requested 65536, which is lower than the `strict` default (131072). Accepted because it is stricter. |

---

## MCP Client Configuration

SecureIOMCP uses stdio transport and works with any MCP-compatible client. Below are configuration examples for common clients.

### Claude Code

Create or edit the MCP configuration file at `.claude/mcp.json` in your project directory (for project-scoped configuration) or at `~/.claude/mcp.json` (for global configuration):

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

With CLI flags:

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp", "--preset", "strict", "--audit-output", "file"]
    }
  }
}
```

With a custom project root:

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp", "--root", "/path/to/project"]
    }
  }
}
```

### Cursor

Create or edit `.cursor/mcp.json` in your project directory:

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

With CLI flags:

```json
{
  "mcpServers": {
    "secureio": {
      "command": "npx",
      "args": ["secureio-mcp", "--preset", "strict", "--audit-output", "stderr"]
    }
  }
}
```

### VS Code with MCP Extension

Add the following to your VS Code `settings.json` (user or workspace level):

```json
{
  "mcp": {
    "servers": {
      "secureio": {
        "command": "npx",
        "args": ["secureio-mcp"]
      }
    }
  }
}
```

With CLI flags:

```json
{
  "mcp": {
    "servers": {
      "secureio": {
        "command": "npx",
        "args": ["secureio-mcp", "--preset", "strict", "--audit-output", "file"]
      }
    }
  }
}
```
