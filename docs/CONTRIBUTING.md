# Contributing to SecureIOMCP

Thank you for your interest in contributing to SecureIOMCP. This guide walks you through everything you need to get started, from setting up the project locally to submitting a pull request.

## Getting Started

### Prerequisites

- **Node.js** >= 20.0.0
- **npm**
- **git**

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/your-org/SecureIOMCP.git
   cd SecureIOMCP
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Build the project:

   ```bash
   npm run build
   ```

4. Run the test suite to verify everything works:

   ```bash
   npm test
   ```

## Project Structure

```
src/
  index.ts              # CLI entry point
  server.ts             # MCP server setup (registers all 10 tools)
  response.ts           # ResponseBuilder for enforcing response limits
  config/
    defaults.ts         # Preset limit definitions
    loader.ts           # Configuration loading and merging
  security/
    index.ts            # Security module re-exports
    middleware.ts        # Central security orchestrator
    path-resolver.ts    # Path traversal prevention
    access-control.ts   # Denylist + gitignore enforcement
    redaction-engine.ts # Secret detection and masking
    patterns.ts         # Built-in pattern library
    audit-logger.ts     # Structured audit logging
    encoding-detector.ts # Encoding detection + binary check
  types/
    index.ts            # Type re-exports
    config.ts           # Configuration interfaces
    errors.ts           # Error types
    response.ts         # Response interfaces
    patterns.ts         # Pattern interfaces
  tools/
    read/               # 5 read-only tool handlers
    write/              # 2 write tool handlers
    meta/               # 3 meta tool handlers
tests/
  unit/                 # Unit tests (mirrors src/ structure)
  integration/          # Integration tests
  security/             # Security-specific tests
  fixtures/             # Test data and corpora
```

## Development Workflow

1. Create a feature branch from `main`.
2. Make your changes.
3. Write tests that cover the new or modified behavior.
4. Run the full test suite:

   ```bash
   npm test
   ```

5. Run coverage to make sure thresholds are met:

   ```bash
   npm run test:coverage
   ```

6. Submit a pull request.

## Testing

- **Framework:** Vitest
- **Test commands:**

  | Command                      | Description                        |
  | ---------------------------- | ---------------------------------- |
  | `npm test`                   | Run the full test suite            |
  | `npm run test:unit`          | Run unit tests only                |
  | `npm run test:integration`   | Run integration tests only         |
  | `npm run test:security`      | Run security-specific tests        |
  | `npm run test:coverage`      | Run tests with coverage reporting  |

- **Coverage requirements:**
  - **90%** on `src/security/`
  - **80%** on `src/tools/`
  - **100%** on the known-safe allowlist
- **Test categories:** unit, integration, security (secret corpus), platform (cross-platform)

## Code Style

- TypeScript strict mode is enabled for the entire project.
- Use ESM modules (`import`/`export`) exclusively.
- No external binary dependencies -- the project is pure JavaScript with zero native binaries (no ripgrep, no native addons).
- Security-first: every file operation must go through `SecurityMiddleware`. Direct `fs` calls that bypass the middleware are not acceptable.
- CWE-209 compliance: error messages returned to agents must never expose absolute paths, the project root, or OS details.

## Adding a New Secret Pattern

1. Add the pattern to `src/security/patterns.ts` in the appropriate confidence array (`high`, `medium`, or `low`).
2. Add corresponding test cases to `tests/fixtures/secret-corpus.ts` that the pattern must detect.
3. Add false positive cases to `tests/fixtures/false-positive-corpus.ts` to verify the pattern does not over-match.
4. Run the self-test to validate the full corpus:

   ```bash
   npx secureio-mcp --self-test
   ```

## Adding a New Tool

1. Create the handler in the appropriate directory under `src/tools/` (`read/`, `write/`, or `meta/`).
2. Export the handler function from the new module.
3. Register the tool in `src/server.ts` with a Zod input schema.
4. Add unit tests under `tests/unit/` mirroring the source path.
5. Add integration tests under `tests/integration/`.

## Security Guidelines

- **Never expose absolute paths** in error messages returned to agents.
- **Always use SecurityMiddleware** for every file operation -- no direct filesystem access.
- **Scan write content for secrets** before writing to disk.
- **Log every operation** via the audit logger; the audit log lives in `.secureio/` and is on the immutable denylist so agents cannot tamper with it.
- **Denylist is extend-only** -- built-in entries (`.env`, `*.pem`, `.secureio/`, `.secureiorc`) must never be removed.
