# SecureIOMCP Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a TypeScript MCP server that provides AI agents with secure, token-efficient, read-write codebase access with redaction, access control, and audit logging.

**Architecture:** Three-layer design — Tool Router dispatches to Security Layer (path resolver, encoding detector, access control, redaction engine, audit logger) which wraps Read/Write/Meta tool handlers. Every operation flows through the security layer in both directions. See `docs/plans/2026-02-26-secureio-mcp-design.md` for the full design.

**Tech Stack:** TypeScript, Node.js, `@modelcontextprotocol/server`, Zod v4, `ignore` (gitignore parsing), Vitest

---

## Phase 1: Foundation

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `src/index.ts` (empty entry point)
- Create: `.gitignore`

**Step 1: Initialize npm project**

Run: `npm init -y`

Then replace `package.json` contents:

```json
{
  "name": "secureio-mcp",
  "version": "0.1.0",
  "description": "Secure, token-efficient MCP server for AI agent codebase access",
  "type": "module",
  "main": "dist/index.js",
  "bin": {
    "secureio-mcp": "dist/index.js"
  },
  "scripts": {
    "build": "tsc",
    "dev": "tsc --watch",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:unit": "vitest run tests/unit",
    "test:integration": "vitest run tests/integration",
    "test:security": "vitest run tests/security",
    "test:platform": "vitest run tests/platform",
    "test:coverage": "vitest run --coverage"
  },
  "keywords": ["mcp", "security", "govtech", "ai-agent"],
  "author": "Grant Mooney",
  "license": "MIT"
}
```

**Step 2: Install dependencies**

Run:
```bash
npm install @modelcontextprotocol/server zod ignore
npm install -D typescript vitest @vitest/coverage-v8 @types/node
```

Expected: packages install without errors.

**Step 3: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "Node16",
    "moduleResolution": "Node16",
    "outDir": "dist",
    "rootDir": "src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "resolveJsonModule": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

**Step 4: Create vitest.config.ts**

```typescript
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts'],
      thresholds: {
        'src/security/**': {
          lines: 90,
          functions: 90,
          branches: 85,
        },
      },
    },
  },
});
```

**Step 5: Create directory structure**

Run:
```bash
mkdir -p src/security src/tools/read src/tools/write src/tools/meta src/config src/types
mkdir -p tests/unit/security tests/unit/tools tests/integration tests/security tests/platform tests/performance tests/fixtures/test-repo
```

**Step 6: Create .gitignore**

```
node_modules/
dist/
.secureio/
*.tmp
coverage/
```

**Step 7: Create empty entry point**

Create `src/index.ts`:
```typescript
#!/usr/bin/env node
// SecureIOMCP - Secure MCP server for AI agent codebase access
// Entry point — will be implemented in Task 23
```

**Step 8: Verify build works**

Run: `npx tsc --noEmit`
Expected: no errors

**Step 9: Verify test runner works**

Create `tests/unit/smoke.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';

describe('smoke test', () => {
  it('should run', () => {
    expect(true).toBe(true);
  });
});
```

Run: `npm test`
Expected: 1 test passes

**Step 10: Commit**

```bash
git add -A
git commit -m "feat: project scaffolding with TypeScript, Vitest, MCP SDK"
```

---

### Task 2: Types & Interfaces

**Files:**
- Create: `src/types/config.ts`
- Create: `src/types/errors.ts`
- Create: `src/types/response.ts`
- Create: `src/types/patterns.ts`
- Create: `src/types/index.ts`

**Step 1: Write config types**

Create `src/types/config.ts`:
```typescript
export type Preset = 'standard' | 'strict';

export interface RedactionPattern {
  name: string;
  pattern: string;
  description: string;
  confidence: 'high' | 'medium' | 'entropy';
}

export interface DenylistConfig {
  extend: string[];
}

export interface RedactionConfig {
  customPatterns: RedactionPattern[];
}

export interface AuditConfig {
  output: 'file' | 'stdout' | 'none';
  path: string;
  required?: boolean;
  minimumOutput?: 'file' | 'stdout';
}

export interface LimitsConfig {
  maxResultCount: number;
  maxLineLength: number;
  maxResponseBytes: number;
  maxFileReadLines: number;
  maxWriteBytes: number;
  maxTreeDepth: number;
  maxAuditLogSizeMB: number;
}

export interface ProjectConfig {
  preset: Preset;
  projectRoot: string;
  denylist: DenylistConfig;
  redaction: RedactionConfig;
  audit: AuditConfig;
  limits: LimitsConfig;
}

export interface SystemPolicy {
  minimumPreset: Preset;
  denylist: DenylistConfig;
  redaction: RedactionConfig;
  audit: {
    required: boolean;
    minimumOutput: 'file' | 'stdout';
  };
}

export interface ResolvedConfig {
  preset: Preset;
  projectRoot: string;
  denylist: string[];
  redactionPatterns: RedactionPattern[];
  audit: AuditConfig;
  limits: LimitsConfig;
  entropyDetection: boolean;
}
```

**Step 2: Write error types**

Create `src/types/errors.ts`:
```typescript
export type ErrorCode =
  | 'PATH_DENIED'
  | 'SECRET_IN_WRITE'
  | 'INVALID_REGEX'
  | 'FILE_NOT_FOUND'
  | 'BINARY_FILE'
  | 'ENCODING_UNSUPPORTED'
  | 'SIZE_EXCEEDED'
  | 'HASH_MISMATCH'
  | 'CONFIG_ERROR'
  | 'INTERNAL_ERROR';

export interface SecureIOError {
  code: ErrorCode;
  message: string;
  suggestion?: string;
}

export type AuditSeverity = 'normal' | 'warning' | 'security';

export interface AuditLogEntry {
  timestamp: string;
  tool: string;
  params: Record<string, unknown>;
  redactions: AuditRedaction[];
  access_denied: boolean;
  severity: AuditSeverity;
  duration_ms: number;
  error?: ErrorCode;
}

export interface AuditRedaction {
  line: number;
  category: string;
  confidence: 'high' | 'medium' | 'entropy';
}
```

**Step 3: Write response types**

Create `src/types/response.ts`:
```typescript
export interface ResponseMeta {
  total: number;
  returned: number;
  offset: number;
  has_more: boolean;
  truncated_lines: number;
  redactions: number;
  bytes: number;
  constrained_by?: 'maxResultCount' | 'maxResponseBytes' | 'maxLineLength';
}

export interface SecureResponse<T> {
  results: T;
  meta: ResponseMeta;
}

export interface SearchResult {
  file: string;
  line: number;
  content: string;
  context_before: string[];
  context_after: string[];
  redacted: boolean;
}

export interface GlobResult {
  path: string;
  size: number;
}

export interface TreeEntry {
  name: string;
  type: 'file' | 'directory';
  children?: TreeEntry[];
  file_count?: number;
}

export interface ReadResult {
  path: string;
  content: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  redacted_lines: number[];
  encoding_detected: string;
}

export interface WriteResult {
  path: string;
  success: boolean;
  hash: string;
}

export interface PatchResult {
  path: string;
  success: boolean;
  changed_range: { start: number; end: number };
  hash: string;
}

export interface OverviewResult {
  name: string;
  framework: string | null;
  language: string | null;
  packageManager: string | null;
  entryPoints: string[];
  scripts: Record<string, string>;
  dependencyCount: number;
  devDependencyCount: number;
  structure: string;
  configFiles: string[];
}

export interface AuditResult {
  preset: string;
  files_blocked: number;
  secrets_detected: number;
  files_with_secrets: number;
  denylist_rules: number;
  custom_patterns: number;
  details?: AuditFileDetail[];
}

export interface AuditFileDetail {
  path: string;
  blocked: boolean;
  redactions: { line: number; category: string; confidence: string }[];
}

export interface SelfTestResult {
  passed: boolean;
  categories: SelfTestCategory[];
}

export interface SelfTestCategory {
  name: string;
  passed: boolean;
  total: number;
  failures: string[];
}
```

**Step 4: Write pattern types**

Create `src/types/patterns.ts`:
```typescript
export interface CompiledPattern {
  name: string;
  regex: RegExp;
  confidence: 'high' | 'medium' | 'entropy';
  description: string;
}

export interface RedactionMatch {
  start: number;
  end: number;
  category: string;
  confidence: 'high' | 'medium' | 'entropy';
}
```

**Step 5: Create barrel export**

Create `src/types/index.ts`:
```typescript
export * from './config.js';
export * from './errors.js';
export * from './response.js';
export * from './patterns.js';
```

**Step 6: Verify types compile**

Run: `npx tsc --noEmit`
Expected: no errors

**Step 7: Commit**

```bash
git add src/types/
git commit -m "feat: add type definitions for config, errors, responses, patterns"
```

---

### Task 3: Test Fixtures

**Files:**
- Create: `tests/fixtures/secret-corpus.ts`
- Create: `tests/fixtures/false-positive-corpus.ts`
- Create: `tests/fixtures/traversal-corpus.ts`
- Create: `tests/fixtures/test-repo/` (directory with planted secrets)

**Step 1: Create secret corpus**

Create `tests/fixtures/secret-corpus.ts`:
```typescript
/** Each entry: [category, test_value, confidence_level] */
export const SECRET_CORPUS: [string, string, string][] = [
  // High confidence — distinct prefixes
  ['AWS_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE', 'high'],
  ['AWS_ACCESS_KEY', 'AKIA1234567890ABCDEF', 'high'],
  ['AWS_ACCESS_KEY', 'AKIAZ26MRUQLEXAMPLE1', 'high'],
  ['GITHUB_TOKEN', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl', 'high'],
  ['GITHUB_TOKEN', 'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl', 'high'],
  ['GITHUB_FINE_GRAINED_TOKEN', 'github_pat_' + 'A'.repeat(82), 'high'],
  ['STRIPE_LIVE_KEY', 'sk_live_abcdefghijklmnopqrstuvwx', 'high'],
  ['STRIPE_PUBLISHABLE_KEY', 'pk_live_abcdefghijklmnopqrstuvwx', 'high'],
  ['SLACK_WEBHOOK', 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx', 'high'],
  ['SENDGRID_KEY', 'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789_abcde', 'high'],
  ['TWILIO_AUTH_TOKEN', 'SK0123456789abcdef0123456789abcdef', 'high'],
  ['PRIVATE_KEY_BLOCK', '-----BEGIN RSA PRIVATE KEY-----', 'high'],
  ['PRIVATE_KEY_BLOCK', '-----BEGIN EC PRIVATE KEY-----', 'high'],
  ['JWT', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'high'],

  // Medium confidence — context-anchored
  ['AWS_SECRET_KEY', 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'medium'],
  ['AWS_SECRET_KEY', "aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", 'medium'],
  ['AZURE_STORAGE_KEY', 'AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv==', 'medium'],
  ['CONNECTION_STRING', 'postgres://admin:s3cretP@ss@db.example.com:5432/mydb', 'medium'],
  ['CONNECTION_STRING', 'mongodb://user:password123@mongo.example.com:27017/app', 'medium'],
  ['CONNECTION_STRING', 'redis://default:mypassword@redis.example.com:6379', 'medium'],
  ['CONNECTION_STRING', 'amqp://guest:guest@rabbitmq.example.com:5672', 'medium'],
  ['GENERIC_API_KEY', 'api_key = "sk_test_abcdef123456789abcdef"', 'medium'],
  ['GENERIC_API_KEY', 'secret_key: "my-super-secret-key-value"', 'medium'],
  ['GENERIC_API_KEY', 'auth_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"', 'medium'],
  ['GENERIC_SECRET', 'password = "MyS3cur3P@ssw0rd!"', 'medium'],
  ['GENERIC_SECRET', "token: 'a1b2c3d4e5f6g7h8i9j0klmnopqrstuv'", 'medium'],
  ['GENERIC_SECRET', 'credential = "super-secret-credential-value"', 'medium'],
];

/** Lines containing secrets for integration testing */
export const LINES_WITH_SECRETS = [
  'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
  'const apiKey = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";',
  'DATABASE_URL=postgres://admin:s3cretP@ss@db.example.com:5432/mydb',
  '-----BEGIN RSA PRIVATE KEY-----',
  'STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx',
  'password = "MyS3cur3P@ssw0rd!"',
];
```

**Step 2: Create false positive corpus**

Create `tests/fixtures/false-positive-corpus.ts`:
```typescript
/** Strings that look like secrets but SHOULD NOT be redacted */
export const FALSE_POSITIVE_CORPUS: [string, string][] = [
  // UUIDs
  ['UUID', '550e8400-e29b-41d4-a716-446655440000'],
  ['UUID', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'],
  ['UUID', '6ba7b810-9dad-11d1-80b4-00c04fd430c8'],

  // Git commit SHAs
  ['GIT_SHA', 'commit abc123def456789012345678901234567890abcd'],
  ['GIT_SHA', 'ref: abc123def456789012345678901234567890abcd'],

  // Common code patterns
  ['IMPORT_PATH', "import { something } from '@my-org/my-package';"],
  ['HASH_CONSTANT', 'const ALGORITHM = "SHA-256";'],
  ['BASE64_TEST_DATA', '// Test: atob("SGVsbG8gV29ybGQ=")'],
  ['HEX_COLOR', 'color: #AABBCCDD;'],
  ['LONG_CLASS_NAME', 'class MyVeryLongClassNameThatExceedsTwentyCharacters {}'],

  // Variable names that contain "secret"/"password" but no values
  ['VAR_NAME_ONLY', 'const passwordField = document.getElementById("password");'],
  ['VAR_NAME_ONLY', 'function validatePassword(input: string): boolean {'],
  ['VAR_NAME_ONLY', 'export interface SecretConfig {'],

  // Short values that should not trigger
  ['SHORT_VALUE', 'token = "abc"'],
  ['SHORT_VALUE', 'password = "test"'],

  // URLs without credentials
  ['PLAIN_URL', 'https://api.example.com/v1/users'],
  ['PLAIN_URL', 'mongodb://localhost:27017/testdb'],

  // Lockfile hashes
  ['LOCKFILE_HASH', '"integrity": "sha512-abc123def456789012345678901234567890abcdefghijklmnopqrstuvwxyz012345678901234567890"'],
];
```

**Step 3: Create traversal corpus**

Create `tests/fixtures/traversal-corpus.ts`:
```typescript
/** Path traversal attack strings — all should be rejected */
export const TRAVERSAL_CORPUS: string[] = [
  // Basic traversals
  '../etc/passwd',
  '../../etc/passwd',
  '../../../../../../../etc/passwd',

  // Backslash variants (Windows)
  '..\\etc\\passwd',
  '..\\..\\..\\Windows\\System32\\config\\SAM',

  // Mixed separators
  '../..\\etc/passwd',
  '..\\../etc\\passwd',

  // Encoded dots
  '%2e%2e/etc/passwd',
  '%2e%2e%2fetc%2fpasswd',
  '..%2fetc%2fpasswd',

  // Null byte injection
  '../etc/passwd\x00.txt',
  'safe-file.txt\x00../../etc/passwd',

  // Unicode normalization
  '..\\u002f..\\u002fetc/passwd',

  // Windows device names (should be rejected)
  'CON',
  'PRN',
  'AUX',
  'NUL',
  'COM1',
  'LPT1',
  'CON.txt',
  'NUL.js',

  // Absolute paths (escape attempts)
  '/etc/passwd',
  'C:\\Windows\\System32\\config\\SAM',
  '\\\\server\\share\\file',

  // Dot-only paths
  '.',
  '..',
  '...',

  // Hidden git internals
  '.git/config',
  '.git/objects/pack/pack-abc123.pack',
  '.git/refs/heads/main',
  '.git/HEAD',

  // Protected paths
  '.env',
  '.env.local',
  '.env.production',
  '.aws/credentials',
  '.ssh/id_rsa',
  '.secureio/audit.log',
  '.secureiorc',
];
```

**Step 4: Create test repo structure**

Create the following files in `tests/fixtures/test-repo/`:

`tests/fixtures/test-repo/src/index.ts`:
```typescript
// Entry point
export function main() {
  console.log('Hello');
}
```

`tests/fixtures/test-repo/src/config.ts`:
```typescript
// This file has planted secrets for testing
export const config = {
  apiUrl: 'https://api.example.com',
  apiKey: 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl',
  database: 'postgres://admin:s3cretP@ss@db.example.com:5432/mydb',
  debug: false,
};
```

`tests/fixtures/test-repo/src/clean.ts`:
```typescript
// This file has no secrets
export function add(a: number, b: number): number {
  return a + b;
}

export function greet(name: string): string {
  return `Hello, ${name}!`;
}
```

`tests/fixtures/test-repo/.env`:
```
DB_PASSWORD=super_secret_password
API_KEY=sk_live_abcdefghijklmnopqrstuvwx
```

`tests/fixtures/test-repo/.gitignore`:
```
node_modules/
dist/
*.log
```

`tests/fixtures/test-repo/package.json`:
```json
{
  "name": "test-repo",
  "version": "1.0.0",
  "scripts": {
    "build": "tsc",
    "test": "vitest",
    "start": "node dist/index.js"
  },
  "dependencies": {
    "express": "^4.18.0",
    "pg": "^8.11.0"
  },
  "devDependencies": {
    "typescript": "^5.3.0",
    "vitest": "^1.0.0"
  }
}
```

**Step 5: Verify fixtures load**

Create `tests/unit/fixtures.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { SECRET_CORPUS } from '../fixtures/secret-corpus.js';
import { FALSE_POSITIVE_CORPUS } from '../fixtures/false-positive-corpus.js';
import { TRAVERSAL_CORPUS } from '../fixtures/traversal-corpus.js';

describe('test fixtures', () => {
  it('secret corpus has entries', () => {
    expect(SECRET_CORPUS.length).toBeGreaterThan(20);
  });

  it('false positive corpus has entries', () => {
    expect(FALSE_POSITIVE_CORPUS.length).toBeGreaterThan(10);
  });

  it('traversal corpus has entries', () => {
    expect(TRAVERSAL_CORPUS.length).toBeGreaterThan(20);
  });
});
```

Run: `npm test`
Expected: all tests pass

**Step 6: Commit**

```bash
git add tests/fixtures/ tests/unit/fixtures.test.ts
git commit -m "feat: add test fixtures — secret corpus, false positives, traversal attacks, test repo"
```

---

## Phase 2: Security Layer

### Task 4: Path Resolver

**Files:**
- Create: `src/security/path-resolver.ts`
- Create: `tests/unit/security/path-resolver.test.ts`

**Step 1: Write the failing tests**

Create `tests/unit/security/path-resolver.test.ts`:
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { PathResolver } from '../../../src/security/path-resolver.js';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';

describe('PathResolver', () => {
  let resolver: PathResolver;
  const projectRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    resolver = new PathResolver(projectRoot);
  });

  describe('valid paths', () => {
    it('resolves relative paths within project root', () => {
      const result = resolver.resolve('src/index.ts');
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.path).toBe(path.join(projectRoot, 'src', 'index.ts'));
      }
    });

    it('resolves nested paths', () => {
      const result = resolver.resolve('src/config.ts');
      expect(result.ok).toBe(true);
    });

    it('resolves paths with ./ prefix', () => {
      const result = resolver.resolve('./src/index.ts');
      expect(result.ok).toBe(true);
    });
  });

  describe('traversal attacks', () => {
    it('rejects basic ../ traversal', () => {
      const result = resolver.resolve('../etc/passwd');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe('PATH_DENIED');
        // Must NOT contain resolved path or project root
        expect(result.error.message).not.toContain(projectRoot);
        expect(result.error.message).not.toContain('/etc/passwd');
      }
    });

    it('rejects deeply nested traversal', () => {
      const result = resolver.resolve('../../../../../../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('rejects null bytes', () => {
      const result = resolver.resolve('safe.txt\x00../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('rejects absolute paths', () => {
      const result = resolver.resolve('/etc/passwd');
      expect(result.ok).toBe(false);
    });

    if (os.platform() === 'win32') {
      it('rejects Windows absolute paths', () => {
        const result = resolver.resolve('C:\\Windows\\System32\\config\\SAM');
        expect(result.ok).toBe(false);
      });

      it('rejects UNC paths', () => {
        const result = resolver.resolve('\\\\server\\share\\file');
        expect(result.ok).toBe(false);
      });

      it('rejects Windows device names', () => {
        for (const name of ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'LPT1']) {
          const result = resolver.resolve(name);
          expect(result.ok).toBe(false);
        }
      });
    }
  });

  describe('.git internals', () => {
    it('rejects .git/config', () => {
      const result = resolver.resolve('.git/config');
      expect(result.ok).toBe(false);
    });

    it('rejects .git/objects', () => {
      const result = resolver.resolve('.git/objects/pack/something.pack');
      expect(result.ok).toBe(false);
    });

    it('rejects .git/HEAD', () => {
      const result = resolver.resolve('.git/HEAD');
      expect(result.ok).toBe(false);
    });
  });

  describe('backslash normalization', () => {
    it('normalizes backslashes to forward slashes', () => {
      const result = resolver.resolve('src\\index.ts');
      expect(result.ok).toBe(true);
    });
  });

  describe('error sanitization', () => {
    it('never leaks project root in error messages', () => {
      const result = resolver.resolve('../../secret');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).not.toContain(projectRoot);
        expect(JSON.stringify(result.error)).not.toContain(projectRoot);
      }
    });

    it('never leaks resolved path in error messages', () => {
      const result = resolver.resolve('../../../etc/passwd');
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.message).not.toContain('etc/passwd');
      }
    });
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm run test:unit -- tests/unit/security/path-resolver.test.ts`
Expected: FAIL — module not found

**Step 3: Write the implementation**

Create `src/security/path-resolver.ts`:
```typescript
import path from 'node:path';
import os from 'node:os';
import { SecureIOError } from '../types/errors.js';

const WINDOWS_DEVICE_NAMES = new Set([
  'CON', 'PRN', 'AUX', 'NUL',
  'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
  'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
]);

export type PathResult =
  | { ok: true; path: string }
  | { ok: false; error: SecureIOError };

export class PathResolver {
  private readonly root: string;

  constructor(projectRoot: string) {
    this.root = path.resolve(projectRoot);
  }

  resolve(inputPath: string): PathResult {
    // Reject null bytes
    if (inputPath.includes('\x00')) {
      return this.denied();
    }

    // Normalize backslashes
    const normalized = inputPath.replace(/\\/g, '/');

    // Reject absolute paths
    if (path.isAbsolute(normalized) || normalized.startsWith('//')) {
      return this.denied();
    }

    // Reject UNC paths (Windows)
    if (inputPath.startsWith('\\\\')) {
      return this.denied();
    }

    // Reject Windows drive letters
    if (/^[a-zA-Z]:/.test(inputPath)) {
      return this.denied();
    }

    // Reject Windows device names
    const baseName = path.basename(normalized).split('.')[0].toUpperCase();
    if (WINDOWS_DEVICE_NAMES.has(baseName)) {
      return this.denied();
    }

    // Reject .git internals
    const parts = normalized.split('/');
    if (parts.some((p, i) => p === '.git')) {
      return this.denied();
    }

    // Resolve to absolute path
    const resolved = path.resolve(this.root, normalized);

    // Verify the resolved path is within the project root
    const normalizedResolved = resolved.toLowerCase();
    const normalizedRoot = this.root.toLowerCase();
    if (!normalizedResolved.startsWith(normalizedRoot + path.sep) &&
        normalizedResolved !== normalizedRoot) {
      return this.denied();
    }

    return { ok: true, path: resolved };
  }

  /** Resolve with symlink/realpath check (async — for actual file access) */
  async resolveReal(inputPath: string): Promise<PathResult> {
    const initial = this.resolve(inputPath);
    if (!initial.ok) return initial;

    try {
      const { realpath } = await import('node:fs/promises');
      const real = await realpath(initial.path);
      const normalizedReal = real.toLowerCase();
      const normalizedRoot = this.root.toLowerCase();

      if (!normalizedReal.startsWith(normalizedRoot + path.sep) &&
          normalizedReal !== normalizedRoot) {
        return this.denied();
      }

      return { ok: true, path: real };
    } catch (err: unknown) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'ELOOP') {
        return this.denied();
      }
      if (code === 'ENOENT') {
        // File doesn't exist yet (valid for write operations)
        // Return the resolved path without realpath
        return initial;
      }
      return this.denied();
    }
  }

  getRoot(): string {
    return this.root;
  }

  private denied(): PathResult {
    return {
      ok: false,
      error: {
        code: 'PATH_DENIED',
        message: 'The requested path is not accessible',
        suggestion: 'Use secure_tree to discover available paths within the project.',
      },
    };
  }
}
```

**Step 4: Run tests to verify they pass**

Run: `npm run test:unit -- tests/unit/security/path-resolver.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/security/path-resolver.ts tests/unit/security/path-resolver.test.ts
git commit -m "feat: add path resolver with traversal prevention and error sanitization"
```

---

### Task 5: Encoding Detector

**Files:**
- Create: `src/security/encoding-detector.ts`
- Create: `tests/unit/security/encoding-detector.test.ts`

**Step 1: Write the failing tests**

Create `tests/unit/security/encoding-detector.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { detectEncoding, transcodeToUtf8 } from '../../../src/security/encoding-detector.js';

describe('Encoding Detector', () => {
  describe('detectEncoding', () => {
    it('detects UTF-8 BOM', () => {
      const buf = Buffer.from([0xEF, 0xBB, 0xBF, 0x48, 0x65, 0x6C, 0x6C, 0x6F]);
      expect(detectEncoding(buf)).toBe('utf-8-bom');
    });

    it('detects UTF-16LE BOM', () => {
      const buf = Buffer.from([0xFF, 0xFE, 0x48, 0x00, 0x65, 0x00]);
      expect(detectEncoding(buf)).toBe('utf-16le');
    });

    it('detects UTF-16BE BOM', () => {
      const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x65]);
      expect(detectEncoding(buf)).toBe('utf-16be');
    });

    it('defaults to UTF-8 without BOM', () => {
      const buf = Buffer.from('Hello, world!', 'utf-8');
      expect(detectEncoding(buf)).toBe('utf-8');
    });

    it('handles empty buffer', () => {
      const buf = Buffer.alloc(0);
      expect(detectEncoding(buf)).toBe('utf-8');
    });
  });

  describe('transcodeToUtf8', () => {
    it('passes through UTF-8 content unchanged', () => {
      const buf = Buffer.from('Hello, world!', 'utf-8');
      expect(transcodeToUtf8(buf)).toBe('Hello, world!');
    });

    it('strips UTF-8 BOM', () => {
      const buf = Buffer.from([0xEF, 0xBB, 0xBF, ...Buffer.from('Hello')]);
      expect(transcodeToUtf8(buf)).toBe('Hello');
    });

    it('transcodes UTF-16LE to UTF-8', () => {
      const buf = Buffer.from([0xFF, 0xFE, ...Buffer.from('Hello', 'utf16le')]);
      expect(transcodeToUtf8(buf)).toBe('Hello');
    });

    it('transcodes UTF-16BE to UTF-8', () => {
      // UTF-16BE BOM + "Hi" in UTF-16BE
      const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69]);
      expect(transcodeToUtf8(buf)).toBe('Hi');
    });
  });

  describe('isBinary', () => {
    // Import isBinary from the module
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm run test:unit -- tests/unit/security/encoding-detector.test.ts`
Expected: FAIL

**Step 3: Write the implementation**

Create `src/security/encoding-detector.ts`:
```typescript
export type DetectedEncoding = 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be';

export function detectEncoding(buffer: Buffer): DetectedEncoding {
  if (buffer.length >= 3 &&
      buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
    return 'utf-8-bom';
  }
  if (buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xFE) {
    return 'utf-16le';
  }
  if (buffer.length >= 2 && buffer[0] === 0xFE && buffer[1] === 0xFF) {
    return 'utf-16be';
  }
  return 'utf-8';
}

export function transcodeToUtf8(buffer: Buffer): string {
  const encoding = detectEncoding(buffer);

  switch (encoding) {
    case 'utf-8-bom':
      return buffer.subarray(3).toString('utf-8');
    case 'utf-16le':
      return buffer.subarray(2).toString('utf16le');
    case 'utf-16be': {
      // Node.js doesn't have native UTF-16BE, swap bytes to LE
      const content = buffer.subarray(2);
      const swapped = Buffer.alloc(content.length);
      for (let i = 0; i < content.length - 1; i += 2) {
        swapped[i] = content[i + 1];
        swapped[i + 1] = content[i];
      }
      return swapped.toString('utf16le');
    }
    default:
      return buffer.toString('utf-8');
  }
}

/** Check if buffer contains binary content (non-text) */
export function isBinary(buffer: Buffer): boolean {
  // Check first 512 bytes for null bytes or control characters
  const checkLength = Math.min(buffer.length, 512);
  for (let i = 0; i < checkLength; i++) {
    const byte = buffer[i];
    // Null byte is strong indicator of binary
    if (byte === 0x00) {
      // Exception: UTF-16 encoded files have null bytes
      const encoding = detectEncoding(buffer);
      if (encoding === 'utf-16le' || encoding === 'utf-16be') return false;
      return true;
    }
  }
  return false;
}
```

**Step 4: Run tests to verify they pass**

Run: `npm run test:unit -- tests/unit/security/encoding-detector.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/security/encoding-detector.ts tests/unit/security/encoding-detector.test.ts
git commit -m "feat: add encoding detector with BOM detection and UTF-16 transcoding"
```

---

### Task 6: Redaction Engine — High Confidence Patterns

**Files:**
- Create: `src/security/patterns.ts`
- Create: `src/security/redaction-engine.ts`
- Create: `tests/unit/security/redaction-engine.test.ts`

**Step 1: Write the pattern definitions**

Create `src/security/patterns.ts`:
```typescript
import { CompiledPattern } from '../types/patterns.js';

export const HIGH_CONFIDENCE_PATTERNS: CompiledPattern[] = [
  {
    name: 'AWS_ACCESS_KEY',
    regex: /AKIA[0-9A-Z]{16}/g,
    confidence: 'high',
    description: 'AWS access key ID',
  },
  {
    name: 'GITHUB_TOKEN',
    regex: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    confidence: 'high',
    description: 'GitHub personal access or server token',
  },
  {
    name: 'GITHUB_FINE_GRAINED_TOKEN',
    regex: /github_pat_[A-Za-z0-9_]{82,}/g,
    confidence: 'high',
    description: 'GitHub fine-grained personal access token',
  },
  {
    name: 'STRIPE_LIVE_KEY',
    regex: /sk_live_[A-Za-z0-9]{24,}/g,
    confidence: 'high',
    description: 'Stripe live secret key',
  },
  {
    name: 'STRIPE_PUBLISHABLE_KEY',
    regex: /pk_live_[A-Za-z0-9]{24,}/g,
    confidence: 'high',
    description: 'Stripe live publishable key',
  },
  {
    name: 'SLACK_WEBHOOK',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    confidence: 'high',
    description: 'Slack incoming webhook URL',
  },
  {
    name: 'SENDGRID_KEY',
    regex: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    confidence: 'high',
    description: 'SendGrid API key',
  },
  {
    name: 'TWILIO_AUTH_TOKEN',
    regex: /SK[0-9a-f]{32}/g,
    confidence: 'high',
    description: 'Twilio API key SID',
  },
  {
    name: 'PRIVATE_KEY_BLOCK',
    regex: /-----BEGIN [A-Z ]+PRIVATE KEY-----/g,
    confidence: 'high',
    description: 'PEM private key header',
  },
  {
    name: 'JWT',
    regex: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    confidence: 'high',
    description: 'JSON Web Token',
  },
];

export const MEDIUM_CONFIDENCE_PATTERNS: CompiledPattern[] = [
  {
    name: 'AWS_SECRET_KEY',
    regex: /(?<=aws_secret_access_key\s*[=:]\s*['"]?)[A-Za-z0-9/+=]{40}/gi,
    confidence: 'medium',
    description: 'AWS secret access key (context-anchored)',
  },
  {
    name: 'AZURE_STORAGE_KEY',
    regex: /(?<=AccountKey=)[A-Za-z0-9+/]{86}==/g,
    confidence: 'medium',
    description: 'Azure storage account key (context-anchored)',
  },
  {
    name: 'CONNECTION_STRING',
    regex: /(mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+@[^\s'"]+/g,
    confidence: 'medium',
    description: 'Database connection string with credentials',
  },
  {
    name: 'GENERIC_API_KEY',
    regex: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[=:]\s*['"][^\s'"]{8,}['"]/gi,
    confidence: 'medium',
    description: 'API key or secret assigned to recognized variable name',
  },
  {
    name: 'GENERIC_SECRET',
    regex: /(?:password|passwd|token|secret|credential)\s*[=:]\s*['"][^\s'"]{8,}['"]/gi,
    confidence: 'medium',
    description: 'Secret value assigned to recognized variable name',
  },
];

/** Known-safe patterns exempt from entropy detection */
export const SAFE_PATTERNS: RegExp[] = [
  // UUIDs
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
  // Git SHAs on lines with git context
  /(?:commit|ref|sha|hash)\s*[=:]*\s*[0-9a-f]{40}/gi,
];
```

**Step 2: Write the redaction engine**

Create `src/security/redaction-engine.ts`:
```typescript
import { CompiledPattern, RedactionMatch } from '../types/patterns.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS, SAFE_PATTERNS } from './patterns.js';

export interface RedactResult {
  text: string;
  matches: RedactionMatch[];
}

export class RedactionEngine {
  private patterns: CompiledPattern[];
  private entropyEnabled: boolean;
  private safePatterns: RegExp[];

  constructor(options: {
    entropyDetection: boolean;
    customPatterns?: CompiledPattern[];
  }) {
    this.patterns = [
      ...HIGH_CONFIDENCE_PATTERNS,
      ...MEDIUM_CONFIDENCE_PATTERNS,
      ...(options.customPatterns ?? []),
    ];
    this.entropyEnabled = options.entropyDetection;
    this.safePatterns = [...SAFE_PATTERNS];
  }

  redactLine(line: string): RedactResult {
    const matches: RedactionMatch[] = [];
    let result = line;

    // Apply pattern-based detection (high + medium confidence)
    for (const pattern of this.patterns) {
      // Reset regex lastIndex for global patterns
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(result)) !== null) {
        const replacement = `[REDACTED:${pattern.name}]`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: pattern.name,
          confidence: pattern.confidence,
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        // Adjust regex position for replacement
        regex.lastIndex = match.index + replacement.length;
      }
    }

    // Apply entropy-based detection if enabled
    if (this.entropyEnabled) {
      result = this.redactHighEntropy(result, matches);
    }

    return { text: result, matches };
  }

  private redactHighEntropy(line: string, matches: RedactionMatch[]): string {
    // Find unquoted high-entropy strings (20+ chars, alphanumeric + special)
    const tokenRegex = /['"][A-Za-z0-9+/=_\-]{20,}['"]/g;
    let result = line;
    let match: RegExpExecArray | null;

    // Reset regex
    const regex = new RegExp(tokenRegex.source, tokenRegex.flags);

    while ((match = regex.exec(result)) !== null) {
      const token = match[0].slice(1, -1); // strip quotes

      // Skip if already redacted
      if (token.startsWith('[REDACTED:')) continue;

      // Skip known-safe patterns
      if (this.isSafe(token, result)) continue;

      const entropy = this.shannonEntropy(token);
      if (entropy > 4.5) {
        const replacement = `"[REDACTED:HIGH_ENTROPY]"`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: 'HIGH_ENTROPY',
          confidence: 'entropy',
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        regex.lastIndex = match.index + replacement.length;
      }
    }

    return result;
  }

  private isSafe(token: string, line: string): boolean {
    for (const safe of this.safePatterns) {
      const regex = new RegExp(safe.source, safe.flags);
      if (regex.test(token) || regex.test(line)) {
        return true;
      }
    }
    return false;
  }

  shannonEntropy(str: string): number {
    if (str.length === 0) return 0;
    const freq = new Map<string, number>();
    for (const char of str) {
      freq.set(char, (freq.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
```

**Step 3: Write the tests**

Create `tests/unit/security/redaction-engine.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { RedactionEngine } from '../../../src/security/redaction-engine.js';
import { SECRET_CORPUS } from '../../fixtures/secret-corpus.js';
import { FALSE_POSITIVE_CORPUS } from '../../fixtures/false-positive-corpus.js';

describe('RedactionEngine', () => {
  const engine = new RedactionEngine({ entropyDetection: true });
  const engineNoEntropy = new RedactionEngine({ entropyDetection: false });

  describe('high confidence patterns', () => {
    const highConfidence = SECRET_CORPUS.filter(([, , c]) => c === 'high');

    for (const [category, testValue] of highConfidence) {
      it(`catches ${category}: ${testValue.substring(0, 30)}...`, () => {
        const result = engine.redactLine(testValue);
        expect(result.text).toContain('[REDACTED:');
        expect(result.matches.length).toBeGreaterThan(0);
      });
    }
  });

  describe('medium confidence patterns', () => {
    const mediumConfidence = SECRET_CORPUS.filter(([, , c]) => c === 'medium');

    for (const [category, testValue] of mediumConfidence) {
      it(`catches ${category}: ${testValue.substring(0, 40)}...`, () => {
        const result = engine.redactLine(testValue);
        expect(result.text).toContain('[REDACTED:');
        expect(result.matches.length).toBeGreaterThan(0);
      });
    }
  });

  describe('false positive prevention', () => {
    for (const [category, testValue] of FALSE_POSITIVE_CORPUS) {
      it(`does not redact ${category}: ${testValue.substring(0, 40)}...`, () => {
        const result = engineNoEntropy.redactLine(testValue);
        expect(result.matches.length).toBe(0);
      });
    }
  });

  describe('output format', () => {
    it('replaces secrets with [REDACTED:CATEGORY]', () => {
      const result = engine.redactLine('key=AKIAIOSFODNN7EXAMPLE');
      expect(result.text).toBe('key=[REDACTED:AWS_ACCESS_KEY]');
    });

    it('handles multiple secrets on one line', () => {
      const line = 'AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl';
      const result = engine.redactLine(line);
      expect(result.matches.length).toBe(2);
      expect(result.text).toContain('[REDACTED:AWS_ACCESS_KEY]');
      expect(result.text).toContain('[REDACTED:GITHUB_TOKEN]');
    });
  });

  describe('entropy detection', () => {
    it('catches high-entropy strings when enabled', () => {
      const line = 'secret = "aB3$dE6fG8hI0jK2lM4nO6pQ8rS0tU2vW4xY6z"';
      const result = engine.redactLine(line);
      // Should be caught by either GENERIC_SECRET pattern or entropy
      expect(result.matches.length).toBeGreaterThan(0);
    });

    it('does not catch high-entropy when disabled', () => {
      // Use a value that won't match any named pattern
      const line = 'data = "xK9mP2vL7nQ4wR8jT3yU6bA1cF5gH0iD"';
      const noEntropy = engineNoEntropy.redactLine(line);
      const withEntropy = engine.redactLine(line);
      // With entropy should catch more or equal
      expect(withEntropy.matches.length).toBeGreaterThanOrEqual(
        noEntropy.matches.length
      );
    });
  });

  describe('shannon entropy calculation', () => {
    it('returns 0 for empty string', () => {
      expect(engine.shannonEntropy('')).toBe(0);
    });

    it('returns 0 for single-char string', () => {
      expect(engine.shannonEntropy('aaaa')).toBe(0);
    });

    it('returns high entropy for random-looking strings', () => {
      expect(engine.shannonEntropy('aB3$dE6fG8hI0jK2lM4nO6pQ8r')).toBeGreaterThan(4.0);
    });

    it('returns low entropy for repetitive strings', () => {
      expect(engine.shannonEntropy('aaabbbccc')).toBeLessThan(2.0);
    });
  });

  describe('edge cases', () => {
    it('handles empty string', () => {
      const result = engine.redactLine('');
      expect(result.text).toBe('');
      expect(result.matches).toEqual([]);
    });

    it('handles string with no secrets', () => {
      const result = engine.redactLine('const x = 42;');
      expect(result.text).toBe('const x = 42;');
      expect(result.matches).toEqual([]);
    });
  });
});
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/security/redaction-engine.test.ts`
Expected: all tests pass. Some false-positive tests may need iteration — adjust the engine or corpus as needed until all pass.

**Step 5: Commit**

```bash
git add src/security/patterns.ts src/security/redaction-engine.ts tests/unit/security/redaction-engine.test.ts
git commit -m "feat: add redaction engine with high/medium confidence patterns and entropy detection"
```

---

### Task 7: Access Control (Denylist + Gitignore)

**Files:**
- Create: `src/security/access-control.ts`
- Create: `tests/unit/security/access-control.test.ts`

**Step 1: Write the failing tests**

Create `tests/unit/security/access-control.test.ts`:
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { AccessControl } from '../../../src/security/access-control.js';
import path from 'node:path';

describe('AccessControl', () => {
  const testRepoRoot = path.resolve('tests/fixtures/test-repo');

  describe('immutable denylist', () => {
    let ac: AccessControl;

    beforeEach(() => {
      ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
    });

    it('blocks .env', () => {
      expect(ac.isAllowed('.env')).toBe(false);
    });

    it('blocks .env.local', () => {
      expect(ac.isAllowed('.env.local')).toBe(false);
    });

    it('blocks .env.production', () => {
      expect(ac.isAllowed('.env.production')).toBe(false);
    });

    it('blocks *.pem files', () => {
      expect(ac.isAllowed('certs/server.pem')).toBe(false);
    });

    it('blocks *.key files', () => {
      expect(ac.isAllowed('ssl/private.key')).toBe(false);
    });

    it('blocks *.p12 files', () => {
      expect(ac.isAllowed('certs/client.p12')).toBe(false);
    });

    it('blocks *.pfx files', () => {
      expect(ac.isAllowed('certs/client.pfx')).toBe(false);
    });

    it('blocks credentials.json', () => {
      expect(ac.isAllowed('credentials.json')).toBe(false);
    });

    it('blocks secrets.yaml', () => {
      expect(ac.isAllowed('secrets.yaml')).toBe(false);
    });

    it('blocks .aws/ directory', () => {
      expect(ac.isAllowed('.aws/credentials')).toBe(false);
    });

    it('blocks .ssh/ directory', () => {
      expect(ac.isAllowed('.ssh/id_rsa')).toBe(false);
    });

    it('blocks .gnupg/ directory', () => {
      expect(ac.isAllowed('.gnupg/secring.gpg')).toBe(false);
    });

    it('blocks .secureio/ directory (tamper protection)', () => {
      expect(ac.isAllowed('.secureio/audit.log')).toBe(false);
    });

    it('blocks .secureiorc (config protection)', () => {
      expect(ac.isAllowed('.secureiorc')).toBe(false);
    });

    it('allows normal source files', () => {
      expect(ac.isAllowed('src/index.ts')).toBe(true);
    });

    it('allows package.json', () => {
      expect(ac.isAllowed('package.json')).toBe(true);
    });
  });

  describe('gitignore integration', () => {
    let ac: AccessControl;

    beforeEach(() => {
      ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
    });

    it('blocks files matched by .gitignore', () => {
      // test-repo/.gitignore has node_modules/ and dist/
      expect(ac.isAllowed('node_modules/express/index.js')).toBe(false);
      expect(ac.isAllowed('dist/index.js')).toBe(false);
    });

    it('allows files not in .gitignore', () => {
      expect(ac.isAllowed('src/index.ts')).toBe(true);
    });
  });

  describe('extend-only denylist', () => {
    it('applies custom extensions', () => {
      const ac = new AccessControl(testRepoRoot, {
        extendDenylist: ['*.tfvars', 'internal/**'],
      });
      expect(ac.isAllowed('main.tfvars')).toBe(false);
      expect(ac.isAllowed('internal/config.json')).toBe(false);
    });

    it('cannot remove built-in rules via extension', () => {
      const ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
      // Even with empty extensions, built-ins are active
      expect(ac.isAllowed('.env')).toBe(false);
    });
  });

  describe('files on denylist but allowed by gitignore', () => {
    it('denylist takes precedence over gitignore allowance', () => {
      const ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
      // .env is not in .gitignore in our test repo, but is on denylist
      expect(ac.isAllowed('.env')).toBe(false);
    });
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm run test:unit -- tests/unit/security/access-control.test.ts`
Expected: FAIL

**Step 3: Write the implementation**

Create `src/security/access-control.ts`:
```typescript
import ignore, { Ignore } from 'ignore';
import fs from 'node:fs';
import path from 'node:path';

const IMMUTABLE_DENYLIST = [
  '.env',
  '.env.*',
  '*.pem',
  '*.key',
  '*.p12',
  '*.pfx',
  'credentials.json',
  'secrets.yaml',
  '*secret*',
  '.aws/**',
  '.ssh/**',
  '.gnupg/**',
  '.secureio/**',
  '.secureiorc',
];

export interface AccessControlOptions {
  extendDenylist: string[];
}

export class AccessControl {
  private denylist: Ignore;
  private gitignore: Ignore;

  constructor(projectRoot: string, options: AccessControlOptions) {
    // Build denylist (immutable + extensions)
    this.denylist = ignore();
    this.denylist.add(IMMUTABLE_DENYLIST);
    if (options.extendDenylist.length > 0) {
      this.denylist.add(options.extendDenylist);
    }

    // Parse .gitignore files
    this.gitignore = ignore();
    this.loadGitignore(projectRoot, projectRoot);
  }

  isAllowed(relativePath: string): boolean {
    // Normalize path separators
    const normalized = relativePath.replace(/\\/g, '/');

    // Check denylist first (takes precedence)
    if (this.denylist.ignores(normalized)) {
      return false;
    }

    // Check gitignore
    if (this.gitignore.ignores(normalized)) {
      return false;
    }

    return true;
  }

  private loadGitignore(dir: string, projectRoot: string): void {
    const gitignorePath = path.join(dir, '.gitignore');
    try {
      const content = fs.readFileSync(gitignorePath, 'utf-8');
      const relativeTo = path.relative(projectRoot, dir);
      const lines = content.split('\n').filter(l => l.trim() && !l.startsWith('#'));

      if (relativeTo === '') {
        this.gitignore.add(lines);
      } else {
        // Prefix nested gitignore patterns with their directory
        this.gitignore.add(lines.map(l => `${relativeTo}/${l}`));
      }
    } catch {
      // No .gitignore in this directory — fine
    }

    // Recurse into subdirectories (up to a reasonable depth)
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
          this.loadGitignore(path.join(dir, entry.name), projectRoot);
        }
      }
    } catch {
      // Permission error or similar — skip
    }
  }
}
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/security/access-control.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/security/access-control.ts tests/unit/security/access-control.test.ts
git commit -m "feat: add access control with immutable denylist and gitignore integration"
```

---

### Task 8: Audit Logger

**Files:**
- Create: `src/security/audit-logger.ts`
- Create: `tests/unit/security/audit-logger.test.ts`

**Step 1: Write the failing tests**

Create `tests/unit/security/audit-logger.test.ts`:
```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { AuditLogger } from '../../../src/security/audit-logger.js';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

describe('AuditLogger', () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'secureio-test-'));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it('writes valid JSON log entries', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({
      tool: 'secure_read',
      params: { path: 'src/index.ts' },
      redactions: [],
      access_denied: false,
      severity: 'normal',
      duration_ms: 10,
    });

    const content = await fs.readFile(logPath, 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.tool).toBe('secure_read');
    expect(entry.timestamp).toBeDefined();
    expect(entry.severity).toBe('normal');
  });

  it('includes ISO 8601 UTC timestamps', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({
      tool: 'secure_read',
      params: {},
      redactions: [],
      access_denied: false,
      severity: 'normal',
      duration_ms: 5,
    });

    const content = await fs.readFile(logPath, 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{3}Z$/);
  });

  it('flags security events with severity', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({
      tool: 'secure_read',
      params: { path: '../../etc/passwd' },
      redactions: [],
      access_denied: true,
      severity: 'security',
      duration_ms: 1,
    });

    const content = await fs.readFile(logPath, 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.severity).toBe('security');
    expect(entry.access_denied).toBe(true);
  });

  it('appends multiple entries', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({ tool: 'a', params: {}, redactions: [], access_denied: false, severity: 'normal', duration_ms: 1 });
    await logger.log({ tool: 'b', params: {}, redactions: [], access_denied: false, severity: 'normal', duration_ms: 2 });

    const content = await fs.readFile(logPath, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines.length).toBe(2);
    expect(JSON.parse(lines[0]).tool).toBe('a');
    expect(JSON.parse(lines[1]).tool).toBe('b');
  });

  it('creates log directory if it does not exist', async () => {
    const logPath = path.join(tmpDir, 'subdir', 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({ tool: 'test', params: {}, redactions: [], access_denied: false, severity: 'normal', duration_ms: 1 });

    const content = await fs.readFile(logPath, 'utf-8');
    expect(JSON.parse(content.trim()).tool).toBe('test');
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm run test:unit -- tests/unit/security/audit-logger.test.ts`
Expected: FAIL

**Step 3: Write the implementation**

Create `src/security/audit-logger.ts`:
```typescript
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { AuditLogEntry, AuditRedaction, AuditSeverity } from '../types/errors.js';

export interface AuditLogOptions {
  output: 'file' | 'stdout' | 'none';
  path: string;
  maxSizeMB?: number;
}

export interface AuditLogInput {
  tool: string;
  params: Record<string, unknown>;
  redactions: AuditRedaction[];
  access_denied: boolean;
  severity: AuditSeverity;
  duration_ms: number;
  error?: string;
}

export class AuditLogger {
  private options: AuditLogOptions;

  constructor(options: Partial<AuditLogOptions> & { output: string }) {
    this.options = {
      output: options.output as 'file' | 'stdout' | 'none',
      path: options.path ?? '.secureio/audit.log',
      maxSizeMB: options.maxSizeMB ?? 50,
    };
  }

  async log(input: AuditLogInput): Promise<void> {
    // Hash any content params (never log raw content)
    const sanitizedParams = this.sanitizeParams(input.params);

    const entry: AuditLogEntry = {
      timestamp: new Date().toISOString(),
      tool: input.tool,
      params: sanitizedParams,
      redactions: input.redactions,
      access_denied: input.access_denied,
      severity: input.severity,
      duration_ms: input.duration_ms,
      ...(input.error ? { error: input.error as AuditLogEntry['error'] } : {}),
    };

    const line = JSON.stringify(entry) + '\n';

    if (this.options.output === 'file') {
      await this.writeToFile(line);
    } else if (this.options.output === 'stdout') {
      process.stderr.write(line); // stderr to avoid polluting MCP stdio
    }
    // 'none' — no output
  }

  private async writeToFile(line: string): Promise<void> {
    const logPath = this.options.path;
    const dir = path.dirname(logPath);

    // Ensure directory exists
    await fs.mkdir(dir, { recursive: true });

    // Check log rotation
    await this.rotateIfNeeded(logPath);

    // Append
    await fs.appendFile(logPath, line, 'utf-8');
  }

  private async rotateIfNeeded(logPath: string): Promise<void> {
    try {
      const stat = await fs.stat(logPath);
      const maxBytes = (this.options.maxSizeMB ?? 50) * 1024 * 1024;
      if (stat.size >= maxBytes) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const rotatedPath = logPath.replace(/\.log$/, `-${timestamp}.log`);
        await fs.rename(logPath, rotatedPath);
      }
    } catch {
      // File doesn't exist yet — fine
    }
  }

  private sanitizeParams(params: Record<string, unknown>): Record<string, unknown> {
    const sanitized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(params)) {
      if (key === 'content' && typeof value === 'string') {
        // Hash content instead of logging raw
        sanitized[key] = `sha256:${crypto.createHash('sha256').update(value).digest('hex').substring(0, 16)}`;
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
}
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/security/audit-logger.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/security/audit-logger.ts tests/unit/security/audit-logger.test.ts
git commit -m "feat: add audit logger with JSON entries, tamper protection, and log rotation"
```

---

### Task 9: Configuration Loader

**Files:**
- Create: `src/config/loader.ts`
- Create: `src/config/defaults.ts`
- Create: `tests/unit/config/loader.test.ts`

**Step 1: Write defaults**

Create `src/config/defaults.ts`:
```typescript
import { LimitsConfig, Preset, ResolvedConfig } from '../types/config.js';

export const STRICT_LIMITS: LimitsConfig = {
  maxResultCount: 50,
  maxLineLength: 2000,
  maxResponseBytes: 51200,
  maxFileReadLines: 500,
  maxWriteBytes: 131072, // 128KB
  maxTreeDepth: 4,
  maxAuditLogSizeMB: 50,
};

export const STANDARD_LIMITS: LimitsConfig = {
  maxResultCount: 100,
  maxLineLength: 2000,
  maxResponseBytes: 102400,
  maxFileReadLines: 1000,
  maxWriteBytes: 262144, // 256KB
  maxTreeDepth: 5,
  maxAuditLogSizeMB: 50,
};

export const LIMITS_CEILINGS: Partial<LimitsConfig> = {
  maxResponseBytes: 524288, // 512KB
  maxWriteBytes: 1048576,   // 1MB
};

export function getDefaultConfig(projectRoot: string): ResolvedConfig {
  return {
    preset: 'strict',
    projectRoot,
    denylist: [],
    redactionPatterns: [],
    audit: {
      output: 'file',
      path: '.secureio/audit.log',
    },
    limits: { ...STRICT_LIMITS },
    entropyDetection: true,
  };
}
```

**Step 2: Write the config loader**

Create `src/config/loader.ts`:
```typescript
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { ProjectConfig, SystemPolicy, ResolvedConfig, Preset, RedactionPattern } from '../types/config.js';
import { getDefaultConfig, STRICT_LIMITS, STANDARD_LIMITS, LIMITS_CEILINGS } from './defaults.js';

export interface CLIFlags {
  preset?: Preset;
  root?: string;
  auditOutput?: 'file' | 'stdout' | 'none';
}

export function loadConfig(projectRoot: string, cliFlags: CLIFlags = {}): ResolvedConfig {
  const config = getDefaultConfig(projectRoot);

  // Layer 1: Load system policy
  const systemPolicy = loadSystemPolicy();

  // Layer 2: Load project config
  const projectConfig = loadProjectConfig(projectRoot);

  // Merge system policy (sets floors)
  if (systemPolicy) {
    applySystemPolicy(config, systemPolicy);
  }

  // Merge project config (cannot weaken system policy)
  if (projectConfig) {
    applyProjectConfig(config, projectConfig, systemPolicy);
  }

  // Merge CLI flags (cannot violate system policy)
  applyCLIFlags(config, cliFlags, systemPolicy);

  // Enforce ceilings
  enforceCeilings(config);

  return config;
}

function loadSystemPolicy(): SystemPolicy | null {
  const policyPath = path.join(os.homedir(), '.secureio', 'policy.json');
  try {
    const content = fs.readFileSync(policyPath, 'utf-8');
    return JSON.parse(content) as SystemPolicy;
  } catch {
    return null;
  }
}

function loadProjectConfig(projectRoot: string): Partial<ProjectConfig> | null {
  const configPath = path.join(projectRoot, '.secureiorc');
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(content) as Partial<ProjectConfig>;
  } catch {
    return null;
  }
}

function applySystemPolicy(config: ResolvedConfig, policy: SystemPolicy): void {
  // System policy sets minimum preset
  if (policy.minimumPreset === 'strict') {
    config.preset = 'strict';
    config.entropyDetection = true;
    config.limits = { ...STRICT_LIMITS };
  }

  // Extend denylist
  if (policy.denylist?.extend) {
    config.denylist.push(...policy.denylist.extend);
  }

  // Add custom patterns
  if (policy.redaction?.customPatterns) {
    config.redactionPatterns.push(
      ...policy.redaction.customPatterns.map(p => ({
        ...p,
        confidence: 'high' as const,
      }))
    );
  }

  // Enforce audit requirements
  if (policy.audit?.required) {
    config.audit.output = policy.audit.minimumOutput ?? 'file';
  }
}

function applyProjectConfig(
  config: ResolvedConfig,
  project: Partial<ProjectConfig>,
  policy: SystemPolicy | null,
): void {
  // Preset: can only upgrade, not downgrade
  if (project.preset) {
    const minimumPreset = policy?.minimumPreset ?? 'standard';
    if (canApplyPreset(project.preset, minimumPreset)) {
      config.preset = project.preset;
      config.entropyDetection = project.preset === 'strict';
      config.limits = project.preset === 'strict'
        ? { ...STRICT_LIMITS }
        : { ...STANDARD_LIMITS };
    }
  }

  // Extend denylist (additive only)
  if (project.denylist?.extend) {
    config.denylist.push(...project.denylist.extend);
  }

  // Custom patterns (additive only)
  if (project.redaction?.customPatterns) {
    config.redactionPatterns.push(
      ...project.redaction.customPatterns.map(p => ({
        ...p,
        confidence: 'medium' as const,
      }))
    );
  }

  // Audit config
  if (project.audit) {
    if (policy?.audit?.required && project.audit.output === 'none') {
      // Cannot disable audit when policy requires it
    } else {
      if (project.audit.output) config.audit.output = project.audit.output;
      if (project.audit.path) config.audit.path = project.audit.path;
    }
  }

  // Limits: can only make stricter (lower)
  if (project.limits) {
    for (const [key, value] of Object.entries(project.limits)) {
      const k = key as keyof typeof config.limits;
      if (typeof value === 'number' && value < config.limits[k]) {
        config.limits[k] = value;
      }
    }
  }
}

function applyCLIFlags(
  config: ResolvedConfig,
  flags: CLIFlags,
  policy: SystemPolicy | null,
): void {
  if (flags.preset) {
    const minimumPreset = policy?.minimumPreset ?? 'standard';
    if (canApplyPreset(flags.preset, minimumPreset)) {
      config.preset = flags.preset;
      config.entropyDetection = flags.preset === 'strict';
    }
  }

  if (flags.auditOutput) {
    if (policy?.audit?.required && flags.auditOutput === 'none') {
      // Cannot disable audit when policy requires it
    } else {
      config.audit.output = flags.auditOutput;
    }
  }
}

function canApplyPreset(requested: Preset, minimum: Preset): boolean {
  const levels: Record<Preset, number> = { standard: 0, strict: 1 };
  return levels[requested] >= levels[minimum];
}

function enforceCeilings(config: ResolvedConfig): void {
  for (const [key, ceiling] of Object.entries(LIMITS_CEILINGS)) {
    const k = key as keyof typeof config.limits;
    if (ceiling !== undefined && config.limits[k] > ceiling) {
      config.limits[k] = ceiling;
    }
  }
}
```

**Step 3: Write the tests**

Create `tests/unit/config/loader.test.ts`:
```typescript
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig } from '../../../src/config/loader.js';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

describe('Config Loader', () => {
  const testRoot = path.resolve('tests/fixtures/test-repo');

  describe('defaults', () => {
    it('uses strict preset by default', () => {
      const config = loadConfig(testRoot);
      expect(config.preset).toBe('strict');
      expect(config.entropyDetection).toBe(true);
    });

    it('sets file audit output by default', () => {
      const config = loadConfig(testRoot);
      expect(config.audit.output).toBe('file');
    });
  });

  describe('CLI flags', () => {
    it('overrides preset via CLI flag', () => {
      const config = loadConfig(testRoot, { preset: 'standard' });
      expect(config.preset).toBe('standard');
      expect(config.entropyDetection).toBe(false);
    });

    it('overrides audit output via CLI flag', () => {
      const config = loadConfig(testRoot, { auditOutput: 'stdout' });
      expect(config.audit.output).toBe('stdout');
    });
  });

  describe('ceilings', () => {
    it('maxResponseBytes cannot exceed 512KB', () => {
      const config = loadConfig(testRoot);
      expect(config.limits.maxResponseBytes).toBeLessThanOrEqual(524288);
    });

    it('maxWriteBytes cannot exceed 1MB', () => {
      const config = loadConfig(testRoot);
      expect(config.limits.maxWriteBytes).toBeLessThanOrEqual(1048576);
    });
  });
});
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/config/loader.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/config/ tests/unit/config/
git commit -m "feat: add layered configuration loader with system policy and project config merging"
```

---

## Phase 3: Security Middleware

### Task 10: Security Middleware (orchestrates security components)

**Files:**
- Create: `src/security/middleware.ts`
- Create: `src/security/index.ts`
- Create: `tests/unit/security/middleware.test.ts`

**Step 1: Write the middleware that orchestrates all security components**

Create `src/security/middleware.ts`:
```typescript
import { PathResolver, PathResult } from './path-resolver.js';
import { AccessControl } from './access-control.js';
import { RedactionEngine, RedactResult } from './redaction-engine.js';
import { AuditLogger, AuditLogInput } from './audit-logger.js';
import { transcodeToUtf8, detectEncoding, isBinary } from './encoding-detector.js';
import { ResolvedConfig } from '../types/config.js';
import { SecureIOError } from '../types/errors.js';
import { CompiledPattern } from '../types/patterns.js';
import fs from 'node:fs/promises';
import path from 'node:path';

export type SecurityCheckResult =
  | { ok: true; absolutePath: string }
  | { ok: false; error: SecureIOError };

export class SecurityMiddleware {
  readonly pathResolver: PathResolver;
  readonly accessControl: AccessControl;
  readonly redactionEngine: RedactionEngine;
  readonly auditLogger: AuditLogger;
  readonly config: ResolvedConfig;

  constructor(config: ResolvedConfig) {
    this.config = config;
    this.pathResolver = new PathResolver(config.projectRoot);
    this.accessControl = new AccessControl(config.projectRoot, {
      extendDenylist: config.denylist,
    });
    this.redactionEngine = new RedactionEngine({
      entropyDetection: config.entropyDetection,
      customPatterns: config.redactionPatterns.map(p => ({
        name: p.name,
        regex: new RegExp(p.pattern, 'g'),
        confidence: p.confidence,
        description: p.description,
      })),
    });
    this.auditLogger = new AuditLogger({
      output: config.audit.output,
      path: path.resolve(config.projectRoot, config.audit.path),
      maxSizeMB: config.limits.maxAuditLogSizeMB,
    });
  }

  /** Validate a path for read access */
  async checkReadAccess(relativePath: string): Promise<SecurityCheckResult> {
    const resolved = this.pathResolver.resolve(relativePath);
    if (!resolved.ok) return resolved;

    const relToRoot = path.relative(this.config.projectRoot, resolved.path);
    if (!this.accessControl.isAllowed(relToRoot)) {
      return {
        ok: false,
        error: {
          code: 'PATH_DENIED',
          message: 'The requested path is not accessible',
          suggestion: 'Use secure_tree to discover available paths within the project.',
        },
      };
    }

    return { ok: true, absolutePath: resolved.path };
  }

  /** Validate a path for write access */
  async checkWriteAccess(relativePath: string): Promise<SecurityCheckResult> {
    const resolved = this.pathResolver.resolve(relativePath);
    if (!resolved.ok) return resolved;

    const relToRoot = path.relative(this.config.projectRoot, resolved.path);
    if (!this.accessControl.isAllowed(relToRoot)) {
      return {
        ok: false,
        error: {
          code: 'PATH_DENIED',
          message: 'The requested path is not accessible for writing',
          suggestion: 'This path is on the denylist and cannot be written to.',
        },
      };
    }

    return { ok: true, absolutePath: resolved.path };
  }

  /** Read a file with encoding detection and redaction */
  async readFileSecure(absolutePath: string): Promise<{ content: string; encoding: string; redactedLines: number[] }> {
    const rawBuffer = await fs.readFile(absolutePath);

    if (isBinary(rawBuffer)) {
      throw { code: 'BINARY_FILE' as const, message: 'File appears to be binary' };
    }

    const encoding = detectEncoding(rawBuffer);
    const text = transcodeToUtf8(rawBuffer);
    const lines = text.split('\n');
    const redactedLines: number[] = [];
    const processedLines: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const result = this.redactionEngine.redactLine(lines[i]);
      processedLines.push(result.text);
      if (result.matches.length > 0) {
        redactedLines.push(i + 1); // 1-indexed
      }
    }

    return {
      content: processedLines.join('\n'),
      encoding,
      redactedLines,
    };
  }

  /** Scan write content for secrets — returns error if secrets found */
  scanWriteContent(content: string): SecureIOError | null {
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const result = this.redactionEngine.redactLine(lines[i]);
      if (result.matches.length > 0) {
        const firstMatch = result.matches[0];
        return {
          code: 'SECRET_IN_WRITE',
          message: `Content rejected: secret detected on line ${i + 1}, category: ${firstMatch.category}`,
          suggestion: 'Remove the secret from the content before writing.',
        };
      }
    }
    return null;
  }

  /** Redact a single line of text */
  redactLine(line: string): RedactResult {
    return this.redactionEngine.redactLine(line);
  }
}
```

**Step 2: Create barrel export**

Create `src/security/index.ts`:
```typescript
export { SecurityMiddleware } from './middleware.js';
export { PathResolver } from './path-resolver.js';
export { AccessControl } from './access-control.js';
export { RedactionEngine } from './redaction-engine.js';
export { AuditLogger } from './audit-logger.js';
export { detectEncoding, transcodeToUtf8, isBinary } from './encoding-detector.js';
```

**Step 3: Write tests**

Create `tests/unit/security/middleware.test.ts`:
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('SecurityMiddleware', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    const config = getDefaultConfig(testRoot);
    mw = new SecurityMiddleware(config);
  });

  describe('checkReadAccess', () => {
    it('allows access to normal source files', async () => {
      const result = await mw.checkReadAccess('src/index.ts');
      expect(result.ok).toBe(true);
    });

    it('denies access to .env', async () => {
      const result = await mw.checkReadAccess('.env');
      expect(result.ok).toBe(false);
    });

    it('denies path traversal', async () => {
      const result = await mw.checkReadAccess('../../etc/passwd');
      expect(result.ok).toBe(false);
    });

    it('denies .secureiorc', async () => {
      const result = await mw.checkReadAccess('.secureiorc');
      expect(result.ok).toBe(false);
    });
  });

  describe('scanWriteContent', () => {
    it('returns null for clean content', () => {
      const error = mw.scanWriteContent('const x = 42;\nconsole.log(x);');
      expect(error).toBeNull();
    });

    it('catches AWS keys in write content', () => {
      const error = mw.scanWriteContent('const key = "AKIAIOSFODNN7EXAMPLE";');
      expect(error).not.toBeNull();
      expect(error!.code).toBe('SECRET_IN_WRITE');
    });
  });
});
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/security/middleware.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/security/middleware.ts src/security/index.ts tests/unit/security/middleware.test.ts
git commit -m "feat: add security middleware orchestrating path resolver, access control, redaction, and audit"
```

---

## Phase 4: Response Infrastructure

### Task 11: Response Envelope Builder

**Files:**
- Create: `src/response.ts`
- Create: `tests/unit/response.test.ts`

**Step 1: Write the response builder**

Create `src/response.ts`:
```typescript
import { ResponseMeta, SecureResponse } from './types/response.js';
import { LimitsConfig } from './types/config.js';

export class ResponseBuilder<T> {
  private items: T[] = [];
  private totalAvailable = 0;
  private offset = 0;
  private truncatedLines = 0;
  private redactionCount = 0;
  private currentBytes = 0;
  private limits: LimitsConfig;
  private constrainedBy?: ResponseMeta['constrained_by'];

  constructor(limits: LimitsConfig, offset = 0) {
    this.limits = limits;
    this.offset = offset;
  }

  setTotal(total: number): void {
    this.totalAvailable = total;
  }

  addRedactions(count: number): void {
    this.redactionCount += count;
  }

  /** Try to add an item. Returns false if limits are exceeded. */
  add(item: T): boolean {
    // Check result count limit
    if (this.items.length >= this.limits.maxResultCount) {
      this.constrainedBy = 'maxResultCount';
      return false;
    }

    // Check byte limit
    const itemBytes = Buffer.byteLength(JSON.stringify(item), 'utf-8');
    if (this.currentBytes + itemBytes > this.limits.maxResponseBytes) {
      this.constrainedBy = 'maxResponseBytes';
      return false;
    }

    this.items.push(item);
    this.currentBytes += itemBytes;
    return true;
  }

  /** Truncate a line if it exceeds maxLineLength */
  truncateLine(line: string): string {
    if (line.length > this.limits.maxLineLength) {
      this.truncatedLines++;
      return line.substring(0, this.limits.maxLineLength) + ' [TRUNCATED]';
    }
    return line;
  }

  build(): SecureResponse<T[]> {
    return {
      results: this.items,
      meta: {
        total: this.totalAvailable,
        returned: this.items.length,
        offset: this.offset,
        has_more: this.items.length + this.offset < this.totalAvailable,
        truncated_lines: this.truncatedLines,
        redactions: this.redactionCount,
        bytes: this.currentBytes,
        ...(this.constrainedBy ? { constrained_by: this.constrainedBy } : {}),
      },
    };
  }
}
```

**Step 2: Write tests**

Create `tests/unit/response.test.ts`:
```typescript
import { describe, it, expect } from 'vitest';
import { ResponseBuilder } from '../../src/response.js';
import { STRICT_LIMITS } from '../../src/config/defaults.js';

describe('ResponseBuilder', () => {
  it('builds a response with correct meta', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResultCount: 10 });
    builder.setTotal(100);
    builder.add('item1');
    builder.add('item2');

    const response = builder.build();
    expect(response.results).toEqual(['item1', 'item2']);
    expect(response.meta.total).toBe(100);
    expect(response.meta.returned).toBe(2);
    expect(response.meta.has_more).toBe(true);
  });

  it('stops adding when maxResultCount reached', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResultCount: 2 });
    builder.setTotal(10);
    expect(builder.add('a')).toBe(true);
    expect(builder.add('b')).toBe(true);
    expect(builder.add('c')).toBe(false);

    const response = builder.build();
    expect(response.meta.constrained_by).toBe('maxResultCount');
  });

  it('stops adding when maxResponseBytes reached', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResponseBytes: 20 });
    builder.setTotal(10);
    expect(builder.add('short')).toBe(true);
    expect(builder.add('a very long string that exceeds the byte limit')).toBe(false);

    const response = builder.build();
    expect(response.meta.constrained_by).toBe('maxResponseBytes');
  });

  it('truncates long lines', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxLineLength: 10 });
    const result = builder.truncateLine('this is a very long line');
    expect(result).toContain('[TRUNCATED]');
    expect(result.length).toBeLessThan(30);
  });

  it('tracks redaction count', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(1);
    builder.addRedactions(3);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.redactions).toBe(3);
  });

  it('handles offset correctly', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS, 50);
    builder.setTotal(100);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.offset).toBe(50);
    expect(response.meta.has_more).toBe(true);
  });
});
```

**Step 3: Run tests**

Run: `npm run test:unit -- tests/unit/response.test.ts`
Expected: all tests pass

**Step 4: Commit**

```bash
git add src/response.ts tests/unit/response.test.ts
git commit -m "feat: add response envelope builder with limit precedence and pagination"
```

---

## Phase 5: Read Tools

### Task 12: secure_read Tool

**Files:**
- Create: `src/tools/read/secure-read.ts`
- Create: `tests/unit/tools/secure-read.test.ts`

**Step 1: Write the test**

Create `tests/unit/tools/secure-read.test.ts`:
```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureRead } from '../../../src/tools/read/secure-read.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_read', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('reads a clean file without redaction', async () => {
    const result = await handleSecureRead(mw, { path: 'src/clean.ts' });
    expect(result.results.content).toContain('function add');
    expect(result.results.redacted_lines).toEqual([]);
  });

  it('redacts secrets in config file', async () => {
    const result = await handleSecureRead(mw, { path: 'src/config.ts' });
    expect(result.results.content).toContain('[REDACTED:');
    expect(result.results.content).not.toContain('ghp_');
    expect(result.results.redacted_lines.length).toBeGreaterThan(0);
  });

  it('rejects reading .env', async () => {
    const result = await handleSecureRead(mw, { path: '.env' });
    expect('error' in result).toBe(true);
  });

  it('supports line range reading', async () => {
    const result = await handleSecureRead(mw, { path: 'src/clean.ts', start_line: 2, end_line: 4 });
    expect(result.results.start_line).toBe(2);
    expect(result.results.end_line).toBeLessThanOrEqual(4);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `npm run test:unit -- tests/unit/tools/secure-read.test.ts`
Expected: FAIL

**Step 3: Write the implementation**

Create `src/tools/read/secure-read.ts`:
```typescript
import { SecurityMiddleware } from '../../security/middleware.js';
import { ReadResult, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import fs from 'node:fs/promises';

export interface SecureReadParams {
  path: string;
  start_line?: number;
  end_line?: number;
}

export async function handleSecureRead(
  mw: SecurityMiddleware,
  params: SecureReadParams,
): Promise<SecureResponse<ReadResult> | { error: SecureIOError }> {
  const startTime = Date.now();

  // Check access
  const access = await mw.checkReadAccess(params.path);
  if (!access.ok) {
    await mw.auditLogger.log({
      tool: 'secure_read',
      params: { path: params.path },
      redactions: [],
      access_denied: true,
      severity: 'security',
      duration_ms: Date.now() - startTime,
    });
    return { error: access.error };
  }

  try {
    const { content, encoding, redactedLines } = await mw.readFileSecure(access.absolutePath);
    const allLines = content.split('\n');

    // Apply line range
    const start = Math.max(1, params.start_line ?? 1);
    const maxEnd = Math.min(allLines.length, start + mw.config.limits.maxFileReadLines - 1);
    const end = params.end_line ? Math.min(params.end_line, maxEnd) : maxEnd;

    const selectedLines = allLines.slice(start - 1, end);
    const selectedContent = selectedLines.join('\n');

    // Filter redacted lines to the selected range
    const rangeRedactedLines = redactedLines.filter(l => l >= start && l <= end);

    await mw.auditLogger.log({
      tool: 'secure_read',
      params: { path: params.path, start_line: start, end_line: end },
      redactions: rangeRedactedLines.map(l => ({
        line: l,
        category: 'REDACTED',
        confidence: 'high' as const,
      })),
      access_denied: false,
      severity: 'normal',
      duration_ms: Date.now() - startTime,
    });

    return {
      results: {
        path: params.path,
        content: selectedContent,
        start_line: start,
        end_line: end,
        total_lines: allLines.length,
        redacted_lines: rangeRedactedLines,
        encoding_detected: encoding,
      },
      meta: {
        total: allLines.length,
        returned: selectedLines.length,
        offset: start - 1,
        has_more: end < allLines.length,
        truncated_lines: 0,
        redactions: rangeRedactedLines.length,
        bytes: Buffer.byteLength(selectedContent, 'utf-8'),
      },
    };
  } catch (err: unknown) {
    const nodeErr = err as NodeJS.ErrnoException & { code?: string };
    if (nodeErr.code === 'ENOENT') {
      return {
        error: {
          code: 'FILE_NOT_FOUND',
          message: 'File not found',
          suggestion: 'Use secure_glob to find available files.',
        },
      };
    }
    if (nodeErr.code === 'BINARY_FILE') {
      return {
        error: {
          code: 'BINARY_FILE',
          message: 'File appears to be binary',
          suggestion: 'Use secure_glob to discover file types.',
        },
      };
    }
    throw err;
  }
}
```

**Step 4: Run tests**

Run: `npm run test:unit -- tests/unit/tools/secure-read.test.ts`
Expected: all tests pass

**Step 5: Commit**

```bash
git add src/tools/read/secure-read.ts tests/unit/tools/secure-read.test.ts
git commit -m "feat: add secure_read tool with redaction and line range support"
```

---

### Task 13: secure_search Tool

**Files:**
- Create: `src/tools/read/secure-search.ts`
- Create: `tests/unit/tools/secure-search.test.ts`

This is the core search tool. It streams through files line-by-line, matching a regex pattern, applying redaction, and building paginated results. The implementation should use `fs.createReadStream` + `readline` for memory efficiency on large files.

Follow the same TDD pattern as Task 12:
1. Write tests covering: basic regex search, pagination (offset/max_results), context lines, redaction of matches, denylist file exclusion, binary file skipping, invalid regex handling
2. Verify tests fail
3. Implement using streaming file reader with `readline.createInterface`
4. Verify tests pass
5. Commit

---

### Task 14: secure_glob Tool

**Files:**
- Create: `src/tools/read/secure-glob.ts`
- Create: `tests/unit/tools/secure-glob.test.ts`

File discovery tool. Recursively walks directories matching a glob pattern, returns paths + sizes. Must respect access control (never return denylist files), use streaming enumeration with early termination.

Follow TDD pattern: tests first (glob matching, denylist exclusion, pagination, default directory skipping), then implement, verify, commit.

---

### Task 15: secure_tree Tool

**Files:**
- Create: `src/tools/read/secure-tree.ts`
- Create: `tests/unit/tools/secure-tree.test.ts`

Directory tree tool. Returns compact tree with file counts per directory. Skips `node_modules`, `.git`, `dist`, `build`, `vendor` by default. Depth-limited.

Follow TDD pattern.

---

### Task 16: secure_diff Tool

**Files:**
- Create: `src/tools/read/secure-diff.ts`
- Create: `tests/unit/tools/secure-diff.test.ts`

Git diff tool. Runs `git diff` via `child_process.execFile`, parses output, applies redaction to both `+` and `-` lines. Blocks entire hunks referencing denylist files. Replaces file paths in headers with `[REDACTED PATH]` when the path is on the denylist.

Follow TDD pattern. Key test cases:
- Diff with no secrets passes through
- Diff with secrets gets redacted
- Diff referencing a denylist file gets entire hunk blocked
- Error response when not in a git repo

---

## Phase 6: Write Tools

### Task 17: secure_write Tool

**Files:**
- Create: `src/tools/write/secure-write.ts`
- Create: `tests/unit/tools/secure-write.test.ts`

Atomic file write with secret scanning. Key behaviors:
- Scans content for secrets before writing (rejects if found)
- Blocks writing to denylist paths
- Rejects content exceeding `maxWriteBytes`
- Atomic write: write to temp file, then rename
- Windows: retry rename up to 3 times with 100ms backoff
- Returns success + path + hash (no content echo)

Follow TDD pattern.

---

### Task 18: secure_patch Tool

**Files:**
- Create: `src/tools/write/secure-patch.ts`
- Create: `tests/unit/tools/secure-patch.test.ts`

Partial file edit with optimistic locking. Key behaviors:
- Scans `new_content` for secrets
- Reads current file, computes hash, compares to `expected_hash`
- Rejects if hash mismatch (returns current hash)
- Finds and replaces `old_content` with `new_content`
- Returns changed line range + new hash

Follow TDD pattern.

---

## Phase 7: Meta Tools

### Task 19: secure_audit Tool

**Files:**
- Create: `src/tools/meta/secure-audit.ts`
- Create: `tests/unit/tools/secure-audit.test.ts`

Security scan report. Walks the project, checks each file against the denylist and redaction engine. Summary mode returns counts. Verbose mode returns file-by-file details (line numbers + categories, never secret values).

Follow TDD pattern.

---

### Task 20: secure_overview Tool

**Files:**
- Create: `src/tools/meta/secure-overview.ts`
- Create: `tests/unit/tools/secure-overview.test.ts`

Project summary. Detects framework, language, package manager by reading `package.json`, `tsconfig.json`, `pyproject.toml`, etc. Returns entry points, scripts, dependency counts, directory structure summary, config files. Verbose mode includes full dependency names.

Follow TDD pattern.

---

### Task 21: secure_self_test Tool

**Files:**
- Create: `src/tools/meta/secure-self-test.ts`
- Create: `tests/unit/tools/secure-self-test.test.ts`

Validation suite. Runs the redaction engine against a built-in secret corpus, tests path resolver against traversal corpus, tests denylist against known sensitive patterns. Returns pass/fail per category.

This tool reuses the same corpus data from `tests/fixtures/` but bundles a subset in the source for runtime use.

Follow TDD pattern.

---

## Phase 8: Server Assembly

### Task 22: MCP Server Wiring

**Files:**
- Create: `src/server.ts`
- Create: `tests/integration/server.test.ts`

Wire all 10 tools into the MCP server using `@modelcontextprotocol/server`:

```typescript
import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { SecurityMiddleware } from './security/index.js';

export function createServer(mw: SecurityMiddleware): McpServer {
  const server = new McpServer({
    name: 'secureio-mcp',
    version: '0.1.0',
  });

  // Register each tool with Zod input schemas
  server.registerTool('secure_read', {
    description: 'Read a file with automatic secret redaction',
    inputSchema: z.object({
      path: z.string().describe('File path relative to project root'),
      start_line: z.number().optional().describe('Starting line number (1-indexed)'),
      end_line: z.number().optional().describe('Ending line number'),
    }),
  }, async (params) => {
    // Delegate to handleSecureRead
    // Return MCP content format
  });

  // ... register all 10 tools

  return server;
}
```

Integration test should verify:
- Server creates without error
- Each tool is registered
- A basic tool call through the server produces a response

Follow TDD pattern.

---

### Task 23: CLI Entry Point

**Files:**
- Modify: `src/index.ts`
- Create: `tests/integration/cli.test.ts`

Parse CLI flags (`--preset`, `--root`, `--audit-output`, `--self-test`), load config, create security middleware, create MCP server, connect stdio transport.

```typescript
#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/server';
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { loadConfig } from './config/loader.js';
import { SecurityMiddleware } from './security/index.js';
import { createServer } from './server.js';

const args = parseArgs(process.argv.slice(2));

if (args.selfTest) {
  // Run self-test and exit
  process.exit(0);
}

const config = loadConfig(args.root ?? process.cwd(), {
  preset: args.preset,
  auditOutput: args.auditOutput,
});

const mw = new SecurityMiddleware(config);
const server = createServer(mw);
const transport = new StdioServerTransport();
await server.connect(transport);
```

Test: verify `--self-test` runs and exits. Verify `--help` shows usage. Verify the binary is executable.

Follow TDD pattern. Commit.

---

## Phase 9: Full Test Suites

### Task 24: Security Test Suite

**Files:**
- Create: `tests/security/secret-detection.test.ts`
- Create: `tests/security/path-traversal.test.ts`
- Create: `tests/security/error-disclosure.test.ts`

**Secret detection tests:** Run the full `SECRET_CORPUS` against the redaction engine and verify every entry is caught. Run the full `FALSE_POSITIVE_CORPUS` and verify no false positives.

**Path traversal tests:** Run the full `TRAVERSAL_CORPUS` against the path resolver and verify every entry is rejected.

**Error disclosure tests:** Trigger every error code and verify no response contains absolute paths, project root, or OS details.

Follow TDD pattern. Commit.

---

### Task 25: Integration Test Suite

**Files:**
- Create: `tests/integration/read-pipeline.test.ts`
- Create: `tests/integration/write-pipeline.test.ts`
- Create: `tests/integration/config-pipeline.test.ts`

Full pipeline tests using the test-repo fixture. Verify:
- Read pipeline: path → access control → read → redact → response envelope
- Write pipeline: path → access control → secret scan → atomic write → audit
- Config pipeline: system policy + project config + CLI flags merge correctly

Follow TDD pattern. Commit.

---

### Task 26: Final Verification

**Step 1: Run full test suite**

Run: `npm test`
Expected: all tests pass

**Step 2: Run coverage check**

Run: `npm run test:coverage`
Expected: meets thresholds (90% on security, 80% on tools)

**Step 3: Build**

Run: `npm run build`
Expected: compiles without errors

**Step 4: Manual smoke test**

Run: `node dist/index.js --self-test`
Expected: self-test passes

**Step 5: Final commit**

```bash
git add -A
git commit -m "feat: complete SecureIOMCP v0.1.0 — all tools, tests, and security validation"
```
