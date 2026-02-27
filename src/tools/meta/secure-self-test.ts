/**
 * @module secure-self-test
 *
 * MCP tool handler for `secure_self_test`. Runs a built-in validation suite
 * that exercises the security middleware's core defences at runtime, suitable
 * for deployment smoke-testing via the `--self-test` CLI flag.
 *
 * The suite is organised into four test categories:
 * 1. **Pattern detection** -- verifies that known secret formats (AWS keys,
 *    GitHub tokens, Stripe keys, private key blocks, JWTs, connection strings,
 *    generic passwords) are correctly identified by the redaction engine.
 * 2. **Path traversal prevention** -- confirms that `../`, `..\\`, and
 *    absolute paths outside the project root are rejected by the path resolver.
 * 3. **Denylist enforcement** -- checks that immutable denylist entries
 *    (`.env`, `*.pem`, `*.key`, `.ssh/`, `.aws/`, `.secureio/`, `.secureiorc`)
 *    are blocked by the access-control layer.
 * 4. **False positive prevention** -- ensures that common safe strings
 *    (UUIDs, simple code, imports, URLs) do not trigger secret detection.
 *
 * No parameters are required; the tool always runs the full suite.
 */

import { SecurityMiddleware } from '../../security/middleware.js';
import { SelfTestResult, SelfTestCategory, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS } from '../../security/patterns.js';
import { RedactionEngine } from '../../security/redaction-engine.js';

/**
 * Test corpus of known secret formats.
 *
 * Each entry is a `[category, testValue]` tuple where `category` is a
 * human-readable label and `testValue` is a representative string that
 * the redaction engine must detect.
 */
const SECRET_TEST_CASES: [string, string][] = [
  ['AWS_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE'],
  ['GITHUB_TOKEN', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl'],
  ['STRIPE_LIVE_KEY', 'sk_live_abcdefghijklmnopqrstuvwx'],
  ['PRIVATE_KEY_BLOCK', '-----BEGIN RSA PRIVATE KEY-----'],
  ['JWT', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'],
  ['CONNECTION_STRING', 'postgres://admin:s3cretP@ss@db.example.com:5432/mydb'],
  ['GENERIC_SECRET', 'password = "MyS3cur3P@ssw0rd!"'],
];

/**
 * Test corpus of path traversal attack strings.
 *
 * Each entry is a relative or absolute path that must be rejected by the
 * path resolver to prevent directory-traversal attacks.
 */
const TRAVERSAL_TEST_CASES: string[] = [
  '../etc/passwd',
  '../../etc/passwd',
  '..\\..\\etc\\passwd',
  '/etc/passwd',
];

/**
 * Test corpus of denylist-protected file paths.
 *
 * Each entry is a relative path that must be blocked by the access-control
 * denylist regardless of project configuration.
 */
const DENYLIST_TEST_CASES: string[] = [
  '.env',
  '.env.local',
  'certs/server.pem',
  'ssl/private.key',
  '.ssh/id_rsa',
  '.aws/credentials',
  '.secureio/audit.log',
  '.secureiorc',
];

/**
 * Parameters accepted by the `secure_self_test` MCP tool.
 *
 * This tool takes no parameters -- it always runs the full validation suite.
 */
export interface SecureSelfTestParams {
  // No params needed — runs full validation suite
}

/**
 * Handle a `secure_self_test` tool invocation.
 *
 * Executes all four test categories ({@link testPatternDetection},
 * {@link testTraversalPrevention}, {@link testDenylistEnforcement},
 * {@link testFalsePositivePrevention}) and aggregates their results.
 * The overall `passed` flag is `true` only if every category passes.
 * The invocation is recorded in the audit log with a `warning` severity
 * when any test fails.
 *
 * @param mw      - The initialised {@link SecurityMiddleware} instance.
 * @param _params - Unused (no parameters are required).
 * @returns A {@link SecureResponse} containing a {@link SelfTestResult},
 *          or an object with a {@link SecureIOError} on failure.
 */
export async function handleSecureSelfTest(
  mw: SecurityMiddleware,
  _params: SecureSelfTestParams,
): Promise<SecureResponse<SelfTestResult> | { error: SecureIOError }> {
  const startTime = Date.now();
  const categories: SelfTestCategory[] = [];

  // Test 1: Pattern detection
  const patternCategory = testPatternDetection(mw);
  categories.push(patternCategory);

  // Test 2: Path traversal prevention
  const traversalCategory = testTraversalPrevention(mw);
  categories.push(traversalCategory);

  // Test 3: Denylist enforcement
  const denylistCategory = testDenylistEnforcement(mw);
  categories.push(denylistCategory);

  // Test 4: False positive prevention
  const falsePositiveCategory = testFalsePositivePrevention();
  categories.push(falsePositiveCategory);

  const allPassed = categories.every(c => c.passed);

  const result: SelfTestResult = {
    passed: allPassed,
    categories,
  };

  await mw.auditLogger.log({
    tool: 'secure_self_test',
    params: {},
    redactions: [],
    access_denied: false,
    severity: allPassed ? 'normal' : 'warning',
    duration_ms: Date.now() - startTime,
  });

  return {
    results: result,
    meta: {
      total: 1,
      returned: 1,
      offset: 0,
      has_more: false,
      truncated_lines: 0,
      redactions: 0,
      bytes: Buffer.byteLength(JSON.stringify(result), 'utf-8'),
    },
  };
}

/**
 * Test that all known secret patterns in {@link SECRET_TEST_CASES} are
 * detected by the redaction engine.
 *
 * @param mw - The security middleware providing the `redactLine` method.
 * @returns A {@link SelfTestCategory} with the `pattern_detection` results.
 */
function testPatternDetection(mw: SecurityMiddleware): SelfTestCategory {
  const failures: string[] = [];
  for (const [category, testValue] of SECRET_TEST_CASES) {
    const result = mw.redactLine(testValue);
    if (result.matches.length === 0) {
      failures.push(`${category}: not detected`);
    }
  }
  return {
    name: 'pattern_detection',
    passed: failures.length === 0,
    total: SECRET_TEST_CASES.length,
    failures,
  };
}

/**
 * Test that all path traversal strings in {@link TRAVERSAL_TEST_CASES}
 * are rejected by the path resolver.
 *
 * @param mw - The security middleware providing the `pathResolver`.
 * @returns A {@link SelfTestCategory} with the `traversal_prevention` results.
 */
function testTraversalPrevention(mw: SecurityMiddleware): SelfTestCategory {
  const failures: string[] = [];
  for (const traversal of TRAVERSAL_TEST_CASES) {
    const result = mw.pathResolver.resolve(traversal);
    if (result.ok) {
      failures.push(`${traversal}: not blocked`);
    }
  }
  return {
    name: 'traversal_prevention',
    passed: failures.length === 0,
    total: TRAVERSAL_TEST_CASES.length,
    failures,
  };
}

/**
 * Test that all paths in {@link DENYLIST_TEST_CASES} are blocked by the
 * access-control denylist.
 *
 * @param mw - The security middleware providing the `accessControl` layer.
 * @returns A {@link SelfTestCategory} with the `denylist_enforcement` results.
 */
function testDenylistEnforcement(mw: SecurityMiddleware): SelfTestCategory {
  const failures: string[] = [];
  for (const denied of DENYLIST_TEST_CASES) {
    if (mw.accessControl.isAllowed(denied)) {
      failures.push(`${denied}: not blocked`);
    }
  }
  return {
    name: 'denylist_enforcement',
    passed: failures.length === 0,
    total: DENYLIST_TEST_CASES.length,
    failures,
  };
}

/**
 * Test that common safe strings do not trigger false positive secret
 * detections.
 *
 * Uses a standalone {@link RedactionEngine} with entropy detection disabled
 * to verify that UUIDs, simple code statements, scoped-package imports,
 * and HTTPS URLs pass through without being flagged.
 *
 * @returns A {@link SelfTestCategory} with the `false_positive_prevention` results.
 */
function testFalsePositivePrevention(): SelfTestCategory {
  // Test that common safe patterns don't trigger false positives
  const engine = new RedactionEngine({ entropyDetection: false });
  const safeStrings = [
    '550e8400-e29b-41d4-a716-446655440000', // UUID
    'const x = 42;', // Simple code
    'import { something } from "@my-org/my-package";', // Import
    'https://api.example.com/v1/users', // URL
  ];

  const failures: string[] = [];
  for (const safe of safeStrings) {
    const result = engine.redactLine(safe);
    if (result.matches.length > 0) {
      failures.push(`False positive: "${safe.substring(0, 40)}..."`);
    }
  }

  return {
    name: 'false_positive_prevention',
    passed: failures.length === 0,
    total: safeStrings.length,
    failures,
  };
}
