import { SecurityMiddleware } from '../../security/middleware.js';
import { SelfTestResult, SelfTestCategory, SecureResponse } from '../../types/response.js';
import { SecureIOError } from '../../types/errors.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS } from '../../security/patterns.js';
import { RedactionEngine } from '../../security/redaction-engine.js';

/**
 * Built-in test corpus of known secret formats for runtime validation.
 * Each entry is a `[category, testValue]` pair that must be detected by the redaction engine.
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

/** Path traversal attack vectors that must be blocked by the path resolver. */
const TRAVERSAL_TEST_CASES: string[] = [
  '../etc/passwd',
  '../../etc/passwd',
  '..\\..\\etc\\passwd',
  '/etc/passwd',
];

/** Sensitive file patterns that must be blocked by the access control denylist. */
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

/** Parameters for the `secure_self_test` MCP tool (no parameters required). */
export interface SecureSelfTestParams {
  // No params needed -- runs full validation suite
}

/**
 * Handles the `secure_self_test` MCP tool: runs the built-in security validation suite.
 * Tests four categories: pattern detection, path traversal prevention, denylist enforcement,
 * and false positive prevention. Used by security teams to verify deployment integrity.
 * Also available via CLI: `npx secureio-mcp --self-test`
 *
 * @param mw - Security middleware instance
 * @param _params - Unused (no parameters)
 * @returns Self-test results with pass/fail per category, or a safe error response
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

/** Tests that all known secret formats in the test corpus are detected by the redaction engine. */
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

/** Tests that all path traversal attack vectors are blocked by the path resolver. */
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

/** Tests that all sensitive file patterns are blocked by the denylist. */
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

/** Tests that common safe strings (UUIDs, code, imports, URLs) are not flagged as secrets. */
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
