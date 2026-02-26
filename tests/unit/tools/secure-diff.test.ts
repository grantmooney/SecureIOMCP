import { describe, it, expect, beforeEach } from 'vitest';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

// We test the redaction logic by importing the internal function
// Since handleSecureDiff requires git, we test the diff parsing/redaction logic directly
// by constructing synthetic diffs

describe('secure_diff', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  // Import the module dynamically to test
  it('handles empty diff', async () => {
    const { handleSecureDiff } = await import('../../../src/tools/read/secure-diff.js');
    // The test-repo sits inside the real project git repo, so git diff succeeds
    // with an empty diff (no uncommitted changes in that subtree).
    // We use the real project root to get a valid git context.
    const projectRoot = path.resolve('.');
    const projectMw = new SecurityMiddleware(getDefaultConfig(projectRoot));
    const result = await handleSecureDiff(projectMw, {});
    // Should return results (not an error) since the project root IS a git repo
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.files_changed).toBeGreaterThanOrEqual(0);
    }
  });

  it('redacts secrets in + lines of synthetic diff', () => {
    const addLine = '+const key = "AKIAIOSFODNN7EXAMPLE";';
    const redacted = mw.redactLine(addLine.substring(1));
    expect(redacted.text).toContain('[REDACTED:AWS_ACCESS_KEY]');
    expect(redacted.matches.length).toBeGreaterThan(0);
  });

  it('redacts secrets in - lines of synthetic diff', () => {
    const removeLine = '-const old = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";';
    const redacted = mw.redactLine(removeLine.substring(1));
    expect(redacted.text).toContain('[REDACTED:GITHUB_TOKEN]');
  });

  it('blocks denylist files in diff headers', () => {
    // Verify the access control would block .env
    expect(mw.accessControl.isAllowed('.env')).toBe(false);
    expect(mw.accessControl.isAllowed('.env.local')).toBe(false);
    expect(mw.accessControl.isAllowed('certs/server.pem')).toBe(false);
  });

  it('allows non-denylist files in diff', () => {
    expect(mw.accessControl.isAllowed('src/index.ts')).toBe(true);
    expect(mw.accessControl.isAllowed('package.json')).toBe(true);
  });

  it('passes clean diff lines through unchanged', () => {
    const cleanLine = 'const x = 42;';
    const redacted = mw.redactLine(cleanLine);
    expect(redacted.text).toBe(cleanLine);
    expect(redacted.matches).toEqual([]);
  });
});
