import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureAudit } from '../../../src/tools/meta/secure-audit.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import { AuditResult, SecureResponse } from '../../../src/types/response.js';
import path from 'node:path';

/** Type guard: returns true when the result contains `results` (not an error). */
function isSuccess(result: unknown): result is SecureResponse<AuditResult> {
  return typeof result === 'object' && result !== null && 'results' in result;
}

describe('secure_audit', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('reports blocked files count', async () => {
    const result = await handleSecureAudit(mw, {});
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // .env is blocked
      expect(result.results.files_blocked).toBeGreaterThan(0);
    }
  });

  it('reports detected secrets count', async () => {
    const result = await handleSecureAudit(mw, {});
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // config.ts has secrets
      expect(result.results.secrets_detected).toBeGreaterThan(0);
      expect(result.results.files_with_secrets).toBeGreaterThan(0);
    }
  });

  it('reports preset in use', async () => {
    const result = await handleSecureAudit(mw, {});
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.preset).toBe('strict');
    }
  });

  it('does not include details in summary mode', async () => {
    const result = await handleSecureAudit(mw, { verbose: false });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details).toBeUndefined();
    }
  });

  it('includes file details in verbose mode', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details).toBeDefined();
      expect(result.results.details!.length).toBeGreaterThan(0);

      // Should have at least one blocked file
      const blocked = result.results.details!.filter(d => d.blocked);
      expect(blocked.length).toBeGreaterThan(0);

      // Should have config.ts with redactions
      const configFile = result.results.details!.find(d => d.path === 'src/config.ts');
      expect(configFile).toBeDefined();
      expect(configFile!.redactions.length).toBeGreaterThan(0);
    }
  });

  it('verbose details include line numbers and categories', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      const configFile = result.results.details!.find(d => d.path === 'src/config.ts');
      expect(configFile).toBeDefined();
      for (const redaction of configFile!.redactions) {
        expect(typeof redaction.line).toBe('number');
        expect(typeof redaction.category).toBe('string');
        expect(typeof redaction.confidence).toBe('string');
      }
    }
  });

  // ── Pagination tests ──────────────────────────────────────────────

  it('verbose mode respects maxResponseBytes', async () => {
    // Create MW with very tight byte limit
    const config = getDefaultConfig(testRoot);
    config.limits.maxResponseBytes = 200;
    const tightMw = new SecurityMiddleware(config);

    const result = await handleSecureAudit(tightMw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // With a 200 byte limit, not all details should fit
      expect(result.meta.has_more).toBe(true);
      expect(result.meta.constrained_by).toBe('maxResponseBytes');

      // Summary counts still reflect full scan
      expect(result.results.files_blocked).toBeGreaterThan(0);
      expect(result.results.secrets_detected).toBeGreaterThan(0);
    }
  });

  it('verbose mode respects maxResultCount', async () => {
    const config = getDefaultConfig(testRoot);
    config.limits.maxResultCount = 1;
    const tightMw = new SecurityMiddleware(config);

    const result = await handleSecureAudit(tightMw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details!.length).toBe(1);
      expect(result.meta.has_more).toBe(true);
      expect(result.meta.constrained_by).toBe('maxResultCount');
    }
  });

  it('offset skips detail entries', async () => {
    const result0 = await handleSecureAudit(mw, { verbose: true, offset: 0 });
    const result1 = await handleSecureAudit(mw, { verbose: true, offset: 1 });

    expect(isSuccess(result0)).toBe(true);
    expect(isSuccess(result1)).toBe(true);
    if (isSuccess(result0) && isSuccess(result1)) {
      // Different first entries
      expect(result1.results.details![0].path).not.toBe(
        result0.results.details![0].path,
      );

      // Same summary counts (full scan always runs)
      expect(result1.results.files_blocked).toBe(result0.results.files_blocked);
      expect(result1.results.secrets_detected).toBe(result0.results.secrets_detected);

      // Returned differs by 1 (offset skipped one)
      expect(result1.meta.returned).toBe(result0.meta.returned - 1);
    }
  });

  it('max_results limits detail entries', async () => {
    const result = await handleSecureAudit(mw, { verbose: true, max_results: 1 });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details!.length).toBe(1);
      expect(result.meta.returned).toBe(1);
    }
  });

  it('summary counts are always complete regardless of pagination', async () => {
    // Offset beyond all entries
    const result = await handleSecureAudit(mw, { verbose: true, offset: 100 });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // No details returned (offset is past all entries)
      expect(result.results.details!.length).toBe(0);
      expect(result.meta.has_more).toBe(false);

      // Summary counts still complete
      expect(result.results.files_blocked).toBeGreaterThan(0);
      expect(result.results.secrets_detected).toBeGreaterThan(0);
    }
  });

  it('non-verbose mode is unaffected by offset/max_results', async () => {
    const result = await handleSecureAudit(mw, {
      verbose: false,
      offset: 5,
      max_results: 1,
    });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details).toBeUndefined();
      expect(result.meta.total).toBe(1);
      expect(result.meta.returned).toBe(1);
      expect(result.meta.has_more).toBe(false);
    }
  });

  it('constrained_by absent when all details fit', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // Default limits are generous enough for the small test fixture
      expect(result.meta.constrained_by).toBeUndefined();
      expect(result.meta.has_more).toBe(false);
    }
  });

  it('meta.total reflects total detail entries across full scan', async () => {
    const result = await handleSecureAudit(mw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      const expectedTotal =
        result.results.files_blocked + result.results.files_with_secrets;
      expect(result.meta.total).toBe(expectedTotal);
    }
  });

  it('token savings tracked when details are truncated', async () => {
    const config = getDefaultConfig(testRoot);
    config.limits.maxResultCount = 1;
    const tightMw = new SecurityMiddleware(config);

    const result = await handleSecureAudit(tightMw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      // There should be savings since we truncated details
      expect(result.meta.tokens_saved).toBeGreaterThan(0);
      expect(result.meta.session_tokens_saved).toBeGreaterThan(0);
    }
  });

  it('pagination is deterministic across calls', async () => {
    const result1 = await handleSecureAudit(mw, { verbose: true, offset: 0, max_results: 2 });
    const result2 = await handleSecureAudit(mw, { verbose: true, offset: 0, max_results: 2 });

    expect(isSuccess(result1)).toBe(true);
    expect(isSuccess(result2)).toBe(true);
    if (isSuccess(result1) && isSuccess(result2)) {
      expect(result1.results.details).toEqual(result2.results.details);
    }
  });

  it('returns zero details when first entry exceeds maxResponseBytes', async () => {
    const config = getDefaultConfig(testRoot);
    config.limits.maxResponseBytes = 1; // impossibly small
    const tinyMw = new SecurityMiddleware(config);

    const result = await handleSecureAudit(tinyMw, { verbose: true });
    expect(isSuccess(result)).toBe(true);
    if (isSuccess(result)) {
      expect(result.results.details!.length).toBe(0);
      expect(result.meta.has_more).toBe(true);
      expect(result.meta.constrained_by).toBe('maxResponseBytes');
      // Summary counts still complete
      expect(result.results.files_blocked).toBeGreaterThan(0);
    }
  });

  it('offset + max_results work together for windowed pagination', async () => {
    // Get all details first
    const all = await handleSecureAudit(mw, { verbose: true });
    expect(isSuccess(all)).toBe(true);
    if (!isSuccess(all)) return;

    const allDetails = all.results.details!;
    // Need at least 3 entries for a meaningful test
    if (allDetails.length < 3) return;

    // Get a window: offset 1, max_results 1 → should be the 2nd entry
    const windowed = await handleSecureAudit(mw, {
      verbose: true,
      offset: 1,
      max_results: 1,
    });
    expect(isSuccess(windowed)).toBe(true);
    if (isSuccess(windowed)) {
      expect(windowed.results.details!.length).toBe(1);
      expect(windowed.results.details![0].path).toBe(allDetails[1].path);
      expect(windowed.meta.returned).toBe(1);
      expect(windowed.meta.offset).toBe(1);
      expect(windowed.meta.has_more).toBe(true);
    }
  });
});
