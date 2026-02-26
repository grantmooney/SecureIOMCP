import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureSelfTest } from '../../../src/tools/meta/secure-self-test.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_self_test', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('returns a passing result', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.passed).toBe(true);
    }
  });

  it('includes all test categories', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const names = result.results.categories.map(c => c.name);
      expect(names).toContain('pattern_detection');
      expect(names).toContain('traversal_prevention');
      expect(names).toContain('denylist_enforcement');
      expect(names).toContain('false_positive_prevention');
    }
  });

  it('pattern detection passes all cases', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const patternCat = result.results.categories.find(c => c.name === 'pattern_detection');
      expect(patternCat).toBeDefined();
      expect(patternCat!.passed).toBe(true);
      expect(patternCat!.failures).toEqual([]);
      expect(patternCat!.total).toBeGreaterThan(0);
    }
  });

  it('traversal prevention passes all cases', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const travCat = result.results.categories.find(c => c.name === 'traversal_prevention');
      expect(travCat).toBeDefined();
      expect(travCat!.passed).toBe(true);
      expect(travCat!.failures).toEqual([]);
    }
  });

  it('denylist enforcement passes all cases', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const denyCat = result.results.categories.find(c => c.name === 'denylist_enforcement');
      expect(denyCat).toBeDefined();
      expect(denyCat!.passed).toBe(true);
      expect(denyCat!.failures).toEqual([]);
    }
  });

  it('false positive prevention passes', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const fpCat = result.results.categories.find(c => c.name === 'false_positive_prevention');
      expect(fpCat).toBeDefined();
      expect(fpCat!.passed).toBe(true);
      expect(fpCat!.failures).toEqual([]);
    }
  });

  it('each category has a total count', async () => {
    const result = await handleSecureSelfTest(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      for (const cat of result.results.categories) {
        expect(cat.total).toBeGreaterThan(0);
      }
    }
  });
});
