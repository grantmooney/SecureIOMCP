import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureTree } from '../../../src/tools/read/secure-tree.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_tree', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('returns a tree structure', async () => {
    const result = await handleSecureTree(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.type).toBe('directory');
      expect(result.results.children).toBeDefined();
    }
  });

  it('includes src directory with files', async () => {
    const result = await handleSecureTree(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const srcDir = result.results.children?.find(c => c.name === 'src');
      expect(srcDir).toBeDefined();
      expect(srcDir!.type).toBe('directory');
      expect(srcDir!.children!.length).toBeGreaterThan(0);
    }
  });

  it('excludes denylist files from tree', async () => {
    const result = await handleSecureTree(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const topFiles = result.results.children?.filter(c => c.type === 'file').map(c => c.name) ?? [];
      expect(topFiles).not.toContain('.env');
    }
  });

  it('includes file count per directory', async () => {
    const result = await handleSecureTree(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(typeof result.results.file_count).toBe('number');
    }
  });

  it('respects max_depth', async () => {
    const result = await handleSecureTree(mw, { max_depth: 0 });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      // At depth 0, no children expanded
      expect(result.results.children).toBeUndefined();
      expect(typeof result.results.file_count).toBe('number');
    }
  });

  it('scopes to subdirectory', async () => {
    const result = await handleSecureTree(mw, { path: 'src' });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.name).toBe('src');
      const fileNames = result.results.children?.map(c => c.name) ?? [];
      expect(fileNames).toContain('clean.ts');
    }
  });
});
