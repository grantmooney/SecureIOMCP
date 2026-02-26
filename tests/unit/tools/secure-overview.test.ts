import { describe, it, expect, beforeEach } from 'vitest';
import { handleSecureOverview } from '../../../src/tools/meta/secure-overview.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import path from 'node:path';

describe('secure_overview', () => {
  let mw: SecurityMiddleware;
  const testRoot = path.resolve('tests/fixtures/test-repo');

  beforeEach(() => {
    mw = new SecurityMiddleware(getDefaultConfig(testRoot));
  });

  it('detects project name from package.json', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.name).toBe('test-repo');
    }
  });

  it('detects framework', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.framework).toBe('express');
    }
  });

  it('reports dependency counts', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.dependencyCount).toBe(2);
      expect(result.results.devDependencyCount).toBe(2);
    }
  });

  it('includes scripts from package.json', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.scripts).toHaveProperty('build');
      expect(result.results.scripts).toHaveProperty('test');
    }
  });

  it('includes config files list', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.configFiles).toContain('package.json');
    }
  });

  it('includes directory structure summary', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.structure).toContain('src/');
    }
  });

  it('detects language from devDependencies', async () => {
    const result = await handleSecureOverview(mw, {});
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.language).toBe('typescript');
    }
  });
});
