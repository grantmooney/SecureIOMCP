import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { handleSecurePatch } from '../../../src/tools/write/secure-patch.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

describe('secure_patch', () => {
  let mw: SecurityMiddleware;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'secureio-patch-'));
    mw = new SecurityMiddleware(getDefaultConfig(tmpDir));
  });

  afterEach(async () => {
    await fsp.rm(tmpDir, { recursive: true, force: true });
  });

  it('patches a file successfully', async () => {
    // Setup: create a file to patch
    const original = 'line 1\nline 2\nline 3\n';
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), original);

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: 'line 2',
      new_content: 'line TWO',
    });

    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.success).toBe(true);
      expect(result.results.changed_range.start).toBe(2);
    }

    const patched = await fsp.readFile(path.join(tmpDir, 'test.ts'), 'utf-8');
    expect(patched).toBe('line 1\nline TWO\nline 3\n');
  });

  it('rejects patches containing secrets', async () => {
    const original = 'const key = "placeholder";';
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), original);

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: '"placeholder"',
      new_content: '"AKIAIOSFODNN7EXAMPLE"',
    });

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('SECRET_IN_WRITE');
    }
  });

  it('rejects hash mismatch', async () => {
    const original = 'const x = 1;';
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), original);

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: 'const x = 1;',
      new_content: 'const x = 2;',
      expected_hash: 'wrong-hash',
    });

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('HASH_MISMATCH');
      expect(result.error.message).toContain(
        crypto.createHash('sha256').update(original).digest('hex')
      );
    }
  });

  it('succeeds with correct expected_hash', async () => {
    const original = 'const x = 1;';
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), original);
    const hash = crypto.createHash('sha256').update(original).digest('hex');

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: 'const x = 1;',
      new_content: 'const x = 2;',
      expected_hash: hash,
    });

    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.success).toBe(true);
    }
  });

  it('returns error when old_content not found', async () => {
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), 'hello world');

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: 'nonexistent content',
      new_content: 'replacement',
    });

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('INTERNAL_ERROR');
    }
  });

  it('returns file not found for missing file', async () => {
    const result = await handleSecurePatch(mw, {
      path: 'missing.ts',
      old_content: 'x',
      new_content: 'y',
    });

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('FILE_NOT_FOUND');
    }
  });

  it('blocks patching denylist paths', async () => {
    const result = await handleSecurePatch(mw, {
      path: '.env',
      old_content: 'x',
      new_content: 'y',
    });

    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('PATH_DENIED');
    }
  });

  it('returns new hash after patch', async () => {
    const original = 'abc';
    await fsp.writeFile(path.join(tmpDir, 'test.ts'), original);

    const result = await handleSecurePatch(mw, {
      path: 'test.ts',
      old_content: 'abc',
      new_content: 'def',
    });

    expect('results' in result).toBe(true);
    if ('results' in result) {
      const expected = crypto.createHash('sha256').update('def').digest('hex');
      expect(result.results.hash).toBe(expected);
    }
  });
});
