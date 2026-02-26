import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { handleSecureWrite } from '../../../src/tools/write/secure-write.js';
import { SecurityMiddleware } from '../../../src/security/middleware.js';
import { getDefaultConfig } from '../../../src/config/defaults.js';
import fsp from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

describe('secure_write', () => {
  let mw: SecurityMiddleware;
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'secureio-write-'));
    mw = new SecurityMiddleware(getDefaultConfig(tmpDir));
  });

  afterEach(async () => {
    await fsp.rm(tmpDir, { recursive: true, force: true });
  });

  it('writes a clean file successfully', async () => {
    const content = 'const x = 42;\nconsole.log(x);';
    const result = await handleSecureWrite(mw, { path: 'test.ts', content });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.success).toBe(true);
      expect(result.results.path).toBe('test.ts');
      expect(result.results.hash).toBe(
        crypto.createHash('sha256').update(content).digest('hex')
      );
    }

    // Verify file was actually written
    const written = await fsp.readFile(path.join(tmpDir, 'test.ts'), 'utf-8');
    expect(written).toBe(content);
  });

  it('rejects content containing secrets', async () => {
    const content = 'const key = "AKIAIOSFODNN7EXAMPLE";';
    const result = await handleSecureWrite(mw, { path: 'test.ts', content });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('SECRET_IN_WRITE');
    }
  });

  it('blocks writing to denylist paths', async () => {
    const result = await handleSecureWrite(mw, { path: '.env', content: 'clean content' });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('PATH_DENIED');
    }
  });

  it('rejects content exceeding maxWriteBytes', async () => {
    const bigContent = 'x'.repeat(mw.config.limits.maxWriteBytes + 1);
    const result = await handleSecureWrite(mw, { path: 'big.ts', content: bigContent });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('SIZE_EXCEEDED');
    }
  });

  it('creates parent directories if needed', async () => {
    const content = 'const y = 1;';
    const result = await handleSecureWrite(mw, { path: 'deep/nested/file.ts', content });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      expect(result.results.success).toBe(true);
    }

    const written = await fsp.readFile(path.join(tmpDir, 'deep/nested/file.ts'), 'utf-8');
    expect(written).toBe(content);
  });

  it('returns SHA-256 hash of written content', async () => {
    const content = 'hello world';
    const result = await handleSecureWrite(mw, { path: 'hello.txt', content });
    expect('results' in result).toBe(true);
    if ('results' in result) {
      const expected = crypto.createHash('sha256').update(content).digest('hex');
      expect(result.results.hash).toBe(expected);
    }
  });

  it('blocks writing to .secureio directory', async () => {
    const result = await handleSecureWrite(mw, { path: '.secureio/audit.log', content: 'tamper' });
    expect('error' in result).toBe(true);
    if ('error' in result) {
      expect(result.error.code).toBe('PATH_DENIED');
    }
  });
});
