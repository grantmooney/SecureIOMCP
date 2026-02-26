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

  it('hashes content params instead of logging raw', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'file', path: logPath });

    await logger.log({
      tool: 'secure_write',
      params: { path: 'test.ts', content: 'const secret = "mypassword";' },
      redactions: [],
      access_denied: false,
      severity: 'normal',
      duration_ms: 5,
    });

    const content = await fs.readFile(logPath, 'utf-8');
    const entry = JSON.parse(content.trim());
    expect(entry.params.content).toMatch(/^sha256:[0-9a-f]{16}$/);
    expect(entry.params.content).not.toContain('mypassword');
  });

  it('does not write when output is none', async () => {
    const logPath = path.join(tmpDir, 'audit.log');
    const logger = new AuditLogger({ output: 'none', path: logPath });

    await logger.log({ tool: 'test', params: {}, redactions: [], access_denied: false, severity: 'normal', duration_ms: 1 });

    await expect(fs.access(logPath)).rejects.toThrow();
  });
});
