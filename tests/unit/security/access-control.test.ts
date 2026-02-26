import { describe, it, expect, beforeEach } from 'vitest';
import { AccessControl } from '../../../src/security/access-control.js';
import path from 'node:path';

describe('AccessControl', () => {
  const testRepoRoot = path.resolve('tests/fixtures/test-repo');

  describe('immutable denylist', () => {
    let ac: AccessControl;

    beforeEach(() => {
      ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
    });

    it('blocks .env', () => {
      expect(ac.isAllowed('.env')).toBe(false);
    });

    it('blocks .env.local', () => {
      expect(ac.isAllowed('.env.local')).toBe(false);
    });

    it('blocks .env.production', () => {
      expect(ac.isAllowed('.env.production')).toBe(false);
    });

    it('blocks *.pem files', () => {
      expect(ac.isAllowed('certs/server.pem')).toBe(false);
    });

    it('blocks *.key files', () => {
      expect(ac.isAllowed('ssl/private.key')).toBe(false);
    });

    it('blocks *.p12 files', () => {
      expect(ac.isAllowed('certs/client.p12')).toBe(false);
    });

    it('blocks *.pfx files', () => {
      expect(ac.isAllowed('certs/client.pfx')).toBe(false);
    });

    it('blocks credentials.json', () => {
      expect(ac.isAllowed('credentials.json')).toBe(false);
    });

    it('blocks secrets.yaml', () => {
      expect(ac.isAllowed('secrets.yaml')).toBe(false);
    });

    it('blocks .aws/ directory', () => {
      expect(ac.isAllowed('.aws/credentials')).toBe(false);
    });

    it('blocks .ssh/ directory', () => {
      expect(ac.isAllowed('.ssh/id_rsa')).toBe(false);
    });

    it('blocks .gnupg/ directory', () => {
      expect(ac.isAllowed('.gnupg/secring.gpg')).toBe(false);
    });

    it('blocks .secureio/ directory (tamper protection)', () => {
      expect(ac.isAllowed('.secureio/audit.log')).toBe(false);
    });

    it('blocks .secureiorc (config protection)', () => {
      expect(ac.isAllowed('.secureiorc')).toBe(false);
    });

    it('allows normal source files', () => {
      expect(ac.isAllowed('src/index.ts')).toBe(true);
    });

    it('allows package.json', () => {
      expect(ac.isAllowed('package.json')).toBe(true);
    });
  });

  describe('gitignore integration', () => {
    let ac: AccessControl;

    beforeEach(() => {
      ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
    });

    it('blocks files matched by .gitignore', () => {
      expect(ac.isAllowed('node_modules/express/index.js')).toBe(false);
      expect(ac.isAllowed('dist/index.js')).toBe(false);
    });

    it('allows files not in .gitignore', () => {
      expect(ac.isAllowed('src/index.ts')).toBe(true);
    });
  });

  describe('extend-only denylist', () => {
    it('applies custom extensions', () => {
      const ac = new AccessControl(testRepoRoot, {
        extendDenylist: ['*.tfvars', 'internal/**'],
      });
      expect(ac.isAllowed('main.tfvars')).toBe(false);
      expect(ac.isAllowed('internal/config.json')).toBe(false);
    });

    it('cannot remove built-in rules via extension', () => {
      const ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
      expect(ac.isAllowed('.env')).toBe(false);
    });
  });

  describe('denylist takes precedence', () => {
    it('denylist blocks even when gitignore allows', () => {
      const ac = new AccessControl(testRepoRoot, { extendDenylist: [] });
      expect(ac.isAllowed('.env')).toBe(false);
    });
  });
});
