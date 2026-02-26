import { describe, it, expect } from 'vitest';
import { RedactionEngine } from '../../../src/security/redaction-engine.js';
import { SECRET_CORPUS } from '../../fixtures/secret-corpus.js';
import { FALSE_POSITIVE_CORPUS } from '../../fixtures/false-positive-corpus.js';

describe('RedactionEngine', () => {
  const engine = new RedactionEngine({ entropyDetection: true });
  const engineNoEntropy = new RedactionEngine({ entropyDetection: false });

  describe('high confidence patterns', () => {
    const highConfidence = SECRET_CORPUS.filter(([, , c]) => c === 'high');

    for (const [category, testValue] of highConfidence) {
      it(`catches ${category}: ${testValue.substring(0, 30)}...`, () => {
        const result = engine.redactLine(testValue);
        expect(result.text).toContain('[REDACTED:');
        expect(result.matches.length).toBeGreaterThan(0);
      });
    }
  });

  describe('medium confidence patterns', () => {
    const mediumConfidence = SECRET_CORPUS.filter(([, , c]) => c === 'medium');

    for (const [category, testValue] of mediumConfidence) {
      it(`catches ${category}: ${testValue.substring(0, 40)}...`, () => {
        const result = engine.redactLine(testValue);
        expect(result.text).toContain('[REDACTED:');
        expect(result.matches.length).toBeGreaterThan(0);
      });
    }
  });

  describe('false positive prevention', () => {
    for (const [category, testValue] of FALSE_POSITIVE_CORPUS) {
      it(`does not redact ${category}: ${testValue.substring(0, 40)}...`, () => {
        const result = engineNoEntropy.redactLine(testValue);
        expect(result.matches.length).toBe(0);
      });
    }
  });

  describe('output format', () => {
    it('replaces secrets with [REDACTED:CATEGORY]', () => {
      const result = engine.redactLine('key=AKIAIOSFODNN7EXAMPLE');
      expect(result.text).toBe('key=[REDACTED:AWS_ACCESS_KEY]');
    });

    it('handles multiple secrets on one line', () => {
      const line = 'AKIAIOSFODNN7EXAMPLE and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl';
      const result = engine.redactLine(line);
      expect(result.matches.length).toBe(2);
      expect(result.text).toContain('[REDACTED:AWS_ACCESS_KEY]');
      expect(result.text).toContain('[REDACTED:GITHUB_TOKEN]');
    });
  });

  describe('entropy detection', () => {
    it('catches high-entropy quoted strings when enabled', () => {
      const line = 'data = "xK9mP2vL7nQ4wR8jT3yU6bA1cF5gH0iD"';
      const withEntropy = engine.redactLine(line);
      expect(withEntropy.matches.length).toBeGreaterThan(0);
      expect(withEntropy.text).toContain('[REDACTED:');
    });

    it('does not catch when entropy disabled', () => {
      // Use a value that won't match any named pattern
      const line = 'data = "xK9mP2vL7nQ4wR8jT3yU6bA1cF5gH0iD"';
      const noEntropy = engineNoEntropy.redactLine(line);
      const withEntropy = engine.redactLine(line);
      expect(withEntropy.matches.length).toBeGreaterThan(noEntropy.matches.length);
    });
  });

  describe('shannon entropy calculation', () => {
    it('returns 0 for empty string', () => {
      expect(engine.shannonEntropy('')).toBe(0);
    });

    it('returns 0 for single-char repeated', () => {
      expect(engine.shannonEntropy('aaaa')).toBe(0);
    });

    it('returns high entropy for random-looking strings', () => {
      expect(engine.shannonEntropy('aB3dE6fG8hI0jK2lM4nO6pQ8r')).toBeGreaterThan(4.0);
    });

    it('returns low entropy for repetitive strings', () => {
      expect(engine.shannonEntropy('aaabbbccc')).toBeLessThan(2.0);
    });
  });

  describe('edge cases', () => {
    it('handles empty string', () => {
      const result = engine.redactLine('');
      expect(result.text).toBe('');
      expect(result.matches).toEqual([]);
    });

    it('handles string with no secrets', () => {
      const result = engine.redactLine('const x = 42;');
      expect(result.text).toBe('const x = 42;');
      expect(result.matches).toEqual([]);
    });
  });
});
