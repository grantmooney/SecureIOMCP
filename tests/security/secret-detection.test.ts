import { describe, it, expect } from 'vitest';
import { RedactionEngine } from '../../src/security/redaction-engine.js';
import { SECRET_CORPUS, LINES_WITH_SECRETS } from '../fixtures/secret-corpus.js';
import { FALSE_POSITIVE_CORPUS } from '../fixtures/false-positive-corpus.js';

describe('Secret Detection — Full Corpus', () => {
  const engine = new RedactionEngine({ entropyDetection: true });

  describe('SECRET_CORPUS: every entry must be detected', () => {
    for (const [category, value, confidence] of SECRET_CORPUS) {
      it(`detects ${category} (${confidence})`, () => {
        const result = engine.redactLine(value);
        expect(result.matches.length).toBeGreaterThan(0);
        expect(result.text).toContain('[REDACTED:');
        expect(result.text).not.toBe(value);
      });
    }
  });

  describe('LINES_WITH_SECRETS: full lines are redacted', () => {
    for (const line of LINES_WITH_SECRETS) {
      it(`redacts line: ${line.substring(0, 50)}...`, () => {
        const result = engine.redactLine(line);
        expect(result.matches.length).toBeGreaterThan(0);
        expect(result.text).toContain('[REDACTED:');
      });
    }
  });

  describe('FALSE_POSITIVE_CORPUS: no false positives', () => {
    for (const [category, value] of FALSE_POSITIVE_CORPUS) {
      it(`does NOT redact ${category}: ${value.substring(0, 50)}...`, () => {
        const result = engine.redactLine(value);
        expect(result.matches.length).toBe(0);
        expect(result.text).toBe(value);
      });
    }
  });

  describe('entropy detection edge cases', () => {
    it('detects high-entropy quoted strings', () => {
      const line = 'const key = "aB3xR7qW9mK2pL5nJ8vF4hD6gS0tY1u";';
      const result = engine.redactLine(line);
      expect(result.matches.length).toBeGreaterThan(0);
      expect(result.text).toContain('[REDACTED:HIGH_ENTROPY]');
    });

    it('does NOT flag low-entropy strings', () => {
      const line = 'const msg = "aaaaaaaaaaaaaaaaaaaaaaaaa";';
      const result = engine.redactLine(line);
      // Low entropy - all same char
      const entropyMatches = result.matches.filter(m => m.category === 'HIGH_ENTROPY');
      expect(entropyMatches.length).toBe(0);
    });

    it('does NOT flag short strings even with high entropy', () => {
      const line = 'const x = "aB3xR7q";';
      const result = engine.redactLine(line);
      const entropyMatches = result.matches.filter(m => m.category === 'HIGH_ENTROPY');
      expect(entropyMatches.length).toBe(0);
    });

    it('does not flag when entropy is disabled', () => {
      const noEntropy = new RedactionEngine({ entropyDetection: false });
      const line = 'const key = "aB3xR7qW9mK2pL5nJ8vF4hD6gS0tY1u";';
      const result = noEntropy.redactLine(line);
      const entropyMatches = result.matches.filter(m => m.category === 'HIGH_ENTROPY');
      expect(entropyMatches.length).toBe(0);
    });
  });
});
