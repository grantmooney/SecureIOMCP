import { describe, it, expect } from 'vitest';
import { detectEncoding, transcodeToUtf8, isBinary } from '../../../src/security/encoding-detector.js';

describe('Encoding Detector', () => {
  describe('detectEncoding', () => {
    it('detects UTF-8 BOM', () => {
      const buf = Buffer.from([0xEF, 0xBB, 0xBF, 0x48, 0x65, 0x6C, 0x6C, 0x6F]);
      expect(detectEncoding(buf)).toBe('utf-8-bom');
    });

    it('detects UTF-16LE BOM', () => {
      const buf = Buffer.from([0xFF, 0xFE, 0x48, 0x00, 0x65, 0x00]);
      expect(detectEncoding(buf)).toBe('utf-16le');
    });

    it('detects UTF-16BE BOM', () => {
      const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x65]);
      expect(detectEncoding(buf)).toBe('utf-16be');
    });

    it('defaults to UTF-8 without BOM', () => {
      const buf = Buffer.from('Hello, world!', 'utf-8');
      expect(detectEncoding(buf)).toBe('utf-8');
    });

    it('handles empty buffer', () => {
      const buf = Buffer.alloc(0);
      expect(detectEncoding(buf)).toBe('utf-8');
    });
  });

  describe('transcodeToUtf8', () => {
    it('passes through UTF-8 content unchanged', () => {
      const buf = Buffer.from('Hello, world!', 'utf-8');
      expect(transcodeToUtf8(buf)).toBe('Hello, world!');
    });

    it('strips UTF-8 BOM', () => {
      const buf = Buffer.from([0xEF, 0xBB, 0xBF, ...Buffer.from('Hello')]);
      expect(transcodeToUtf8(buf)).toBe('Hello');
    });

    it('transcodes UTF-16LE to UTF-8', () => {
      const buf = Buffer.from([0xFF, 0xFE, ...Buffer.from('Hello', 'utf16le')]);
      expect(transcodeToUtf8(buf)).toBe('Hello');
    });

    it('transcodes UTF-16BE to UTF-8', () => {
      const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69]);
      expect(transcodeToUtf8(buf)).toBe('Hi');
    });
  });

  describe('isBinary', () => {
    it('detects binary content with null bytes', () => {
      const buf = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x00, 0x00, 0x00]);
      expect(isBinary(buf)).toBe(true);
    });

    it('does not flag UTF-8 text as binary', () => {
      const buf = Buffer.from('Hello, world!\nThis is text.', 'utf-8');
      expect(isBinary(buf)).toBe(false);
    });

    it('does not flag UTF-16LE as binary', () => {
      const buf = Buffer.from([0xFF, 0xFE, ...Buffer.from('Hello', 'utf16le')]);
      expect(isBinary(buf)).toBe(false);
    });

    it('does not flag UTF-16BE as binary', () => {
      const buf = Buffer.from([0xFE, 0xFF, 0x00, 0x48, 0x00, 0x69]);
      expect(isBinary(buf)).toBe(false);
    });

    it('handles empty buffer', () => {
      const buf = Buffer.alloc(0);
      expect(isBinary(buf)).toBe(false);
    });
  });
});
