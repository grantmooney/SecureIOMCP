/**
 * @module security/encoding-detector
 * @description File encoding detection, transcoding, and binary detection for SecureIOMCP.
 *
 * This module handles the encoding layer of the security pipeline:
 * 1. **Detect encoding** via Byte Order Mark (BOM) analysis
 * 2. **Transcode** non-UTF-8 content to UTF-8 for consistent redaction
 * 3. **Detect binary** files (null byte in first 512 bytes) to skip processing
 *
 * Supported encodings:
 * - UTF-8 (default, no BOM)
 * - UTF-8 with BOM (3-byte BOM: `0xEF 0xBB 0xBF`)
 * - UTF-16 Little Endian (2-byte BOM: `0xFF 0xFE`)
 * - UTF-16 Big Endian (2-byte BOM: `0xFE 0xFF`)
 *
 * All text content is transcoded to UTF-8 before redaction to ensure pattern
 * matching works correctly regardless of the original encoding.
 */

/**
 * Detected file encoding type.
 */
export type DetectedEncoding = 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be';

/**
 * Detect the encoding of a file buffer by examining the Byte Order Mark (BOM).
 *
 * @param buffer - The raw file buffer to analyze.
 * @returns The detected encoding. Defaults to `'utf-8'` if no BOM is found.
 *
 * @example
 * ```typescript
 * const buf = await fs.readFile('file.txt');
 * const encoding = detectEncoding(buf); // 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be'
 * ```
 */
export function detectEncoding(buffer: Buffer): DetectedEncoding {
  if (buffer.length >= 3 &&
      buffer[0] === 0xEF && buffer[1] === 0xBB && buffer[2] === 0xBF) {
    return 'utf-8-bom';
  }
  if (buffer.length >= 2 && buffer[0] === 0xFF && buffer[1] === 0xFE) {
    return 'utf-16le';
  }
  if (buffer.length >= 2 && buffer[0] === 0xFE && buffer[1] === 0xFF) {
    return 'utf-16be';
  }
  return 'utf-8';
}

/**
 * Transcode a file buffer to a UTF-8 string, stripping BOM if present.
 *
 * Handles UTF-8, UTF-8 with BOM, UTF-16LE, and UTF-16BE. For UTF-16BE,
 * performs byte-swapping to convert to UTF-16LE before Node.js decoding
 * (since Node.js natively supports UTF-16LE but not UTF-16BE).
 *
 * @param buffer - The raw file buffer to transcode.
 * @returns The file content as a UTF-8 string.
 */
export function transcodeToUtf8(buffer: Buffer): string {
  const encoding = detectEncoding(buffer);

  switch (encoding) {
    case 'utf-8-bom':
      return buffer.subarray(3).toString('utf-8');
    case 'utf-16le':
      return buffer.subarray(2).toString('utf16le');
    case 'utf-16be': {
      const content = buffer.subarray(2);
      const swapped = Buffer.alloc(content.length);
      for (let i = 0; i < content.length - 1; i += 2) {
        swapped[i] = content[i + 1];
        swapped[i + 1] = content[i];
      }
      return swapped.toString('utf16le');
    }
    default:
      return buffer.toString('utf-8');
  }
}

/**
 * Detect whether a file buffer contains binary content.
 *
 * Checks the first 512 bytes for null bytes (`0x00`). If a null byte is found,
 * the file is considered binary **unless** it has a UTF-16 BOM (which legitimately
 * contains null bytes in text content).
 *
 * @param buffer - The raw file buffer to check.
 * @returns `true` if the file appears to be binary, `false` if it appears to be text.
 */
export function isBinary(buffer: Buffer): boolean {
  const checkLength = Math.min(buffer.length, 512);
  for (let i = 0; i < checkLength; i++) {
    const byte = buffer[i];
    if (byte === 0x00) {
      const encoding = detectEncoding(buffer);
      if (encoding === 'utf-16le' || encoding === 'utf-16be') return false;
      return true;
    }
  }
  return false;
}
