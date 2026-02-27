/**
 * Detected file encoding based on Byte Order Mark (BOM) analysis.
 *
 * - `'utf-8'` -- No BOM detected, assumed UTF-8
 * - `'utf-8-bom'` -- UTF-8 with explicit BOM (0xEF 0xBB 0xBF)
 * - `'utf-16le'` -- UTF-16 Little Endian (0xFF 0xFE)
 * - `'utf-16be'` -- UTF-16 Big Endian (0xFE 0xFF)
 */
export type DetectedEncoding = 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be';

/**
 * Detects file encoding by inspecting the Byte Order Mark (BOM).
 * Files without a BOM are assumed to be UTF-8.
 *
 * @param buffer - Raw file buffer to analyze
 * @returns The detected encoding type
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
 * Transcodes a file buffer to a UTF-8 string, handling BOM stripping and byte-swapping.
 * UTF-16BE files are byte-swapped to UTF-16LE before decoding since Node.js only
 * natively supports UTF-16LE.
 *
 * @param buffer - Raw file buffer to transcode
 * @returns UTF-8 string content with BOM removed
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
 * Checks whether a file appears to be binary by scanning for null bytes in the first 512 bytes.
 * UTF-16 encoded files (which naturally contain null bytes) are excluded from this check.
 *
 * @param buffer - Raw file buffer to analyze
 * @returns `true` if the file appears to be binary
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
