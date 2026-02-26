export type DetectedEncoding = 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be';

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
