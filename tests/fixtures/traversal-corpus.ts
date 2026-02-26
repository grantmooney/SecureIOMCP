/** Path traversal attack strings — all should be rejected by path resolver */
export const TRAVERSAL_CORPUS: string[] = [
  // Basic traversals
  '../etc/passwd',
  '../../etc/passwd',
  '../../../../../../../etc/passwd',

  // Backslash variants (Windows)
  '..\\etc\\passwd',
  '..\\..\\..\\Windows\\System32\\config\\SAM',

  // Mixed separators
  '../..\\etc/passwd',
  '..\\../etc\\passwd',

  // Null byte injection
  '../etc/passwd\x00.txt',
  'safe-file.txt\x00../../etc/passwd',

  // Absolute paths (escape attempts)
  '/etc/passwd',
  'C:\\Windows\\System32\\config\\SAM',
  '\\\\server\\share\\file',

  // Dot-only paths
  '..',

  // Hidden git internals
  '.git/config',
  '.git/objects/pack/pack-abc123.pack',
  '.git/refs/heads/main',
  '.git/HEAD',
];

/** Access control paths — blocked by denylist, NOT by path resolver */
export const DENYLIST_CORPUS: string[] = [
  '.env',
  '.env.local',
  '.env.production',
  '.aws/credentials',
  '.ssh/id_rsa',
  '.secureio/audit.log',
  '.secureiorc',
  'certs/server.pem',
  'keys/private.key',
  'credentials.json',
  'secrets.yaml',
];
