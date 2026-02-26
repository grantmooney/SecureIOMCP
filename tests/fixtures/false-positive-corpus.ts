/** Strings that look like secrets but SHOULD NOT be redacted */
export const FALSE_POSITIVE_CORPUS: [string, string][] = [
  // UUIDs
  ['UUID', '550e8400-e29b-41d4-a716-446655440000'],
  ['UUID', 'f47ac10b-58cc-4372-a567-0e02b2c3d479'],
  ['UUID', '6ba7b810-9dad-11d1-80b4-00c04fd430c8'],

  // Git commit SHAs
  ['GIT_SHA', 'commit abc123def456789012345678901234567890abcd'],
  ['GIT_SHA', 'ref: abc123def456789012345678901234567890abcd'],

  // Common code patterns
  ['IMPORT_PATH', "import { something } from '@my-org/my-package';"],
  ['HASH_CONSTANT', 'const ALGORITHM = "SHA-256";'],
  ['BASE64_TEST_DATA', '// Test: atob("SGVsbG8gV29ybGQ=")'],
  ['HEX_COLOR', 'color: #AABBCCDD;'],
  ['LONG_CLASS_NAME', 'class MyVeryLongClassNameThatExceedsTwentyCharacters {}'],

  // Variable names that contain "secret"/"password" but no values
  ['VAR_NAME_ONLY', 'const passwordField = document.getElementById("password");'],
  ['VAR_NAME_ONLY', 'function validatePassword(input: string): boolean {'],
  ['VAR_NAME_ONLY', 'export interface SecretConfig {'],

  // Short values that should not trigger
  ['SHORT_VALUE', 'token = "abc"'],
  ['SHORT_VALUE', 'password = "test"'],

  // URLs without credentials
  ['PLAIN_URL', 'https://api.example.com/v1/users'],
  ['PLAIN_URL', 'mongodb://localhost:27017/testdb'],

  // Lockfile hashes
  ['LOCKFILE_HASH', '"integrity": "sha512-abc123def456789012345678901234567890abcdefghijklmnopqrstuvwxyz012345678901234567890"'],
];
