import { describe, it, expect } from 'vitest';
import { main } from '../../src/index.js';

describe('CLI', () => {
  it('--help does not throw', async () => {
    // main with --help should just print usage and return
    await expect(main(['--help'])).resolves.toBeUndefined();
  });

  it('--self-test runs and returns', async () => {
    await expect(main(['--self-test', '--root', 'tests/fixtures/test-repo'])).resolves.toBeUndefined();
  });

  it('--self-test with --preset standard works', async () => {
    await expect(main(['--self-test', '--preset', 'standard', '--root', 'tests/fixtures/test-repo'])).resolves.toBeUndefined();
  });
});
