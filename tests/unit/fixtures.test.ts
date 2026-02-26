import { describe, it, expect } from 'vitest';
import { SECRET_CORPUS } from '../fixtures/secret-corpus.js';
import { FALSE_POSITIVE_CORPUS } from '../fixtures/false-positive-corpus.js';
import { TRAVERSAL_CORPUS, DENYLIST_CORPUS } from '../fixtures/traversal-corpus.js';

describe('test fixtures', () => {
  it('secret corpus has entries', () => {
    expect(SECRET_CORPUS.length).toBeGreaterThan(20);
  });

  it('false positive corpus has entries', () => {
    expect(FALSE_POSITIVE_CORPUS.length).toBeGreaterThan(10);
  });

  it('traversal corpus has entries', () => {
    expect(TRAVERSAL_CORPUS.length).toBeGreaterThan(10);
  });

  it('denylist corpus has entries', () => {
    expect(DENYLIST_CORPUS.length).toBeGreaterThan(5);
  });
});
