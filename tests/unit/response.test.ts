import { describe, it, expect } from 'vitest';
import { ResponseBuilder, estimateTokensSaved } from '../../src/response.js';
import { STRICT_LIMITS } from '../../src/config/defaults.js';

describe('estimateTokensSaved', () => {
  it('calculates savings correctly', () => {
    expect(estimateTokensSaved(1000, 200)).toBe(200); // (1000-200)/4 = 200
  });

  it('returns 0 when no savings', () => {
    expect(estimateTokensSaved(100, 100)).toBe(0);
  });

  it('returns 0 when efficient is larger than raw', () => {
    expect(estimateTokensSaved(50, 100)).toBe(0);
  });

  it('floors the result', () => {
    expect(estimateTokensSaved(101, 0)).toBe(25); // 101/4 = 25.25 → 25
  });
});

describe('ResponseBuilder', () => {
  it('builds a response with correct meta', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResultCount: 10 });
    builder.setTotal(100);
    builder.add('item1');
    builder.add('item2');

    const response = builder.build();
    expect(response.results).toEqual(['item1', 'item2']);
    expect(response.meta.total).toBe(100);
    expect(response.meta.returned).toBe(2);
    expect(response.meta.has_more).toBe(true);
  });

  it('stops adding when maxResultCount reached', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResultCount: 2 });
    builder.setTotal(10);
    expect(builder.add('a')).toBe(true);
    expect(builder.add('b')).toBe(true);
    expect(builder.add('c')).toBe(false);

    const response = builder.build();
    expect(response.meta.constrained_by).toBe('maxResultCount');
  });

  it('stops adding when maxResponseBytes reached', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxResponseBytes: 20 });
    builder.setTotal(10);
    expect(builder.add('short')).toBe(true);
    expect(builder.add('a very long string that exceeds the byte limit')).toBe(false);

    const response = builder.build();
    expect(response.meta.constrained_by).toBe('maxResponseBytes');
  });

  it('truncates long lines', () => {
    const builder = new ResponseBuilder<string>({ ...STRICT_LIMITS, maxLineLength: 10 });
    const result = builder.truncateLine('this is a very long line');
    expect(result).toContain('[TRUNCATED]');
    expect(result.length).toBeLessThan(30);
  });

  it('tracks redaction count', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(1);
    builder.addRedactions(3);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.redactions).toBe(3);
  });

  it('handles offset correctly', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS, 50);
    builder.setTotal(100);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.offset).toBe(50);
    expect(response.meta.has_more).toBe(true);
  });

  it('has_more is false when all items returned', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(2);
    builder.add('a');
    builder.add('b');

    const response = builder.build();
    expect(response.meta.has_more).toBe(false);
  });

  it('includes raw_bytes and tokens_saved in meta', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(1);
    builder.addRawBytes(1000);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.raw_bytes).toBe(1000);
    expect(response.meta.tokens_saved).toBeGreaterThan(0);
    expect(response.meta.raw_bytes).toBeGreaterThanOrEqual(response.meta.bytes);
  });

  it('accumulates raw bytes across multiple addRawBytes calls', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(2);
    builder.addRawBytes(500);
    builder.add('a');
    builder.addRawBytes(500);
    builder.add('b');

    const response = builder.build();
    expect(response.meta.raw_bytes).toBe(1000);
  });

  it('invokes session tracker callback on build', () => {
    let trackerCalled = false;
    let trackerRaw = 0;
    let trackerEfficient = 0;
    const sessionTracker = (raw: number, efficient: number) => {
      trackerCalled = true;
      trackerRaw = raw;
      trackerEfficient = efficient;
      return 42; // mock session total
    };

    const builder = new ResponseBuilder<string>(STRICT_LIMITS, 0, sessionTracker);
    builder.setTotal(1);
    builder.addRawBytes(200);
    builder.add('item');

    const response = builder.build();
    expect(trackerCalled).toBe(true);
    expect(trackerRaw).toBe(200);
    expect(trackerEfficient).toBeGreaterThan(0);
    expect(response.meta.session_tokens_saved).toBe(42);
  });

  it('defaults session_tokens_saved to 0 without tracker', () => {
    const builder = new ResponseBuilder<string>(STRICT_LIMITS);
    builder.setTotal(1);
    builder.add('item');

    const response = builder.build();
    expect(response.meta.session_tokens_saved).toBe(0);
  });
});
