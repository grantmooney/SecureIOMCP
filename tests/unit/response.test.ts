import { describe, it, expect } from 'vitest';
import { ResponseBuilder } from '../../src/response.js';
import { STRICT_LIMITS } from '../../src/config/defaults.js';

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
});
