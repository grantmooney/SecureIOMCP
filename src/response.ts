import { SecureResponse } from './types/response.js';
import { LimitsConfig } from './types/config.js';

/**
 * Generic response builder for constructing paginated, size-limited tool responses.
 * Tracks item count, byte size, and redaction counts against configured limits,
 * and produces a standard {@link SecureResponse} envelope.
 *
 * @typeParam T - The individual result item type
 *
 * @example
 * ```typescript
 * const builder = new ResponseBuilder<SearchResult>(config.limits, offset);
 * builder.setTotal(totalMatches);
 * for (const match of matches) {
 *   if (!builder.add(match)) break; // Limit reached
 * }
 * return builder.build();
 * ```
 */
export class ResponseBuilder<T> {
  private items: T[] = [];
  private totalAvailable = 0;
  private offset = 0;
  private redactionCount = 0;
  private currentBytes = 0;
  private limits: LimitsConfig;
  private constrainedBy?: 'maxResultCount' | 'maxResponseBytes';

  constructor(limits: LimitsConfig, offset = 0) {
    this.limits = limits;
    this.offset = offset;
  }

  /** Sets the total number of available results (for pagination metadata). */
  setTotal(total: number): void {
    this.totalAvailable = total;
  }

  /** Increments the redaction counter by the given count. */
  addRedactions(count: number): void {
    this.redactionCount += count;
  }

  /**
   * Attempts to add an item to the response. Returns `false` if adding the item
   * would exceed `maxResultCount` or `maxResponseBytes` limits.
   *
   * @param item - The result item to add
   * @returns `true` if the item was added, `false` if limits are exceeded
   */
  add(item: T): boolean {
    // Check result count limit
    if (this.items.length >= this.limits.maxResultCount) {
      this.constrainedBy = 'maxResultCount';
      return false;
    }

    // Check byte limit
    const itemBytes = Buffer.byteLength(JSON.stringify(item), 'utf-8');
    if (this.currentBytes + itemBytes > this.limits.maxResponseBytes) {
      this.constrainedBy = 'maxResponseBytes';
      return false;
    }

    this.items.push(item);
    this.currentBytes += itemBytes;
    return true;
  }

  /**
   * Truncates a line if it exceeds `maxLineLength`, appending `[TRUNCATED]`.
   *
   * @param line - The line to potentially truncate
   * @returns The original line or truncated version with `[TRUNCATED]` suffix
   */
  truncateLine(line: string): string {
    if (line.length > this.limits.maxLineLength) {
      return line.substring(0, this.limits.maxLineLength) + ' [TRUNCATED]';
    }
    return line;
  }

  /**
   * Builds the final response envelope with results and pagination metadata.
   *
   * @returns A {@link SecureResponse} containing all added items and metadata
   */
  build(): SecureResponse<T[]> {
    return {
      results: this.items,
      meta: {
        total: this.totalAvailable,
        returned: this.items.length,
        offset: this.offset,
        has_more: this.items.length + this.offset < this.totalAvailable,
        redactions: this.redactionCount,
      },
    };
  }
}
