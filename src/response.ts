/**
 * @module response
 *
 * Provides the {@link ResponseBuilder} class, which enforces token-efficiency
 * limits on tool responses. Every tool that returns a list of results uses
 * a `ResponseBuilder` to accumulate items while respecting the configured
 * `maxResultCount`, `maxResponseBytes`, and `maxLineLength` constraints.
 *
 * When a limit is reached, the builder records which constraint caused the
 * cut-off (`constrained_by`) so the agent can adjust its request (e.g. use
 * pagination or reduce scope).
 */

import { ResponseMeta, SecureResponse } from './types/response.js';
import { LimitsConfig } from './types/config.js';

/**
 * Accumulates tool-response items while enforcing configured size and
 * count limits.
 *
 * Instantiate with the active {@link LimitsConfig} and an optional
 * pagination `offset`, then call {@link add} for each candidate item.
 * When finished, call {@link build} to produce the final
 * {@link SecureResponse} with metadata.
 *
 * @typeParam T - The type of individual result items (e.g. `SearchResult`,
 *               `GlobResult`).
 */
export class ResponseBuilder<T> {
  private items: T[] = [];
  private totalAvailable = 0;
  private offset = 0;
  private truncatedLines = 0;
  private redactionCount = 0;
  private currentBytes = 0;
  private limits: LimitsConfig;
  private constrainedBy?: ResponseMeta['constrained_by'];

  constructor(limits: LimitsConfig, offset = 0) {
    this.limits = limits;
    this.offset = offset;
  }

  /**
   * Set the total number of available matches (before pagination/limits).
   *
   * This value is included in the response metadata so the agent knows
   * how many results exist in total and whether further pages are available.
   *
   * @param total - The total match count across the entire data set.
   */
  setTotal(total: number): void {
    this.totalAvailable = total;
  }

  /**
   * Increment the running redaction counter.
   *
   * Called by tool handlers whenever the redaction engine replaces
   * secret content in a result item, so the final metadata reflects
   * the total number of redactions applied.
   *
   * @param count - Number of additional redactions to record.
   */
  addRedactions(count: number): void {
    this.redactionCount += count;
  }

  /** Try to add an item. Returns false if limits are exceeded. */
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

  /** Truncate a line if it exceeds maxLineLength */
  truncateLine(line: string): string {
    if (line.length > this.limits.maxLineLength) {
      this.truncatedLines++;
      return line.substring(0, this.limits.maxLineLength) + ' [TRUNCATED]';
    }
    return line;
  }

  /**
   * Finalise and return the accumulated response.
   *
   * Produces a {@link SecureResponse} containing the collected items and
   * a {@link ResponseMeta} block with pagination, truncation, redaction,
   * and byte-size information. If a limit caused early termination, the
   * `constrained_by` field identifies which one.
   *
   * @returns The complete paginated response ready to be serialised.
   */
  build(): SecureResponse<T[]> {
    return {
      results: this.items,
      meta: {
        total: this.totalAvailable,
        returned: this.items.length,
        offset: this.offset,
        has_more: this.items.length + this.offset < this.totalAvailable,
        truncated_lines: this.truncatedLines,
        redactions: this.redactionCount,
        bytes: this.currentBytes,
        ...(this.constrainedBy ? { constrained_by: this.constrainedBy } : {}),
      },
    };
  }
}
