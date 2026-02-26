import { ResponseMeta, SecureResponse } from './types/response.js';
import { LimitsConfig } from './types/config.js';

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

  setTotal(total: number): void {
    this.totalAvailable = total;
  }

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
