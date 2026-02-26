import { CompiledPattern, RedactionMatch } from '../types/patterns.js';
import { HIGH_CONFIDENCE_PATTERNS, MEDIUM_CONFIDENCE_PATTERNS, SAFE_PATTERNS } from './patterns.js';

export interface RedactResult {
  text: string;
  matches: RedactionMatch[];
}

export class RedactionEngine {
  private patterns: CompiledPattern[];
  private entropyEnabled: boolean;
  private safePatterns: RegExp[];

  constructor(options: {
    entropyDetection: boolean;
    customPatterns?: CompiledPattern[];
  }) {
    this.patterns = [
      ...HIGH_CONFIDENCE_PATTERNS,
      ...MEDIUM_CONFIDENCE_PATTERNS,
      ...(options.customPatterns ?? []),
    ];
    this.entropyEnabled = options.entropyDetection;
    this.safePatterns = [...SAFE_PATTERNS];
  }

  redactLine(line: string): RedactResult {
    const matches: RedactionMatch[] = [];
    let result = line;

    for (const pattern of this.patterns) {
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(result)) !== null) {
        const replacement = `[REDACTED:${pattern.name}]`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: pattern.name,
          confidence: pattern.confidence,
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        regex.lastIndex = match.index + replacement.length;
      }
    }

    if (this.entropyEnabled) {
      result = this.redactHighEntropy(result, matches);
    }

    return { text: result, matches };
  }

  private redactHighEntropy(line: string, matches: RedactionMatch[]): string {
    const tokenRegex = /['"][A-Za-z0-9+/=_\-]{20,}['"]/g;
    let result = line;
    const regex = new RegExp(tokenRegex.source, tokenRegex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(result)) !== null) {
      const token = match[0].slice(1, -1);

      if (token.startsWith('[REDACTED:')) continue;
      if (this.isSafe(token, result)) continue;

      const entropy = this.shannonEntropy(token);
      if (entropy > 4.5) {
        const quoteChar = match[0][0];
        const replacement = `${quoteChar}[REDACTED:HIGH_ENTROPY]${quoteChar}`;
        matches.push({
          start: match.index,
          end: match.index + match[0].length,
          category: 'HIGH_ENTROPY',
          confidence: 'entropy',
        });
        result =
          result.substring(0, match.index) +
          replacement +
          result.substring(match.index + match[0].length);
        regex.lastIndex = match.index + replacement.length;
      }
    }

    return result;
  }

  private isSafe(token: string, line: string): boolean {
    for (const safe of this.safePatterns) {
      const regex = new RegExp(safe.source, safe.flags);
      if (regex.test(token) || regex.test(line)) {
        return true;
      }
    }
    return false;
  }

  shannonEntropy(str: string): number {
    if (str.length === 0) return 0;
    const freq = new Map<string, number>();
    for (const char of str) {
      freq.set(char, (freq.get(char) ?? 0) + 1);
    }
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
