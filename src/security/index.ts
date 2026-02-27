/**
 * @module security
 * @description Security layer re-exports for SecureIOMCP.
 *
 * The security layer is the mandatory middleware that wraps every tool operation.
 * It provides five core capabilities:
 *
 * - **Path Resolution** — Prevents path traversal, rejects absolute/UNC paths
 * - **Access Control** — Enforces immutable denylist + gitignore rules
 * - **Redaction** — Detects and masks secrets using pattern matching + entropy analysis
 * - **Audit Logging** — Records every operation with structured JSON logs
 * - **Encoding Detection** — Handles UTF-8/UTF-16 with BOM detection and binary rejection
 *
 * @example
 * ```typescript
 * import { SecurityMiddleware } from './security/index.js';
 *
 * const mw = new SecurityMiddleware(config);
 * const access = await mw.checkReadAccess('src/app.ts');
 * if (access.ok) {
 *   const { content, encoding, redactedLines } = await mw.readFileSecure(access.absolutePath);
 * }
 * ```
 */
export { SecurityMiddleware } from './middleware.js';
export { PathResolver } from './path-resolver.js';
export { AccessControl } from './access-control.js';
export { RedactionEngine } from './redaction-engine.js';
export { AuditLogger } from './audit-logger.js';
export { detectEncoding, transcodeToUtf8, isBinary } from './encoding-detector.js';
