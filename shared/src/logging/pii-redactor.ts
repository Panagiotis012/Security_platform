/**
 * PII Redaction module.
 *
 * Implements an allowlist-based approach: fields not on the allowlist are
 * redacted when they match known PII patterns.  Tokens and secrets are
 * **always** redacted regardless of configuration.
 *
 * Key design decisions:
 *  - Deep-clone before mutating so the caller's original object is never
 *    modified.
 *  - Regex patterns are compiled once (module load) and reused.
 *  - The redaction placeholder includes the field category so auditors can
 *    understand *why* a value was removed.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Category of sensitive data detected. */
export type PIICategory =
  | 'email'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'token'
  | 'secret'
  | 'ip_address'
  | 'custom';

export interface RedactionRule {
  /** Human-readable name. */
  name: string;
  /** PII category for labelling redacted output. */
  category: PIICategory;
  /** If the field name matches this pattern it is always redacted. */
  fieldPattern?: RegExp;
  /** If the *value* matches this pattern the value is redacted. */
  valuePattern?: RegExp;
}

export interface PIIRedactorConfig {
  /** Placeholder template. `{category}` is replaced with the PIICategory. */
  placeholder?: string;
  /** Additional rules beyond the built-in defaults. */
  additionalRules?: RedactionRule[];
  /** Fields to never redact (allowlist). Case-insensitive match. */
  allowedFields?: string[];
  /** Maximum depth to traverse nested objects (prevent prototype pollution). */
  maxDepth?: number;
}

// ---------------------------------------------------------------------------
// Default rules
// ---------------------------------------------------------------------------

const DEFAULT_RULES: ReadonlyArray<RedactionRule> = [
  // --- Field-name based rules (always redact regardless of value) ---
  {
    name: 'token-field',
    category: 'token',
    fieldPattern:
      /^(access_?token|refresh_?token|id_?token|authorization|bearer|jwt|api_?key|apikey)$/i,
  },
  {
    name: 'secret-field',
    category: 'secret',
    fieldPattern:
      /^(password|passwd|secret|private_?key|signing_?key|client_?secret|credentials?)$/i,
  },
  {
    name: 'ssn-field',
    category: 'ssn',
    fieldPattern: /^(ssn|social_?security|national_?id|sin)$/i,
  },
  {
    name: 'credit-card-field',
    category: 'credit_card',
    fieldPattern:
      /^(credit_?card|card_?number|cc_?number|pan)$/i,
  },

  // --- Value-based rules (match on string content) ---
  {
    name: 'email-value',
    category: 'email',
    valuePattern:
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
  },
  {
    name: 'phone-value',
    category: 'phone',
    // Matches common international & US formats.
    valuePattern:
      /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/,
  },
  {
    name: 'ssn-value',
    category: 'ssn',
    valuePattern: /\b\d{3}-\d{2}-\d{4}\b/,
  },
  {
    name: 'credit-card-value',
    category: 'credit_card',
    valuePattern: /\b(?:\d[ -]*?){13,19}\b/,
  },
  {
    name: 'jwt-value',
    category: 'token',
    // Compact JWS: three base64url segments separated by dots.
    valuePattern:
      /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/,
  },
  {
    name: 'bearer-value',
    category: 'token',
    valuePattern: /^Bearer\s+[A-Za-z0-9_\-.~+/]+=*$/i,
  },
];

// ---------------------------------------------------------------------------
// PIIRedactor class
// ---------------------------------------------------------------------------

export class PIIRedactor {
  private readonly rules: ReadonlyArray<RedactionRule>;
  private readonly placeholderTemplate: string;
  private readonly allowedFieldsLower: ReadonlySet<string>;
  private readonly maxDepth: number;

  constructor(config: PIIRedactorConfig = {}) {
    this.placeholderTemplate = config.placeholder ?? '[REDACTED:{category}]';
    this.rules = [...DEFAULT_RULES, ...(config.additionalRules ?? [])];
    this.allowedFieldsLower = new Set(
      (config.allowedFields ?? []).map((f) => f.toLowerCase()),
    );
    this.maxDepth = config.maxDepth ?? 20;
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Return a deep copy of `obj` with PII fields redacted.
   *
   * The original object is never modified.
   */
  public redact<T>(obj: T): T {
    // Fast-path for primitives.
    if (obj === null || obj === undefined) return obj;
    if (typeof obj !== 'object') return obj;

    const seen = new WeakSet<object>();
    return this.redactValue(obj, undefined, 0, seen) as T;
  }

  /**
   * Redact sensitive fields from a flat key/value map.
   * Convenience wrapper for header maps, query params, etc.
   */
  public redactRecord(
    record: Record<string, string>,
  ): Record<string, string> {
    const result: Record<string, string> = {};
    for (const [key, value] of Object.entries(record)) {
      const match = this.matchField(key, value);
      result[key] = match
        ? this.placeholder(match.category)
        : value;
    }
    return result;
  }

  /**
   * Returns `true` if the given field name + value would be redacted.
   */
  public isSensitive(fieldName: string, value: string): boolean {
    return this.matchField(fieldName, value) !== null;
  }

  // -----------------------------------------------------------------------
  // Internals
  // -----------------------------------------------------------------------

  private placeholder(category: PIICategory): string {
    return this.placeholderTemplate.replace('{category}', category);
  }

  /**
   * Check a field name / value pair against all rules.
   * Returns the first matching rule, or `null`.
   */
  private matchField(
    fieldName: string | undefined,
    value: unknown,
  ): RedactionRule | null {
    // Always-redact rules (tokens & secrets) cannot be allowlisted.
    for (const rule of this.rules) {
      if (
        rule.fieldPattern &&
        fieldName !== undefined &&
        rule.fieldPattern.test(fieldName)
      ) {
        // Tokens / secrets are NEVER allowlisted.
        if (
          rule.category === 'token' ||
          rule.category === 'secret'
        ) {
          return rule;
        }
        // Other field-name rules respect the allowlist.
        if (
          !this.allowedFieldsLower.has(fieldName.toLowerCase())
        ) {
          return rule;
        }
      }
    }

    // Value-based rules – only for strings.
    if (typeof value === 'string' && value.length > 0) {
      for (const rule of this.rules) {
        if (rule.valuePattern && rule.valuePattern.test(value)) {
          // Tokens are never allowlisted.
          if (rule.category === 'token' || rule.category === 'secret') {
            return rule;
          }
          if (
            fieldName === undefined ||
            !this.allowedFieldsLower.has(fieldName.toLowerCase())
          ) {
            return rule;
          }
        }
      }
    }

    return null;
  }

  /**
   * Recursively traverse and redact.
   */
  private redactValue(
    value: unknown,
    fieldName: string | undefined,
    depth: number,
    seen: WeakSet<object>,
  ): unknown {
    if (depth > this.maxDepth) return '[MAX_DEPTH_EXCEEDED]';
    if (value === null || value === undefined) return value;

    // Primitive string – check value-based patterns.
    if (typeof value === 'string') {
      const match = this.matchField(fieldName, value);
      return match ? this.placeholder(match.category) : value;
    }

    if (typeof value === 'number' || typeof value === 'boolean') {
      return value;
    }

    if (typeof value !== 'object') return value;

    // Guard against circular references.
    const obj = value as object;
    if (seen.has(obj)) return '[CIRCULAR]';
    seen.add(obj);

    // Arrays
    if (Array.isArray(obj)) {
      return obj.map((item) =>
        this.redactValue(item, fieldName, depth + 1, seen),
      );
    }

    // Date objects – pass through as ISO string.
    if (obj instanceof Date) {
      return obj.toISOString();
    }

    // Plain objects / records.
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
      // Check field-name rules first (before recursing).
      const fieldMatch = this.matchField(key, val);
      if (fieldMatch) {
        result[key] = this.placeholder(fieldMatch.category);
      } else {
        result[key] = this.redactValue(val, key, depth + 1, seen);
      }
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// Singleton convenience
// ---------------------------------------------------------------------------

let defaultRedactor: PIIRedactor | null = null;

/**
 * Get or create the default PIIRedactor instance.
 */
export function getDefaultRedactor(
  config?: PIIRedactorConfig,
): PIIRedactor {
  if (!defaultRedactor || config) {
    defaultRedactor = new PIIRedactor(config);
  }
  return defaultRedactor;
}

/**
 * Convenience function: redact PII from an object using the default config.
 */
export function redactPII<T>(obj: T): T {
  return getDefaultRedactor().redact(obj);
}
