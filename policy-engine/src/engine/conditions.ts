import { z } from 'zod';
import type {
  ConditionNode,
  ConditionOperator,
  ConditionValue,
  SingleCondition,
  PolicyRequest,
} from '../models/policy-schema';

/**
 * ConditionEvaluator handles complex condition trees including
 * AND/OR/NOT logic and all supported condition operators.
 */
export class ConditionEvaluator {
  /**
   * Evaluate a condition tree against a policy request context.
   * Returns true if the condition is satisfied.
   */
  evaluate(node: ConditionNode, context: EvaluationContext): boolean {
    switch (node.type) {
      case 'single':
        return this.evaluateSingle(node.condition, context);
      case 'and':
        return node.conditions.every((child) => this.evaluate(child, context));
      case 'or':
        return node.conditions.some((child) => this.evaluate(child, context));
      case 'not':
        return !this.evaluate(node.condition, context);
      default:
        // Fail-closed: unknown condition type means condition not met
        return false;
    }
  }

  /**
   * Evaluate a single condition against the context.
   */
  private evaluateSingle(condition: SingleCondition, context: EvaluationContext): boolean {
    const fieldValue = this.resolveField(condition.field, context);
    if (fieldValue === undefined) {
      // Field not present in context - condition cannot be satisfied (fail-closed)
      return false;
    }

    try {
      return this.applyOperator(condition.operator, fieldValue, condition.value);
    } catch {
      // Any evaluation error means condition is not met (fail-closed)
      return false;
    }
  }

  /**
   * Resolve a dotted field path from the evaluation context.
   * Supports paths like: actor.id, resource.attributes.department, environment.ip
   */
  private resolveField(field: string, context: EvaluationContext): ConditionValue | undefined {
    const parts = field.split('.');
    let current: unknown = context;

    for (const part of parts) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }

    if (current === undefined || current === null) {
      return undefined;
    }

    // Validate the resolved value is a valid ConditionValue
    const parsed = z
      .union([z.string(), z.number(), z.boolean(), z.array(z.string()), z.array(z.number())])
      .safeParse(current);

    if (!parsed.success) {
      return undefined;
    }

    return parsed.data;
  }

  /**
   * Apply a condition operator to compare the actual field value with the expected value.
   */
  private applyOperator(
    operator: ConditionOperator,
    actual: ConditionValue,
    expected: ConditionValue
  ): boolean {
    switch (operator) {
      case 'StringEquals':
        return this.stringEquals(actual, expected);
      case 'StringNotEquals':
        return !this.stringEquals(actual, expected);
      case 'StringLike':
        return this.stringLike(actual, expected);
      case 'IpAddress':
        return this.ipAddressMatch(actual, expected);
      case 'NotIpAddress':
        return !this.ipAddressMatch(actual, expected);
      case 'DateGreaterThan':
        return this.dateGreaterThan(actual, expected);
      case 'DateLessThan':
        return this.dateLessThan(actual, expected);
      case 'NumericEquals':
        return this.numericEquals(actual, expected);
      case 'NumericGreaterThan':
        return this.numericGreaterThan(actual, expected);
      case 'NumericLessThan':
        return this.numericLessThan(actual, expected);
      case 'Bool':
        return this.boolMatch(actual, expected);
      case 'ArrayContains':
        return this.arrayContains(actual, expected);
      case 'ArrayContainsAll':
        return this.arrayContainsAll(actual, expected);
      default:
        return false;
    }
  }

  // ─── String operators ────────────────────────────────────────────────────

  private stringEquals(actual: ConditionValue, expected: ConditionValue): boolean {
    return String(actual) === String(expected);
  }

  /**
   * Glob-style pattern matching.
   * Supports * (match any characters) and ? (match single character).
   */
  private stringLike(actual: ConditionValue, expected: ConditionValue): boolean {
    const str = String(actual);
    const pattern = String(expected);
    const regex = this.globToRegex(pattern);
    return regex.test(str);
  }

  private globToRegex(pattern: string): RegExp {
    let regexStr = '^';
    for (let i = 0; i < pattern.length; i++) {
      const ch = pattern[i];
      switch (ch) {
        case '*':
          regexStr += '.*';
          break;
        case '?':
          regexStr += '.';
          break;
        case '.':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '+':
        case '^':
        case '$':
        case '|':
        case '\\':
          regexStr += '\\' + ch;
          break;
        default:
          regexStr += ch;
      }
    }
    regexStr += '$';
    return new RegExp(regexStr, 'i');
  }

  // ─── IP address operators ────────────────────────────────────────────────

  /**
   * Check if an IP address falls within a CIDR range.
   * Supports IPv4 addresses and CIDR notation.
   */
  private ipAddressMatch(actual: ConditionValue, expected: ConditionValue): boolean {
    const ip = String(actual);
    const cidrOrIp = String(expected);

    // If expected is a comma-separated list, check against each
    const ranges = cidrOrIp.split(',').map((s) => s.trim());
    return ranges.some((range) => this.isIpInCidr(ip, range));
  }

  private isIpInCidr(ip: string, cidr: string): boolean {
    // Handle plain IP comparison
    if (!cidr.includes('/')) {
      return ip === cidr;
    }

    const [rangeIp, prefixStr] = cidr.split('/');
    const prefix = parseInt(prefixStr, 10);

    if (isNaN(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }

    const ipNum = this.ipToNumber(ip);
    const rangeNum = this.ipToNumber(rangeIp);

    if (ipNum === null || rangeNum === null) {
      return false;
    }

    // Create mask from prefix length
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipNum & mask) === (rangeNum & mask);
  }

  private ipToNumber(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) {
      return null;
    }

    let result = 0;
    for (const part of parts) {
      const num = parseInt(part, 10);
      if (isNaN(num) || num < 0 || num > 255) {
        return null;
      }
      result = (result << 8) + num;
    }
    return result >>> 0; // Convert to unsigned 32-bit
  }

  // ─── Date operators ──────────────────────────────────────────────────────

  private dateGreaterThan(actual: ConditionValue, expected: ConditionValue): boolean {
    const actualDate = new Date(String(actual));
    const expectedDate = new Date(String(expected));
    if (isNaN(actualDate.getTime()) || isNaN(expectedDate.getTime())) {
      return false;
    }
    return actualDate.getTime() > expectedDate.getTime();
  }

  private dateLessThan(actual: ConditionValue, expected: ConditionValue): boolean {
    const actualDate = new Date(String(actual));
    const expectedDate = new Date(String(expected));
    if (isNaN(actualDate.getTime()) || isNaN(expectedDate.getTime())) {
      return false;
    }
    return actualDate.getTime() < expectedDate.getTime();
  }

  // ─── Numeric operators ───────────────────────────────────────────────────

  private numericEquals(actual: ConditionValue, expected: ConditionValue): boolean {
    const a = Number(actual);
    const b = Number(expected);
    if (isNaN(a) || isNaN(b)) return false;
    return a === b;
  }

  private numericGreaterThan(actual: ConditionValue, expected: ConditionValue): boolean {
    const a = Number(actual);
    const b = Number(expected);
    if (isNaN(a) || isNaN(b)) return false;
    return a > b;
  }

  private numericLessThan(actual: ConditionValue, expected: ConditionValue): boolean {
    const a = Number(actual);
    const b = Number(expected);
    if (isNaN(a) || isNaN(b)) return false;
    return a < b;
  }

  // ─── Boolean operator ────────────────────────────────────────────────────

  private boolMatch(actual: ConditionValue, expected: ConditionValue): boolean {
    const a = this.toBool(actual);
    const b = this.toBool(expected);
    if (a === null || b === null) return false;
    return a === b;
  }

  private toBool(value: ConditionValue): boolean | null {
    if (typeof value === 'boolean') return value;
    if (typeof value === 'string') {
      if (value.toLowerCase() === 'true') return true;
      if (value.toLowerCase() === 'false') return false;
    }
    if (typeof value === 'number') return value !== 0;
    return null;
  }

  // ─── Array operators ─────────────────────────────────────────────────────

  /**
   * Check if the actual array contains at least one of the expected values.
   */
  private arrayContains(actual: ConditionValue, expected: ConditionValue): boolean {
    const actualArr = this.toStringArray(actual);
    const expectedArr = this.toStringArray(expected);
    if (!actualArr || !expectedArr) return false;
    return expectedArr.some((e) => actualArr.includes(e));
  }

  /**
   * Check if the actual array contains ALL of the expected values.
   */
  private arrayContainsAll(actual: ConditionValue, expected: ConditionValue): boolean {
    const actualArr = this.toStringArray(actual);
    const expectedArr = this.toStringArray(expected);
    if (!actualArr || !expectedArr) return false;
    return expectedArr.every((e) => actualArr.includes(e));
  }

  private toStringArray(value: ConditionValue): string[] | null {
    if (Array.isArray(value)) {
      return value.map(String);
    }
    if (typeof value === 'string') {
      return [value];
    }
    if (typeof value === 'number') {
      return [String(value)];
    }
    return null;
  }
}

// ─── Time-based condition helpers ──────────────────────────────────────────

/**
 * Check if the given time falls within business hours.
 */
export function isWithinBusinessHours(
  time: Date,
  startHour: number,
  endHour: number,
  daysOfWeek?: number[],
  timezone: string = 'UTC'
): boolean {
  let hour: number;
  let dayOfWeek: number;

  try {
    // Use Intl to get the time in the specified timezone
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      hour: 'numeric',
      hour12: false,
      weekday: 'short',
    });
    const parts = formatter.formatToParts(time);
    const hourPart = parts.find((p) => p.type === 'hour');
    hour = hourPart ? parseInt(hourPart.value, 10) : time.getUTCHours();

    // Get day of week in timezone
    const dayFormatter = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone,
      weekday: 'long',
    });
    const dayStr = dayFormatter.format(time);
    const dayMap: Record<string, number> = {
      Sunday: 0,
      Monday: 1,
      Tuesday: 2,
      Wednesday: 3,
      Thursday: 4,
      Friday: 5,
      Saturday: 6,
    };
    dayOfWeek = dayMap[dayStr] ?? time.getUTCDay();
  } catch {
    // Fallback to UTC
    hour = time.getUTCHours();
    dayOfWeek = time.getUTCDay();
  }

  // Check day of week if specified
  if (daysOfWeek && daysOfWeek.length > 0 && !daysOfWeek.includes(dayOfWeek)) {
    return false;
  }

  // Handle ranges that span midnight (e.g., 22 to 6)
  if (startHour <= endHour) {
    return hour >= startHour && hour < endHour;
  } else {
    return hour >= startHour || hour < endHour;
  }
}

/**
 * Check if the given time falls within a maintenance window.
 */
export function isInMaintenanceWindow(
  time: Date,
  windowStart: Date,
  windowEnd: Date
): boolean {
  const t = time.getTime();
  return t >= windowStart.getTime() && t <= windowEnd.getTime();
}

// ─── Evaluation context ────────────────────────────────────────────────────

/**
 * The flattened evaluation context built from a PolicyRequest.
 * Provides dotted-path field resolution for conditions.
 */
export interface EvaluationContext {
  actor: {
    id: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  action: string;
  resource: {
    type: string;
    id: string;
    attributes: Record<string, unknown>;
  };
  environment: {
    ip?: string;
    time?: string;
    deviceId?: string;
    sessionId?: string;
    stepUpLevel?: number;
    custom?: Record<string, unknown>;
  };
}

/**
 * Build an EvaluationContext from a PolicyRequest.
 */
export function buildEvaluationContext(request: PolicyRequest): EvaluationContext {
  return {
    actor: {
      id: request.actor.id,
      roles: request.actor.roles,
      attributes: request.actor.attributes ?? {},
    },
    action: request.action,
    resource: {
      type: request.resource.type,
      id: request.resource.id,
      attributes: request.resource.attributes ?? {},
    },
    environment: {
      ip: request.environment?.ip,
      time: request.environment?.time ?? new Date().toISOString(),
      deviceId: request.environment?.deviceId,
      sessionId: request.environment?.sessionId,
      stepUpLevel: request.environment?.stepUpLevel,
      custom: request.environment?.custom as Record<string, unknown> | undefined,
    },
  };
}

export const conditionEvaluator = new ConditionEvaluator();
