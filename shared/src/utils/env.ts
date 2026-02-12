import fs from 'node:fs';

export interface ReadEnvOptions {
  /**
   * When true, throws if the value is missing/empty after trimming.
   * Use sparingly; most code should decide "required" based on mode (prod/dev).
   */
  required?: boolean;
  /** Fallback when the env var (and *_FILE) are not set. */
  defaultValue?: string;
  /** Defaults to true. */
  trim?: boolean;
  /**
   * Defaults to false. When false, empty strings are treated as missing.
   * When true, an empty string is allowed.
   */
  allowEmpty?: boolean;
}

function normalize(v: string, opts: ReadEnvOptions): string {
  const trim = opts.trim !== false;
  const next = trim ? v.trim() : v;
  if (!opts.allowEmpty && next.length === 0) return '';
  return next;
}

/**
 * Read an environment variable, supporting the common `${NAME}_FILE` convention.
 *
 * If `${NAME}_FILE` is set, the value is read from that path. Otherwise `process.env[NAME]`
 * is used.
 *
 * File values are trimmed by default to remove trailing newlines from secret mounts.
 */
export function readSecret(name: string, opts: ReadEnvOptions = {}): string {
  const fileVar = `${name}_FILE`;
  const filePathRaw = process.env[fileVar];
  if (filePathRaw) {
    const filePath = normalize(filePathRaw, { ...opts, trim: true });
    if (!filePath) {
      if (opts.required) throw new Error(`${fileVar} is set but empty`);
      return '';
    }

    try {
      const raw = fs.readFileSync(filePath, 'utf8');
      const v = normalize(raw, { ...opts, trim: true });
      if (opts.required && !v) throw new Error(`${name} is missing (empty ${fileVar} file)`);
      return v;
    } catch (err) {
      if (opts.required) {
        throw new Error(`${fileVar} points to an unreadable file: ${filePath}`);
      }
      return '';
    }
  }

  const envRaw = process.env[name];
  const v = normalize(envRaw ?? (opts.defaultValue ?? ''), opts);
  if (opts.required && !v) throw new Error(`${name} is missing`);
  return v;
}

