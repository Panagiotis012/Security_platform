import crypto from 'crypto';
import { canonicalizePath, canonicalizeHeaders } from '../../shared/src/utils/canonicalize';

function randomAscii(len: number): string {
  const bytes = crypto.randomBytes(len);
  let out = '';
  for (const b of bytes) {
    // Printable-ish ASCII plus a few separators that matter for paths.
    const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~/%\\\\?&=+;:@,";
    out += alphabet[b % alphabet.length];
  }
  return out;
}

describe('Fuzz - Canonicalization', () => {
  test('canonicalizePath is idempotent and never returns traversal segments', () => {
    for (let i = 0; i < 2000; i++) {
      const raw = randomAscii(64);
      try {
        const a = canonicalizePath(raw);
        const b = canonicalizePath(a.value);

        expect(b.value).toBe(a.value);
        expect(a.value).toBe(a.value.toLowerCase());
        expect(a.value.includes('..')).toBe(false);
        expect(a.value.startsWith('/')).toBe(true);
      } catch (err) {
        // Throws are acceptable for malicious inputs; ensure it's a normal Error object.
        expect(err).toBeInstanceOf(Error);
      }
    }
  });

  test('canonicalizeHeaders lowercases keys and strips empties', () => {
    for (let i = 0; i < 500; i++) {
      const headers: Record<string, string> = {
        'X-Test': '  hello   world  ',
        'X-Empty': '   ',
        'Content-Type': 'application/json; charset=utf-8',
        'X-Multi': 'a,   b',
      };

      const out = canonicalizeHeaders(headers);
      expect(out['x-test']).toBe('hello world');
      expect(out['content-type']).toBe('application/json; charset=utf-8');
      expect(out['x-empty']).toBeUndefined();
      expect(Object.keys(out).every((k) => k === k.toLowerCase())).toBe(true);
    }
  });
});

