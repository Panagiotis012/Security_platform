/* Minimal Express req/res mocks for unit-testing middleware without supertest. */

export interface MockResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: unknown;
  ended: boolean;
  status(code: number): MockResponse;
  json(payload: unknown): MockResponse;
  end(payload?: unknown): MockResponse;
  setHeader(name: string, value: string): void;
  getHeader(name: string): string | undefined;
}

export function createMockRes(): MockResponse {
  const res: MockResponse = {
    statusCode: 200,
    headers: {},
    body: undefined,
    ended: false,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(payload: unknown) {
      res.body = payload;
      res.ended = true;
      return res;
    },
    end(payload?: unknown) {
      res.body = payload;
      res.ended = true;
      return res;
    },
    setHeader(name: string, value: string) {
      res.headers[name.toLowerCase()] = String(value);
    },
    getHeader(name: string) {
      return res.headers[name.toLowerCase()];
    },
  };

  return res;
}

export function createNext() {
  const next = jest.fn();
  return next;
}

