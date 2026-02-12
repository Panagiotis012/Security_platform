export type ControlPlaneAuditOutcome = 'success' | 'failure';

export interface ControlPlaneAuditEvent {
  cursor: string;
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  method: string;
  path: string;
  statusCode: number;
  outcome: ControlPlaneAuditOutcome;
  requestBodyHash: string;
  requestContentLength?: number;
  idempotencyKey?: string;
  permissionScope?: string;
}

export interface ControlPlaneAuditEventAppendInput {
  eventId: string;
  source: string;
  occurredAt: string;
  actor: string;
  correlationId?: string;
  method: string;
  path: string;
  statusCode: number;
  outcome: ControlPlaneAuditOutcome;
  requestBodyHash: string;
  requestContentLength?: number;
  idempotencyKey?: string;
  permissionScope?: string;
}

export interface ControlPlaneAuditEventListResult {
  entries: ControlPlaneAuditEvent[];
  nextCursor: string;
}

export interface ControlPlaneAuditImportCursorAdvanceResult {
  source: string;
  previousCursor: string;
  currentCursor: string;
  updated: boolean;
}

export interface ControlPlaneAuditStore {
  append(
    event: ControlPlaneAuditEventAppendInput,
    maxEntries: number,
  ): Promise<ControlPlaneAuditEvent>;
  listAfter(afterCursor: string, limit: number): Promise<ControlPlaneAuditEventListResult>;
  latestCursor(): Promise<string>;
  getImportedCursor(source: string): Promise<string>;
  advanceImportedCursor(
    source: string,
    cursor: string,
  ): Promise<ControlPlaneAuditImportCursorAdvanceResult>;
}
