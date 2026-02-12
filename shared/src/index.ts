/**
 * @zerotrust/shared – Shared utilities layer for the Zero Trust security platform.
 *
 * This barrel file re-exports everything so consumers can import from a
 * single entry point:
 *
 *   import { AuditEventSchema, StructuredLogger, KeyManager } from '@zerotrust/shared';
 */

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

export {
  // Audit event
  AuditSchemaVersion,
  CURRENT_AUDIT_SCHEMA_VERSION,
  ActorType,
  SubjectType,
  AuditDecision,
  ActorSchema,
  SubjectSchema,
  ResourceSchema,
  ResultSchema,
  GeoLocationSchema,
  AuditContextSchema,
  AuditEventV2Additions,
  AuditEventSchema,
  createAuditEvent,
  parseAuditEvent,
  redactAuditEvent,
} from './models/audit-event';

export type {
  Actor,
  Subject,
  Resource,
  AuditResult,
  GeoLocation,
  AuditContext,
  AuditEvent,
  AuditEventInput,
} from './models/audit-event';

export {
  // Policy
  PolicyEffect,
  ConditionOperator,
  AttributeConditionSchema,
  RBACConditionSchema,
  ConditionsSchema,
  PolicySchema,
  PolicyDecisionSchema,
  PolicyEvaluationResultSchema,
  parsePolicy,
  actionMatchesPattern,
  resourceMatchesPattern,
} from './models/policy';

export type {
  AttributeCondition,
  RBACCondition,
  Conditions,
  Policy,
  PolicyDecision,
  PolicyEvaluationResult,
} from './models/policy';

export {
  // Identity
  IdentityType,
  PrivilegeLevel,
  SessionStatus,
  UserIdentitySchema,
  WorkloadIdentitySchema,
  IdentitySchema,
  SessionSchema,
  TokenClaimsSchema,
  isSessionIdle,
  isSessionExpired,
  isSessionValid,
  parseTokenClaims,
  isTokenExpired,
  getScopes,
  hasScopes,
} from './models/identity';

export type {
  UserIdentity,
  WorkloadIdentity,
  Identity,
  Session,
  TokenClaims,
} from './models/identity';

// ---------------------------------------------------------------------------
// Crypto
// ---------------------------------------------------------------------------

export { KeyManager } from './crypto/keys';

export type {
  KeyAlgorithm,
  KeyMetadata,
  ManagedKeyPair,
  SignResult,
  VerifyResult,
} from './crypto/keys';

export { HashChain } from './crypto/hash-chain';

export type {
  HashChainEntry,
  HashChainVerificationResult,
} from './crypto/hash-chain';

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

export {
  PIIRedactor,
  getDefaultRedactor,
  redactPII,
} from './logging/pii-redactor';

export type {
  PIICategory,
  RedactionRule,
  PIIRedactorConfig,
} from './logging/pii-redactor';

export {
  StructuredLogger,
  initLogger,
  getLogger,
} from './logging/structured-logger';

export type {
  StructuredLoggerConfig,
  LogPayload,
} from './logging/structured-logger';

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

export {
  correlationIdMiddleware,
  getCorrelationId,
} from './middleware/correlation-id';

export type {
  CorrelationRequest,
  CorrelationResponse,
  NextFunction,
  CorrelationIdMiddlewareOptions,
} from './middleware/correlation-id';

export {
  INTERNAL_AUTH_HEADERS,
  computeInternalAuthHeaders,
  verifyInternalAuth,
  verifyInternalAuthAsync,
  sha256Hex,
  hmacSha256Hex,
  buildInternalSignatureInput,
  InMemoryInternalAuthReplayStore,
  RedisInternalAuthReplayStore,
} from './middleware/internal-auth';

export type {
  InternalAuthOptions,
  InternalAuthRequestLike,
  InternalAuthReplayStore,
} from './middleware/internal-auth';

// ---------------------------------------------------------------------------
// Utils
// ---------------------------------------------------------------------------

export {
  canonicalizePath,
  canonicalizeHeaders,
  detectAmbiguousEncoding,
  blockTraversalAttempts,
} from './utils/canonicalize';

export type {
  CanonicalizationResult,
  AmbiguousEncodingResult,
} from './utils/canonicalize';

export {
  validate,
  validateOrThrow,
  validateRequestBody,
  validateQueryParams,
  validateHeaders,
  SafeString,
  TrimmedString,
  UUIDString,
  ISODateString,
  StrictInt,
  PositiveInt,
  NonNegativeInt,
  StrictFloat,
  EmailString,
  HttpsUrl,
  IPAddress,
  PaginationSchema,
} from './utils/validation';

export type {
  ValidationResult,
  ValidationFailure,
  PaginationParams,
} from './utils/validation';

export { readSecret } from './utils/env';
export type { ReadEnvOptions } from './utils/env';

export {
  InMemoryRateLimitStore,
  rateLimitKeyByIP,
  rateLimitKeyByIdentity,
  rateLimitKeyByRoute,
  rateLimitKeyComposite,
} from './utils/rate-limit-store';

export type {
  RateLimitStore,
  RateLimitConfig,
  RateLimitResult,
  GreylistEntry,
} from './utils/rate-limit-store';

export {
  SecurityErrorCode,
  SecurityError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  ValidationError,
  PolicyViolationError,
  IntegrityError,
  toSecurityError,
} from './utils/errors';

export type { SecurityErrorOptions } from './utils/errors';

export { RedisRateLimitStore } from './utils/redis-rate-limit-store';

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export {
  MetricsRegistry,
  globalMetrics,
  initializeDefaultMetrics,
} from './metrics/prometheus';

export {
  createRequestMetricsMiddleware,
  requestMetricsMiddleware,
  recordRateLimitHit,
  recordAuthAttempt,
  recordPolicyDecision,
  recordDetectionAlert,
  setCircuitBreakerState,
  recordAuditEventsIngested,
  setActiveSessionCount,
  setRedisConnectionStatus,
} from './metrics/request-metrics';

// ---------------------------------------------------------------------------
// Crypto – Merkle Tree
// ---------------------------------------------------------------------------

export {
  MerkleTree,
  AuditAnchorChain,
  hashAuditEvent,
  verifyAnchorChain,
} from './crypto/merkle-tree';

export type {
  MerkleNode,
  InclusionProof,
  MerkleTreeState,
  AuditAnchor,
  AuditAnchorSnapshot,
} from './crypto/merkle-tree';

// ---------------------------------------------------------------------------
// Middleware – Break Glass
// ---------------------------------------------------------------------------

export {
  BreakGlassManager,
  BreakGlassErrorCode,
  breakGlassMiddleware,
  getBreakGlassSession,
  isBreakGlassRequest,
} from './middleware/break-glass';

export type {
  BreakGlassSession,
  BreakGlassAction,
  BreakGlassAuditEntry,
  BreakGlassEligibility,
  BreakGlassApprovalConfig,
  BreakGlassReviewConfig,
  BreakGlassManagerConfig,
  BreakGlassReviewStatus,
  BreakGlassSessionStore,
  BreakGlassAuditStore,
  BreakGlassMiddlewareOptions,
} from './middleware/break-glass';

// ---------------------------------------------------------------------------
// Health Probes
// ---------------------------------------------------------------------------

export {
  HealthProbeManager,
  createRedisCheck,
  createHttpCheck,
  createCustomCheck,
} from './middleware/health-probes';

export type {
  DependencyCheckResult,
  DependencyCheckFunction,
  HealthProbeManagerOptions,
  HealthProbeResponse,
} from './middleware/health-probes';

// ---------------------------------------------------------------------------
// Tracing
// ---------------------------------------------------------------------------

export {
  TracingManager,
  initializeTracing,
  createSpan,
  addSecurityEvent,
  recordError,
  injectTraceContext,
  extractTraceContext,
  tracingMiddleware,
} from './tracing/tracer';

export type {
  SecurityContext,
  SecurityEvent,
  TracingConfig,
  TracingRequest,
  TracingResponse,
  TracingMiddlewareOptions,
} from './tracing/tracer';
