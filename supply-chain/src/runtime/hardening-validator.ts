/**
 * Hardening Validator
 *
 * Validates container runtime configurations against security hardening
 * requirements. Ensures workloads follow the principle of least privilege
 * and meet organizational security baselines before deployment.
 */

import winston from 'winston';
import type { HardeningRequirement } from '../../config/default';
import defaultConfig from '../../config/default';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  defaultMeta: { service: 'hardening-validator' },
  transports: [new winston.transports.Console()],
});

// ── Container Config Types ──

export interface SecurityContext {
  runAsNonRoot?: boolean;
  runAsUser?: number;
  runAsGroup?: number;
  readOnlyRootFilesystem?: boolean;
  allowPrivilegeEscalation?: boolean;
  privileged?: boolean;
  capabilities?: {
    add?: string[];
    drop?: string[];
  };
  seccompProfile?: {
    type: 'RuntimeDefault' | 'Localhost' | 'Unconfined';
    localhostProfile?: string;
  };
  seLinuxOptions?: {
    level?: string;
    role?: string;
    type?: string;
    user?: string;
  };
}

export interface ResourceRequirements {
  limits?: {
    cpu?: string;
    memory?: string;
    'ephemeral-storage'?: string;
  };
  requests?: {
    cpu?: string;
    memory?: string;
    'ephemeral-storage'?: string;
  };
}

export interface NetworkPolicy {
  egressDefined: boolean;
  ingressDefined: boolean;
  defaultDeny?: boolean;
}

export interface ContainerConfig {
  name: string;
  image: string;
  securityContext?: SecurityContext;
  resources?: ResourceRequirements;
  hostNetwork?: boolean;
  hostPID?: boolean;
  hostIPC?: boolean;
  networkPolicy?: NetworkPolicy;
  environment?: string;
  serviceAccountName?: string;
  automountServiceAccountToken?: boolean;
  ports?: Array<{
    containerPort: number;
    protocol: string;
    hostPort?: number;
  }>;
}

export interface ValidationResult {
  compliant: boolean;
  violations: string[];
  recommendations: string[];
  checkedAt: string;
  environment: string;
  containerName: string;
  score: number; // 0-100 compliance score
}

// ── Allowed capabilities (minimal set) ──

const SAFE_CAPABILITIES = new Set([
  'NET_BIND_SERVICE', // Bind to ports < 1024
  'SETUID',           // Only when absolutely required (e.g., init containers)
  'SETGID',           // Only when absolutely required
]);

const DANGEROUS_CAPABILITIES = new Set([
  'SYS_ADMIN',
  'NET_ADMIN',
  'SYS_PTRACE',
  'SYS_RAWIO',
  'SYS_MODULE',
  'SYS_BOOT',
  'DAC_OVERRIDE',
  'NET_RAW',
  'MKNOD',
  'AUDIT_WRITE',
  'CHOWN',
  'FOWNER',
  'KILL',
  'SETPCAP',
  'SYS_CHROOT',
  'SYS_TIME',
  'SYS_RESOURCE',
]);

/**
 * Parse a resource quantity string (Kubernetes format) to a numeric value in base units.
 * CPU: millicores, Memory: bytes.
 */
function parseResourceQuantity(value: string, type: 'cpu' | 'memory'): number {
  if (type === 'cpu') {
    if (value.endsWith('m')) {
      return parseInt(value.slice(0, -1), 10);
    }
    return parseFloat(value) * 1000; // cores to millicores
  }

  // Memory
  const units: Record<string, number> = {
    Ki: 1024,
    Mi: 1024 ** 2,
    Gi: 1024 ** 3,
    Ti: 1024 ** 4,
    K: 1000,
    M: 1000 ** 2,
    G: 1000 ** 3,
    T: 1000 ** 4,
  };

  for (const [suffix, multiplier] of Object.entries(units)) {
    if (value.endsWith(suffix)) {
      return parseFloat(value.slice(0, -suffix.length)) * multiplier;
    }
  }

  return parseFloat(value); // bare bytes
}

export class HardeningValidator {
  private readonly requirements: Map<string, HardeningRequirement> = new Map();

  constructor(customRequirements?: HardeningRequirement[]) {
    const reqs = customRequirements ?? defaultConfig.hardening;
    for (const req of reqs) {
      this.requirements.set(req.environment, req);
    }
  }

  /**
   * Validate a container configuration against hardening requirements
   * for the specified environment.
   */
  validateContainerConfig(config: ContainerConfig): ValidationResult {
    const environment = config.environment ?? 'production';
    const req = this.requirements.get(environment);

    if (!req) {
      logger.warn('No hardening requirements for environment, using production defaults', {
        environment,
      });
      return this.validateAgainstRequirements(
        config,
        this.requirements.get('production') ?? this.getStrictDefaults(),
        environment
      );
    }

    return this.validateAgainstRequirements(config, req, environment);
  }

  /**
   * Validate multiple containers (e.g., a pod spec).
   */
  validatePod(
    containers: ContainerConfig[],
    podEnvironment: string
  ): { overall: boolean; results: ValidationResult[] } {
    const results = containers.map((c) => {
      c.environment = c.environment ?? podEnvironment;
      return this.validateContainerConfig(c);
    });

    const overall = results.every((r) => r.compliant);

    return { overall, results };
  }

  // ── Private ──

  private validateAgainstRequirements(
    config: ContainerConfig,
    req: HardeningRequirement,
    environment: string
  ): ValidationResult {
    const violations: string[] = [];
    const recommendations: string[] = [];
    const sc = config.securityContext ?? {};

    // 1. runAsNonRoot
    if (req.runAsNonRoot) {
      if (sc.runAsNonRoot !== true) {
        violations.push('Container must set securityContext.runAsNonRoot: true');
      }
      if (sc.runAsUser === 0) {
        violations.push('Container must not run as root (UID 0)');
      }
      if (sc.runAsUser === undefined && sc.runAsNonRoot !== true) {
        recommendations.push('Explicitly set runAsUser to a non-root UID for clarity');
      }
    }

    // 2. readOnlyRootFilesystem
    if (req.readOnlyRootFilesystem) {
      if (sc.readOnlyRootFilesystem !== true) {
        violations.push('Container must set securityContext.readOnlyRootFilesystem: true');
      }
    } else {
      if (sc.readOnlyRootFilesystem !== true) {
        recommendations.push('Consider enabling readOnlyRootFilesystem for defense in depth');
      }
    }

    // 3. allowPrivilegeEscalation
    if (req.disallowPrivilegeEscalation) {
      if (sc.allowPrivilegeEscalation !== false) {
        violations.push('Container must set securityContext.allowPrivilegeEscalation: false');
      }
      if (sc.privileged === true) {
        violations.push('Container must not run in privileged mode');
      }
    }

    // 4. Capabilities
    if (req.dropAllCapabilities) {
      const dropped = sc.capabilities?.drop ?? [];
      if (!dropped.includes('ALL')) {
        violations.push('Container must drop ALL capabilities (capabilities.drop: ["ALL"])');
      }

      // Check added capabilities against allowlist
      const added = sc.capabilities?.add ?? [];
      for (const cap of added) {
        if (DANGEROUS_CAPABILITIES.has(cap)) {
          violations.push(`Dangerous capability "${cap}" must not be added`);
        } else if (!SAFE_CAPABILITIES.has(cap)) {
          recommendations.push(`Capability "${cap}" added - ensure it is necessary`);
        }
      }
    } else {
      // Even if not dropping all, flag dangerous capabilities
      const added = sc.capabilities?.add ?? [];
      for (const cap of added) {
        if (DANGEROUS_CAPABILITIES.has(cap)) {
          violations.push(`Dangerous capability "${cap}" should not be added without justification`);
        }
      }
      recommendations.push('Consider dropping ALL capabilities and only adding required ones');
    }

    // 5. Seccomp profile
    if (req.requireSeccompProfile) {
      if (!sc.seccompProfile) {
        violations.push('Container must define a seccomp profile');
      } else if (sc.seccompProfile.type === 'Unconfined') {
        violations.push('Seccomp profile must not be "Unconfined" - use "RuntimeDefault" or a custom profile');
      }
    } else {
      if (!sc.seccompProfile) {
        recommendations.push('Consider adding a seccomp profile (RuntimeDefault) for syscall filtering');
      }
    }

    // 6. Resource limits
    if (req.requireResourceLimits) {
      if (!config.resources?.limits) {
        violations.push('Container must define resource limits (CPU and memory)');
      } else {
        if (!config.resources.limits.cpu) {
          violations.push('Container must define a CPU limit');
        } else {
          const cpuLimit = parseResourceQuantity(config.resources.limits.cpu, 'cpu');
          const maxCpu = parseResourceQuantity(req.maxCpuLimit, 'cpu');
          if (cpuLimit > maxCpu) {
            violations.push(
              `CPU limit ${config.resources.limits.cpu} exceeds maximum ${req.maxCpuLimit}`
            );
          }
        }

        if (!config.resources.limits.memory) {
          violations.push('Container must define a memory limit');
        } else {
          const memLimit = parseResourceQuantity(config.resources.limits.memory, 'memory');
          const maxMem = parseResourceQuantity(req.maxMemoryLimit, 'memory');
          if (memLimit > maxMem) {
            violations.push(
              `Memory limit ${config.resources.limits.memory} exceeds maximum ${req.maxMemoryLimit}`
            );
          }
        }
      }

      if (!config.resources?.requests) {
        recommendations.push('Define resource requests for proper scheduling');
      }
    }

    // 7. Host namespaces
    if (req.disallowHostNamespaces) {
      if (config.hostNetwork === true) {
        violations.push('Container must not use host network (hostNetwork: false)');
      }
      if (config.hostPID === true) {
        violations.push('Container must not use host PID namespace (hostPID: false)');
      }
      if (config.hostIPC === true) {
        violations.push('Container must not use host IPC namespace (hostIPC: false)');
      }

      // Check for host ports
      if (config.ports) {
        for (const port of config.ports) {
          if (port.hostPort !== undefined && port.hostPort > 0) {
            violations.push(`Container must not bind to host port ${port.hostPort}`);
          }
        }
      }
    }

    // 8. Network policy (egress restrictions)
    if (req.requireNetworkPolicy) {
      if (!config.networkPolicy) {
        violations.push('Network policy must be defined (no unrestricted outbound traffic)');
      } else {
        if (!config.networkPolicy.egressDefined) {
          violations.push('Egress network policy must be defined');
        }
        if (!config.networkPolicy.ingressDefined) {
          recommendations.push('Consider defining ingress network policy');
        }
        if (config.networkPolicy.defaultDeny !== true) {
          recommendations.push('Consider setting default deny on network policy');
        }
      }
    }

    // Additional best-practice recommendations
    if (config.automountServiceAccountToken !== false) {
      recommendations.push(
        'Set automountServiceAccountToken: false unless the pod needs Kubernetes API access'
      );
    }

    if (config.serviceAccountName === 'default') {
      recommendations.push('Avoid using the default service account; create a dedicated one');
    }

    // Compute compliance score
    const totalChecks = violations.length + recommendations.length + 8; // base checks
    const passedChecks = totalChecks - violations.length;
    const score = Math.round((passedChecks / totalChecks) * 100);

    const compliant = violations.length === 0;

    const result: ValidationResult = {
      compliant,
      violations,
      recommendations,
      checkedAt: new Date().toISOString(),
      environment,
      containerName: config.name,
      score,
    };

    logger.info('Container hardening validation completed', {
      containerName: config.name,
      environment,
      compliant,
      violationCount: violations.length,
      recommendationCount: recommendations.length,
      score,
    });

    return result;
  }

  private getStrictDefaults(): HardeningRequirement {
    return {
      environment: 'default',
      runAsNonRoot: true,
      readOnlyRootFilesystem: true,
      disallowPrivilegeEscalation: true,
      dropAllCapabilities: true,
      requireSeccompProfile: true,
      requireResourceLimits: true,
      disallowHostNamespaces: true,
      requireNetworkPolicy: true,
      maxCpuLimit: '1000m',
      maxMemoryLimit: '2Gi',
    };
  }
}

export default HardeningValidator;
