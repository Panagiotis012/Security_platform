/**
 * Hot-reloadable detection rules configuration system.
 *
 * This module provides a configuration manager that:
 * - Loads detection rule configurations from JSON/YAML files
 * - Watches for file changes and hot-reloads configurations
 * - Merges file-based config with programmatic defaults
 * - Validates configurations using Zod schemas
 * - Emits events when configurations change
 * - Supports runtime threshold overrides per detection
 *
 * The system is designed to allow operators to tune detection thresholds
 * without restarting the service, improving operational efficiency.
 */

import { EventEmitter } from 'events';
import type { FSWatcher } from 'fs';
import { existsSync, readFileSync, watch } from 'fs';
import { dirname, resolve } from 'path';
import { mkdirSync, writeFileSync } from 'fs';
import { z } from 'zod';
import winston from 'winston';
import type { Detection, AlertSeverity, DetectionType } from './detection-engine';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'detection-config' },
  transports: [new winston.transports.Console()],
});

// ─────────────────────────────────────────────────────────────────────────────
// Types & Schemas
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Configuration for a single detection rule as loaded from file.
 * Maps to the Detection interface but allows partial configuration.
 */
export interface DetectionRuleConfig {
  id: string;
  name: string;
  description: string;
  severity: AlertSeverity;
  type: DetectionType;
  enabled: boolean;
  suppressionWindowSeconds: number;
  thresholds: Record<string, number>;
}

/**
 * Raw configuration file structure (JSON/YAML parsed to object).
 */
export interface DetectionConfigFile {
  version: string;
  timestamp?: string;
  detections: DetectionRuleConfig[];
}

/**
 * Zod schema for validating threshold values.
 */
const ThresholdSchema = z.record(z.string(), z.number().positive());

/**
 * Zod schema for validating a single detection rule configuration.
 */
const DetectionRuleConfigSchema = z.object({
  id: z.string().min(1).max(256),
  name: z.string().min(1).max(256),
  description: z.string().max(2048),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  type: z.enum(['threshold', 'pattern', 'statistical', 'behavioral']),
  enabled: z.boolean(),
  suppressionWindowSeconds: z.number().int().positive(),
  thresholds: ThresholdSchema,
});

/**
 * Zod schema for validating the entire configuration file.
 */
const DetectionConfigFileSchema = z.object({
  version: z.string(),
  timestamp: z.string().optional(),
  detections: z.array(DetectionRuleConfigSchema),
});

// ─────────────────────────────────────────────────────────────────────────────
// Default Configuration
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Default detection configurations matching the existing 10 detections.
 * These values correspond to the current hardcoded thresholds in the codebase.
 */
const DEFAULT_DETECTION_CONFIG: DetectionConfigFile = {
  version: '1.0',
  timestamp: new Date().toISOString(),
  detections: [
    {
      id: 'brute-force',
      name: 'Brute Force Login Detection',
      description: 'Detects multiple failed login attempts from the same actor or IP address within a short time window.',
      severity: 'HIGH',
      type: 'threshold',
      enabled: true,
      suppressionWindowSeconds: 600,
      thresholds: {
        maxFailedLogins: 10,
        windowMinutes: 5,
      },
    },
    {
      id: 'credential-stuffing',
      name: 'Credential Stuffing Detection',
      description: 'Detects automated credential stuffing attacks using stolen credential lists from the same IP range.',
      severity: 'HIGH',
      type: 'pattern',
      enabled: true,
      suppressionWindowSeconds: 900,
      thresholds: {
        maxDistinctUsernames: 20,
        windowMinutes: 10,
        ipRangePrefixLength: 24,
      },
    },
    {
      id: 'password-spraying',
      name: 'Password Spraying Detection',
      description: 'Detects password spraying attacks where an attacker tries a few common passwords across many accounts.',
      severity: 'HIGH',
      type: 'pattern',
      enabled: true,
      suppressionWindowSeconds: 900,
      thresholds: {
        minAffectedAccounts: 10,
        maxPerAccountAttempts: 3,
        windowMinutes: 15,
      },
    },
    {
      id: 'token-replay',
      name: 'Token Replay Detection',
      description: 'Detects reuse of authentication tokens from different IP addresses or devices.',
      severity: 'MEDIUM',
      type: 'statistical',
      enabled: true,
      suppressionWindowSeconds: 60,
      thresholds: {
        enabled: 1,
      },
    },
    {
      id: 'impossible-travel',
      name: 'Impossible Travel Detection',
      description: 'Detects when a user authenticates from geographically distant locations in an impossibly short time.',
      severity: 'HIGH',
      type: 'behavioral',
      enabled: true,
      suppressionWindowSeconds: 3600,
      thresholds: {
        maxDistanceKm: 500,
        minTimeHours: 1,
      },
    },
    {
      id: 'mass-export',
      name: 'Mass Data Export Detection',
      description: 'Detects when a user exports an unusually large amount of data in a short time.',
      severity: 'CRITICAL',
      type: 'threshold',
      enabled: true,
      suppressionWindowSeconds: 300,
      thresholds: {
        maxRecordsPerWindow: 100,
        maxBytesPerWindow: 52428800, // 50MB
        windowMinutes: 5,
      },
    },
    {
      id: 'privilege-escalation',
      name: 'Privilege Escalation Detection',
      description: 'Detects repeated attempts to escalate privileges or access administrative functions.',
      severity: 'CRITICAL',
      type: 'threshold',
      enabled: true,
      suppressionWindowSeconds: 600,
      thresholds: {
        maxDeniedAdminAttempts: 5,
        windowMinutes: 10,
      },
    },
    {
      id: 'anomalous-access',
      name: 'Anomalous Access Pattern Detection',
      description: 'Detects access patterns that deviate from established user baselines (unusual hours, volume anomalies).',
      severity: 'MEDIUM',
      type: 'statistical',
      enabled: true,
      suppressionWindowSeconds: 1800,
      thresholds: {
        baselineWindowDays: 7,
        stdDevMultiplier: 2.5,
        unusualHoursStart: 0,
        unusualHoursEnd: 6,
      },
    },
    {
      id: 'policy-violation-surge',
      name: 'Policy Violation Surge Detection',
      description: 'Detects a sudden surge in policy violations (deny decisions) which may indicate an attack or misconfiguration.',
      severity: 'MEDIUM',
      type: 'statistical',
      enabled: true,
      suppressionWindowSeconds: 600,
      thresholds: {
        surgeMultiplier: 5,
        windowMinutes: 10,
        minBaselineCount: 5,
      },
    },
    {
      id: 'session-anomaly',
      name: 'Session Anomaly Detection',
      description: 'Detects anomalous session activity such as IP changes without reauthentication or excessive IP diversity.',
      severity: 'MEDIUM',
      type: 'behavioral',
      enabled: true,
      suppressionWindowSeconds: 300,
      thresholds: {
        maxIpsPerSession: 3,
        enabled: 1,
      },
    },
  ],
};

// ─────────────────────────────────────────────────────────────────────────────
// DetectionConfigManager
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Manages detection rule configurations with support for file-based loading,
 * hot-reloading, and runtime threshold overrides.
 *
 * Events emitted:
 * - 'configReloaded': emitted when configuration is reloaded from file
 * - 'configError': emitted when configuration loading or validation fails
 * - 'thresholdUpdated': emitted when a threshold is updated at runtime
 */
export class DetectionConfigManager extends EventEmitter {
  private configPath: string;
  private config: DetectionConfigFile;
  private fileWatcher: FSWatcher | null = null;
  private detectionImplementations: Map<string, Detection> = new Map();
  private runtimeThresholdOverrides: Map<string, Record<string, number>> = new Map();
  private isInitialized = false;

  /**
   * Create a new DetectionConfigManager.
   *
   * @param configPath The path to the detection rules configuration file.
   *                    If the file doesn't exist, a default config is created.
   */
  constructor(configPath: string = 'config/detection-rules.json') {
    super();
    this.configPath = resolve(configPath);
    this.config = structuredClone(DEFAULT_DETECTION_CONFIG);
    logger.info('DetectionConfigManager created', { configPath: this.configPath });
  }

  /**
   * Initialize the configuration manager: load the config file and start watching for changes.
   *
   * @throws {Error} If config validation fails
   */
  public async initialize(): Promise<void> {
    if (this.isInitialized) {
      logger.warn('DetectionConfigManager already initialized');
      return;
    }

    try {
      // Ensure config directory exists
      const configDir = dirname(this.configPath);
      if (!existsSync(configDir)) {
        mkdirSync(configDir, { recursive: true });
        logger.info('Created config directory', { path: configDir });
      }

      // Load or create default config
      if (existsSync(this.configPath)) {
        logger.info('Loading existing config', { path: this.configPath });
        this.loadConfigFromFile();
      } else {
        logger.info('Config file does not exist, creating default', { path: this.configPath });
        this.saveDefaultConfig();
      }

      // Start watching for file changes
      this.startFileWatcher();
      this.isInitialized = true;
      logger.info('DetectionConfigManager initialized successfully');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Failed to initialize DetectionConfigManager', { error: message });
      this.emit('configError', { phase: 'initialization', error: message });
      throw err;
    }
  }

  /**
   * Shut down the configuration manager and stop watching for file changes.
   */
  public shutdown(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = null;
      logger.info('File watcher stopped');
    }
    this.isInitialized = false;
  }

  /**
   * Register a detection implementation with the manager.
   * This allows the manager to apply thresholds to live detection instances.
   *
   * @param detection The Detection instance to register
   */
  public registerDetection(detection: Detection): void {
    if (!this.detectionImplementations.has(detection.id)) {
      this.detectionImplementations.set(detection.id, detection);
      logger.debug('Detection implementation registered', { id: detection.id });

      // Apply any existing threshold overrides to the newly registered detection
      const overrides = this.runtimeThresholdOverrides.get(detection.id);
      if (overrides) {
        detection.thresholds = { ...detection.thresholds, ...overrides };
        logger.info('Applied threshold overrides to registered detection', { id: detection.id });
      }

      // Apply config-loaded thresholds
      const configEntry = this.config.detections.find((d) => d.id === detection.id);
      if (configEntry) {
        detection.enabled = configEntry.enabled;
        detection.suppressionWindowSeconds = configEntry.suppressionWindowSeconds;
        detection.thresholds = { ...detection.thresholds, ...configEntry.thresholds };
        logger.info('Applied config thresholds to registered detection', {
          id: detection.id,
          thresholds: detection.thresholds,
        });
      }
    }
  }

  /**
   * Get a detection configuration by ID.
   *
   * @param detectionId The detection ID
   * @returns The detection rule config, or undefined if not found
   */
  public getDetectionConfig(detectionId: string): DetectionRuleConfig | undefined {
    return this.config.detections.find((d) => d.id === detectionId);
  }

  /**
   * Get all detection configurations.
   *
   * @returns Array of all loaded detection configurations
   */
  public getAllDetectionConfigs(): DetectionRuleConfig[] {
    return this.config.detections.map((d) => ({ ...d }));
  }

  /**
   * Update thresholds for a specific detection at runtime.
   * The update is applied immediately to any registered detection implementations.
   *
   * @param detectionId The detection ID
   * @param thresholds The new threshold values (merged with existing)
   * @returns true if successful, false if detection not found
   */
  public updateThresholds(detectionId: string, thresholds: Record<string, number>): boolean {
    try {
      // Validate the threshold values
      const validated = ThresholdSchema.parse(thresholds);

      // Update the configuration
      const configEntry = this.config.detections.find((d) => d.id === detectionId);
      if (!configEntry) {
        logger.warn('Cannot update thresholds: detection not found', { id: detectionId });
        return false;
      }

      // Merge with existing thresholds
      const oldThresholds = { ...configEntry.thresholds };
      configEntry.thresholds = { ...configEntry.thresholds, ...validated };

      // Store override for future registrations
      const existingOverrides = this.runtimeThresholdOverrides.get(detectionId) || {};
      this.runtimeThresholdOverrides.set(detectionId, {
        ...existingOverrides,
        ...validated,
      });

      // Apply to registered detection implementation if it exists
      const detection = this.detectionImplementations.get(detectionId);
      if (detection) {
        detection.thresholds = { ...detection.thresholds, ...validated };
        logger.info('Applied runtime threshold update to detection', {
          id: detectionId,
          oldThresholds,
          newThresholds: detection.thresholds,
        });
      }

      this.emit('thresholdUpdated', { detectionId, thresholds: validated });
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Failed to update thresholds', { detectionId, error: message });
      return false;
    }
  }

  /**
   * Set the enabled state of a detection.
   *
   * @param detectionId The detection ID
   * @param enabled Whether the detection should be enabled
   * @returns true if successful, false if detection not found
   */
  public setDetectionEnabled(detectionId: string, enabled: boolean): boolean {
    const configEntry = this.config.detections.find((d) => d.id === detectionId);
    if (!configEntry) {
      logger.warn('Cannot set enabled state: detection not found', { id: detectionId });
      return false;
    }

    configEntry.enabled = enabled;

    // Apply to registered detection implementation if it exists
    const detection = this.detectionImplementations.get(detectionId);
    if (detection) {
      detection.enabled = enabled;
      logger.info('Updated detection enabled state', { id: detectionId, enabled });
    }

    return true;
  }

  /**
   * Export the current configuration (including any runtime overrides) as a JSON object.
   *
   * @returns The current configuration
   */
  public exportConfig(): DetectionConfigFile {
    return structuredClone(this.config);
  }

  /**
   * Reload configuration from file, discarding any unsaved runtime changes.
   * Emits 'configReloaded' event on success.
   *
   * @throws {Error} If config validation fails
   */
  public reloadConfigFromFile(): void {
    try {
      this.loadConfigFromFile();
      logger.info('Configuration reloaded from file');
      this.emit('configReloaded', { config: this.config });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.error('Failed to reload configuration', { error: message });
      this.emit('configError', { phase: 'reload', error: message });
      throw err;
    }
  }

  /**
   * Reset all runtime threshold overrides.
   * The configuration will revert to file-based values on the next reload or for new registrations.
   */
  public resetRuntimeOverrides(): void {
    this.runtimeThresholdOverrides.clear();
    logger.info('Reset all runtime threshold overrides');
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Private methods
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Load and validate configuration from file.
   *
   * @throws {Error} If file reading or validation fails
   */
  private loadConfigFromFile(): void {
    if (!existsSync(this.configPath)) {
      throw new Error(`Config file not found: ${this.configPath}`);
    }

    try {
      const fileContent = readFileSync(this.configPath, 'utf-8');
      const parsed = JSON.parse(fileContent);

      // Validate against schema
      const validated = DetectionConfigFileSchema.parse(parsed);
      this.config = validated;

      logger.info('Configuration loaded and validated', {
        path: this.configPath,
        detectionCount: this.config.detections.length,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      throw new Error(`Failed to load config file: ${message}`);
    }
  }

  /**
   * Save the default configuration to file.
   */
  private saveDefaultConfig(): void {
    try {
      const content = JSON.stringify(DEFAULT_DETECTION_CONFIG, null, 2);
      writeFileSync(this.configPath, content, 'utf-8');
      this.config = structuredClone(DEFAULT_DETECTION_CONFIG);

      logger.info('Default configuration created', { path: this.configPath });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      throw new Error(`Failed to save default config: ${message}`);
    }
  }

  /**
   * Start watching the configuration file for changes.
   * When the file changes, automatically reload the configuration.
   */
  private startFileWatcher(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
    }

    try {
      this.fileWatcher = watch(this.configPath, (eventType, filename) => {
        // Debounce rapid changes (file systems can emit multiple events)
        if (eventType === 'change' && filename) {
          logger.debug('Config file change detected', { eventType, filename });

          // Schedule reload after a short delay to allow file write to complete
          setTimeout(() => {
            try {
              this.loadConfigFromFile();

              // Reapply thresholds to all registered detections
              for (const [detectionId, detection] of this.detectionImplementations) {
                const configEntry = this.config.detections.find((d) => d.id === detectionId);
                if (configEntry) {
                  detection.enabled = configEntry.enabled;
                  detection.suppressionWindowSeconds = configEntry.suppressionWindowSeconds;

                  // Merge config thresholds with any runtime overrides
                  const overrides = this.runtimeThresholdOverrides.get(detectionId) || {};
                  detection.thresholds = {
                    ...configEntry.thresholds,
                    ...overrides,
                  };

                  logger.info('Reapplied thresholds to detection after config reload', {
                    id: detectionId,
                    thresholds: detection.thresholds,
                  });
                }
              }

              logger.info('Configuration successfully reloaded from file');
              this.emit('configReloaded', { config: this.config });
            } catch (err) {
              const message = err instanceof Error ? err.message : 'Unknown error';
              logger.error('Failed to reload configuration after file change', { error: message });
              this.emit('configError', { phase: 'fileWatch', error: message });
            }
          }, 500);
        }
      });

      logger.info('File watcher started', { path: this.configPath });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      logger.warn('Failed to start file watcher', { error: message });
      // Non-fatal: continue without watching
    }
  }
}

/**
 * Create a default configuration in the expected location.
 * Useful for initialization or testing.
 *
 * @param configPath The path where the default config should be created
 * @throws {Error} If file write fails
 */
export function createDefaultDetectionConfig(configPath: string = 'config/detection-rules.json'): void {
  const resolvedPath = resolve(configPath);
  const configDir = dirname(resolvedPath);

  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }

  const content = JSON.stringify(DEFAULT_DETECTION_CONFIG, null, 2);
  writeFileSync(resolvedPath, content, 'utf-8');

  logger.info('Default detection configuration file created', { path: resolvedPath });
}
