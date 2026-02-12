/**
 * Adaptive Baseline System for Statistical Anomaly Detection
 *
 * Maintains rolling statistical baselines for security metrics and detects
 * anomalous behavior through statistical analysis. Uses exponential moving
 * averages (EMA) for trend tracking and standard deviation for sensitivity.
 *
 * Key features:
 * - Automatic baseline updates as new data arrives
 * - Exponential moving average for trend tracking
 * - Standard deviation-based anomaly scoring
 * - Support for seasonality (hourly/daily/weekly patterns)
 * - Configurable sensitivity thresholds
 * - Anomaly explainability (why something was flagged)
 * - False positive rate tracking
 * - Manual baseline resets for legitimate changes
 * - Persistent storage (in-memory by default, pluggable)
 *
 * Anomaly scores are normalized to [0-100]:
 * - 0-20: Normal behavior
 * - 21-40: Slightly unusual
 * - 41-60: Notable anomaly
 * - 61-80: High anomaly
 * - 81-100: Critical anomaly
 *
 * Baselines are updated continuously but respect a minimum sample size
 * to ensure statistical validity. Seasonality handling allows different
 * baselines for different times of day/week.
 */

/**
 * Represents a statistical baseline for a single metric.
 * Includes mean, standard deviation, count, EMA, and min/max bounds.
 */
export interface BaselineMetric {
  /** Name of the metric (e.g., "request_volume_per_hour") */
  name: string;
  /** Current mean (average) value */
  mean: number;
  /** Current standard deviation (measure of variability) */
  stddev: number;
  /** Number of samples used to compute baseline */
  count: number;
  /** Minimum observed value */
  min: number;
  /** Maximum observed value */
  max: number;
  /** ISO 8601 timestamp of last update */
  lastUpdated: string;
  /** Exponential moving average (tracks recent trend) */
  ema: number;
  /** Smoothing factor for EMA (typically 0.1-0.3, lower = slower response) */
  emaSmoothingFactor: number;
}

/**
 * Granularity for time-based seasonality.
 *
 * Allows maintaining separate baselines for different time periods:
 * - 'hourly': Different baselines for each hour of the day (24 baselines)
 * - 'daily': Different baselines for each day of the week (7 baselines)
 * - 'weekly': Single baseline for entire week
 */
export type TimeGranularity = 'hourly' | 'daily' | 'weekly';

/**
 * Configuration for a baseline metric.
 */
export interface BaselineConfig {
  /** Unique metric name */
  name: string;
  /** Time granularity for seasonality */
  granularity?: TimeGranularity;
  /** EMA smoothing factor (0.0-1.0, default: 0.2) */
  emaSmoothingFactor?: number;
  /** Minimum samples before baseline is considered valid (default: 10) */
  minSamples?: number;
}

/**
 * Result of anomaly detection for a single data point.
 */
export interface AnomalyDetectionResult {
  /** Whether the value is anomalous based on the configured threshold */
  isAnomaly: boolean;
  /** Anomaly score (0-100, higher = more anomalous) */
  score: number;
  /** Number of standard deviations from mean (>0 is high, <0 is low) */
  zScore: number;
  /** Explanation of why this was flagged (if isAnomaly) */
  explanation?: string;
  /** The baseline used for this comparison */
  baseline: BaselineMetric;
  /** False positive confidence (0-1, higher = more likely to be false positive) */
  falsePositiveConfidence?: number;
}

/**
 * Configuration for anomaly detection thresholds.
 */
export interface AnomalyThreshold {
  /** Metric name */
  name: string;
  /** Number of standard deviations above mean to trigger anomaly (default: 2.5) */
  stddevThresholdHigh?: number;
  /** Number of standard deviations below mean to trigger anomaly (default: 2.5) */
  stddevThresholdLow?: number;
  /** Absolute minimum value to flag as anomaly (optional) */
  absoluteMinThreshold?: number;
  /** Absolute maximum value to flag as anomaly (optional) */
  absoluteMaxThreshold?: number;
}

/**
 * Persistent storage interface for baselines.
 * Implementations can use disk, database, cache, etc.
 */
export interface BaselineStore {
  /**
   * Load a baseline metric from storage.
   * Returns null if not found.
   */
  load(metricName: string, seasonKey?: string): Promise<BaselineMetric | null>;

  /**
   * Save a baseline metric to storage.
   */
  save(metric: BaselineMetric, seasonKey?: string): Promise<void>;

  /**
   * Delete a baseline metric from storage (for resets).
   */
  delete(metricName: string, seasonKey?: string): Promise<void>;

  /**
   * Load all baselines for a metric (including seasonal variants).
   */
  loadAll(metricName: string): Promise<Map<string, BaselineMetric>>;
}

/**
 * In-memory implementation of BaselineStore.
 * Suitable for development and testing; production should use persistent storage.
 */
class InMemoryBaselineStore implements BaselineStore {
  private storage = new Map<string, BaselineMetric>();

  private makeKey(metricName: string, seasonKey?: string): string {
    return seasonKey ? `${metricName}:${seasonKey}` : metricName;
  }

  async load(
    metricName: string,
    seasonKey?: string,
  ): Promise<BaselineMetric | null> {
    const key = this.makeKey(metricName, seasonKey);
    return this.storage.get(key) ?? null;
  }

  async save(metric: BaselineMetric, seasonKey?: string): Promise<void> {
    const key = this.makeKey(metric.name, seasonKey);
    this.storage.set(key, { ...metric });
  }

  async delete(metricName: string, seasonKey?: string): Promise<void> {
    const key = this.makeKey(metricName, seasonKey);
    this.storage.delete(key);
  }

  async loadAll(metricName: string): Promise<Map<string, BaselineMetric>> {
    const result = new Map<string, BaselineMetric>();
    for (const [key, metric] of this.storage.entries()) {
      if (key.startsWith(metricName)) {
        const seasonKey = key === metricName ? 'default' : key.split(':')[1];
        result.set(seasonKey ?? 'default', metric);
      }
    }
    return result;
  }
}

// ---------------------------------------------------------------------------
// AdaptiveBaseline Class
// ---------------------------------------------------------------------------

/**
 * Maintains and updates statistical baselines for anomaly detection.
 *
 * Responsibilities:
 * - Store and retrieve baseline metrics
 * - Update baselines with new observations
 * - Calculate exponential moving averages
 * - Handle seasonal variations
 * - Support baseline resets
 *
 * Thread-safe operations are handled by the caller (e.g., request queueing).
 */
export class AdaptiveBaseline {
  private store: BaselineStore;
  private configs = new Map<string, BaselineConfig>();
  private memoryCache = new Map<string, BaselineMetric>();

  /**
   * Create a new AdaptiveBaseline instance.
   *
   * @param store - Baseline storage backend (in-memory if not provided)
   */
  constructor(store?: BaselineStore) {
    this.store = store ?? new InMemoryBaselineStore();
  }

  /**
   * Register a metric to be tracked.
   *
   * @param config - Configuration for the metric
   */
  registerMetric(config: BaselineConfig): void {
    this.configs.set(config.name, {
      granularity: config.granularity ?? 'weekly',
      emaSmoothingFactor: config.emaSmoothingFactor ?? 0.2,
      minSamples: config.minSamples ?? 10,
      ...config,
    });
  }

  /**
   * Update a metric's baseline with a new observation.
   *
   * Incrementally updates mean, stddev, min, and max.
   * Also updates the EMA for trend tracking.
   *
   * @param metricName - Name of the metric to update
   * @param value - The observed value
   * @param timestamp - Optional timestamp (now if not provided)
   */
  async updateMetric(
    metricName: string,
    value: number,
    timestamp?: string,
  ): Promise<BaselineMetric> {
    if (!Number.isFinite(value)) {
      throw new Error(`Invalid metric value: ${value}`);
    }

    const config = this.configs.get(metricName);
    if (!config) {
      throw new Error(`Metric not registered: ${metricName}`);
    }

    const now = timestamp ?? new Date().toISOString();
    const seasonKey = this.getSeasonKey(config.granularity ?? 'weekly', new Date(now));

    // Load existing baseline or create new one
    let metric = await this.store.load(metricName, seasonKey);
    if (!metric) {
      metric = this.initializeMetric(metricName, value, config);
    } else {
      metric = this.updateBaselineStats(metric, value, config);
    }

    // Update EMA
    const emaSmoothingFactor = config.emaSmoothingFactor ?? 0.2;
    metric.ema =
      value * emaSmoothingFactor +
      metric.ema * (1 - emaSmoothingFactor);

    metric.lastUpdated = now;

    // Persist
    await this.store.save(metric, seasonKey);

    // Update cache
    const cacheKey = `${metricName}:${seasonKey}`;
    this.memoryCache.set(cacheKey, { ...metric });

    return metric;
  }

  /**
   * Get the current baseline for a metric.
   *
   * Automatically applies seasonality if configured.
   * Returns null if not enough samples have been collected.
   *
   * @param metricName - Name of the metric
   * @param timestamp - Optional timestamp for seasonality (now if not provided)
   * @returns The baseline metric, or null if not ready
   */
  async getBaseline(
    metricName: string,
    timestamp?: string,
  ): Promise<BaselineMetric | null> {
    const config = this.configs.get(metricName);
    if (!config) {
      throw new Error(`Metric not registered: ${metricName}`);
    }

    const now = timestamp ?? new Date().toISOString();
    const seasonKey = this.getSeasonKey(config.granularity ?? 'weekly', new Date(now));

    // Check cache first
    const cacheKey = `${metricName}:${seasonKey}`;
    const cached = this.memoryCache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Load from store
    const metric = await this.store.load(metricName, seasonKey);
    if (metric && metric.count >= (config.minSamples ?? 10)) {
      return metric;
    }

    return null;
  }

  /**
   * Reset a baseline metric (after legitimate change or misconfiguration).
   *
   * Clears historical data and starts fresh. Useful when a service deployment
   * changes performance characteristics.
   *
   * @param metricName - Name of the metric to reset
   * @param seasonKey - Optional season key (all if not provided)
   */
  async resetMetric(metricName: string, seasonKey?: string): Promise<void> {
    if (seasonKey) {
      await this.store.delete(metricName, seasonKey);
      const cacheKey = `${metricName}:${seasonKey}`;
      this.memoryCache.delete(cacheKey);
    } else {
      // Reset all seasonal variants
      const all = await this.store.loadAll(metricName);
      for (const key of all.keys()) {
        await this.store.delete(metricName, key === 'default' ? undefined : key);
        const cacheKey = `${metricName}:${key}`;
        this.memoryCache.delete(cacheKey);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private initializeMetric(
    name: string,
    value: number,
    config: BaselineConfig,
  ): BaselineMetric {
    return {
      name,
      mean: value,
      stddev: 0,
      count: 1,
      min: value,
      max: value,
      lastUpdated: new Date().toISOString(),
      ema: value,
      emaSmoothingFactor: config.emaSmoothingFactor ?? 0.2,
    };
  }

  private updateBaselineStats(
    metric: BaselineMetric,
    value: number,
    config: BaselineConfig,
  ): BaselineMetric {
    const oldMean = metric.mean;
    const newCount = metric.count + 1;
    const newMean = (oldMean * metric.count + value) / newCount;

    // Welford's online algorithm for variance
    const delta1 = value - oldMean;
    const delta2 = value - newMean;
    const variance =
      (metric.stddev ** 2 * metric.count +
        delta1 * delta2) /
      newCount;
    const newStddev = Math.sqrt(Math.max(0, variance)); // Avoid negative due to floating point

    return {
      ...metric,
      mean: newMean,
      stddev: newStddev,
      count: newCount,
      min: Math.min(metric.min, value),
      max: Math.max(metric.max, value),
      emaSmoothingFactor: config.emaSmoothingFactor ?? 0.2,
    };
  }

  private getSeasonKey(granularity: TimeGranularity, date: Date): string {
    switch (granularity) {
      case 'hourly':
        return `hour_${date.getUTCHours()}`;
      case 'daily':
        return `day_${date.getUTCDay()}`;
      case 'weekly':
      default:
        return 'week';
    }
  }
}

// ---------------------------------------------------------------------------
// AnomalyDetector Class
// ---------------------------------------------------------------------------

/**
 * Detects anomalies by comparing values against baselines.
 *
 * Responsibilities:
 * - Compare values against baselines
 * - Calculate z-scores and anomaly confidence
 * - Generate explanations for flagged anomalies
 * - Track false positive rates
 * - Support manual feedback for model improvement
 *
 * Anomaly detection is statistical, so thresholds should be tuned for
 * your specific use case. A z-score of 2.5 corresponds to ~98.8% confidence
 * that the value is abnormal (assuming normal distribution).
 */
export class AnomalyDetector {
  private baseline: AdaptiveBaseline;
  private thresholds = new Map<string, AnomalyThreshold>();
  private falsePositives = new Map<string, { count: number; total: number }>();

  /**
   * Create a new AnomalyDetector instance.
   *
   * @param baseline - The AdaptiveBaseline to use for detection
   */
  constructor(baseline: AdaptiveBaseline) {
    this.baseline = baseline;
  }

  /**
   * Set anomaly detection threshold for a metric.
   *
   * @param threshold - The threshold configuration
   */
  setThreshold(threshold: AnomalyThreshold): void {
    this.thresholds.set(threshold.name, {
      stddevThresholdHigh: threshold.stddevThresholdHigh ?? 2.5,
      stddevThresholdLow: threshold.stddevThresholdLow ?? 2.5,
      ...threshold,
    });
  }

  /**
   * Detect anomaly in a single observation.
   *
   * Compares the value against the baseline and returns a detailed result
   * including z-score, anomaly score, and explanation.
   *
   * @param metricName - Name of the metric
   * @param value - Observed value
   * @param timestamp - Optional timestamp for seasonality
   * @returns Detection result with anomaly score and explanation
   */
  async detect(
    metricName: string,
    value: number,
    timestamp?: string,
  ): Promise<AnomalyDetectionResult> {
    if (!Number.isFinite(value)) {
      throw new Error(`Invalid metric value: ${value}`);
    }

    const baseline = await this.baseline.getBaseline(metricName, timestamp);

    if (!baseline) {
      // Not enough data yet, return neutral
      return {
        isAnomaly: false,
        score: 0,
        zScore: 0,
        explanation: 'Insufficient baseline data',
        baseline: this.createPlaceholderBaseline(metricName),
      };
    }

    const threshold: AnomalyThreshold = this.thresholds.get(metricName) ?? {
      name: metricName,
      stddevThresholdHigh: 2.5,
      stddevThresholdLow: 2.5,
    };

    // Calculate z-score
    let zScore = 0;
    if (baseline.stddev > 0) {
      zScore = (value - baseline.mean) / baseline.stddev;
    } else {
      // If stddev is 0, all values are the same
      zScore = value === baseline.mean ? 0 : Infinity;
    }

    // Check absolute thresholds
    let isAbsoluteAnomaly = false;
    let absoluteReason = '';

    if (
      threshold.absoluteMinThreshold !== undefined &&
      value < threshold.absoluteMinThreshold
    ) {
      isAbsoluteAnomaly = true;
      absoluteReason = `below absolute minimum ${threshold.absoluteMinThreshold}`;
    }

    if (
      threshold.absoluteMaxThreshold !== undefined &&
      value > threshold.absoluteMaxThreshold
    ) {
      isAbsoluteAnomaly = true;
      absoluteReason = `above absolute maximum ${threshold.absoluteMaxThreshold}`;
    }

    // Check statistical thresholds
    const isHighAnomaly = zScore > (threshold.stddevThresholdHigh ?? 2.5);
    const isLowAnomaly =
      zScore < -(threshold.stddevThresholdLow ?? 2.5);

    const isStatisticalAnomaly = isHighAnomaly || isLowAnomaly;
    const isAnomaly = isAbsoluteAnomaly || isStatisticalAnomaly;

    // Generate explanation
    let explanation = '';
    if (isAnomaly) {
      if (isAbsoluteAnomaly) {
        explanation = `Value ${value} is ${absoluteReason}`;
      } else if (isHighAnomaly) {
        const deviations = (Math.abs(zScore) * baseline.stddev) / baseline.mean;
        explanation = `Value ${value} is ${deviations.toFixed(1)}x above baseline mean of ${baseline.mean.toFixed(2)}`;
      } else if (isLowAnomaly) {
        const deviations = (Math.abs(zScore) * baseline.stddev) / baseline.mean;
        explanation = `Value ${value} is ${deviations.toFixed(1)}x below baseline mean of ${baseline.mean.toFixed(2)}`;
      }
    }

    // Calculate anomaly score (0-100)
    const anomalyScore = this.calculateAnomalyScore(zScore);

    // Calculate false positive confidence
    const fpConfidence = this.calculateFalsePositiveConfidence(
      metricName,
      value,
      baseline,
    );

    return {
      isAnomaly,
      score: anomalyScore,
      zScore,
      explanation: isAnomaly ? explanation : undefined,
      baseline,
      falsePositiveConfidence: fpConfidence,
    };
  }

  /**
   * Provide feedback on anomaly detection (was it a true or false positive?).
   *
   * Used to track false positive rates and improve model tuning over time.
   *
   * @param metricName - Name of the metric
   * @param wasPositive - Was the detected anomaly positive (true) or false positive?
   */
  recordFeedback(metricName: string, wasPositive: boolean): void {
    let fpData = this.falsePositives.get(metricName);
    if (!fpData) {
      fpData = { count: 0, total: 0 };
    }

    if (!wasPositive) {
      fpData.count++;
    }
    fpData.total++;

    this.falsePositives.set(metricName, fpData);
  }

  /**
   * Get false positive rate for a metric.
   *
   * Useful for understanding if a detection rule is too aggressive.
   *
   * @param metricName - Name of the metric
   * @returns False positive rate (0-1), or null if no feedback yet
   */
  getFalsePositiveRate(metricName: string): number | null {
    const fpData = this.falsePositives.get(metricName);
    if (!fpData || fpData.total === 0) {
      return null;
    }
    return fpData.count / fpData.total;
  }

  // -------------------------------------------------------------------------
  // Private helpers
  // -------------------------------------------------------------------------

  private calculateAnomalyScore(zScore: number): number {
    // Clamp z-score to reasonable range for score calculation
    const clampedZ = Math.min(Math.max(zScore, -5), 5);

    // Convert z-score to 0-100 scale
    // z=0 → score=0, z=±2.5 → score=80, z=±5 → score=100
    const score = Math.abs(clampedZ) * 16; // 5 * 16 = 80 at z=2.5
    return Math.min(100, score);
  }

  private calculateFalsePositiveConfidence(
    metricName: string,
    _value: number,
    _baseline: BaselineMetric,
  ): number {
    void _value;
    void _baseline;
    const fpRate = this.getFalsePositiveRate(metricName);
    if (fpRate === null) {
      // No feedback yet, assume moderate false positive risk
      return 0.3;
    }
    return fpRate;
  }

  private createPlaceholderBaseline(name: string): BaselineMetric {
    return {
      name,
      mean: 0,
      stddev: 0,
      count: 0,
      min: 0,
      max: 0,
      lastUpdated: new Date().toISOString(),
      ema: 0,
      emaSmoothingFactor: 0.2,
    };
  }
}

// ---------------------------------------------------------------------------
// Helper: Create Default Baselines
// ---------------------------------------------------------------------------

/**
 * Create a pre-configured AdaptiveBaseline instance with common security metrics.
 *
 * Registers baselines for:
 * - Request volume per hour
 * - Authentication failure rate
 * - Policy denial rate
 * - Data export volume
 * - Session creation rate
 * - Error rate
 * - Response latency
 *
 * All metrics use hourly granularity to detect time-of-day patterns.
 *
 * @param store - Optional baseline storage backend
 * @returns Configured AdaptiveBaseline instance
 */
export function createDefaultBaselines(
  store?: BaselineStore,
): AdaptiveBaseline {
  const baseline = new AdaptiveBaseline(store);

  // Request volume anomalies (per hour)
  baseline.registerMetric({
    name: 'request_volume_per_hour',
    granularity: 'hourly',
    emaSmoothingFactor: 0.2,
    minSamples: 7, // ~1 week of data at 1 hour granularity
  });

  // Authentication failure rate (per minute, hourly baseline)
  baseline.registerMetric({
    name: 'auth_failure_rate',
    granularity: 'hourly',
    emaSmoothingFactor: 0.25,
    minSamples: 10,
  });

  // Policy denial rate (per minute, hourly baseline)
  baseline.registerMetric({
    name: 'policy_denial_rate',
    granularity: 'hourly',
    emaSmoothingFactor: 0.25,
    minSamples: 10,
  });

  // Data export volume (per hour)
  baseline.registerMetric({
    name: 'data_export_volume_gb',
    granularity: 'hourly',
    emaSmoothingFactor: 0.2,
    minSamples: 7,
  });

  // Session creation rate (per minute, hourly baseline)
  baseline.registerMetric({
    name: 'session_creation_rate',
    granularity: 'hourly',
    emaSmoothingFactor: 0.2,
    minSamples: 10,
  });

  // Error rate (percentage, per minute)
  baseline.registerMetric({
    name: 'error_rate_percent',
    granularity: 'hourly',
    emaSmoothingFactor: 0.25,
    minSamples: 10,
  });

  // Response latency (milliseconds, per minute)
  baseline.registerMetric({
    name: 'response_latency_ms',
    granularity: 'hourly',
    emaSmoothingFactor: 0.15,
    minSamples: 30, // 30 minutes of data
  });

  return baseline;
}

/**
 * Create a pre-configured AnomalyDetector with sensible defaults for
 * common security metrics.
 *
 * @param baseline - The AdaptiveBaseline to use
 * @returns Configured AnomalyDetector instance
 */
export function createDefaultDetector(
  baseline: AdaptiveBaseline,
): AnomalyDetector {
  const detector = new AnomalyDetector(baseline);

  // Request volume: >3 sigma deviation
  detector.setThreshold({
    name: 'request_volume_per_hour',
    stddevThresholdHigh: 3,
    stddevThresholdLow: 3,
    absoluteMinThreshold: 0,
  });

  // Auth failures: >2.5 sigma (more sensitive, security-critical)
  detector.setThreshold({
    name: 'auth_failure_rate',
    stddevThresholdHigh: 2.5,
    stddevThresholdLow: 2.5,
    absoluteMinThreshold: 0,
  });

  // Policy denials: >2.5 sigma
  detector.setThreshold({
    name: 'policy_denial_rate',
    stddevThresholdHigh: 2.5,
    stddevThresholdLow: 2.5,
    absoluteMinThreshold: 0,
  });

  // Data exports: >2 sigma (highly sensitive)
  detector.setThreshold({
    name: 'data_export_volume_gb',
    stddevThresholdHigh: 2,
    stddevThresholdLow: 2,
    absoluteMinThreshold: 0,
    absoluteMaxThreshold: 1000, // Prevent exfiltration
  });

  // Session creation: >2.5 sigma
  detector.setThreshold({
    name: 'session_creation_rate',
    stddevThresholdHigh: 2.5,
    stddevThresholdLow: 2.5,
    absoluteMinThreshold: 0,
  });

  // Error rate: >3 sigma (don't be too sensitive to normal errors)
  detector.setThreshold({
    name: 'error_rate_percent',
    stddevThresholdHigh: 3,
    stddevThresholdLow: 3,
    absoluteMinThreshold: 0,
    absoluteMaxThreshold: 100,
  });

  // Latency: >2.5 sigma high, >2 sigma low (timeouts are critical)
  detector.setThreshold({
    name: 'response_latency_ms',
    stddevThresholdHigh: 2.5,
    stddevThresholdLow: 2,
    absoluteMinThreshold: 0,
    absoluteMaxThreshold: 30000, // 30 second timeout
  });

  return detector;
}
