import fs from 'fs';
import path from 'path';
import { InMemoryPolicyStore, type PolicyStoreStateV1 } from './policy-store';
import { createLogger } from '../utils/logger';

const logger = createLogger('file-policy-store');

export interface FilePolicyStoreOptions {
  filePath: string;
}

/**
 * Durable snapshot wrapper around InMemoryPolicyStore.
 *
 * This is deliberately simple: policies are low-churn, so we persist the full
 * snapshot atomically after any mutation.
 */
export class FilePolicyStore extends InMemoryPolicyStore {
  private readonly filePath: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(options: FilePolicyStoreOptions) {
    super();
    this.filePath = options.filePath;
    this.loadFromDisk();
  }

  override async create(input: Parameters<InMemoryPolicyStore['create']>[0]) {
    const p = await super.create(input);
    await this.enqueuePersist();
    return p;
  }

  override async update(id: string, input: Parameters<InMemoryPolicyStore['update']>[1]) {
    const p = await super.update(id, input);
    await this.enqueuePersist();
    return p;
  }

  override async delete(id: string) {
    await super.delete(id);
    await this.enqueuePersist();
  }

  override async loadDefaults(policies: Parameters<InMemoryPolicyStore['loadDefaults']>[0]) {
    await super.loadDefaults(policies);
    await this.enqueuePersist();
  }

  private loadFromDisk(): void {
    try {
      const dir = path.dirname(this.filePath);
      fs.mkdirSync(dir, { recursive: true });

      if (!fs.existsSync(this.filePath)) {
        logger.info('No policy snapshot found; starting fresh', { filePath: this.filePath });
        return;
      }

      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(raw) as PolicyStoreStateV1;
      this.importState(parsed);
      logger.info('Loaded policy snapshot', { filePath: this.filePath, policyCount: parsed.policies?.length ?? 0 });
    } catch (err) {
      logger.error('Failed to load policy snapshot; continuing with empty store', {
        filePath: this.filePath,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  private enqueuePersist(): Promise<void> {
    this.writeChain = this.writeChain
      .then(() => this.persist())
      .catch((err) => {
        logger.error('Previous policy persist failed; retrying', {
          filePath: this.filePath,
          error: err instanceof Error ? err.message : String(err),
        });
        return this.persist();
      });
    return this.writeChain;
  }

  private async persist(): Promise<void> {
    const dir = path.dirname(this.filePath);
    await fs.promises.mkdir(dir, { recursive: true });

    const tmp = `${this.filePath}.tmp`;
    const snapshot = this.exportState();
    const data = JSON.stringify(snapshot);

    await fs.promises.writeFile(tmp, data, { encoding: 'utf8', mode: 0o600 });
    await fs.promises.rename(tmp, this.filePath);
  }
}

