import { AdmissionGate } from '../../supply-chain/src/admission/admission-gate';
import { RequireApproval } from '../../supply-chain/src/admission/deploy-policies';
import { ArtifactSigner, InMemoryKeyProvider } from '../../supply-chain/src/signing/artifact-signer';
import { KeyRegistry } from '../../supply-chain/src/signing/key-registry';
import { InMemoryProvenanceStore } from '../../supply-chain/src/provenance/provenance-store';
import { InMemorySBOMStore } from '../../supply-chain/src/sbom/sbom-store';
import type { CycloneDXBom } from '../../supply-chain/src/sbom/sbom-generator';
import { VulnerabilityChecker } from '../../supply-chain/src/vulnerability/vuln-checker';

describe('Supply Chain - Admission Gate (Real)', () => {
  test('key rotation: rotated-to keyId matches stored key material (can sign)', async () => {
    const keyProvider = new InMemoryKeyProvider();
    const signer = new ArtifactSigner(keyProvider);
    const keyRegistry = new KeyRegistry();

    const initial = await signer.generateSigningKeyPair('EC-P256-SHA256', 'artifact-signing', 'dev');
    keyRegistry.registerKey(initial.keyId, initial.publicKeyPem, {
      algorithm: initial.metadata.algorithm,
      purpose: initial.metadata.purpose,
      environment: 'dev',
      createdBy: 'test',
    });

    const rotation = keyRegistry.rotateKey(initial.keyId, 'test');
    expect(rotation.newKeyId).toBeTruthy();

    const oldKey = keyRegistry.getKey(initial.keyId, 'test');
    expect(oldKey?.state).toBe('ROTATED');
    expect(keyRegistry.isValidForSigning(initial.keyId)).toBe(false);

    const newKeyPair = await signer.generateSigningKeyPair(
      'EC-P256-SHA256',
      'artifact-signing',
      'dev',
      rotation.newKeyId ?? undefined
    );

    keyRegistry.registerKey(rotation.newKeyId!, newKeyPair.publicKeyPem, {
      algorithm: newKeyPair.metadata.algorithm,
      purpose: newKeyPair.metadata.purpose,
      environment: 'dev',
      createdBy: 'test',
    });
    expect(keyRegistry.isValidForSigning(rotation.newKeyId!)).toBe(true);

    // This would have failed prior to the keyId override fix (key material stored under a different id).
    expect(() => signer.signArtifact('sha256:rotated', rotation.newKeyId!)).not.toThrow();
  });

  test('dev: allows when signature + SBOM present', async () => {
    const keyProvider = new InMemoryKeyProvider();
    const signer = new ArtifactSigner(keyProvider);
    const keyRegistry = new KeyRegistry();
    const provenanceStore = new InMemoryProvenanceStore();
    const sbomStore = new InMemorySBOMStore();
    const vulnChecker = new VulnerabilityChecker();
    const approvalPolicy = new RequireApproval();

    const gate = new AdmissionGate({
      signer,
      keyRegistry,
      provenanceStore,
      sbomStore,
      vulnChecker,
      approvalPolicy,
    });

    const artifactDigest = 'sha256:abc123';

    const keyPair = await signer.generateSigningKeyPair('EC-P256-SHA256', 'artifact-signing', 'dev');
    keyRegistry.registerKey(keyPair.keyId, keyPair.publicKeyPem, {
      algorithm: keyPair.metadata.algorithm,
      purpose: keyPair.metadata.purpose,
      environment: 'dev',
      createdBy: 'test',
    });

    signer.signArtifact(artifactDigest, keyPair.keyId);

    // SBOM lookup uses buildId if provided, otherwise artifactDigest.
    const sbom: CycloneDXBom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:test-sbom-1',
      version: 1,
      metadata: { timestamp: new Date().toISOString(), tools: [] },
      components: [
        { type: 'library', name: 'express', version: '4.18.2', purl: 'pkg:npm/express@4.18.2', hashes: [], licenses: [] },
      ],
      dependencies: [],
    };
    sbomStore.store(artifactDigest, 'project-1', sbom, 'test');

    const decision = gate.evaluate({
      artifactDigest,
      imageRef: 'example.com/app:dev',
      namespace: 'default',
      environment: 'dev',
      requestor: 'ci',
      pipelineId: 'github-actions-main',
      buildId: artifactDigest,
    });

    expect(decision.verdict).toBe('ALLOW');
    expect(decision.failedPolicies.length).toBe(0);
  });

  test('dev: denies when signature missing', () => {
    const keyProvider = new InMemoryKeyProvider();
    const signer = new ArtifactSigner(keyProvider);
    const keyRegistry = new KeyRegistry();
    const provenanceStore = new InMemoryProvenanceStore();
    const sbomStore = new InMemorySBOMStore();
    const vulnChecker = new VulnerabilityChecker();
    const approvalPolicy = new RequireApproval();

    const gate = new AdmissionGate({
      signer,
      keyRegistry,
      provenanceStore,
      sbomStore,
      vulnChecker,
      approvalPolicy,
    });

    const artifactDigest = 'sha256:no-sig';

    const sbom: CycloneDXBom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:test-sbom-2',
      version: 1,
      metadata: { timestamp: new Date().toISOString(), tools: [] },
      components: [],
      dependencies: [],
    };
    sbomStore.store(artifactDigest, 'project-1', sbom, 'test');

    const decision = gate.evaluate({
      artifactDigest,
      imageRef: 'example.com/app:dev',
      namespace: 'default',
      environment: 'dev',
      requestor: 'ci',
      pipelineId: 'github-actions-main',
      buildId: artifactDigest,
    });

    expect(decision.verdict).toBe('DENY');
    expect(decision.failedPolicies).toContain('RequireSignature');
  });

  test('staging: denies when pipeline not allowlisted', async () => {
    const keyProvider = new InMemoryKeyProvider();
    const signer = new ArtifactSigner(keyProvider);
    const keyRegistry = new KeyRegistry();
    const provenanceStore = new InMemoryProvenanceStore();
    const sbomStore = new InMemorySBOMStore();
    const vulnChecker = new VulnerabilityChecker();
    const approvalPolicy = new RequireApproval();

    const gate = new AdmissionGate({
      signer,
      keyRegistry,
      provenanceStore,
      sbomStore,
      vulnChecker,
      approvalPolicy,
    });

    const artifactDigest = 'sha256:staging-1';

    const keyPair = await signer.generateSigningKeyPair('EC-P256-SHA256', 'artifact-signing', 'staging');
    keyRegistry.registerKey(keyPair.keyId, keyPair.publicKeyPem, {
      algorithm: keyPair.metadata.algorithm,
      purpose: keyPair.metadata.purpose,
      environment: 'staging',
      createdBy: 'test',
    });
    signer.signArtifact(artifactDigest, keyPair.keyId);

    const sbom: CycloneDXBom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: 'urn:uuid:test-sbom-3',
      version: 1,
      metadata: { timestamp: new Date().toISOString(), tools: [] },
      components: [],
      dependencies: [],
    };
    sbomStore.store(artifactDigest, 'project-1', sbom, 'test');

    // We intentionally do NOT add provenance; deny could be for multiple reasons.
    // This asserts that pipeline allowlist is definitely enforced.
    const decision = gate.evaluate({
      artifactDigest,
      imageRef: 'example.com/app:staging',
      namespace: 'default',
      environment: 'staging',
      requestor: 'ci',
      pipelineId: 'ci/rogue-pipeline',
      buildId: artifactDigest,
    });

    expect(decision.verdict).toBe('DENY');
    expect(decision.failedPolicies).toContain('RequireAllowlistedPipeline');
  });
});
