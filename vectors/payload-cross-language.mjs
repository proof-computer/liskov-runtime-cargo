// Independent Node Ed25519 proof. No network or package dependencies.
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import assert from 'node:assert/strict';
const read = name => readFileSync(new URL(name, import.meta.url));
const fixture = JSON.parse(read('payload-download-v1.json'));
const descriptorFixture = JSON.parse(read('payload-descriptor-v1.json'));
const sha = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const compact = value => Buffer.from(JSON.stringify(value));
const job = r => ({ originKind: r.originKind, originKey: r.originKey, sequence: r.sequence });
const launch = r => ({ launchId: r.launchId, policyDigest: r.policyDigest });
const workload = r => r === null ? null : ({ authorizationId: r.authorizationId, revisionDigest: r.revisionDigest, policyDigest: r.policyDigest });
const range = r => r.mode === 'whole' ? { mode: 'whole' } : { mode: 'bytes', start: r.start, endInclusive: r.endInclusive };
const message = r => compact({
  domain: r.domain, method: r.method, requestTarget: r.requestTarget,
  range: range(r.range), artifactDigest: r.artifactDigest,
  organisationId: r.organisationId, applicationUid: r.applicationUid,
  job: job(r.job), processorId: r.processorId, runtimeInstanceId: r.runtimeInstanceId,
  launch: launch(r.launch), workload: workload(r.workload),
  issuedAtMs: r.issuedAtMs, expiresAtMs: r.expiresAtMs, nonce: r.nonce,
});
const privateKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(fixture.testOnlySeedHex, 'hex'),
]) });
const publicKey = createPublicKey(privateKey);
assert.equal(publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex'), fixture.publicKeyHex);
for (const row of fixture.valid) {
  const bytes = message(row.envelope.request);
  assert.equal(bytes.toString(), row.messageUtf8, row.name);
  assert.equal(sha(bytes), row.messageDigest, row.name);
  assert.equal(sign(null, bytes, privateKey).toString('hex'), row.envelope.signature, row.name);
  assert.equal(verify(null, bytes, publicKey, Buffer.from(row.envelope.signature, 'hex')), true, row.name);
}
for (const row of fixture.invalid) {
  // Preserve the mutated request, including unknown fields: rebuilding the
  // valid schema here would silently strip fields before verifying the bytes.
  assert.equal(verify(null, compact(row.envelope.request), publicKey, Buffer.from(row.envelope.signature, 'hex')), row.signatureValid, row.name);
}
const r = descriptorFixture.descriptor;
const descriptor = compact({
  format: r.format, artifactDigest: r.artifactDigest, artifactSizeBytes: r.artifactSizeBytes,
  encryption: r.encryption,
  targetAbi: { os: r.targetAbi.os, architecture: r.targetAbi.architecture, environment: r.targetAbi.environment },
  entries: r.entries.map(e => e.kind === 'directory' ? { kind: e.kind, path: e.path } : {
    kind: e.kind, path: e.path, sizeBytes: e.sizeBytes, digest: e.digest, executable: e.executable,
  }),
  entrypoints: r.entrypoints,
  producer: { kind: r.producer.kind, subject: r.producer.subject, sourceRevision: r.producer.sourceRevision, buildId: r.producer.buildId },
});
assert.equal(descriptor.toString(), descriptorFixture.canonicalUtf8);
assert.equal(sha(descriptor), descriptorFixture.descriptorDigest);
assert.equal(sha(read('payload-archive-v1.tar.gz')), descriptorFixture.archiveDigest);
for (const line of read('payload-fixtures.sha256').toString().trim().split('\n')) {
  const [expected, name] = line.split('  ');
  assert.equal(sha(read(name)).slice(7), expected, name);
}
console.log(`payload cross-language proof: ${fixture.valid.length} signatures, ${fixture.invalid.length} negative requests and descriptor/archive digests passed (${process.version})`);
