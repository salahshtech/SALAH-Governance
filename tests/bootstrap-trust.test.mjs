import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { after, test } from 'node:test';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyG0, verifyG1 } from '../bootstrap/verify.mjs';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const originalPolicy = JSON.parse(await readFile(path.join(sourceRoot, 'governance/trust-policy.json'), 'utf8'));
const header = { kind: 'SALAH_APPROVAL_REGISTER', schemaVersion: 1, initialRevision: 0 };
const fixtures = [];
const NOW = Date.parse('2026-10-07T12:00:00.000Z');

after(async () => {
  for (const root of fixtures) await rm(root, { recursive: true, force: true });
});

async function fixture({ policy = structuredClone(originalPolicy), rows = [], policyText, registerText } = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'salah-g0-'));
  fixtures.push(root);
  execFileSync('git', ['init', '-q', '-b', 'main', root]);
  execFileSync('git', ['-C', root, 'remote', 'add', 'origin', 'https://github.com/salahshtech/SALAH-Governance.git']);
  await mkdir(path.join(root, 'governance'));
  if (policyText !== null) await writeFile(path.join(root, 'governance/trust-policy.json'),
    policyText ?? JSON.stringify({ ...policy, revisions: { ...policy.revisions, register: rows.length } }, null, 2) + '\n');
  if (registerText !== null) await writeFile(path.join(root, 'governance/approvals.jsonl'),
    registerText ?? [header, ...rows].map(row => JSON.stringify(row)).join('\n') + '\n');
  return root;
}

function decision(state = 'DRAFT', registerRevision = 1, overrides = {}) {
  return {
    kind: 'DECISION', decisionId: `TEST-${registerRevision}`, amendmentId: 'TEST-AMENDMENT', version: 1,
    owner: 'PROJECT_OWNER', type: 'TEST_ONLY', purpose: 'Exercise G0 schema', reason: 'Synthetic test record',
    paths: ['tests/example.test.js'], baseline: { commit: 'b'.repeat(64),
      sha256ByPath: { 'tests/example.test.js': 'a'.repeat(64) } },
    scope: { id: 'TEST-SCOPE', digest: 'c'.repeat(64) }, architectureRevision: null,
    state, registerRevision, decidedAtUtc: `2026-10-07T10:${String(registerRevision).padStart(2, '0')}:00.000Z`,
    expiresAtUtc: null, revokesDecisionId: null, rollbackToDecisionId: null,
    finalSha256ByPath: null, runtimeAuthority: false, ...overrides
  };
}

async function rejects(options, pattern) {
  await assert.rejects(verifyG0({ root: await fixture(options), now: NOW }), pattern);
}

test('valid empty register is diagnostic and has no authority', async () => {
  const result = await verifyG0({ root: await fixture(), now: NOW });
  assert.equal(result.result, 'G0_SCHEMA_VALID');
  assert.equal(result.mode, 'DIAGNOSTIC');
  assert.equal(result.authoritative, false);
  assert.equal(result.authority, 'NONE');
  assert.equal(result.register.decisions, 0);
  assert.deepEqual(result.pendingGates, ['G1', 'G2', 'G3', 'V4']);
});

test('missing policy fails closed', () => rejects({ policyText: null }, /ENOENT/));
test('missing register fails closed', () => rejects({ registerText: null }, /ENOENT/));
test('malformed policy fails closed', () => rejects({ policyText: '{' }, /JSON/));
test('malformed register fails closed', () => rejects({ registerText: '{\n' }, /JSON/));
test('unsupported policy version fails closed', () => {
  const policy = structuredClone(originalPolicy);
  policy.schemaVersion = 2;
  return rejects({ policy }, /Unsupported policy version/);
});
test('unsupported register version fails closed', () => rejects({
  registerText: JSON.stringify({ ...header, schemaVersion: 2 }) + '\n'
}, /Unsupported register version/));
test('duplicate JSON keys fail closed', () => rejects({
  registerText: '{"kind":"SALAH_APPROVAL_REGISTER","kind":"SALAH_APPROVAL_REGISTER","schemaVersion":1,"initialRevision":0}\n'
}, /non-canonical JSON/));
test('duplicate decision ID fails closed', () => rejects({ rows: [decision(),
  decision('DRAFT', 2, { decisionId: 'TEST-1', amendmentId: 'OTHER-AMENDMENT' })] }, /Duplicate decision ID/));
test('invalid state fails closed', () => rejects({ rows: [decision('APPROVED')] }, /Invalid decision state/));
test('ambiguous amendment identity fails closed', () => rejects({
  rows: [decision('DRAFT', 1, { amendmentId: '../V4' })]
}, /Invalid amendment identity/));
test('invalid state transition fails closed', () => rejects({ rows: [decision(), decision('ACTIVE', 2)] }, /Invalid state transition/));
test('contradictory revocation target fails closed', () => rejects({
  rows: [decision(), decision('PENDING_REVIEW', 2), decision('ADMITTED', 3),
    decision('REVOKED', 4, { revokesDecisionId: 'SOME-OTHER-DECISION' })]
}, /Wrong revocation target/));

test('revoked decision is denied, never authoritative', async () => {
  const rows = [decision(), decision('PENDING_REVIEW', 2), decision('ADMITTED', 3),
    decision('REVOKED', 4, { revokesDecisionId: 'TEST-3' })];
  const result = await verifyG0({ root: await fixture({ rows }), now: NOW });
  assert.deepEqual(result.register.amendments, [{ amendmentId: 'TEST-AMENDMENT',
    state: 'REVOKED', disposition: 'DENIED' }]);
  assert.equal(result.authoritative, false);
});

test('expired decision is denied, never authoritative', async () => {
  const rows = [decision(), decision('PENDING_REVIEW', 2),
    decision('ADMITTED', 3, { expiresAtUtc: '2026-10-07T11:00:00.000Z' })];
  const result = await verifyG0({ root: await fixture({ rows }), now: NOW });
  assert.equal(result.register.amendments[0].disposition, 'DENIED_EXPIRED');
  assert.equal(result.authoritative, false);
});

test('rolled-back decision is denied, never authoritative', async () => {
  const rows = [decision(), decision('PENDING_REVIEW', 2), decision('ADMITTED', 3),
    decision('FINAL_BYTES_APPROVED', 4), decision('ACTIVE', 5),
    decision('ROLLED_BACK', 6, { rollbackToDecisionId: 'TEST-3' })];
  const result = await verifyG0({ root: await fixture({ rows }), now: NOW });
  assert.equal(result.register.amendments[0].disposition, 'DENIED');
  assert.equal(result.authoritative, false);
});

test('diagnostic result cannot be requested as authoritative', async () => {
  await assert.rejects(verifyG0({ root: await fixture(), mode: 'AUTHORITATIVE' }), /cannot produce AUTHORITATIVE/);
});
test('TEST_ONLY record cannot imply runtime authority', () => rejects({
  rows: [decision('DRAFT', 1, { runtimeAuthority: true })]
}, /cannot grant runtime authority/));
test('V4 is not implicitly admitted', async () => {
  const result = await verifyG0({ root: await fixture(), now: NOW });
  assert.equal(result.register.amendments.some(row => row.amendmentId === 'V4'), false);
  await rejects({ rows: [decision('ADMITTED', 1, { amendmentId: 'V4' })] }, /First decision must be DRAFT/);
});
test('revision mismatch fails closed', () => rejects({ rows: [decision('DRAFT', 2)] }, /Invalid\/stale register revision/));
test('unknown decision fields fail closed', () => rejects({ rows: [decision('DRAFT', 1, { hiddenAuthority: true })] }, /missing\/extra fields/));
test('ambiguous amendment paths fail closed', () => rejects({ rows: [decision('DRAFT', 1, { paths: ['../app.js'] })] }, /Non-literal amendment path/));
test('final-byte digest cannot be approved in G0', () => rejects({ rows: [decision('DRAFT', 1,
  { finalSha256ByPath: { 'tests/example.test.js': 'a'.repeat(64) } })] }, /cannot approve final bytes/));
test('wrong governance remote fails closed', async () => {
  const root = await fixture();
  execFileSync('git', ['-C', root, 'remote', 'set-url', 'origin', 'https://example.invalid/other.git']);
  await assert.rejects(verifyG0({ root }), /remote mismatch/);
});

const G1_VERIFIER_PATH = 'scripts/testing/verify-phase2-notification-boundary.mjs';
const G1_REJECTED_SHA = 'b67eb901941bf755274f6f1fe833c8ccf9d7ae1ac766841aa11db937cdbbd570';
const G1_MAPPING_DIGEST = '2e1a5a688e85bc78ba0dd4c6d2d9c284f13dec8c3796c8df5956eccff6c80856';
const G1_HASHES = {
  'android/salah-local-notifications/build.gradle': '4c70a6b1f631d174c96e6b8bc9db1df87e9669aef233ba62510f886470ce527d',
  'android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthority.java':
    'dcb9dccd470a14f079f2471f17dbf57b20214c4c63b85c2ec7a81605e625a4b5',
  'android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthorityBridge.java':
    'b25fc9b5e0622b1139a93469b443ba346b88e04deb69d948d7d89b6bd52c7596'
};
const G1_SOURCE = `export const TRUSTED_MAPPING_VERSION = 1;
export const TRUSTED_CONTROLLED_ONLY_SHA256 = Object.freeze({
  'build.gradle': '${G1_HASHES['android/salah-local-notifications/build.gradle']}',
  'src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthority.java':
    '${G1_HASHES['android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthority.java']}',
  'src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthorityBridge.java':
    '${G1_HASHES['android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthorityBridge.java']}'
});
export const TRUSTED_MAPPING_DIGEST = '${G1_MAPPING_DIGEST}';
`;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
function git(root, ...args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8' }).trim();
}
function commitFixture(root, message) {
  git(root, 'add', '-A');
  git(root, '-c', 'user.name=G1 Synthetic Test', '-c', 'user.email=g1-test@example.invalid',
    'commit', '-q', '-m', message);
}
function g1Row(state, revision, base, verifierSha256, options = {}) {
  const amendmentId = options.amendmentId || 'TEST-G1';
  const decisionPrefix = options.decisionPrefix || 'TEST-G1';
  const approvalRevision = options.approvalRevision || 3;
  const approved = revision >= approvalRevision;
  return {
    kind: 'G1_SOURCE_VERIFIER_PIN', schemaVersion: 1,
    decisionId: `${decisionPrefix}-${revision}`, amendmentId, owner: 'PROJECT_OWNER', state,
    registerRevision: revision, decidedAtUtc: `2026-10-07T10:${String(revision).padStart(2, '0')}:00.000Z`,
    approvedAtUtc: approved ? `2026-10-07T10:${String(approvalRevision).padStart(2, '0')}:00.000Z` : null,
    expiresAtUtc: options.expiresAtUtc || null,
    revokesDecisionId: state === 'REVOKED' ? `${decisionPrefix}-${revision - 1}` : null,
    rollbackToDecisionId: state === 'ROLLED_BACK' ? `${decisionPrefix}-${approvalRevision}` : null,
    governanceBaseCommit: base, governanceRevision: 1,
    approvalRevision: approved ? approvalRevision : null,
    approvalDecisionId: approved ? `${decisionPrefix}-${approvalRevision}` : null,
    verifierPath: G1_VERIFIER_PATH, verifierSha256, mappingVersion: 1,
    mappingDigest: G1_MAPPING_DIGEST, controlledOnlySha256: structuredClone(G1_HASHES),
    executionScope: 'SOURCE_VERIFICATION_CLI_ONLY', repairStatus: 'REPAIR_COMPLETE',
    securityReviewStatus: 'PASSED_WITH_NON_BLOCKING_FINDINGS',
    previousRejectedVerifierSha256: G1_REJECTED_SHA,
    runtimeAuthority: false, productionAuthorized: false
  };
}
async function g1Fixture({ mutateRows, mutatePolicy, unborn = false, commitApproval = true,
  states = ['DRAFT', 'PENDING_REVIEW', 'FINAL_BYTES_APPROVED', 'ACTIVE'],
  expiresAtUtc = null } = {}) {
  const root = await fixture();
  await mkdir(path.join(root, 'bootstrap'));
  await writeFile(path.join(root, 'bootstrap/verify.mjs'),
    await readFile(path.join(sourceRoot, 'bootstrap/verify.mjs')));
  if (!unborn) commitFixture(root, 'Synthetic G0 baseline');
  const base = unborn ? 'a'.repeat(40) : git(root, 'rev-parse', 'HEAD');
  const candidateRoot = await realpath(await mkdtemp(path.join(os.tmpdir(), 'salah-g1-candidate-')));
  fixtures.push(candidateRoot);
  execFileSync('git', ['init', '-q', '-b', 'main', candidateRoot]);
  git(candidateRoot, 'remote', 'add', 'origin', 'https://github.com/salahshtech/SALAH.git');
  const verifier = path.join(candidateRoot, G1_VERIFIER_PATH);
  await mkdir(path.dirname(verifier), { recursive: true });
  await writeFile(verifier, G1_SOURCE);
  const expectedSha = sha256(G1_SOURCE);
  const rows = states.map((state, index) => g1Row(state, index + 1, base, expectedSha, { expiresAtUtc }));
  if (mutateRows) mutateRows(rows, { base, expectedSha });
  const policy = structuredClone(originalPolicy);
  policy.revisions.governance = 1;
  policy.revisions.register = rows.length;
  if (mutatePolicy) mutatePolicy(policy);
  await writeFile(path.join(root, 'governance/trust-policy.json'), JSON.stringify(policy, null, 2) + '\n');
  await writeFile(path.join(root, 'governance/approvals.jsonl'),
    [header, ...rows].map(row => JSON.stringify(row)).join('\n') + '\n');
  if (commitApproval && !unborn) commitFixture(root, 'Synthetic G1 decision sequence');
  let executions = 0;
  const runner = () => { executions++; return { exitCode: 0, stdout: 'SYNTHETIC_SOURCE_PASS', stderr: '' }; };
  return { root, candidateRoot, verifier, rows, expectedSha, runner,
    get executions() { return executions; },
    verify: options => verifyG1({ root, candidateRoot, now: NOW, runner, ...options }) };
}

test('G1 exact synthetic owner pin verifies bytes before source-only execution', async () => {
  const f = await g1Fixture();
  const result = await f.verify();
  assert.equal(result.result, 'PIN_VERIFIED');
  assert.equal(result.authority, 'G1_SOURCE_VERIFIER_IDENTITY_ONLY');
  assert.equal(result.runtimeAuthority, false);
  assert.equal(result.productionAuthorized, false);
  assert.equal(result.verifier.sha256, f.expectedSha);
  assert.equal(result.verifier.mappingDigest, G1_MAPPING_DIGEST);
  assert.equal(result.executionScope, 'SOURCE_VERIFICATION_CLI_ONLY');
  assert.equal(result.approvalDecisionId, 'TEST-G1-3');
  assert.equal(f.executions, 1);
});
test('G1 default runner executes a matched synthetic source verifier without extra arguments', async () => {
  const f = await g1Fixture();
  const result = await verifyG1({ root: f.root, candidateRoot: f.candidateRoot, now: NOW });
  assert.equal(result.result, 'PIN_VERIFIED');
  assert.equal(result.evidenceMode, 'LOCAL_BOOTSTRAP');
  assert.equal(result.sourceVerification.exitCode, 0);
  assert.equal(result.sourceVerification.stdout, '');
});
test('G1 empty register never activates a pin or executes a verifier', async () => {
  const root = await fixture();
  const candidateRoot = await mkdtemp(path.join(os.tmpdir(), 'salah-g1-empty-'));
  fixtures.push(candidateRoot);
  let executions = 0;
  const result = await verifyG1({ root, candidateRoot, runner: () => { executions++; } });
  assert.equal(result.result, 'G1_PIN_NOT_ACTIVE');
  assert.equal(result.authority, 'NONE');
  assert.equal(executions, 0);
});

test('G1 malformed record and wrong register revision fail before execution', async () => {
  const malformed = await g1Fixture({ mutateRows: rows => { delete rows[3].mappingDigest; } });
  await assert.rejects(malformed.verify(), /missing\/extra fields/);
  assert.equal(malformed.executions, 0);
  const revision = await g1Fixture({ mutateRows: rows => { rows[3].registerRevision = 99; } });
  await assert.rejects(revision.verify(), /register revision/);
  assert.equal(revision.executions, 0);
});
test('G1 duplicate active records and superseded pins fail closed', async () => {
  const addSecond = (rows, { base, expectedSha }, active) => {
    const states = active ? ['DRAFT', 'PENDING_REVIEW', 'FINAL_BYTES_APPROVED', 'ACTIVE'] :
      ['DRAFT', 'PENDING_REVIEW', 'FINAL_BYTES_APPROVED'];
    rows.push(...states.map((state, index) => g1Row(state, index + 5, base, expectedSha,
      { amendmentId: 'TEST-G1B', decisionPrefix: 'TEST-G1B', approvalRevision: 7 })));
  };
  const duplicate = await g1Fixture({ mutateRows: (rows, context) => addSecond(rows, context, true) });
  await assert.rejects(duplicate.verify(), /Duplicate\/conflicting active G1 pins/);
  assert.equal(duplicate.executions, 0);
  const superseded = await g1Fixture({ mutateRows: (rows, context) => addSecond(rows, context, false) });
  await assert.rejects(superseded.verify(), /Superseded G1 pin/);
  assert.equal(superseded.executions, 0);
});
test('G1 dirty or unborn governance checkout never executes', async () => {
  const dirty = await g1Fixture();
  await writeFile(path.join(dirty.root, 'untracked-evidence.txt'), 'dirty');
  await assert.rejects(dirty.verify(), /Dirty governance checkout/);
  assert.equal(dirty.executions, 0);
  const unborn = await g1Fixture({ unborn: true });
  await assert.rejects(unborn.verify(), /Command failed|HEAD/);
  assert.equal(unborn.executions, 0);
});
test('G1 revoked, expired, rolled-back, rejected and unapproved states never execute', async () => {
  for (const state of ['REVOKED', 'EXPIRED', 'ROLLED_BACK']) {
    const f = await g1Fixture({ mutateRows: (rows, { base, expectedSha }) => {
      rows.push(g1Row(state, 5, base, expectedSha));
    } });
    assert.equal((await f.verify()).result, 'G1_PIN_NOT_ACTIVE');
    assert.equal(f.executions, 0);
  }
  const pending = await g1Fixture({ states: ['DRAFT', 'PENDING_REVIEW'] });
  assert.equal((await pending.verify()).result, 'G1_PIN_NOT_ACTIVE');
  assert.equal(pending.executions, 0);
  const rejected = await g1Fixture({ states: ['DRAFT', 'REJECTED'] });
  assert.equal((await rejected.verify()).result, 'G1_PIN_NOT_ACTIVE');
  assert.equal(rejected.executions, 0);
});
test('G1 expired active pin fails before execution', async () => {
  const f = await g1Fixture({ expiresAtUtc: '2026-10-07T11:00:00.000Z' });
  await assert.rejects(f.verify(), /G1 pin expired/);
  assert.equal(f.executions, 0);
});
test('G1 owner approval cannot become effective before its recorded UTC time', async () => {
  const f = await g1Fixture();
  await assert.rejects(f.verify({ now: Date.parse('2026-10-07T09:00:00.000Z') }),
    /G1 approval is not yet effective/);
  assert.equal(f.executions, 0);
});
test('G1 cannot reactivate a previously revoked verifier SHA in another amendment', async () => {
  const f = await g1Fixture({ mutateRows: (rows, { base, expectedSha }) => {
    rows.push(g1Row('REVOKED', 5, base, expectedSha));
    rows.push(...['DRAFT', 'PENDING_REVIEW', 'FINAL_BYTES_APPROVED', 'ACTIVE']
      .map((state, index) => g1Row(state, index + 6, base, expectedSha,
        { amendmentId: 'TEST-G1B', decisionPrefix: 'TEST-G1B', approvalRevision: 8 })));
  } });
  await assert.rejects(f.verify(), /Rejected\/revoked\/expired verifier SHA/);
  assert.equal(f.executions, 0);
});

test('G1 one-byte verifier change cannot execute, even when workspace knows its new SHA', async () => {
  const f = await g1Fixture();
  const changed = G1_SOURCE + '\n';
  await writeFile(f.verifier, changed);
  assert.notEqual(sha256(changed), f.expectedSha);
  await assert.rejects(f.verify(), /Candidate verifier SHA differs from owner approval/);
  assert.equal(f.executions, 0);
});
test('G1 permanently rejects the old verifier SHA', async () => {
  const f = await g1Fixture({ mutateRows: rows => rows.forEach(row => {
    row.verifierSha256 = G1_REJECTED_SHA;
  }) });
  await assert.rejects(f.verify(), /Previously rejected verifier SHA/);
  assert.equal(f.executions, 0);
});
test('G1 rejects wrong, absolute, traversing, aliased and duplicate-separator verifier paths', async () => {
  for (const target of ['README.md', '../bootstrap/verify.mjs', '/tmp/verify.mjs',
    './scripts/testing/verify-phase2-notification-boundary.mjs',
    'scripts//testing/verify-phase2-notification-boundary.mjs',
    'scripts\\testing\\verify-phase2-notification-boundary.mjs',
    'scripts/testing/verify-phase2-notification-boundary.mjs/',
    'scripts/testing/verify-phase2-notification-boundary.mjs2']) {
    const f = await g1Fixture({ mutateRows: rows => rows.forEach(row => { row.verifierPath = target; }) });
    await assert.rejects(f.verify(), /Wrong G1 verifier path/);
    assert.equal(f.executions, 0);
  }
});
test('G1 rejects symlinked verifier, symlinked parent and non-regular verifier', async () => {
  const finalLink = await g1Fixture();
  const outside = path.join(finalLink.candidateRoot, 'outside.mjs');
  await writeFile(outside, G1_SOURCE);
  await rm(finalLink.verifier);
  await symlink(outside, finalLink.verifier);
  await assert.rejects(finalLink.verify(), /Symlinked G1 path component/);
  assert.equal(finalLink.executions, 0);

  const parentLink = await g1Fixture();
  const replacement = path.join(parentLink.candidateRoot, 'replacement');
  await mkdir(path.join(replacement, 'testing'), { recursive: true });
  await writeFile(path.join(replacement, 'testing', 'verify-phase2-notification-boundary.mjs'), G1_SOURCE);
  await rm(path.join(parentLink.candidateRoot, 'scripts'), { recursive: true });
  await symlink(replacement, path.join(parentLink.candidateRoot, 'scripts'));
  await assert.rejects(parentLink.verify(), /Symlinked G1 path component/);
  assert.equal(parentLink.executions, 0);

  const directory = await g1Fixture();
  await rm(directory.verifier);
  await mkdir(directory.verifier);
  await assert.rejects(directory.verify(), /Non-regular G1 verifier/);
  assert.equal(directory.executions, 0);
});
test('G1 rejects candidate-root symlink and repository-root escape', async () => {
  const f = await g1Fixture();
  const alias = path.join(path.dirname(f.candidateRoot), `salah-g1-alias-${path.basename(f.candidateRoot)}`);
  fixtures.push(alias);
  await symlink(f.candidateRoot, alias);
  await assert.rejects(f.verify({ candidateRoot: alias }), /SALAH root symlink or path alias/);
  await assert.rejects(f.verify({ candidateRoot: path.dirname(f.candidateRoot) }), /Command failed|SALAH repository root/);
  assert.equal(f.executions, 0);
});
test('G1 requires an exact committed governance base revision', async () => {
  const f = await g1Fixture({ mutateRows: rows => rows.forEach(row => {
    row.governanceBaseCommit = 'f'.repeat(40);
  }) });
  await assert.rejects(f.verify(), /Command failed|governance base commit unavailable/);
  assert.equal(f.executions, 0);
});
test('G1 rejects wrong mapping version, mapping digest and each controlled-only hash', async () => {
  const cases = [
    { change: row => { row.mappingVersion = 2; }, error: /Wrong G1 mapping version/ },
    { change: row => { row.mappingDigest = 'f'.repeat(64); }, error: /Owner-approved mapping digest differs/ },
    ...Object.keys(G1_HASHES).map(name => ({
      change: row => { row.controlledOnlySha256[name] = 'f'.repeat(64); },
      error: /Owner-approved controlled-only hashes differ/
    }))
  ];
  for (const { change, error } of cases) {
    const f = await g1Fixture({ mutateRows: rows => rows.forEach(change) });
    await assert.rejects(f.verify(), error);
    assert.equal(f.executions, 0);
  }
});
test('G1 rejects changed scope, runtime authority, production authority or review lineage', async () => {
  const cases = [
    { key: 'executionScope', value: 'APK_VERIFICATION', error: /source-only/ },
    { key: 'runtimeAuthority', value: true, error: /runtime authority/ },
    { key: 'productionAuthorized', value: true, error: /production/ },
    { key: 'securityReviewStatus', value: 'SELF_APPROVED', error: /security review lineage/ },
    { key: 'repairStatus', value: 'UNREVIEWED', error: /repair lineage/ }
  ];
  for (const { key, value, error } of cases) {
    const f = await g1Fixture({ mutateRows: rows => rows.forEach(row => { row[key] = value; }) });
    await assert.rejects(f.verify(), error);
    assert.equal(f.executions, 0);
  }
});
test('G1 rejects an ACTIVE status without the owner approval transition', async () => {
  const f = await g1Fixture({ states: ['DRAFT', 'PENDING_REVIEW', 'ACTIVE'] });
  await assert.rejects(f.verify(), /Invalid G1 state transition/);
  assert.equal(f.executions, 0);
});
test('G1 owner approval ID and timestamp cannot be rewritten by an ACTIVE row', async () => {
  const id = await g1Fixture({ mutateRows: rows => { rows[3].approvalDecisionId = 'FORGED'; } });
  await assert.rejects(id.verify(), /owner decision ID changed/);
  assert.equal(id.executions, 0);
  const time = await g1Fixture({ mutateRows: rows => {
    rows[3].approvedAtUtc = '2026-10-07T11:00:00.000Z';
  } });
  await assert.rejects(time.verify(), /approval time changed/);
  assert.equal(time.executions, 0);
});
test('G1 candidate UPSTREAM, claimed output and workspace SHA cannot supply approval', async () => {
  const f = await g1Fixture();
  await mkdir(path.join(f.candidateRoot, 'android/salah-local-notifications'), { recursive: true });
  await writeFile(path.join(f.candidateRoot, 'android/salah-local-notifications/UPSTREAM.json'),
    JSON.stringify({ verifierSha256: 'f'.repeat(64), status: 'ACTIVE' }));
  const result = await f.verify({ runner: () => {
    return { exitCode: 0, stdout: JSON.stringify({ verifierSha256: 'f'.repeat(64), authority: 'ACTIVE' }), stderr: '' };
  } });
  assert.equal(result.result, 'PIN_VERIFIED');
  assert.equal(result.verifier.sha256, f.expectedSha);
  assert.notEqual(result.verifier.sha256, JSON.parse(result.sourceVerification.stdout).verifierSha256);
  await writeFile(f.verifier, G1_SOURCE + '// candidate generated a new SHA\n');
  await assert.rejects(f.verify(), /Candidate verifier SHA differs from owner approval/);
  assert.equal(f.executions, 0);
});
test('G1 policy cannot replace the rejected SHA or source-only scope', async () => {
  const policy = await g1Fixture({ mutatePolicy: value => {
    value.g1VerifierPin.rejectedVerifierSha256 = 'f'.repeat(64);
  } });
  await assert.rejects(policy.verify(), /G1 policy rules changed/);
  assert.equal(policy.executions, 0);
});
