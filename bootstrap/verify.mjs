import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawnSync } from 'node:child_process';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REMOTE = 'https://github.com/salahshtech/SALAH-Governance.git';
const SALAH_REMOTE = 'https://github.com/salahshtech/SALAH.git';
const POLICY_PATH = 'governance/trust-policy.json';
const REGISTER_PATH = 'governance/approvals.jsonl';
const BOOTSTRAP_PATH = 'bootstrap/verify.mjs';
const STATES = new Set(['DRAFT', 'PENDING_REVIEW', 'ADMITTED', 'FINAL_BYTES_APPROVED', 'ACTIVE',
  'REJECTED', 'REVOKED', 'EXPIRED', 'ROLLED_BACK']);
const TYPES = new Set(['TEST_ONLY', 'CONTROLLED_SOURCE', 'ARCHITECTURE_REVISION', 'MIGRATION',
  'PROTECTED_BOUNDARY', 'RELEASE']);
const NEXT = {
  DRAFT: ['PENDING_REVIEW', 'REJECTED'],
  PENDING_REVIEW: ['ADMITTED', 'REJECTED'],
  ADMITTED: ['FINAL_BYTES_APPROVED', 'REVOKED', 'EXPIRED'],
  FINAL_BYTES_APPROVED: ['ACTIVE', 'REVOKED', 'EXPIRED'],
  ACTIVE: ['REVOKED', 'EXPIRED', 'ROLLED_BACK'],
  REJECTED: [], REVOKED: [], EXPIRED: [], ROLLED_BACK: []
};
const FAIL_CLOSED = [
  'MISSING_OR_MALFORMED_POLICY', 'MISSING_OR_MALFORMED_REGISTER', 'UNSUPPORTED_VERSION',
  'STALE_OR_REVOKED_DECISION', 'UNAPPROVED_CANDIDATE', 'UNVERIFIED_VERIFIER_OR_ENTRYPOINT',
  'MISSING_REQUIRED_STAGE'
];
const SHA = /^[0-9a-f]{64}$/;
const GIT_SHA = /^[0-9a-f]{40,64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const G1_KIND = 'G1_SOURCE_VERIFIER_PIN';
const OWNER_TRANSITION_KIND = 'OWNER_GOVERNANCE_TRANSITION';
const OWNER_TRANSITION_V2_KIND = 'OWNER_GOVERNANCE_TRANSITION_V2';
const OWNER_V2_CORRECTION_KIND = 'OWNER_GOVERNANCE_V2_CORRECTION';
const OWNER_ADMISSION_KIND = 'OWNER_HUNK_ADMISSION';
const OWNER_RISK_PIN_KIND = 'OWNER_RISK_VERIFIER_PIN';
const OWNER_NAME = 'SH Tech';
const OWNER_BASE_COMMIT = '7897d3a57d46dd282bb1628fcf83433710f48aff';
const H171_PACKET_SHA = '8ca558b66016ab30ff658f65c61a321eb719cddcdc49b6387fbdad7d9c649857';
const OWNER_SCOPE_PATHS = [
  'src/features/prayer/notifications.js',
  'tests/unit/notification-complete-sound-contract.unit.test.js',
  'tests/unit/phase-d2-fajr-adhan-custom-time.unit.test.js',
  'tests/unit/prayer-notification-reliability.unit.test.js',
  'www/app.js',
  'www/generated/salah-prayer.js'
];
const OWNER_SOURCE_RECORDS = ['N-01', 'N-02', 'N-03', 'A-01', 'A-02', 'A-03', 'A-04', 'A-05', 'A-06'];
const OWNER_HUNK_IDS_BY_PATH = Object.freeze({
  'src/features/prayer/notifications.js': ['N-01', 'N-02', 'N-03'],
  'tests/unit/notification-complete-sound-contract.unit.test.js': ['T-SOUND-214-240'],
  'tests/unit/phase-d2-fajr-adhan-custom-time.unit.test.js': ['T-FAJR-271-305'],
  'tests/unit/prayer-notification-reliability.unit.test.js': ['T-REL-103-177', 'T-REL-291-304'],
  'www/app.js': ['A-01', 'A-02', 'A-03', 'A-04', 'A-05', 'A-06']
});
const TRANSITION_HASH_PATHS = [POLICY_PATH, BOOTSTRAP_PATH, 'tests/bootstrap-trust.test.mjs'];
const G1_PATH = 'scripts/testing/verify-phase2-notification-boundary.mjs';
const G1_SCOPE = 'SOURCE_VERIFICATION_CLI_ONLY';
const G1_REPAIR_STATUS = 'REPAIR_COMPLETE';
const G1_REVIEW_STATUS = 'PASSED_WITH_NON_BLOCKING_FINDINGS';
const G1_REJECTED_SHA = 'b67eb901941bf755274f6f1fe833c8ccf9d7ae1ac766841aa11db937cdbbd570';
const G1_CONTROLLED_PATHS = [
  'android/salah-local-notifications/build.gradle',
  'android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthority.java',
  'android/salah-local-notifications/src/main/java/com/capacitorjs/plugins/localnotifications/authority/NotificationAuthorityBridge.java'
];
const G1_STATES = ['DRAFT', 'PENDING_REVIEW', 'FINAL_BYTES_APPROVED', 'ACTIVE',
  'REJECTED', 'REVOKED', 'EXPIRED', 'ROLLED_BACK'];
const G1_NEXT = {
  DRAFT: ['PENDING_REVIEW', 'REJECTED'],
  PENDING_REVIEW: ['FINAL_BYTES_APPROVED', 'REJECTED'],
  FINAL_BYTES_APPROVED: ['ACTIVE', 'REVOKED', 'EXPIRED'],
  ACTIVE: ['REVOKED', 'EXPIRED', 'ROLLED_BACK'],
  REJECTED: [], REVOKED: [], EXPIRED: [], ROLLED_BACK: []
};
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function exactKeys(value, expected, label) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${label}: object required`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label}: missing/extra fields`);
}
function utc(value, label) {
  assert.ok(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value, `${label}: invalid UTC timestamp`);
}
function literalPath(value) {
  assert.ok(typeof value === 'string' && value.length > 0 && !value.includes('\\') && !value.startsWith('/') &&
    !value.split('/').some(part => !part || part === '.' || part === '..') &&
    /^[A-Za-z0-9_./-]+$/.test(value), 'Non-literal amendment path');
}
function parseExact(source, pretty, label) {
  const value = JSON.parse(source);
  assert.equal(source, JSON.stringify(value, null, pretty ? 2 : 0) + '\n',
    `${label}: duplicate keys or non-canonical JSON`);
  return value;
}
function validatePolicy(policy) {
  exactKeys(policy, ['schemaVersion', 'model', 'repository', 'paths', 'revisions', 'gates',
    'g1VerifierPin', 'ownerRiskVerifierPin', 'authority', 'ownerAdmission', 'failClosed'], 'Policy');
  assert.equal(policy.schemaVersion, 1, 'Unsupported policy version');
  assert.equal(policy.model, 'SALAH_OWNER_CONTROLLED_GOVERNANCE_G0');
  exactKeys(policy.repository, ['url', 'purpose', 'authority'], 'Repository policy');
  assert.equal(policy.repository.url, REMOTE);
  assert.equal(policy.repository.authority, 'OWNER_CONTROLLED_ACCESS');
  assert.ok(typeof policy.repository.purpose === 'string' && policy.repository.purpose.length > 0);
  exactKeys(policy.paths, ['register', 'bootstrap'], 'Policy paths');
  assert.equal(policy.paths.register, REGISTER_PATH);
  assert.equal(policy.paths.bootstrap, BOOTSTRAP_PATH);
  exactKeys(policy.revisions, ['governance', 'bootstrap', 'register'], 'Policy revisions');
  assert.ok(Number.isSafeInteger(policy.revisions.governance) && policy.revisions.governance >= 0, 'Invalid governance revision');
  assert.equal(policy.revisions.governance, 2, 'Unsupported governance revision');
  assert.equal(policy.revisions.bootstrap, 3, 'Unsupported bootstrap revision');
  assert.ok(Number.isSafeInteger(policy.revisions.register) && policy.revisions.register >= 0, 'Invalid register revision');
  assert.deepEqual(policy.gates, { G0: 'FOUNDATION_ONLY', G1: 'PENDING_VERIFIER_PINNING',
    G2: 'PENDING_MANDATORY_ENTRYPOINT', G3: 'PENDING_AMENDMENT_EXECUTION' });
  assert.deepEqual(policy.g1VerifierPin, {
    schemaVersion: 1, purpose: G1_KIND, verifierPath: G1_PATH, executionScope: G1_SCOPE,
    allowedStates: G1_STATES, repairStatus: G1_REPAIR_STATUS,
    securityReviewStatus: G1_REVIEW_STATUS, controlledOnlyPaths: G1_CONTROLLED_PATHS,
    runtimeAuthority: false, productionAuthorized: false,
    rejectedVerifierSha256: G1_REJECTED_SHA
  }, 'G1 policy rules changed');
  assert.deepEqual(policy.ownerRiskVerifierPin, {
    schemaVersion: 1, kind: OWNER_RISK_PIN_KIND, verifierPath: G1_PATH,
    executionScope: G1_SCOPE, transitionKind: OWNER_V2_CORRECTION_KIND,
    packetSha256: H171_PACKET_SHA, ownerName: OWNER_NAME,
    independentReview: 'UNAVAILABLE_NOT_PERFORMED',
    states: ['DRAFT', 'FINAL_BYTES_APPROVED', 'ACTIVE', 'REJECTED', 'REVOKED', 'EXPIRED'],
    runtimeAuthority: false, productionAuthorized: false
  }, 'Owner-risk verifier-pin policy changed');
  assert.deepEqual(policy.authority, { approver: 'PROJECT_OWNER', ownerName: OWNER_NAME,
    reviewModel: 'SOLE_OWNER_NO_INDEPENDENT_REVIEW', securityRiskAccepted: true,
    localMode: 'DIAGNOSTIC_ONLY',
    authoritativeMode: 'UNAVAILABLE_UNTIL_G1_G2_G3' });
  assert.deepEqual(policy.ownerAdmission, { schemaVersion: 1, transitionKind: OWNER_TRANSITION_KIND,
    admissionKind: OWNER_ADMISSION_KIND, packetSha256: H171_PACKET_SHA,
    candidateState: 'CANDIDATE_SCOPE_APPROVED', admittedState: 'FINAL_BYTES_APPROVED',
    runtimeAuthority: false, productionAuthorized: false }, 'Owner admission policy changed');
  assert.deepEqual(policy.failClosed, FAIL_CLOSED, 'Fail-closed policy changed');
  return policy;
}
function validateDecision(row, previous, seen, revision) {
  exactKeys(row, ['kind', 'decisionId', 'amendmentId', 'version', 'owner', 'type', 'purpose', 'reason',
    'paths', 'baseline', 'scope', 'architectureRevision', 'state', 'registerRevision', 'decidedAtUtc',
    'expiresAtUtc', 'revokesDecisionId', 'rollbackToDecisionId', 'finalSha256ByPath', 'runtimeAuthority'], 'Decision');
  assert.equal(row.kind, 'DECISION');
  assert.match(row.decisionId, ID, 'Invalid decision ID');
  assert.match(row.amendmentId, ID, 'Invalid amendment identity');
  assert.ok(!seen.has(row.decisionId), 'Duplicate decision ID');
  seen.add(row.decisionId);
  assert.equal(row.version, 1, 'Unsupported decision version');
  assert.ok(typeof row.owner === 'string' && row.owner.trim(), 'Missing decision owner');
  assert.ok(TYPES.has(row.type), 'Invalid amendment type');
  assert.ok(typeof row.purpose === 'string' && row.purpose.trim(), 'Missing purpose');
  assert.ok(typeof row.reason === 'string' && row.reason.trim(), 'Missing reason');
  assert.ok(Array.isArray(row.paths) && row.paths.length > 0, 'Exact paths required');
  row.paths.forEach(literalPath);
  assert.equal(new Set(row.paths).size, row.paths.length, 'Duplicate amendment path');
  assert.deepEqual(row.paths, [...row.paths].sort(), 'Amendment paths must be sorted');
  exactKeys(row.baseline, ['commit', 'sha256ByPath'], 'Baseline');
  assert.match(row.baseline.commit, SHA, 'Invalid baseline commit');
  exactKeys(row.baseline.sha256ByPath, row.paths, 'Baseline path hashes');
  for (const digest of Object.values(row.baseline.sha256ByPath)) assert.match(digest, SHA, 'Invalid baseline SHA');
  exactKeys(row.scope, ['id', 'digest'], 'Scope');
  assert.match(row.scope.id, ID, 'Invalid scope identity');
  assert.match(row.scope.digest, SHA, 'Invalid scope digest');
  assert.ok(row.architectureRevision === null || (typeof row.architectureRevision === 'string' && ID.test(row.architectureRevision)),
    'Invalid architecture revision');
  assert.ok(STATES.has(row.state), 'Invalid decision state');
  assert.equal(row.registerRevision, revision, 'Invalid/stale register revision');
  utc(row.decidedAtUtc, 'Decision');
  if (row.expiresAtUtc !== null) utc(row.expiresAtUtc, 'Expiry');
  if (row.revokesDecisionId !== null) assert.match(row.revokesDecisionId, ID, 'Invalid revocation target');
  if (row.rollbackToDecisionId !== null) assert.match(row.rollbackToDecisionId, ID, 'Invalid rollback target');
  assert.equal(row.runtimeAuthority, false, 'G0 cannot grant runtime authority');
  assert.equal(row.finalSha256ByPath, null, 'G0 cannot approve final bytes');
  assert.equal(row.revokesDecisionId === null, row.state !== 'REVOKED', 'Revocation target/state mismatch');
  assert.equal(row.rollbackToDecisionId === null, row.state !== 'ROLLED_BACK', 'Rollback target/state mismatch');
  if (previous) {
    assert.equal(previous.kind, 'DECISION', 'Mixed decision kinds for one amendment');
    assert.ok(NEXT[previous.state].includes(row.state), 'Invalid state transition');
    for (const key of ['version', 'owner', 'type', 'purpose', 'reason', 'paths', 'baseline', 'scope', 'architectureRevision'])
      assert.deepEqual(row[key], previous[key], `Amendment identity changed: ${key}`);
    assert.ok(Date.parse(row.decidedAtUtc) >= Date.parse(previous.decidedAtUtc), 'Decision time went backwards');
    if (row.state === 'REVOKED') assert.equal(row.revokesDecisionId, previous.decisionId, 'Wrong revocation target');
  } else assert.equal(row.state, 'DRAFT', 'First decision must be DRAFT');
  return row;
}
function validateG1Decision(row, previous, seen, revision, policy) {
  exactKeys(row, ['kind', 'schemaVersion', 'decisionId', 'amendmentId', 'owner', 'state',
    'registerRevision', 'decidedAtUtc', 'approvedAtUtc', 'expiresAtUtc', 'revokesDecisionId',
    'rollbackToDecisionId', 'governanceBaseCommit', 'governanceRevision', 'approvalRevision',
    'approvalDecisionId',
    'verifierPath', 'verifierSha256', 'mappingVersion', 'mappingDigest', 'controlledOnlySha256',
    'executionScope', 'repairStatus', 'securityReviewStatus', 'previousRejectedVerifierSha256',
    'runtimeAuthority', 'productionAuthorized'], 'G1 decision');
  assert.equal(row.kind, G1_KIND);
  assert.equal(row.schemaVersion, 1, 'Unsupported G1 version');
  assert.match(row.decisionId, ID, 'Invalid G1 decision ID');
  assert.match(row.amendmentId, ID, 'Invalid G1 amendment ID');
  assert.ok(!seen.has(row.decisionId), 'Duplicate decision ID');
  seen.add(row.decisionId);
  assert.equal(row.owner, 'PROJECT_OWNER', 'G1 decision requires project owner');
  assert.ok(G1_STATES.includes(row.state), 'Invalid G1 state');
  assert.equal(row.registerRevision, revision, 'Invalid/stale G1 register revision');
  utc(row.decidedAtUtc, 'G1 decision');
  if (row.expiresAtUtc !== null) utc(row.expiresAtUtc, 'G1 expiry');
  if (row.approvedAtUtc !== null) utc(row.approvedAtUtc, 'G1 approval');
  assert.match(row.governanceBaseCommit, GIT_SHA, 'Invalid G1 governance base commit');
  assert.ok(Number.isSafeInteger(row.governanceRevision) && row.governanceRevision > 0 &&
    (row.governanceRevision === 1 || row.governanceRevision === policy.revisions.governance),
    'Wrong G1 governance revision');
  assert.equal(row.verifierPath, policy.g1VerifierPin.verifierPath, 'Wrong G1 verifier path');
  assert.match(row.verifierSha256, SHA, 'Invalid G1 verifier SHA');
  assert.notEqual(row.verifierSha256, G1_REJECTED_SHA, 'Previously rejected verifier SHA');
  assert.equal(row.mappingVersion, 1, 'Wrong G1 mapping version');
  assert.match(row.mappingDigest, SHA, 'Invalid G1 mapping digest');
  exactKeys(row.controlledOnlySha256, G1_CONTROLLED_PATHS, 'G1 controlled-only hashes');
  for (const value of Object.values(row.controlledOnlySha256)) assert.match(value, SHA, 'Invalid controlled-only SHA');
  assert.equal(row.executionScope, G1_SCOPE, 'G1 scope must be source-only');
  assert.equal(row.repairStatus, G1_REPAIR_STATUS, 'G1 repair lineage changed');
  assert.equal(row.securityReviewStatus, G1_REVIEW_STATUS, 'G1 security review lineage changed');
  assert.equal(row.previousRejectedVerifierSha256, G1_REJECTED_SHA, 'G1 rejected SHA binding changed');
  assert.equal(row.runtimeAuthority, false, 'G1 cannot grant runtime authority');
  assert.equal(row.productionAuthorized, false, 'G1 cannot approve production');
  assert.equal(row.revokesDecisionId === null, row.state !== 'REVOKED', 'G1 revocation target/state mismatch');
  assert.equal(row.rollbackToDecisionId === null, row.state !== 'ROLLED_BACK', 'G1 rollback target/state mismatch');
  if (previous) {
    assert.equal(previous.kind, G1_KIND, 'Mixed decision kinds for one amendment');
    assert.ok(G1_NEXT[previous.state].includes(row.state), 'Invalid G1 state transition');
    for (const key of ['amendmentId', 'owner', 'expiresAtUtc', 'governanceBaseCommit', 'governanceRevision',
      'verifierPath', 'verifierSha256', 'mappingVersion', 'mappingDigest', 'controlledOnlySha256',
      'executionScope', 'repairStatus', 'securityReviewStatus', 'previousRejectedVerifierSha256',
      'runtimeAuthority', 'productionAuthorized'])
      assert.deepEqual(row[key], previous[key], `G1 identity changed: ${key}`);
    assert.ok(Date.parse(row.decidedAtUtc) >= Date.parse(previous.decidedAtUtc), 'G1 decision time went backwards');
    if (row.state === 'REVOKED') assert.equal(row.revokesDecisionId, previous.decisionId, 'Wrong G1 revocation target');
    if (row.state === 'ROLLED_BACK') assert.match(row.rollbackToDecisionId, ID, 'Missing G1 rollback target');
    if (previous.approvalRevision !== null) {
      assert.equal(row.approvalRevision, previous.approvalRevision, 'G1 approval revision changed');
      assert.equal(row.approvalDecisionId, previous.approvalDecisionId, 'G1 owner decision ID changed');
      assert.equal(row.approvedAtUtc, previous.approvedAtUtc, 'G1 approval time changed');
    }
  } else assert.equal(row.state, 'DRAFT', 'First G1 decision must be DRAFT');
  if (row.state === 'FINAL_BYTES_APPROVED') {
    assert.equal(previous?.state, 'PENDING_REVIEW', 'G1 approval lacks security review');
    assert.equal(row.approvalRevision, revision, 'G1 owner approval revision mismatch');
    assert.equal(row.approvalDecisionId, row.decisionId, 'G1 owner decision ID mismatch');
    assert.equal(row.approvedAtUtc, row.decidedAtUtc, 'G1 owner approval time mismatch');
  } else if (['DRAFT', 'PENDING_REVIEW', 'REJECTED'].includes(row.state)) {
    assert.equal(row.approvalRevision, null, 'Unapproved G1 record carries approval revision');
    assert.equal(row.approvalDecisionId, null, 'Unapproved G1 record carries owner decision ID');
    assert.equal(row.approvedAtUtc, null, 'Unapproved G1 record carries approval time');
  } else {
    assert.ok(Number.isSafeInteger(row.approvalRevision) && row.approvalRevision > 0,
      'G1 active/terminal state lacks owner approval revision');
    assert.match(row.approvalDecisionId, ID, 'G1 active/terminal state lacks owner decision ID');
    assert.ok(row.approvedAtUtc !== null, 'G1 active/terminal state lacks owner approval time');
  }
  return row;
}
function validateOwnerRiskPin(row, previous, seen, revision, policy, rows) {
  exactKeys(row, ['kind', 'schemaVersion', 'decisionId', 'amendmentId', 'ownerName',
    'authority', 'independentReview', 'securityRiskAccepted', 'riskStatement', 'state',
    'registerRevision', 'decidedAtUtc', 'approvedAtUtc', 'approvalDecisionId',
    'transitionDecisionId', 'supersedesDecisionId', 'previousVerifierSha256',
    'governanceBaseCommit', 'governanceRevision', 'bootstrapRevision', 'packetSha256',
    'scopePaths', 'sourceRecordIds', 'verifierPath', 'verifierSha256', 'mappingVersion',
    'mappingDigest', 'controlledOnlySha256', 'executionScope', 'revokesDecisionId',
    'runtimeAuthority', 'productionAuthorized'], 'Owner-risk verifier pin');
  assert.equal(row.kind, OWNER_RISK_PIN_KIND);
  assert.equal(row.schemaVersion, 1, 'Unsupported owner-risk pin version');
  assert.match(row.decisionId, ID);
  assert.match(row.amendmentId, ID);
  assert.ok(!seen.has(row.decisionId), 'Duplicate decision ID');
  seen.add(row.decisionId);
  assert.equal(row.ownerName, OWNER_NAME);
  assert.equal(row.authority, 'SOLE_PROJECT_OWNER');
  assert.equal(row.independentReview, 'UNAVAILABLE_NOT_PERFORMED');
  assert.equal(row.securityRiskAccepted, true, 'Owner risk acceptance required');
  assert.ok(typeof row.riskStatement === 'string' &&
    row.riskStatement.includes('independent security review'), 'Owner risk statement required');
  assert.ok(policy.ownerRiskVerifierPin.states.includes(row.state), 'Invalid owner-risk pin state');
  assert.equal(row.registerRevision, revision, 'Stale owner-risk register revision');
  utc(row.decidedAtUtc, 'Owner-risk decision');
  if (row.approvedAtUtc !== null) utc(row.approvedAtUtc, 'Owner-risk approval');
  assert.equal(row.governanceBaseCommit, OWNER_BASE_COMMIT);
  assert.equal(row.governanceRevision, policy.revisions.governance);
  assert.equal(row.bootstrapRevision, policy.revisions.bootstrap);
  assert.equal(row.packetSha256, H171_PACKET_SHA, 'Wrong transition packet SHA');
  assert.deepEqual(row.scopePaths, OWNER_SCOPE_PATHS, 'Owner-risk scope changed');
  assert.deepEqual(row.sourceRecordIds, OWNER_SOURCE_RECORDS, 'Owner-risk source records changed');
  const transition = rows.find(item => item.kind === OWNER_V2_CORRECTION_KIND);
  assert.ok(transition, 'Owner-risk pin lacks transition');
  assert.equal(row.transitionDecisionId, transition.decisionId, 'Wrong transition binding');
  const historical = rows.find(item => item.kind === G1_KIND && item.state === 'ACTIVE');
  assert.ok(historical, 'Historical G1 pin is missing');
  assert.equal(row.supersedesDecisionId, historical.decisionId, 'Wrong historical G1 binding');
  assert.equal(row.previousVerifierSha256, historical.verifierSha256, 'Wrong prior verifier SHA');
  assert.equal(row.verifierPath, G1_PATH);
  assert.match(row.verifierSha256, SHA, 'Invalid successor verifier SHA');
  assert.notEqual(row.verifierSha256, row.previousVerifierSha256, 'Successor must have distinct bytes');
  assert.notEqual(row.verifierSha256, G1_REJECTED_SHA, 'Rejected verifier SHA');
  assert.equal(row.mappingVersion, 1);
  assert.match(row.mappingDigest, SHA);
  exactKeys(row.controlledOnlySha256, G1_CONTROLLED_PATHS, 'Owner-risk controlled-only hashes');
  for (const value of Object.values(row.controlledOnlySha256)) assert.match(value, SHA);
  assert.equal(row.executionScope, G1_SCOPE);
  assert.equal(row.runtimeAuthority, false);
  assert.equal(row.productionAuthorized, false);
  assert.equal(row.revokesDecisionId === null, row.state !== 'REVOKED', 'Wrong owner-risk revocation');
  if (previous) {
    assert.equal(previous.kind, OWNER_RISK_PIN_KIND, 'Mixed pin amendment kinds');
    assert.ok(({ DRAFT: ['FINAL_BYTES_APPROVED', 'REJECTED'],
      FINAL_BYTES_APPROVED: ['ACTIVE', 'REVOKED', 'EXPIRED'],
      ACTIVE: ['REVOKED', 'EXPIRED'], REJECTED: [], REVOKED: [], EXPIRED: [] })[previous.state]
      .includes(row.state), 'Invalid owner-risk state transition');
    for (const key of ['amendmentId', 'ownerName', 'authority', 'independentReview',
      'securityRiskAccepted', 'riskStatement', 'transitionDecisionId', 'supersedesDecisionId',
      'previousVerifierSha256', 'governanceBaseCommit', 'governanceRevision',
      'bootstrapRevision', 'packetSha256', 'scopePaths', 'sourceRecordIds', 'verifierPath',
      'verifierSha256', 'mappingVersion', 'mappingDigest', 'controlledOnlySha256',
      'executionScope', 'runtimeAuthority', 'productionAuthorized'])
      assert.deepEqual(row[key], previous[key], `Owner-risk pin identity changed: ${key}`);
    assert.ok(Date.parse(row.decidedAtUtc) >= Date.parse(previous.decidedAtUtc), 'Owner-risk time reversed');
  } else assert.equal(row.state, 'DRAFT', 'First owner-risk pin must be DRAFT');
  if (row.state === 'FINAL_BYTES_APPROVED') {
    assert.equal(previous?.state, 'DRAFT', 'Owner-risk approval lacks draft');
    assert.equal(row.approvalDecisionId, row.decisionId, 'Owner approval decision mismatch');
    assert.equal(row.approvedAtUtc, row.decidedAtUtc, 'Owner approval time mismatch');
  } else if (row.state === 'DRAFT' || row.state === 'REJECTED') {
    assert.equal(row.approvalDecisionId, null, 'Unapproved owner-risk pin has approval');
    assert.equal(row.approvedAtUtc, null, 'Unapproved owner-risk pin has approval time');
  } else {
    assert.equal(row.approvalDecisionId, previous.approvalDecisionId, 'Owner approval changed');
    assert.equal(row.approvedAtUtc, previous.approvedAtUtc, 'Owner approval time changed');
  }
  if (row.state === 'REVOKED') assert.equal(row.revokesDecisionId, previous.decisionId,
    'Wrong owner-risk revocation target');
}
function validateOwnerTransition(row, seen, revision, policy) {
  exactKeys(row, ['kind', 'schemaVersion', 'decisionId', 'amendmentId', 'ownerName',
    'authority', 'independentReview', 'securityRiskAccepted', 'riskStatement', 'state',
    'registerRevision', 'recordedAtUtc', 'governanceBaseCommit', 'fromPolicyRevision',
    'toPolicyRevision', 'priorSha256ByPath', 'newSha256ByPath', 'packetSha256',
    'scopePaths', 'sourceRecordIds', 'admissionStatus', 'runtimeAuthority',
    'productionAuthorized'], 'Owner transition');
  assert.equal(row.kind, OWNER_TRANSITION_KIND);
  assert.equal(row.schemaVersion, 1, 'Unsupported owner transition version');
  assert.match(row.decisionId, ID, 'Invalid owner transition ID');
  assert.match(row.amendmentId, ID, 'Invalid owner amendment ID');
  assert.ok(!seen.has(row.decisionId), 'Duplicate decision ID');
  seen.add(row.decisionId);
  assert.equal(row.ownerName, OWNER_NAME, 'Wrong owner identity');
  assert.equal(row.authority, 'SOLE_PROJECT_OWNER', 'Wrong owner authority');
  assert.equal(row.independentReview, 'UNAVAILABLE_NOT_PERFORMED', 'False independent review claim');
  assert.equal(row.securityRiskAccepted, true, 'Missing explicit owner risk acceptance');
  assert.ok(typeof row.riskStatement === 'string' && row.riskStatement.includes('independent security review'),
    'Missing independent-review risk statement');
  assert.equal(row.state, 'CANDIDATE_SCOPE_APPROVED', 'Owner transition cannot admit final bytes');
  assert.equal(row.registerRevision, revision, 'Invalid owner register revision');
  utc(row.recordedAtUtc, 'Owner transition recording');
  assert.match(row.governanceBaseCommit, GIT_SHA, 'Invalid owner governance base commit');
  assert.equal(row.governanceBaseCommit, OWNER_BASE_COMMIT, 'Unexpected owner governance base');
  assert.equal(row.fromPolicyRevision, 1, 'Wrong prior policy revision');
  assert.equal(row.toPolicyRevision, policy.revisions.governance, 'Wrong revised policy revision');
  exactKeys(row.priorSha256ByPath, [...TRANSITION_HASH_PATHS, REGISTER_PATH], 'Prior governance hashes');
  exactKeys(row.newSha256ByPath, TRANSITION_HASH_PATHS, 'Revised governance hashes');
  for (const value of [...Object.values(row.priorSha256ByPath), ...Object.values(row.newSha256ByPath)])
    assert.match(value, SHA, 'Invalid transition SHA');
  assert.equal(row.packetSha256, H171_PACKET_SHA, 'Incorrect H171 approval packet hash');
  assert.deepEqual(row.scopePaths, OWNER_SCOPE_PATHS, 'Incorrect owner-approved path scope');
  assert.deepEqual(row.sourceRecordIds, OWNER_SOURCE_RECORDS, 'Incorrect owner-approved hunk scope');
  assert.equal(row.admissionStatus, 'NOT_ADMITTED', 'Owner scope approval is not source admission');
  assert.equal(row.runtimeAuthority, false, 'Owner transition cannot grant runtime authority');
  assert.equal(row.productionAuthorized, false, 'Owner transition cannot approve production');
  return row;
}
function validateOwnerTransitionV2(row, seen, revision, policy, rows) {
  const original = rows.find(item => item.kind === OWNER_TRANSITION_KIND);
  assert.ok(original, 'Versioned transition lacks original record');
  exactKeys(row, [...Object.keys(original), 'supersedesDecisionId'], 'Versioned owner transition');
  assert.equal(row.kind, OWNER_TRANSITION_V2_KIND);
  assert.equal(row.schemaVersion, 2);
  assert.equal(row.supersedesDecisionId, original.decisionId, 'Wrong prior transition binding');
  assert.notEqual(row.amendmentId, original.amendmentId, 'Versioned transition must be distinct');
  for (const key of ['ownerName', 'authority', 'independentReview', 'securityRiskAccepted',
    'riskStatement', 'state', 'governanceBaseCommit', 'fromPolicyRevision', 'toPolicyRevision',
    'packetSha256', 'scopePaths', 'sourceRecordIds', 'admissionStatus',
    'runtimeAuthority', 'productionAuthorized'])
    assert.deepEqual(row[key], original[key], `Historical transition binding changed: ${key}`);
  exactKeys(row.priorSha256ByPath, [...TRANSITION_HASH_PATHS, REGISTER_PATH],
    'Versioned prior hashes');
  for (const file of TRANSITION_HASH_PATHS)
    assert.equal(row.priorSha256ByPath[file], original.priorSha256ByPath[file],
      `Historical base hash changed: ${file}`);
  assert.match(row.priorSha256ByPath[REGISTER_PATH], SHA, 'Invalid V2 register-prefix SHA');
  const v1Shape = { ...row };
  delete v1Shape.supersedesDecisionId;
  v1Shape.priorSha256ByPath = original.priorSha256ByPath;
  validateOwnerTransition({ ...v1Shape, kind: OWNER_TRANSITION_KIND, schemaVersion: 1 },
    seen, revision, policy);
}
function validateOwnerV2Correction(row, seen, revision, rows, prefixBytes) {
  exactKeys(row, ['kind', 'schemaVersion', 'decisionId', 'amendmentId', 'ownerName',
    'authority', 'independentReview', 'securityRiskAccepted', 'riskStatement', 'state',
    'registerRevision', 'recordedAtUtc', 'predecessorDecisionId', 'predecessorRecordSha256',
    'priorRegisterPrefixSha256', 'governanceBaseCommit', 'policyRevision', 'bootstrapRevision',
    'packetSha256', 'scopePaths', 'sourceRecordIds', 'finalSha256ByPath',
    'sourceAdmission', 'runtimeAuthority', 'productionAuthorized'], 'V2 correction');
  const predecessor = rows.at(-1);
  assert.equal(predecessor?.kind, OWNER_TRANSITION_V2_KIND,
    'V2 correction must immediately follow predecessor');
  assert.equal(row.kind, OWNER_V2_CORRECTION_KIND);
  assert.equal(row.schemaVersion, 1, 'Unsupported V2 correction schema');
  assert.match(row.decisionId, ID);
  assert.match(row.amendmentId, ID);
  assert.ok(!seen.has(row.decisionId), 'Duplicate correction decision ID');
  seen.add(row.decisionId);
  assert.notEqual(row.amendmentId, predecessor.amendmentId, 'Correction requires distinct amendment');
  assert.equal(row.registerRevision, revision, 'Stale correction revision');
  assert.equal(row.predecessorDecisionId, predecessor.decisionId, 'Wrong correction predecessor');
  assert.equal(row.predecessorRecordSha256, digest(Buffer.from(JSON.stringify(predecessor) + '\n')),
    'Altered predecessor record');
  assert.equal(row.priorRegisterPrefixSha256, digest(prefixBytes),
    'Incorrect correction register prefix');
  assert.equal(row.ownerName, OWNER_NAME);
  assert.equal(row.authority, 'SOLE_PROJECT_OWNER');
  assert.equal(row.independentReview, 'UNAVAILABLE_NOT_PERFORMED');
  assert.equal(row.securityRiskAccepted, true, 'Owner risk acceptance required');
  assert.ok(typeof row.riskStatement === 'string' &&
    row.riskStatement.includes('independent security review'), 'Owner risk statement required');
  assert.equal(row.state, 'PROPOSED_CORRECTION', 'Correction cannot activate trust');
  utc(row.recordedAtUtc, 'Correction recording');
  assert.equal(row.governanceBaseCommit, OWNER_BASE_COMMIT);
  assert.equal(row.policyRevision, 2);
  assert.equal(row.bootstrapRevision, 3);
  assert.equal(row.packetSha256, H171_PACKET_SHA);
  assert.deepEqual(row.scopePaths, OWNER_SCOPE_PATHS);
  assert.deepEqual(row.sourceRecordIds, OWNER_SOURCE_RECORDS);
  exactKeys(row.finalSha256ByPath, TRANSITION_HASH_PATHS, 'Final correction file hashes');
  for (const value of Object.values(row.finalSha256ByPath)) assert.match(value, SHA);
  assert.equal(row.sourceAdmission, false);
  assert.equal(row.runtimeAuthority, false);
  assert.equal(row.productionAuthorized, false);
}

/** Pure byte projection: records are owner-controlled inputs, never read from SALAH metadata. */
export function verifyFiniteHunkProjection(baseline, candidate, hunks) {
  assert.ok(Buffer.isBuffer(baseline) && Buffer.isBuffer(candidate), 'Exact byte buffers required');
  assert.ok(Array.isArray(hunks) && hunks.length > 0, 'Approved hunks required');
  const seen = new Set();
  const seenAnchors = new Set();
  let previousEnd = 0;
  let previousStart = -1;
  const segments = [];
  for (const hunk of hunks) {
    exactKeys(hunk, ['id', 'prefix', 'old', 'replacement', 'suffix', 'oldSha256',
      'replacementSha256'], 'Approved hunk');
    assert.match(hunk.id, ID, 'Invalid hunk ID');
    assert.ok(!seen.has(hunk.id), 'Duplicate hunk ID');
    seen.add(hunk.id);
    for (const name of ['prefix', 'old', 'replacement', 'suffix'])
      assert.equal(typeof hunk[name], 'string', `Invalid ${name} bytes`);
    for (const name of ['prefix', 'old', 'replacement', 'suffix'])
      assert.equal(Buffer.from(hunk[name]).toString('utf8'), hunk[name],
        `Non-round-tripping UTF-8 ${name}`);
    assert.ok(hunk.prefix.length && hunk.suffix.length, 'Nonempty hunk anchors required');
    const anchorKey = `${hunk.prefix}\u0000${hunk.old}\u0000${hunk.suffix}`;
    assert.ok(!seenAnchors.has(anchorKey), 'Duplicate approved hunk anchor');
    seenAnchors.add(anchorKey);
    assert.equal(digest(Buffer.from(hunk.old)), hunk.oldSha256, 'Altered approved old bytes');
    assert.equal(digest(Buffer.from(hunk.replacement)), hunk.replacementSha256,
      'Altered approved replacement bytes');
    const old = Buffer.from(hunk.old);
    const needle = Buffer.from(hunk.prefix + hunk.old + hunk.suffix);
    const first = baseline.indexOf(needle);
    assert.ok(first >= 0 && baseline.indexOf(needle, first + 1) === -1,
      'Missing or duplicate hunk anchor');
    const start = first + Buffer.byteLength(hunk.prefix);
    const end = start + old.length;
    assert.ok(start >= previousEnd && start > previousStart,
      'Reordered or overlapping approved hunks');
    segments.push(baseline.subarray(previousEnd, start), Buffer.from(hunk.replacement));
    previousEnd = end;
    previousStart = start;
  }
  segments.push(baseline.subarray(previousEnd));
  assert.deepEqual(candidate, Buffer.concat(segments), 'Extra, missing or altered candidate hunk');
  return { result: 'EXACT_HUNK_PROJECTION', hunkIds: [...seen], sha256: digest(candidate) };
}

function validateOwnerAdmission(row, seen, revision, policy) {
  exactKeys(row, ['kind', 'schemaVersion', 'decisionId', 'amendmentId', 'ownerName',
    'authority', 'independentReview', 'securityRiskAccepted', 'state', 'registerRevision',
    'recordedAtUtc', 'governanceRevision', 'packetSha256', 'scopePaths',
    'baselineSha256ByPath', 'candidateSha256ByPath', 'hunksByPath', 'generated',
    'runtimeAuthority', 'productionAuthorized'], 'Owner hunk admission');
  assert.equal(row.kind, OWNER_ADMISSION_KIND);
  assert.equal(row.schemaVersion, 1, 'Unsupported owner admission version');
  assert.match(row.decisionId, ID, 'Invalid owner admission ID');
  assert.match(row.amendmentId, ID, 'Invalid owner admission amendment ID');
  assert.ok(!seen.has(row.decisionId), 'Duplicate decision ID');
  seen.add(row.decisionId);
  assert.equal(row.ownerName, OWNER_NAME, 'Wrong admission owner');
  assert.equal(row.authority, 'SOLE_PROJECT_OWNER', 'Wrong admission authority');
  assert.equal(row.independentReview, 'UNAVAILABLE_NOT_PERFORMED', 'False independent review claim');
  assert.equal(row.securityRiskAccepted, true, 'Missing admission risk acceptance');
  assert.equal(row.state, 'FINAL_BYTES_APPROVED', 'Admission lacks final-byte approval');
  assert.equal(row.registerRevision, revision, 'Invalid admission register revision');
  utc(row.recordedAtUtc, 'Admission recording');
  assert.equal(row.governanceRevision, policy.revisions.governance, 'Wrong admission policy revision');
  assert.equal(row.packetSha256, H171_PACKET_SHA, 'Incorrect admission packet hash');
  assert.deepEqual(row.scopePaths, OWNER_SCOPE_PATHS, 'Incorrect admission path scope');
  exactKeys(row.baselineSha256ByPath, OWNER_SCOPE_PATHS, 'Admission baseline hashes');
  exactKeys(row.candidateSha256ByPath, OWNER_SCOPE_PATHS, 'Admission candidate hashes');
  for (const value of [...Object.values(row.baselineSha256ByPath),
    ...Object.values(row.candidateSha256ByPath)]) assert.match(value, SHA, 'Invalid admission file SHA');
  exactKeys(row.hunksByPath, OWNER_SCOPE_PATHS.filter(p => p !== 'www/generated/salah-prayer.js'),
    'Admission hunk paths');
  for (const [file, hunks] of Object.entries(row.hunksByPath)) {
    assert.ok(Array.isArray(hunks) && hunks.length > 0, `Missing approved hunks: ${file}`);
    assert.deepEqual(hunks.map(hunk => hunk.id), OWNER_HUNK_IDS_BY_PATH[file],
      `Unapproved, missing or reordered hunk IDs: ${file}`);
    for (const hunk of hunks) {
      exactKeys(hunk, ['id', 'prefix', 'old', 'replacement', 'suffix', 'oldSha256',
        'replacementSha256'], 'Approved hunk');
      assert.match(hunk.oldSha256, SHA, 'Invalid old-hunk SHA');
      assert.match(hunk.replacementSha256, SHA, 'Invalid replacement-hunk SHA');
    }
  }
  exactKeys(row.generated, ['path', 'inputTreeSha256', 'generatorSha256', 'outputSha256',
    'reviewedDiffSha256'], 'Generated output approval');
  assert.equal(row.generated.path, 'www/generated/salah-prayer.js', 'Wrong generated path');
  for (const key of ['inputTreeSha256', 'generatorSha256', 'outputSha256', 'reviewedDiffSha256'])
    assert.match(row.generated[key], SHA, `Invalid generated ${key}`);
  assert.equal(row.generated.outputSha256, row.candidateSha256ByPath[row.generated.path],
    'Generated output hash differs from candidate approval');
  assert.equal(row.runtimeAuthority, false, 'Source admission cannot grant runtime authority');
  assert.equal(row.productionAuthorized, false, 'Source admission cannot approve production');
  return row;
}
function disposition(row, now) {
  if (['REJECTED', 'REVOKED', 'EXPIRED', 'ROLLED_BACK'].includes(row.state)) return 'DENIED';
  if (row.expiresAtUtc && Date.parse(row.expiresAtUtc) <= now) return 'DENIED_EXPIRED';
  return 'SCHEMA_ONLY_NO_AUTHORITY';
}
async function readRegister(canonicalRoot, policy) {
  const registerSource = await readFile(path.join(canonicalRoot, REGISTER_PATH), 'utf8');
  assert.ok(registerSource.endsWith('\n'), 'Register must end with LF');
  const lines = registerSource.trimEnd().split('\n');
  assert.equal(registerSource, lines.join('\n') + '\n', 'Register has non-canonical blank lines');
  const header = parseExact(lines[0] + '\n', false, 'Register header');
  exactKeys(header, ['kind', 'schemaVersion', 'initialRevision'], 'Register header');
  assert.equal(header.kind, 'SALAH_APPROVAL_REGISTER');
  assert.equal(header.schemaVersion, 1, 'Unsupported register version');
  assert.equal(header.initialRevision, 0, 'Invalid initial register revision');
  const latest = new Map(), seen = new Set(), rows = [];
  for (let i = 1; i < lines.length; i++) {
    const row = parseExact(lines[i] + '\n', false, 'Register decision');
    const previous = latest.get(row.amendmentId);
    if (row.kind === 'DECISION') validateDecision(row, previous, seen, i);
    else if (row.kind === G1_KIND) validateG1Decision(row, previous, seen, i, policy);
    else if (row.kind === OWNER_TRANSITION_KIND) {
      assert.equal(previous, undefined, 'Duplicate owner transition amendment');
      validateOwnerTransition(row, seen, i, policy);
      assert.equal(row.priorSha256ByPath[REGISTER_PATH],
        digest(Buffer.from(lines.slice(0, i).join('\n') + '\n')),
        'Incorrect historical transition register prefix');
    } else if (row.kind === OWNER_TRANSITION_V2_KIND) {
      assert.equal(previous, undefined, 'Duplicate versioned owner transition amendment');
      assert.equal(rows.filter(item => item.kind === OWNER_TRANSITION_V2_KIND).length, 0,
        'Duplicate versioned owner transition');
      validateOwnerTransitionV2(row, seen, i, policy, rows);
      assert.equal(row.priorSha256ByPath[REGISTER_PATH],
        digest(Buffer.from(lines.slice(0, i).join('\n') + '\n')),
        'Incorrect V2 transition register prefix');
    } else if (row.kind === OWNER_V2_CORRECTION_KIND) {
      assert.equal(previous, undefined, 'Duplicate correction amendment');
      assert.equal(rows.filter(item => item.kind === OWNER_V2_CORRECTION_KIND).length, 0,
        'Duplicate V2 correction');
      validateOwnerV2Correction(row, seen, i, rows,
        Buffer.from(lines.slice(0, i).join('\n') + '\n'));
    } else if (row.kind === OWNER_ADMISSION_KIND) {
      assert.equal(previous, undefined, 'Duplicate owner admission amendment');
      assert.ok(rows.some(prior => prior.kind === OWNER_TRANSITION_KIND &&
        prior.state === 'CANDIDATE_SCOPE_APPROVED'), 'Owner admission lacks prior transition');
      validateOwnerAdmission(row, seen, i, policy);
    } else if (row.kind === OWNER_RISK_PIN_KIND) {
      validateOwnerRiskPin(row, previous, seen, i, policy, rows);
    }
    else assert.fail('Unknown register decision kind');
    latest.set(row.amendmentId, row);
    rows.push(row);
  }
  assert.equal(policy.revisions.register, lines.length - 1, 'Stale register or policy revision');
  return { latest, rows, decisionCount: rows.length };
}

/** Checks exact recorded file projections; it is not a native alarm or release certification. */
export function verifyOwnerAdmissionProjection(record, baselines, candidates, generatedProof) {
  validateOwnerAdmission(record, new Set(), record.registerRevision,
    { revisions: { governance: 2 } });
  exactKeys(baselines, OWNER_SCOPE_PATHS, 'Admission baseline files');
  exactKeys(candidates, OWNER_SCOPE_PATHS, 'Admission candidate files');
  for (const file of OWNER_SCOPE_PATHS) {
    assert.ok(Buffer.isBuffer(baselines[file]) && Buffer.isBuffer(candidates[file]),
      `Exact file bytes required: ${file}`);
    assert.equal(digest(baselines[file]), record.baselineSha256ByPath[file],
      `Wrong admitted baseline: ${file}`);
    assert.equal(digest(candidates[file]), record.candidateSha256ByPath[file],
      `Wrong admitted candidate: ${file}`);
    if (file !== record.generated.path)
      verifyFiniteHunkProjection(baselines[file], candidates[file], record.hunksByPath[file]);
  }
  exactKeys(generatedProof, ['inputTreeSha256', 'generatorSha256', 'reviewedDiffSha256',
    'reproducedOutput'], 'Generated proof');
  for (const key of ['inputTreeSha256', 'generatorSha256', 'reviewedDiffSha256'])
    assert.equal(generatedProof[key], record.generated[key], `Wrong generated ${key}`);
  assert.ok(Buffer.isBuffer(generatedProof.reproducedOutput), 'Reproduced output bytes required');
  assert.deepEqual(generatedProof.reproducedOutput, candidates[record.generated.path],
    'Generated output differs from reviewed candidate');
  return { result: 'EXACT_PROJECTION_ONLY', authority: 'NONE', runtimeAuthority: false,
    productionAuthorized: false, packetSha256: record.packetSha256 };
}

export async function verifyG0({ root = ROOT, mode = 'DIAGNOSTIC', now = Date.now() } = {}) {
  assert.equal(mode, 'DIAGNOSTIC', 'G0 cannot produce AUTHORITATIVE results');
  assert.ok(Number.isFinite(now), 'Invalid verification time');
  const canonicalRoot = await realpath(root);
  const git = (...args) => execFileSync('git', args, { cwd: canonicalRoot, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  assert.equal(await realpath(git('rev-parse', '--show-toplevel')), canonicalRoot, 'Governance repository unavailable');
  assert.equal(git('remote', 'get-url', 'origin'), REMOTE, 'Governance repository remote mismatch');
  const policy = validatePolicy(parseExact(await readFile(path.join(canonicalRoot, POLICY_PATH), 'utf8'), true, 'Policy'));
  const { latest, decisionCount } = await readRegister(canonicalRoot, policy);
  let head = null;
  try { head = git('rev-parse', '--verify', 'HEAD'); } catch {
    assert.equal(git('rev-list', '--all', '--count'), '0', 'Governance HEAD unavailable in non-empty repository');
    assert.equal(git('symbolic-ref', '--quiet', 'HEAD'), 'refs/heads/main', 'Unexpected unborn branch');
  }
  return {
    schemaVersion: 1, mode: 'DIAGNOSTIC', authoritative: false, result: 'G0_SCHEMA_VALID',
    authority: 'NONE', governance: { root: canonicalRoot, remote: REMOTE,
      branch: git('branch', '--show-current'), head },
    revisions: policy.revisions, register: { decisions: decisionCount,
      amendments: [...latest].map(([amendmentId, row]) => ({ amendmentId, state: row.state,
        disposition: disposition(row, now) })) },
    pendingGates: ['G1', 'G2', 'G3', 'V4']
  };
}

/** The owner's current directive is a candidate-scope decision, not source admission.
 * A dirty/uncommitted governance checkout can report only PENDING_COMMIT.
 */
export async function verifyOwnerTransition({ root = ROOT, packetPath } = {}) {
  const g0 = await verifyG0({ root });
  const governanceRoot = g0.governance.root;
  const policy = validatePolicy(parseExact(await readFile(path.join(governanceRoot, POLICY_PATH), 'utf8'),
    true, 'Policy'));
  const { rows } = await readRegister(governanceRoot, policy);
  const originals = rows.filter(row => row.kind === OWNER_TRANSITION_KIND);
  const successors = rows.filter(row => row.kind === OWNER_TRANSITION_V2_KIND);
  const corrections = rows.filter(row => row.kind === OWNER_V2_CORRECTION_KIND);
  assert.equal(originals.length, 1, 'Exactly one historical owner transition required');
  assert.equal(successors.length, 1, 'Exactly one V2 owner transition required');
  assert.equal(corrections.length, 1, 'Exactly one append-only V2 correction required');
  const row = corrections[0];
  const predecessor = successors[0];
  const git = (...args) => execFileSync('git', args, { cwd: governanceRoot, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  assert.equal(git('rev-parse', '--verify', `${OWNER_BASE_COMMIT}^{commit}`), OWNER_BASE_COMMIT,
    'Owner governance base unavailable');
  for (const file of TRANSITION_HASH_PATHS) {
    const old = execFileSync('git', ['show', `${OWNER_BASE_COMMIT}:${file}`], { cwd: governanceRoot });
    assert.equal(digest(old), predecessor.priorSha256ByPath[file], `Prior governance bytes changed: ${file}`);
    assert.equal(digest(await readFile(path.join(governanceRoot, file))), row.finalSha256ByPath[file],
      `Revised governance bytes changed: ${file}`);
  }
  const register = await readFile(path.join(governanceRoot, REGISTER_PATH));
  if (packetPath !== undefined) {
    assert.ok(typeof packetPath === 'string' && path.isAbsolute(packetPath), 'Absolute packet path required');
    assert.equal(digest(await readFile(packetPath)), row.packetSha256, 'Approval packet hash mismatch');
  }
  const head = git('rev-parse', '--verify', 'HEAD');
  const dirty = git('status', '--porcelain', '--untracked-files=all') !== '';
  let committed = false;
  if (!dirty && head !== OWNER_BASE_COMMIT) {
    git('merge-base', '--is-ancestor', OWNER_BASE_COMMIT, head);
    committed = true;
    for (const file of [POLICY_PATH, REGISTER_PATH, BOOTSTRAP_PATH, 'tests/bootstrap-trust.test.mjs']) {
      const fromHead = execFileSync('git', ['show', `HEAD:${file}`], { cwd: governanceRoot });
      const fromDisk = file === REGISTER_PATH ? register : await readFile(path.join(governanceRoot, file));
      if (!fromHead.equals(fromDisk)) committed = false;
    }
  }
  return { schemaVersion: 1, result: committed && packetPath ? 'OWNER_TRANSITION_RECORDED' :
    'OWNER_TRANSITION_PENDING_COMMIT_OR_PACKET', authority: 'SOLE_PROJECT_OWNER',
    independentReview: 'UNAVAILABLE_NOT_PERFORMED', sourceAdmission: false,
    runtimeAuthority: false, productionAuthorized: false,
    governanceHead: head, governanceDirty: dirty, policyRevision: policy.revisions.governance,
    packetSha256: row.packetSha256, decisionId: row.decisionId };
}

function oneSourceValue(source, expression, label) {
  const matches = [...source.matchAll(expression)];
  assert.equal(matches.length, 1, `Missing/duplicate ${label} in approved verifier bytes`);
  return matches[0][1];
}
function validateVerifierMetadata(bytes, record) {
  const source = bytes.toString('utf8');
  const version = Number(oneSourceValue(source,
    /^export const TRUSTED_MAPPING_VERSION = (\d+);$/gm, 'mapping version'));
  const mappingDigest = oneSourceValue(source,
    /^export const TRUSTED_MAPPING_DIGEST = '([0-9a-f]{64})';$/gm, 'mapping digest');
  assert.equal(version, record.mappingVersion, 'Owner-approved mapping version differs from verifier');
  assert.equal(mappingDigest, record.mappingDigest, 'Owner-approved mapping digest differs from verifier');
  const start = 'export const TRUSTED_CONTROLLED_ONLY_SHA256 = Object.freeze({';
  const end = '\n});';
  assert.equal(source.split(start).length, 2, 'Missing/duplicate controlled-only constant');
  const after = source.slice(source.indexOf(start) + start.length);
  assert.ok(after.includes(end), 'Unterminated controlled-only constant');
  const block = after.slice(0, after.indexOf(end));
  const entries = [...block.matchAll(/'([^']+)'\s*:\s*'([0-9a-f]{64})'/g)];
  assert.equal(entries.length, 3, 'Exactly three controlled-only pins required');
  const actual = Object.fromEntries(entries.map(([, name, hash]) =>
    [`android/salah-local-notifications/${name}`, hash]));
  exactKeys(actual, G1_CONTROLLED_PATHS, 'Verifier controlled-only constants');
  assert.deepEqual(actual, record.controlledOnlySha256,
    'Owner-approved controlled-only hashes differ from verifier');
}
async function literalRegularFile(candidateRoot, relative) {
  literalPath(relative);
  assert.equal(relative, G1_PATH, 'Only the literal G1 verifier path is permitted');
  assert.ok(typeof candidateRoot === 'string' && path.isAbsolute(candidateRoot), 'Absolute SALAH root required');
  const root = path.resolve(candidateRoot);
  assert.equal(await realpath(root), root, 'SALAH root symlink or path alias');
  const candidateGit = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  assert.equal(await realpath(candidateGit('rev-parse', '--show-toplevel')), root,
    'Candidate path is not the SALAH repository root');
  assert.equal(candidateGit('remote', 'get-url', 'origin'), SALAH_REMOTE, 'SALAH candidate remote mismatch');
  let cursor = root;
  const components = relative.split('/');
  for (let index = 0; index < components.length; index++) {
    cursor = path.join(cursor, components[index]);
    const info = await lstat(cursor);
    assert.ok(!info.isSymbolicLink(), 'Symlinked G1 path component');
    assert.ok(index === components.length - 1 ? info.isFile() : info.isDirectory(),
      'Non-regular G1 verifier path component');
  }
  assert.equal(path.relative(root, cursor), relative, 'G1 verifier path escapes SALAH root');
  assert.equal(await realpath(cursor), cursor, 'G1 verifier path resolves through an alias');
  return { root, file: cursor };
}
function defaultVerifierRunner(file, candidateRoot) {
  // No candidate-controlled arguments, Node preload variables, shell, Vite, APK tools, or Git.
  const result = spawnSync(process.execPath, [file], { cwd: candidateRoot, env: {}, encoding: 'utf8',
    shell: false, timeout: 120000, maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  return { exitCode: result.status, stdout: result.stdout, stderr: result.stderr };
}

/** G1 verifies only source-verifier identity. It never grants application or release authority.
 * runner is an isolated test seam; the CLI always uses defaultVerifierRunner.
 */
export async function verifyG1({ root = ROOT, candidateRoot, now = Date.now(), runner } = {}) {
  const g0 = await verifyG0({ root, now });
  const governanceRoot = g0.governance.root;
  const policy = validatePolicy(parseExact(await readFile(path.join(governanceRoot, POLICY_PATH), 'utf8'),
    true, 'Policy'));
  const { latest, rows } = await readRegister(governanceRoot, policy);
  assert.ok(![...latest.values()].some(row => row.kind === OWNER_RISK_PIN_KIND && row.state === 'ACTIVE'),
    'Historical G1 pin superseded by owner-risk successor');
  const decisions = [...latest.values()].filter(row => row.kind === G1_KIND);
  const active = decisions.filter(row => row.state === 'ACTIVE');
  assert.ok(active.length <= 1, 'Duplicate/conflicting active G1 pins');
  if (active.length === 0) return { schemaVersion: 1, result: 'G1_PIN_NOT_ACTIVE',
    authority: 'NONE', runtimeAuthority: false, productionAuthorized: false,
    governance: g0.governance, registerRevision: policy.revisions.register };
  const selected = active[0];
  const terminal = new Set(['REJECTED', 'REVOKED', 'EXPIRED', 'ROLLED_BACK']);
  const deniedHashes = new Set([G1_REJECTED_SHA,
    ...rows.filter(row => row.kind === G1_KIND && terminal.has(row.state)).map(row => row.verifierSha256)]);
  assert.ok(!deniedHashes.has(selected.verifierSha256), 'Rejected/revoked/expired verifier SHA');
  const approved = decisions.filter(row => row.approvalRevision !== null);
  assert.equal(selected.approvalRevision, Math.max(...approved.map(row => row.approvalRevision)),
    'Superseded G1 pin cannot remain active');
  const approval = rows.find(row => row.kind === G1_KIND && row.amendmentId === selected.amendmentId &&
    row.registerRevision === selected.approvalRevision);
  assert.equal(approval?.state, 'FINAL_BYTES_APPROVED', 'Missing exact owner approval transition');
  assert.equal(approval.decisionId, selected.approvalDecisionId, 'Owner approval decision changed');
  assert.equal(approval.decidedAtUtc, selected.approvedAtUtc, 'Owner approval timestamp changed');
  assert.ok(Date.parse(selected.approvedAtUtc) <= now && Date.parse(selected.decidedAtUtc) <= now,
    'G1 approval is not yet effective');
  assert.ok(selected.expiresAtUtc === null || Date.parse(selected.expiresAtUtc) > now, 'G1 pin expired');
  assert.ok(Number.isSafeInteger(policy.revisions.governance) && policy.revisions.governance > 0,
    'G1 governance revision not active');
  const git = (...args) => execFileSync('git', args, { cwd: governanceRoot, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  const head = git('rev-parse', '--verify', 'HEAD');
  assert.match(head, GIT_SHA, 'Governance HEAD is unborn');
  assert.equal(git('status', '--porcelain', '--untracked-files=all'), '', 'Dirty governance checkout');
  const base = selected.governanceBaseCommit;
  assert.equal(git('rev-parse', '--verify', `${base}^{commit}`), base, 'G1 governance base commit unavailable');
  git('merge-base', '--is-ancestor', base, head);
  assert.notEqual(base, head, 'G1 decision must follow its governance base commit');
  for (const file of [POLICY_PATH, REGISTER_PATH, BOOTSTRAP_PATH]) {
    const disk = await readFile(path.join(governanceRoot, file));
    const committed = execFileSync('git', ['show', `HEAD:${file}`], { cwd: governanceRoot,
      stdio: ['ignore', 'pipe', 'pipe'] });
    assert.deepEqual(disk, committed, `Uncommitted G1 governance bytes: ${file}`);
  }
  const candidate = await literalRegularFile(candidateRoot, selected.verifierPath);
  const bytes = await readFile(candidate.file);
  const actualSha256 = digest(bytes);
  assert.notEqual(actualSha256, G1_REJECTED_SHA, 'Previously rejected verifier bytes');
  assert.equal(actualSha256, selected.verifierSha256, 'Candidate verifier SHA differs from owner approval');
  validateVerifierMetadata(bytes, selected);
  // Repeat the byte check immediately before execution; a concurrent filesystem swap is
  // outside this static guarantee and must not be claimed as protected by G1.
  assert.equal(digest(await readFile(candidate.file)), selected.verifierSha256,
    'Candidate verifier changed before execution');
  const execution = await (runner || defaultVerifierRunner)(candidate.file, candidate.root);
  assert.ok(execution && Number.isInteger(execution.exitCode), 'Invalid verifier execution result');
  return { schemaVersion: 1, result: 'PIN_VERIFIED', authority: 'G1_SOURCE_VERIFIER_IDENTITY_ONLY',
    runtimeAuthority: false, productionAuthorized: false, executionScope: G1_SCOPE,
    governance: { ...g0.governance, head, baseCommit: base, revision: policy.revisions.governance },
    registerRevision: policy.revisions.register, approvalRevision: selected.approvalRevision,
    approvalDecisionId: selected.approvalDecisionId, approvedAtUtc: selected.approvedAtUtc,
    verifier: { path: selected.verifierPath, sha256: actualSha256,
      mappingVersion: selected.mappingVersion, mappingDigest: selected.mappingDigest,
      controlledOnlySha256: selected.controlledOnlySha256 },
    sourceVerification: { exitCode: execution.exitCode, stdout: execution.stdout, stderr: execution.stderr },
    evidenceMode: runner ? 'ISOLATED_TEST_RUNNER' : 'LOCAL_BOOTSTRAP' };
}

/** A successor is usable only after the independently recorded governance transition.
 * This is an owner-risk acceptance, never an independent security review or runtime grant.
 */
export async function verifyOwnerRiskPin({ root = ROOT, candidateRoot, packetPath,
  now = Date.now(), runner } = {}) {
  const transition = await verifyOwnerTransition({ root, packetPath });
  assert.equal(transition.result, 'OWNER_TRANSITION_RECORDED',
    'Owner-risk pin requires a committed, packet-bound trust transition');
  const governanceRoot = (await verifyG0({ root, now })).governance.root;
  const policy = validatePolicy(parseExact(await readFile(path.join(governanceRoot, POLICY_PATH), 'utf8'),
    true, 'Policy'));
  const { latest, rows } = await readRegister(governanceRoot, policy);
  const pins = [...latest.values()].filter(row => row.kind === OWNER_RISK_PIN_KIND);
  const active = pins.filter(row => row.state === 'ACTIVE');
  assert.equal(active.length, 1, 'Exactly one active owner-risk successor pin required');
  const selected = active[0];
  assert.equal(selected.transitionDecisionId, transition.decisionId);
  assert.equal(selected.packetSha256, transition.packetSha256);
  assert.ok(Date.parse(selected.approvedAtUtc) <= now && Date.parse(selected.decidedAtUtc) <= now,
    'Owner-risk pin not yet effective');
  const approval = rows.find(row => row.kind === OWNER_RISK_PIN_KIND &&
    row.amendmentId === selected.amendmentId && row.decisionId === selected.approvalDecisionId);
  assert.equal(approval?.state, 'FINAL_BYTES_APPROVED', 'Owner-risk final-byte approval missing');
  const denied = rows.some(row => row.kind === OWNER_RISK_PIN_KIND &&
    ['REJECTED', 'REVOKED', 'EXPIRED'].includes(row.state) &&
    row.verifierSha256 === selected.verifierSha256);
  assert.equal(denied, false, 'Denied successor verifier SHA');
  const candidate = await literalRegularFile(candidateRoot, selected.verifierPath);
  const bytes = await readFile(candidate.file);
  assert.equal(digest(bytes), selected.verifierSha256, 'Unapproved successor verifier bytes');
  validateVerifierMetadata(bytes, selected);
  assert.equal(digest(await readFile(candidate.file)), selected.verifierSha256,
    'Successor verifier changed before execution');
  const execution = await (runner || defaultVerifierRunner)(candidate.file, candidate.root);
  assert.ok(execution && Number.isInteger(execution.exitCode), 'Invalid successor execution result');
  return { schemaVersion: 1, result: 'OWNER_RISK_PIN_VERIFIED',
    authority: 'SOLE_PROJECT_OWNER_RISK_ACCEPTED_SOURCE_ONLY',
    independentReview: 'UNAVAILABLE_NOT_PERFORMED', runtimeAuthority: false,
    productionAuthorized: false, executionScope: G1_SCOPE, governanceHead: transition.governanceHead,
    transitionDecisionId: transition.decisionId, approvalDecisionId: selected.approvalDecisionId,
    verifier: { path: selected.verifierPath, sha256: selected.verifierSha256 },
    sourceVerification: execution, evidenceMode: runner ? 'ISOLATED_TEST_RUNNER' : 'LOCAL_BOOTSTRAP' };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length === 2) process.stdout.write(JSON.stringify(await verifyG0()) + '\n');
    else if (process.argv[2] === '--owner-transition') {
      assert.equal(process.argv.length, 4, 'Owner transition requires one absolute packet path');
      const result = await verifyOwnerTransition({ packetPath: process.argv[3] });
      process.stdout.write(JSON.stringify(result) + '\n');
      if (result.result !== 'OWNER_TRANSITION_RECORDED') process.exitCode = 1;
    }
    else if (process.argv[2] === '--owner-risk-candidate') {
      assert.equal(process.argv.length, 5, 'Owner-risk check requires packet and SALAH root');
      const result = await verifyOwnerRiskPin({ packetPath: process.argv[3], candidateRoot: process.argv[4] });
      process.stdout.write(JSON.stringify(result) + '\n');
      if (result.sourceVerification.exitCode !== 0) process.exitCode = 1;
    }
    else {
      assert.equal(process.argv.length, 4, 'Only --g1-candidate with one absolute path is supported');
      assert.equal(process.argv[2], '--g1-candidate', 'Unknown G1 option');
      const result = await verifyG1({ candidateRoot: process.argv[3] });
      process.stdout.write(JSON.stringify(result) + '\n');
      if (result.result !== 'PIN_VERIFIED' || result.sourceVerification.exitCode !== 0) process.exitCode = 1;
    }
  } catch (error) {
    process.stderr.write(JSON.stringify({ schemaVersion: 1, mode: 'DIAGNOSTIC', authoritative: false,
      result: 'FAIL_CLOSED', authority: 'NONE', error: error.message }) + '\n');
    process.exitCode = 1;
  }
}
