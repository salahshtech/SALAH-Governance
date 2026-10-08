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
    'g1VerifierPin', 'authority', 'failClosed'], 'Policy');
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
  assert.equal(policy.revisions.bootstrap, 2, 'Unsupported bootstrap revision');
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
  assert.deepEqual(policy.authority, { approver: 'PROJECT_OWNER', localMode: 'DIAGNOSTIC_ONLY',
    authoritativeMode: 'UNAVAILABLE_UNTIL_G1_G2_G3' });
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
    row.governanceRevision === policy.revisions.governance, 'Wrong G1 governance revision');
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
    else assert.fail('Unknown register decision kind');
    latest.set(row.amendmentId, row);
    rows.push(row);
  }
  assert.equal(policy.revisions.register, lines.length - 1, 'Stale register or policy revision');
  return { latest, rows, decisionCount: rows.length };
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length === 2) process.stdout.write(JSON.stringify(await verifyG0()) + '\n');
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
