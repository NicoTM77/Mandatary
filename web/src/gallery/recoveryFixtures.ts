import type { ManifestData, ManifestRow, NamedRef, RestoreReportView, SelectorDetail } from '../screens/recovery/contract';

/**
 * Synthetic data for the P1.18 gallery and presentational tests ONLY. Every name starts with "sample-", every id is a short label (never a real
 * UUID), every address would use the reserved .invalid domain, and nothing here is an archive, a credential or a token: the file the restore
 * specimens "choose" is a block of filler characters whose only use is to have a name and a size.
 */

export const SAMPLE_BACKUP_ID = 'sample-backup-0001';

/** A stand-in for a file chosen in the browser. Its content is filler, not an archive. */
export function sampleFile(name = 'sample-backup-0001-clean.json', size = 48 * 1024): File {
  return new File(['x'.repeat(size)], name, { type: 'application/json' });
}

/** A deterministic 64-hex stand-in for the service's detail digest (never a real hash of anything). */
export const sampleDigest = (kind: string, id: string): string => {
  let hex = '';
  for (const ch of `${kind}:${id}`) hex += ch.charCodeAt(0).toString(16).padStart(2, '0');
  return hex.slice(0, 64).padEnd(64, '0');
};

export const ref = (kind: NamedRef['kind'], id: string, name: string, missing = false): NamedRef => ({ kind, id, name: missing ? id : name, missing });
export const selector = (over: Partial<SelectorDetail> & Pick<SelectorDetail, 'id' | 'containerName'>): SelectorDetail => ({
  nameType: 'exact',
  composeProject: '',
  composeService: '',
  imagePattern: '',
  pinnedContainerId: '',
  pinnedImageDigest: '',
  ...over,
});
export const localEndpoint = ref('endpoint', 'ep-local', 'sample-local');

const row = (r: Partial<ManifestRow> & Pick<ManifestRow, 'kind' | 'id' | 'label'>): ManifestRow => ({
  origin: 'imported',
  sourceState: 'active',
  decision: 'pending',
  approvable: true,
  blockedReason: null,
  needs: 'approval',
  comparison: { kind: 'none' },
  detail: null,
  digest: sampleDigest(r.kind, r.id),
  ...r,
});

export const manifestItems: readonly ManifestRow[] = [
  row({ kind: 'endpoint', id: 'ep-local', label: 'sample-local-endpoint' }),
  row({ kind: 'user', id: 'u-restored', label: 'sample-restored', needs: 'credential_enrollment', comparison: { kind: 'mfa', imported: 'optional', effective: 'required', compromised: false } }),
  row({ kind: 'user', id: 'u-risky', label: 'sample-risky', needs: 'credential_enrollment', sourceState: 'disabled', approvable: false, blockedReason: 'compromised', comparison: { kind: 'mfa', imported: 'required', effective: 'required', compromised: true } }),
  row({ kind: 'user', id: 'u-local-only', label: 'sample-local-only', origin: 'local_retained', sourceState: null, needs: 'credential_enrollment' }),
  row({ kind: 'user', id: 'u-sam', label: 'sample-sam', decision: 'approved', needs: 'credential_enrollment' }),
  row({ kind: 'group', id: 'g-ops', label: 'sample-ops' }),
  row({ kind: 'agent', id: 'a-ci', label: 'sample-ci-runner', needs: 'token_reissue' }),
  row({ kind: 'agent', id: 'a-billing', label: 'sample-billing-bot', decision: 'approved', needs: 'token_reissue' }),
  row({ kind: 'user_membership', id: 'u-restored:g-ops', label: 'sample-restored in sample-ops', detail: { kind: 'membership', member: ref('user', 'u-restored', 'sample-restored'), group: ref('group', 'g-ops', 'sample-ops') } }),
  row({ kind: 'agent_membership', id: 'a-ci:g-ops', label: 'sample-ci-runner in sample-ops', detail: { kind: 'membership', member: ref('agent', 'a-ci', 'sample-ci-runner'), group: ref('group', 'g-ops', 'sample-ops') } }),
  row({
    kind: 'policy',
    id: 'p-logs',
    label: 'ALLOW container:logs',
    comparison: { kind: 'rule', imported: 'allow', effective: 'allow', localDenyKept: false },
    detail: { kind: 'rule', effect: 'allow', operation: 'container:logs', subject: ref('group', 'g-ops', 'sample-ops'), endpoint: localEndpoint, selector: selector({ id: 'sel-web', containerName: 'sample-web' }), logTailMax: 500, stopTimeoutMax: null },
  }),
  row({
    kind: 'policy',
    id: 'p-stop',
    label: 'ALLOW container:stop',
    comparison: { kind: 'rule', imported: 'allow', effective: 'deny', localDenyKept: true },
    detail: {
      kind: 'rule',
      effect: 'deny',
      operation: 'container:stop',
      subject: ref('agent', 'a-ci', 'sample-ci-runner'),
      endpoint: localEndpoint,
      selector: selector({ id: 'sel-batch', containerName: 'sample-batch-*', nameType: 'glob', composeProject: 'sample-platform', composeService: 'batch' }),
      logTailMax: null,
      stopTimeoutMax: 30,
    },
  }),
  row({ kind: 'role', id: 'r-admin', label: 'administrator role of sample-admin', approvable: false, blockedReason: 'single_administrator', needs: 'none_in_phase_1' }),
  row({ kind: 'address', id: 'addr-1', label: 'notification address of user sample-restored', sourceState: null, approvable: false, blockedReason: 'needs_reverification', needs: 'reverification' }),
];

export const manifest: ManifestData = {
  backupId: SAMPLE_BACKUP_ID,
  mode: 'full',
  provenance: 'authenticated',
  initiator: 'admin',
  restoredAt: 1794600000,
  credentialsStripped: false,
  inactiveCredentials: { authenticators: 3, agentCredentials: 2 },
  items: manifestItems,
};

export const manifestClean: ManifestData = { ...manifest, mode: 'clean', provenance: 'unauthenticated', credentialsStripped: true, inactiveCredentials: { authenticators: 0, agentCredentials: 0 } };

/** Everything approved except what the service never approves here. */
export const manifestApproved: ManifestData = { ...manifest, items: manifestItems.map((item) => (item.approvable ? { ...item, decision: 'approved' as const } : item)) };

export const reportFull: RestoreReportView = {
  backupId: SAMPLE_BACKUP_ID,
  mode: 'full',
  provenance: 'authenticated',
  initiator: 'admin',
  imported: { endpoint: 1, user: 3, group: 1, agent: 2, user_membership: 1, agent_membership: 1, policy: 2, role: 1, address: 1 },
  retainedLocal: { user: 1, policy: 1 },
  inactiveCredentials: { authenticators: 3, agent_credentials: 2 },
  credentialsStripped: false,
  excluded: ['sessions', 'rate_limit_state', 'usage_statistics', 'setup_and_recovery_state', 'security_notices', 'control_generations_and_quarantine', 'master_key_and_installation_binding'],
};

export const reportClean: RestoreReportView = { ...reportFull, mode: 'clean', provenance: 'unauthenticated', inactiveCredentials: {}, credentialsStripped: true, retainedLocal: {} };
