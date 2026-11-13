import type { NavItem } from '../../ui';

/**
 * Document routes the management screens expect (P1.17.1). Like every P1.16 route they are EXACT paths served by an allowlist in
 * web/assets.go (D-ROUTE-1): there is no wildcard fallback, so each one must be added there on purpose (P1.17.2 owns that).
 */
export const POLICY_ROUTES = {
  rules: '/policy',
  users: '/policy/users',
  groups: '/policy/groups',
  agents: '/policy/agents',
} as const;

/** Where the P1.16 Agent tokens page lives. The management screens only ever link to it. */
export const AGENT_TOKENS_ROUTE = '/agents';

export type PolicyPageId = 'policy-rules' | 'policy-users' | 'policy-groups' | 'policy-agents';

/**
 * The "Policy" group of the admin shell. A container adds these items ONLY for a session whose view says it is the administrator
 * (as P1.16's navFor does for "Agents"). That is a convenience: the server refuses every one of these routes' API calls for anyone
 * else, so hiding the links never protects anything and showing them to the wrong person exposes nothing.
 *
 * P1.16's existing item is labelled "Agents" and leads to credentials. With an "Agents" item in this group too, two entries would
 * share a name, so the integration renames that one "Agent tokens" (see the contract doc §4).
 */
export const POLICY_NAV: readonly NavItem[] = [
  { id: 'policy-rules', label: 'Rules', href: POLICY_ROUTES.rules, icon: 'list', group: 'Policy' },
  { id: 'policy-users', label: 'Users', href: POLICY_ROUTES.users, icon: 'user', group: 'Policy' },
  { id: 'policy-groups', label: 'Groups', href: POLICY_ROUTES.groups, icon: 'users', group: 'Policy' },
  { id: 'policy-agents', label: 'Agents', href: POLICY_ROUTES.agents, icon: 'bot', group: 'Policy' },
];
