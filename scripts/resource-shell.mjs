#!/usr/bin/env node
// One environment boundary for every Make recipe, including recursive/nested tools.
import { spawnSync } from 'node:child_process';
import { resolveResources } from './resource-profile.mjs';

const env = { ...process.env, ...resolveResources(process.env) };
const result = spawnSync('/bin/bash', process.argv.slice(2), { env, stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
