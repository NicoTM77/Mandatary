// Shared by the Make shell and lightweight resource diagnostics/tests.
import { availableParallelism, totalmem } from 'node:os';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

function optional(path) {
  try { return readFileSync(path, 'utf8').trim(); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
}

export function inspectAllocation() {
  const cpuMax = optional('/sys/fs/cgroup/cpu.max');
  const memoryMax = optional('/sys/fs/cgroup/memory.max')
    ?? optional('/sys/fs/cgroup/memory/memory.limit_in_bytes');
  let cpus = availableParallelism(); // Includes the inherited affinity, not host CPU count.
  if (cpuMax && !cpuMax.startsWith('max ')) {
    const [quota, period] = cpuMax.split(/\s+/).map(Number);
    if (!(quota > 0 && period > 0)) throw new Error('BUILD_RESOURCE_ERROR: invalid cgroup CPU quota');
    cpus = Math.min(cpus, Math.max(1, Math.floor(quota / period)));
  }
  const memoryBytes = Math.min(totalmem(), memoryMax && memoryMax !== 'max' ? Number(memoryMax) : Infinity);
  return { cpus, memoryBytes, cpuMax, memoryMax };
}

export function resolveResources(env, allocation = inspectAllocation()) {
  const profile = env.MANDATARY_BUILD_PROFILE ?? 'local';
  if (!['local', 'github-ci'].includes(profile)) throw new Error(`BUILD_RESOURCE_ERROR: unknown profile ${JSON.stringify(profile)}`);
  const { cpus, memoryBytes } = allocation;
  if (!Number.isSafeInteger(cpus) || cpus < 1 || !Number.isFinite(memoryBytes) || memoryBytes <= 0) {
    throw new Error('BUILD_RESOURCE_ERROR: invalid runner allocation');
  }
  const ci = profile === 'github-ci';
  // Leave headroom for concurrent Go/compiler processes, Node and the OS.
  // These remain soft PER-PROCESS GC controls, never whole-job RSS limits.
  const roomy = ci && memoryBytes >= 6 * 1024 ** 3;
  const tiny = ci && memoryBytes < 2 * 1024 ** 3;
  const ceilings = {
    MANDATARY_GO_PROCS: Math.min(ci ? (roomy ? 4 : 2) : 2, cpus),
    MANDATARY_GO_PACKAGES: Math.min(roomy ? 2 : 1, cpus),
    MANDATARY_GO_MEMORY_MIB: roomy ? 2048 : tiny ? 384 : 768,
    MANDATARY_GO_GC: roomy ? 100 : 25,
  };
  if (tiny) ceilings.MANDATARY_GO_PROCS = 1;
  function setting(name) {
    const raw = env[name];
    if (raw === undefined || raw === '') return ceilings[name];
    if (!/^[1-9][0-9]*$/.test(raw) || !Number.isSafeInteger(Number(raw)) || Number(raw) > ceilings[name]) {
      throw new Error(`BUILD_RESOURCE_ERROR: ${name} must be an integer in 1..${ceilings[name]}`);
    }
    return Number(raw);
  }
  return {
    GOTOOLCHAIN: 'local',
    GOFLAGS: `-mod=readonly -p=${setting('MANDATARY_GO_PACKAGES')}`,
    GOMAXPROCS: String(setting('MANDATARY_GO_PROCS')),
    GOMEMLIMIT: `${setting('MANDATARY_GO_MEMORY_MIB')}MiB`,
    GOGC: String(setting('MANDATARY_GO_GC')),
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const allocation = inspectAllocation();
  console.log(JSON.stringify({ profile: process.env.MANDATARY_BUILD_PROFILE ?? 'local', allocation,
    resolved: resolveResources(process.env, allocation),
    cgroupMemoryCurrent: optional('/sys/fs/cgroup/memory.current'),
    cgroupMemoryEvents: optional('/sys/fs/cgroup/memory.events'),
  }, null, 2));
}
