import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Go's ./... must not accidentally discover Go sources shipped in npm tooling.
// This marks only generated node_modules as a separate module; npm audit still
// scans its entire locked dependency graph. No application package is excluded.
export async function isolateNodeModules(directory) {
  await writeFile(resolve(directory, 'go.mod'), 'module mandatary.invalid/npm-dependencies\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await isolateNodeModules(resolve('node_modules'));
}
