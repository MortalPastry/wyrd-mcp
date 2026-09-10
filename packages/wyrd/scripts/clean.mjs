// Removes the build output so `tsc` never emits over a stale tree — a deleted or renamed
// source would otherwise leave its old .js behind for `npm test` to run and pass against.
// Node's own fs rather than rimraf, because this project carries no dependency it can avoid.
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

for (const target of ['dist', 'tsconfig.tsbuildinfo']) {
    rmSync(path.join(repoRoot, target), { recursive: true, force: true });
}

/**
 * ⚠⚠ AND THE REFERENCED FENCE'S BUILD INFO, WHICH IS THE ONE THIS PACKAGE CANNOT REBUILD ITSELF.
 *
 * `tsc -b` decides a referenced project is up to date from its SOURCE and BUILD-INFO timestamps.
 * It never hashes the emitted JavaScript. The mutation harness writes directly into
 * `wyrd-fence/dist/fsgate.js`, so an **interrupted** mutation run — Ctrl-C, a crash, a killed
 * process — leaves MUTATED SECURITY CODE on disk that the next `tsc -b` reports as up to date and
 * every subsequent test, mutation and release run then consumes. Verified by a code-gate lens with
 * `tsc -b --dry --verbose`: the fence read as current while its `fsgate.js` had been rewritten
 * after the build.
 *
 * Deleting the fence's build info is the minimal correct fix: it forces a re-emit from source on
 * the next build without removing the `dist` tree mid-graph. Removing only OUR output would leave
 * the stale fence in place, which is the case that actually matters — this package's own staleness
 * is already structurally handled by the line above.
 */
rmSync(path.join(repoRoot, '..', 'wyrd-fence', 'dist', 'tsconfig.tsbuildinfo'), { force: true });
