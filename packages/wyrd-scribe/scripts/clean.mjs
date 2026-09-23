// Removes the build output so `tsc` never emits over a stale tree — a deleted or renamed
// source would otherwise leave its old .js behind for `npm test` to run and pass against.
//
// ⚠ THE SCRIBE NEEDS THIS FOR THE SAME REASON THE READER DOES, and it acquired the need in the
// same commit as its first test: `test/span.test.js` imports `../dist/span.js`, so deleting
// `src/span.ts` would leave a green suite exercising a file that is no longer built from
// anything. The Reader has carried this script since it had a suite; the Scribe had a build
// script and no suite, so it did not.
//
// Node's own fs rather than rimraf, because this project carries no dependency it can avoid.
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

for (const target of ['dist', 'tsconfig.tsbuildinfo']) {
    rmSync(path.join(pkgRoot, target), { recursive: true, force: true });
}

// ⚠⚠ AND THE REFERENCED FENCE'S BUILD INFO — same reason as the Reader's clean, same fix.
// `tsc -b` decides a referenced project is current from source and build-info TIMESTAMPS and never
// hashes the emitted JS, so an interrupted mutation run leaves mutated fence code that the next
// build reports as up to date. This package consumes the fence too, so it needs the same
// invalidation; a fix applied at one call site is a claim that one is the whole set.
rmSync(path.join(pkgRoot, '..', 'wyrd-fence', 'dist', 'tsconfig.tsbuildinfo'), { force: true });
