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
