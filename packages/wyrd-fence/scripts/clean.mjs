// Removes the build output so `tsc` never emits over a stale tree — a deleted or renamed
// source would otherwise leave its old .js behind for a consumer to run and pass against.
//
// ⚠ THE BUILD INFO LIVES INSIDE `dist`, so removing the directory removes it too. In build mode
// (`tsc -b`) a surviving `.tsbuildinfo` beside a deleted output tree is how the compiler decides
// a project is up to date and skips emitting the files that are no longer there.
import { rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

for (const target of ['dist', 'tsconfig.tsbuildinfo']) {
    rmSync(path.join(repoRoot, target), { recursive: true, force: true });
}
