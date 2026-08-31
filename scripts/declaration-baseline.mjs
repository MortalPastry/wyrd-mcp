#!/usr/bin/env node
/**
 * Regenerates `test/fsgate.d.ts.baseline` from the CURRENT build.
 *
 * ⚠⚠ RUNNING THIS IS NOT A FIX. The baseline is the ORACLE for `E12-declaration-inventory`, and it
 * is an oracle only for as long as a human reads what changed before it moves. Regenerating in
 * response to a red E12 turns the check into a tautology — the arm would then compare the built
 * declarations against themselves and could never fail again.
 *
 * The intended sequence is: E12 goes red → read the diff it printed → decide the public API change
 * is intended (and that the version bump reflects it) → run this → commit the baseline as part of
 * the same change.
 *
 *   npm run build && node scripts/declaration-baseline.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { extractDeclarationApi } from '../test/declarations.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const built = path.join(repo, 'dist', 'fsgate.d.ts');
const baseline = path.join(repo, 'test', 'fsgate.d.ts.baseline');

if (!fs.existsSync(built)) {
    console.error(`⛔ ${path.relative(repo, built)} does not exist — run \`npm run build\` first.`);
    process.exit(1);
}

fs.writeFileSync(baseline, extractDeclarationApi(fs.readFileSync(built, 'utf8')));
console.log(`✔ wrote ${path.relative(repo, baseline)} — now READ IT before committing.`);
