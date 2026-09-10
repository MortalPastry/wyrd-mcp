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
 *
 * ⚠⚠ NOTHING CALLS THIS AUTOMATICALLY AND NOTHING MAY. It is absent from `prebuild`, from `test`,
 * from `test:portable`, from `mutate` and from the release gate, deliberately — a regenerate step
 * inside the thing it grades erases the oracle in the one run where it mattered. It is invoked by
 * a human, by name, having read a diff.
 *
 * ⚠ FENCE-LOCAL SINCE 2026-09-01. It used to live in `wyrd-mcp` and reach this package through
 * `createRequire(...).resolve('wyrd-fence/package.json')`, because the arm it serves lived there
 * too. Both moved together, which is the point: a regenerator and the arm it feeds must read the
 * same file, and the cheapest way to guarantee that is for both to resolve it the same way in the
 * same package.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { extractDeclarationApi } from '../test/declarations.mjs';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ⚠ THE DECLARED `types`, NOT `dist/fsgate.d.ts` SPELLED OUT. This regenerator must read the SAME
// file E12 asserts against or the two drift, and the "documented recovery" then writes a baseline
// for a file nobody checks.
const manifest = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
const declaredTypes = manifest.types ?? manifest.exports?.['.']?.types;
if (!declaredTypes) {
    console.error('⛔ wyrd-fence declares no `types` entry — nothing to baseline.');
    process.exit(1);
}
const built = path.resolve(pkgRoot, declaredTypes);
const baseline = path.join(pkgRoot, 'test', 'fsgate.d.ts.baseline');

if (!fs.existsSync(built)) {
    console.error(`⛔ ${path.relative(pkgRoot, built)} does not exist — run \`npm run build\` first.`);
    process.exit(1);
}

fs.writeFileSync(baseline, extractDeclarationApi(fs.readFileSync(built, 'utf8')));
console.log(`✔ wrote ${path.relative(pkgRoot, baseline)} — now READ IT before committing.`);
