#!/usr/bin/env node
/**
 * THE FENCE'S MUTATION MATRIX, EXECUTED.
 *
 * Each row names a mutation of this package's BUILT output and the arm that must go red. A table
 * is not evidence: this script applies each mutation to `dist/fsgate.js`, runs the whole fence
 * suite, and records which named tests actually failed.
 *
 *   npm run build && npm run mutate            all rows
 *   npm run mutate -- --only M8,M13            selected rows
 *   npm run mutate -- --json                   machine-readable record
 *
 * ⚠ It edits `dist/` in place and restores it in a `finally`, verifying the restore
 *   byte-for-byte. It never touches `src/`. Run `npm run build` afterwards if in doubt.
 *
 * ⚠ A row whose status is EQUIVALENT or NO-KILLING-ARM is the honest output, not a gap to be
 *   papered over by weakening an arm.
 *
 * ⚠⚠ THESE 66 ROWS ARRIVED FROM `wyrd-mcp/scripts/mutate.mjs` ON 2026-09-01 AND KEPT THEIR IDS.
 * Every one of them patched THIS package's built file from inside a consumer, so the consumer's
 * matrix was the only measurement of this fence's adequacy. The 3 rows that genuinely measure the
 * Reader — `M25` (main), `M27` (index), `M44` (server) — stayed there. The ids are the key the
 * plan's §5a table, the relocation contract and every `--only` invocation join on, so renumbering
 * them would have broken the join for a cosmetic gain.
 *
 * ⚠⚠ USE THIS, NOT A HAND-ROLLED RUN THAT SHELLS OUT TO `npm test`. `test` is
 * `npm run build && node scripts/run-tests.mjs`, and the build recompiles `dist/` from `src/`,
 * ERASING a dist-patched mutant before the suite sees it — so every mutant SURVIVES and reads as a
 * weak guard rather than as a dead instrument. Three false survivors were measured that way on
 * 2026-08-31. This script builds nothing: it drives `scripts/run-tests.mjs` DIRECTLY.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { loadContract, verifyMutationRows, verifyMutationResults, refuse } from '../../wyrd/scripts/verify-relocation-contract.mjs';

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * ⚠⚠ THIS ENTRY IS LOAD-BEARING FOR THE WHOLE RUN. Its value is read by an unconditional
 * module-scope `readFileSync` below, OUTSIDE the try/finally — so a wrong path here does not fail
 * one row, it throws ENOENT before a single row runs: no rows, no score, no restore.
 *
 * ⚠ TAKEN FROM THIS PACKAGE'S OWN DECLARED ENTRY POINT rather than spelled `dist/fsgate.js`. The
 * Reader's matrix resolves the fence BY PACKAGE NAME so it cannot acquire a deep-path coupling to
 * a sibling's layout; the analogue inside the package is to read the layout from the manifest that
 * declares it, so that a change to `main` or `exports` moves the mutation target with it instead
 * of leaving this file patching a stale path in the one place where a stale path costs the entire
 * measurement.
 */
const manifest = JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8'));
const declaredMain = manifest.main ?? manifest.exports?.['.']?.default;
if (!declaredMain) {
    console.error('⛔ wyrd-fence declares no main/exports default — there is nothing to mutate.');
    process.exit(1);
}
const FILES = {
    fsgate: path.resolve(pkg, declaredMain),
    preflight: path.join(pkg, 'scripts', 'preflight.mjs'),
    readme: path.join(pkg, 'README.md'),
    attributes: path.resolve(pkg, '..', '..', '.gitattributes')
};

/**
 * `dist/` can be regenerated after a killed run. These product/test-support files cannot:
 * a killed process never enters `finally`, so retain their pristine bytes on disk for `--restore`.
 */
const RECOVERABLE = Object.freeze(['preflight', 'readme', 'attributes']);

/**
 * ⚠⚠ PER-CHECKOUT, AND IT WAS A FIXED GLOBAL PATH UNTIL 2026-09-04. `os.tmpdir()` alone gave every
 * checkout of this repo the SAME backup directory, so a run in one left files a run in another
 * refused to overwrite — and the refusal reads as *"the tree is damaged"* rather than as *"you have
 * two checkouts."* Measured: a dispatched lane in an isolated worktree could not start the matrix
 * at all, because a main-tree run had left a `README.md` there that the worktree's copy no longer
 * matched. A full dispatch was spent discovering it.
 *
 * ⚠ THE REFUSAL IT TRIPPED IS CORRECT AND IS NOT WHAT CHANGED. That guard is the only thing
 * standing between a stale backup and a silently wrong `--restore`; softening it would trade a
 * confusing message for a corrupted tree. The defect was the SHARED path, so the path is what moved.
 *
 * ⚠ IT STAYS OUTSIDE THE CHECKOUT, deliberately. These bytes exist to survive a KILLED process —
 * one that never reaches `finally` — so they cannot live anywhere `dist/`-cleaning or a `git clean`
 * could take them. The hash of the package's absolute path keeps it outside the tree while making
 * it unique per checkout, which is both properties at once.
 */
const BACKUP_DIR = path.join(
    os.tmpdir(),
    `wyrd-fence-mutate-backup-${createHash('sha256').update(pkg).digest('hex').slice(0, 12)}`
);
const RESTORE_COMMAND = 'node scripts/mutate.mjs --restore';

function backupPathFor(key) {
    return path.join(BACKUP_DIR, path.basename(FILES[key]));
}

if (process.argv.slice(2).includes('--restore')) {
    if (!fs.existsSync(BACKUP_DIR)) {
        console.error(`⛔ no backup directory at ${BACKUP_DIR} — nothing to restore from.`);
        process.exit(1);
    }
    const missing = RECOVERABLE.filter(key => !fs.existsSync(backupPathFor(key)));
    if (missing.length) {
        console.error(`⛔ backup directory ${BACKUP_DIR} has no copy of: ${missing.map(key => `${key} (${backupPathFor(key)})`).join(', ')}`);
        process.exit(1);
    }
    for (const key of RECOVERABLE) {
        const backup = fs.readFileSync(backupPathFor(key));
        fs.writeFileSync(FILES[key], backup);
        if (!fs.readFileSync(FILES[key]).equals(backup)) {
            console.error(`⛔ ${FILES[key]} still differs from its backup ${backupPathFor(key)} after being rewritten.`);
            process.exit(1);
        }
        console.log(`[restore] ${FILES[key]} restored byte-for-byte from ${backupPathFor(key)}`);
    }
    process.exit(0);
}

// ⚠ THE SUITE IS DRIVEN DIRECTLY, WITH NO BUILD IN FRONT OF IT — see the header. The mutation
// record must measure exactly what `npm test` measures, so it goes through the same runner,
// including its zero-skipped and inventory assertions.
const SUITE = [path.join('scripts', 'run-tests.mjs')];
const SUITE_TIMEOUT_MS = 240_000;

// The literal backslash-zero escape as it appears in the compiled template literals.
const NUL = String.fromCharCode(92) + 'u0000';

/**
 * Every row carries the EXACT transformation. `plan` is what the design claims kills it; the run
 * records what actually did. Where they differ, that is the finding.
 */
const ROWS = [
    { id: 'M1', file: 'fsgate', what: 'delete the absolute-request rejection', plan: 'A2',
        from: 'if (path.isAbsolute(request))', to: 'if (false && path.isAbsolute(request))' },
    { id: 'M2', file: 'fsgate', what: 'delete the drive-relative regex', plan: 'A3',
        from: 'if (DRIVE_RELATIVE.test(request)) {', to: 'if (false) {' },
    { id: 'M3', file: 'fsgate', what: 'delete the null-byte rejection', plan: 'A5',
        from: "if (request.includes('\\0'))", to: 'if (false)' },
    { id: 'M4', file: 'fsgate', what: 'path.join -> path.resolve in stage (a)', plan: 'A3',
        from: 'path.normalize(path.join(root, request))', to: 'path.normalize(path.resolve(root, request))' },
    { id: 'M4+M2', file: 'fsgate', what: 'path.resolve WITH the drive-relative guard also deleted', plan: '(added)',
        edits: [['if (DRIVE_RELATIVE.test(request)) {', 'if (false) {'],
            ['path.normalize(path.join(root, request))', 'path.normalize(path.resolve(root, request))']] },
    { id: 'M5', file: 'fsgate', what: 'delete CLAMPED detection', plan: 'A10 (reason assertion only)',
        from: "return refuse('CLAMPED', 'the path climbs past the root of the volume');", to: '{ }' },
    { id: 'M6', file: 'fsgate', what: "delete the `..` + sep prefix clause", plan: 'A1',
        from: "if (rel.startsWith(`..${path.sep}`))\n        return false;", to: 'if (false)\n        return false;' },
    { id: 'M7', file: 'fsgate', what: "delete the exact-`..` clause", plan: 'A6',
        from: "if (rel === '..')\n        return false;", to: 'if (false)\n        return false;' },
    { id: 'M8', file: 'fsgate', what: 'delete !path.isAbsolute(rel) from contains()', plan: 'A4',
        from: 'return !path.isAbsolute(rel);', to: 'return true;' },
    { id: 'M9', file: 'fsgate', what: 'delete IS_ROOT', plan: 'A7 / A8',
        from: "return refuse('IS_ROOT', 'that path is the granted folder itself');", to: '{ }' },
    { id: 'M10', file: 'fsgate', what: 'move I/O before the lexical refusal', plan: 'A1 / A2 / A3 / A4 / A5 / A6 spy assertion',
        from: 'const lexical = lexicalStage(root, request, screens);',
        to: 'try { prim.lstat(path.join(root, String(request))); } catch { }\n    const lexical = lexicalStage(root, request, screens);' },
    // ⚠ The row TEXT used to claim these swap which base is USED. They do not — they corrupt
    // the CONTAINMENT TEST for one reading while leaving the other's intact, so the walk judges
    // the traversal reading by the substituted one's containment and vice versa. Same guard,
    // different lever; M39/M40 are the rows that mutate the CHOICE itself.
    { id: 'M11a', file: 'fsgate', what: "judge the traversal reading by the SUBSTITUTED reading's containment", plan: 'A14-M / A14-T',
        from: 'const travOk = contains(root, baseTrav);', to: 'const travOk = contains(root, baseSubst);' },
    { id: 'M11b', file: 'fsgate', what: "judge the substituted reading by the TRAVERSAL reading's containment", plan: 'A14-M / A23-dsym',
        from: 'const substOk = contains(root, baseSubst);', to: 'const substOk = contains(root, baseTrav);' },
    { id: 'M39', file: 'fsgate', what: 'always take the SUBSTITUTED reading (mutates the CHOICE)', plan: '(added — the uncovered cell)',
        from: 'const base = travOk ? baseTrav : baseSubst;', to: 'const base = baseSubst;' },
    { id: 'M40', file: 'fsgate', what: 'always take the TRAVERSAL reading (mutates the CHOICE)', plan: '(added — the uncovered cell)',
        from: 'const base = travOk ? baseTrav : baseSubst;', to: 'const base = baseTrav;' },
    { id: 'M41', file: 'fsgate', what: "return a guessed branch's refusal without arbitrating (the HIGH-1 defect)", plan: '(added — veto finding)',
        from: 'if (isRefusal(walked) && !context.guessed)\n        return walked;',
        to: 'if (isRefusal(walked))\n        return walked;' },
    { id: 'M42', file: 'fsgate', what: 'never record that a guess was made', plan: '(added — veto finding)',
        from: 'if (baseTrav !== baseSubst)\n                    context.guessed = true;',
        to: 'if (false)\n                    context.guessed = true;' },
    { id: 'M43', file: 'fsgate', what: 'drop the trailing-separator fold from volumeIdentity (the UNC defect)', plan: '(added — veto finding)',
        from: "return root.endsWith('\\\\') ? root : `${root}\\\\`;", to: 'return root;' },
    // ⚠ RE-ANCHORED 2026-08-29. This row read `from: 'if (context.sawReparse || isRefusal(walked))'`
    // until the arbitration was made unconditional, and the change turned it into ANCHOR-NOT-FOUND
    // — a mutant that silently stops testing anything. Its INTENT is unchanged: skip arbitration
    // entirely and trust the walk.
    { id: 'M12', file: 'fsgate', what: 'skip the realpath arbitration (trust the walk)', plan: 'A14-M',
        from: '    if (true) {\n', to: '    if (false) {\n' },
    { id: 'M13', file: 'fsgate', what: 'walk one level only (no chain recursion at all)', plan: 'A12',
        edits: [['const resolvedTarget = walk(root, prim, base, context);', 'const resolvedTarget = base;'],
            ['                    candidate = resolvedTarget;\n                    continue;',
                '                    actual = resolvedTarget;\n                    break;']] },
    { id: 'M29', file: 'fsgate', what: 'lstat a multi-component link target OPAQUELY (regress fix 2)', plan: '(added)',
        from: 'const resolvedTarget = walk(root, prim, base, context);', to: 'const resolvedTarget = base;' },
    { id: 'M32', file: 'fsgate', what: 'compare root STRINGS instead of volume identities (the shipped defect)', plan: '(added — FOUND BY USING IT)',
        from: 'if (volumeIdentity(rawGrant) !== volumeIdentity(normalized)) {',
        to: 'if (path.parse(rawGrant).root !== path.parse(normalized).root) {' },
    { id: 'M33', file: 'fsgate', what: 'delete the volume-mangling check', plan: '(added)',
        from: 'if (volumeIdentity(rawGrant) !== volumeIdentity(normalized)) {', to: 'if (false) {' },
    { id: 'M34', file: 'fsgate', what: 'invert the volume-mangling check', plan: '(added)',
        from: 'if (volumeIdentity(rawGrant) !== volumeIdentity(normalized)) {',
        to: 'if (volumeIdentity(rawGrant) === volumeIdentity(normalized)) {' },
    { id: 'M30', file: 'fsgate', what: 'delete the root-identity re-check (all three sites)', plan: '(added)',
        replace: s => s.replaceAll('const moved = rootStillCanonical();', 'const moved = null;') },
    { id: 'M31', file: 'fsgate', what: 'invoke a primitive as a property of the table (leaks `this`)', plan: '(added — EXECUTED defect)',
        from: 'lstat: target => Reflect.apply(lstatFn, undefined, [target]),', to: 'lstat: lstatFn,' },
    { id: 'M14', file: 'fsgate', what: 'refuse every reparse point', plan: 'A13 pass / A12 pass',
        from: 'context.sawReparse = true;', to: "context.sawReparse = true; return refuse('ESCAPES', 'mutant');" },
    { id: 'M15a', file: 'fsgate', what: 'visited set keyed on the ORIGINAL request (absolute branch)', plan: 'A15 pass arm',
        from: 'const key = `A' + NUL + '${derived.toLowerCase()}' + NUL + '${index}' + NUL + '${spelled.toLowerCase()}`;',
        to: 'const key = `A' + NUL + '${spelledInit.toLowerCase()}`;' },
    { id: 'M15b', file: 'fsgate', what: 'visited set keyed on the ORIGINAL request (relative branch)', plan: '(added — was a hole)',
        from: 'const key = `R' + NUL + '${derived.toLowerCase()}`;',
        to: 'const key = `R' + NUL + '${spelledInit.toLowerCase()}`;' },
    { id: 'M16', file: 'fsgate', what: 'delete the visited set, keep only the hop limit', plan: 'A15 refusal arm',
        from: "if (context.visited.has(key))\n        return refuse('ELOOP', 'the links form a cycle');",
        to: "if (false)\n        return refuse('ELOOP', 'the links form a cycle');" },
    { id: 'M17', file: 'fsgate', what: 'delete the TERMINAL-component reparse check', plan: 'A11',
        from: 'if (!stats.isSymbolicLink()) {', to: 'if (!stats.isSymbolicLink() || index === segments.length - 1) {' },
    // ⚠ THE `plan` READ `A14` UNTIL 2026-09-02, AND THERE HAS NEVER BEEN AN ARM CALLED `A14`. The
    // §5a table this field quotes says `A14-M`; the suffix was dropped somewhere between the table
    // and the row, and nothing could notice because nothing read the field. Restored to the table's
    // own wording — not to the run's, which reddens neither `A14-M` nor `A14-T` and is the kind of
    // divergence this field exists to display.
    { id: 'M18', file: 'fsgate', what: 'delete the INTERMEDIATE-component reparse check', plan: 'A14-M',
        from: 'if (!stats.isSymbolicLink()) {', to: 'if (!stats.isSymbolicLink() || index !== segments.length - 1) {' },
    { id: 'M19', file: 'fsgate', what: 'conflate MISSING with ESCAPES', plan: 'A16-in / A16-out / A17 reason assertions',
        from: "return refuse('MISSING', `no such path in the grant: ${what}`);",
        to: "return refuse('ESCAPES', `no such path in the grant: ${what}`);" },
    ...[['ENOTDIR', 'NOT_A_DIRECTORY'], ['EISDIR', 'NOT_A_FILE'], ['EACCES', 'DENIED'],
        ['EPERM', 'DENIED'], ['ELOOP', 'ELOOP'], ['ENAMETOOLONG', 'NAME_TOO_LONG'],
        ['ERR_INVALID_ARG_VALUE', 'BAD_INPUT']].map(([code]) => ({
        id: `M20-${code}`, file: 'fsgate', what: `delete the ${code} errno mapping`, plan: 'injected-error arms',
        from: `        case '${code}':`, to: `        case '__deleted_${code}':`
    })),
    { id: 'M21', file: 'fsgate', what: 'realpathSync.native -> bare realpathSync', plan: 'startup spy',
        from: 'const _realpathNative = target => fs.realpathSync.native(target);',
        to: 'const _realpathNative = target => fs.realpathSync(target);' },
    { id: 'M22', file: 'fsgate', what: 'canonicalize more than once', plan: 'exact realpathNative count = 1',
        from: 'canonicalRoot = path.normalize(prim.realpathNative(named));',
        to: 'canonicalRoot = path.normalize(prim.realpathNative(prim.realpathNative(named)));' },
    { id: 'M23', file: 'fsgate', what: 'delete BOTH missing-root refusals', plan: 'startup grant-missing arm',
        replace: s => s.replace(/return refuse\('GRANT_MISSING'[^\n]*\n/g, '') },
    { id: 'M24', file: 'fsgate', what: 'delete BOTH not-a-directory refusals', plan: 'startup grant-is-a-file arm',
        replace: s => s.replace(/return refuse\('GRANT_NOT_A_DIRECTORY'[^\n]*\n/g, '') },
    { id: 'M26', file: 'fsgate', what: 'add a setter for the canonical root', plan: 'API-shape arm',
        from: 'return Object.freeze(gate);', to: 'gate.setRoot = () => { }; return gate;' },
    { id: 'M28', file: 'fsgate', what: 'export a raw primitive', plan: 'export-inventory arm',
        from: 'export function createFsGate(options) {',
        to: 'export const _lstat_leaked = _lstat;\nexport function createFsGate(options) {' },
    // ⚠ M45-M48 COVER THE GATE-MEDIATED SEAM (scribe spec D8), rewritten 2026-08-29 when that
    // shape was ruled. They replaced three rows mutating a resolver-returning-pathnames design whose
    // review round produced five HIGHs. Every row below corresponds to a guard that a REPRODUCED
    // escape went through — these are regression mutants, not hypotheticals.
    { id: 'M45', file: 'fsgate', what: 'drop the alternate-data-stream (colon) screen', plan: 'A39-not-filenames',
        from: "return refuse('STREAM_SYNTAX', 'the path contains a colon, which names a data stream rather than a file');",
        to: '/* mutated: stream syntax is accepted as a filename */' },
    { id: 'M46', file: 'fsgate', what: 'drop the reserved-device-name screen', plan: 'A39-not-filenames',
        from: 'if (screens.device && isReservedDeviceName(segment)) {',
        to: 'if (false && isReservedDeviceName(segment)) {' },
    { id: 'M47', file: 'fsgate', what: 'resolve the create path\'s PARENT lexically, bypassing the fence', plan: 'A40-create',
        from: 'const parent = resolveInGrant(root, prim, path.relative(root, parentSpelled), createScreens);',
        to: 'const parent = { ok: true, actual: parentSpelled, rel: path.relative(root, parentSpelled) };' },
    // ⚠⚠ M48 IS THE LOAD-BEARING ROW IN THIS WHOLE MATRIX.
    // `wx` is the single character that makes the create path refuse every object already at the
    // name — symlink, hardlink, junction, and the reparse tags this runtime cannot classify at all
    // — WITHOUT having to enumerate them. Two of those were reproduced writing outside the grant
    // under the previous design. If this mutant ever survives, the containment argument for the
    // entire write surface has silently reverted to an enumeration, and the enumeration has been
    // measured wrong four times.
    // ⚠⚠ M48 IS **NOT EQUIVALENT** — IT IS A SURVIVOR WITH NO DETERMINISTIC KILLING ARM, AND THIS
    // ROW SAID "EQUIVALENT" UNTIL BOTH ROUND-3 LENSES CORRECTED IT INDEPENDENTLY.
    //
    // The distinction is not pedantry. EQUIVALENT means the mutation cannot change behaviour, so
    // the guard could be deleted. This mutation CAN change behaviour: once the leaf probe returns
    // ENOENT, an ordinary file appearing before the open is refused by `wx` and truncated by `w`.
    // `wx` is doing real work in exactly the race window it exists for — what is missing is an arm,
    // because killing it requires winning that race deterministically.
    //
    // ⚠ THE FLAG STAYS, AND THE REASON IS NOW THE RIGHT ONE. Calling it equivalent invites a future
    // session to delete `wx` as dead weight. Do not "fix" this by weakening the probe.
    { id: 'M48', file: 'fsgate', what: 'open the create path NON-exclusively (wx -> w)', plan: 'SURVIVES — no deterministic arm, NOT equivalent; see the note above',
        from: "const _openExclusive = target => fs.openSync(target, 'wx');",
        to: "const _openExclusive = target => fs.openSync(target, 'w');" },
    // ⚠⚠ M49-M51 ARE REGRESSION MUTANTS FOR THE ROUND-2 ESCALATION. Each pins a guard whose
    // absence was MEASURED escaping, not theorised — do not weaken an arm to make one of these
    // survive.
    //
    // M49 is the sharpest lesson in this file. The leaf existence probe was DELETED in the first
    // gate-mediated draft, on the reasoning that `wx` made it redundant — and mutation testing
    // could not have caught that, because it perturbs code that exists and is structurally blind
    // to a guard that is not there. A cross-vendor escalation lens found it by reading. This row
    // exists so the guard cannot be deleted a second time silently.
    // ⚠ M49's KILL IS PORTABLE; ITS *BEHAVIOURAL COVERAGE* IS NOT, AND THE ROW SAID THE OPPOSITE
    // FOR ONE ROUND. Labelled "Windows-only" after round 3 — then `A43-probe-errors` landed, which
    // injects `lstat` failures at the leaf probe. Deleting the probe means those injections are
    // never raised and `openExclusive` is reached, so A43 goes red on EVERY platform.
    // What remains Windows-specific is the dangling-link half in A40/A41: on POSIX
    // `O_CREAT|O_EXCL` already refuses a dangling symlink leaf, so those two would not kill it
    // there. A row can be portably killed for one reason and platform-bound for another; saying
    // only the second was the error.
    { id: 'M49', file: 'fsgate', what: 'delete the leaf existence probe, leaving only wx', plan: 'A43-probe-errors (portable kill) + A40-create / A41-exists-refuses dangling-link (Windows-only)',
        from: '            prim.lstat(actual);\n            return refuse(`EXISTS`, `${path.relative(root, actual)} already exists`);'
            .replace('`EXISTS`', "'EXISTS'"),
        to: '            /* mutated: the leaf is not probed */' },
    // ⚠ THE FIRST VERSION OF M50 DID NOT REPRODUCE ITS OWN DEFECT AND SURVIVED FOR THAT REASON.
    // It shortened each `writeSync` by one byte — and the LOOP simply wrote the remainder on the
    // next pass, so the file came out whole and the arm was right to stay green. A mutant that
    // heals itself certifies the guard without testing it. The defect being pinned is the
    // SINGLE-CALL write, which is what the code actually did before the fix, so that is what this
    // now restores.
    { id: 'M50', file: 'fsgate', what: 'restore the single-call write (no loop) — the original short-write defect', plan: 'A41-exists-refuses (uninjected byte-compare)',
        from: '        const n = fs.writeSync(fd, buffer, written, buffer.length - written, written);\n        if (n <= 0)\n            break;\n        written += n;',
        to: '        written += fs.writeSync(fd, buffer, 0, Math.min(4096, buffer.length), 0);\n        break;' },
    { id: 'M51', file: 'fsgate', what: 'restore the sawReparse gate on the realpath arbitration', plan: 'META-primitives',
        from: '    if (true) {', to: '    if (context.sawReparse || isRefusal(walked)) {' },
    // ⚠ M52-M53 PIN THE TWO ROUND-3 GUARDS. Both gaps were found INDEPENDENTLY BY BOTH round-3
    // lenses, which is the strongest signal available that a hole is real rather than stylistic.
    { id: 'M52', file: 'fsgate', what: 'let EVERY leaf-probe error proceed, not only ENOENT', plan: 'A43-probe-errors',
        from: "            if (code !== 'ENOENT')\n                return mapFsError(error, path.relative(root, actual));",
        to: '            /* mutated: every probe error proceeds to the open */' },
    // ⚠⚠ M54 IS THE ROW TWO ROUNDS OF REVIEW WENT LOOKING FOR AND COULD NOT FIND. `A35-root-moved`
    // swaps the root for a junction to `evil`, whose spelling differs by far more than case — so it
    // goes red under case-folding, exact comparison and identity alike. NOTHING DISCRIMINATED THEM,
    // and a regression to `toLowerCase()` on both sides would have stayed green while re-opening the
    // escape round 3 found. `A45-root-identity` is what kills this.
    /* ⚠⚠ M54'S ANCHOR DIED WHEN F8 CLOSED, AND THE ROW IS REPOINTED RATHER THAN RETIRED
     * (2026-09-03). It used to case-fold `if (current !== root)` — the spelling comparison that
     * gated the identity check. Closing F8 made identity unconditional and DELETED that comparison
     * outright, so there is no longer a spelling test to fold and the original defect cannot be
     * expressed at all.
     *
     * The regression the row guards is unchanged in substance: deciding root sameness by NAME
     * instead of by OBJECT. So it now replaces the identity comparison with a case-folded spelling
     * comparison — exactly the pre-2026-08 behaviour the header above records as revision 1, and
     * exactly what someone "simplifying" this function would reach for. `A45-root-identity` still
     * kills it: a re-spelled root must be ACCEPTED (which a case-fold gets right by luck) and a
     * REPLACED one must refuse (which it cannot see at all). */
    /* ⚠ ITS KILLER CHANGED WITH F8, AND THE REASON IS INSTRUCTIVE: `A45-root-identity` no longer
     * catches this. A case-folded comparison still ACCEPTS a re-spelled root, which is exactly what
     * A45 asserts, so A45 passes under the mutant. What the fold cannot see is a REPLACED root —
     * and that is `A55-same-path-replacement`, which only became a detector when F8 closed. Measured
     * 2026-09-03: red set is A55 alone. */
    { id: 'M54', file: 'fsgate', what: 'restore case-folding on the root recheck', plan: 'A55-same-path-replacement',
        from: '        const identifiable = rootIdentity.ino !== 0 && now.ino !== 0 &&\n            rootIdentity.dev === now.dev && rootIdentity.ino === now.ino;',
        to: '        const identifiable = current.toLowerCase() === root.toLowerCase();' },
    { id: 'M55', file: 'fsgate', what: 'drop the stem trailing-space trim (NUL .txt survives)', plan: 'A39-not-filenames',
        from: "    const stem = (trimmed.split('.')[0] ?? '').replace(/[ ]+$/, '');",
        to: "    const stem = (trimmed.split('.')[0] ?? '');" },
    { id: 'M56', file: 'fsgate', what: 'drop the COM0/LPT0 portability entries', plan: 'A39-not-filenames',
        from: "    'COM0', 'LPT0'", to: '    /* mutated: policy entries dropped */' },
    // ⚠⚠ M53's ANCHOR WAS REPAIRED 2026-08-31, NOT REWRITTEN — and the repair is the whole lesson.
    // S1 (the retained/indeterminate write outcome) changed this guard from `refuse(...)` to
    // `writeRefuse(..., retained(...))`, which silently invalidated the anchor: the row stopped
    // APPLYING and therefore tested NOTHING, while the harness's own summary counted it apart from
    // the real survivors and told the reader exactly that. It was caught by the PARENT running the
    // matrix — the build lane had verified its five NEW rows applied and never checked whether its
    // edits broke an OLD one, which is a check that validates one side.
    { id: 'M53', file: 'fsgate', what: 'report a short write as a success with a reduced count', plan: 'A44-short-write',
        from: '            if (written !== bytes.length) {\n                return writeRefuse(`IO_ERROR`, `${target.rel} wrote ${written} of ${bytes.length} bytes`, retained(target.rel));\n            }'
            .replace('`IO_ERROR`', "'IO_ERROR'"),
        to: '            /* mutated: a short write reports ok */' },
    // ⚠⚠ M58 AND M59 PIN THE WIN32-CONDITIONAL NAME SCREENS. They exist because of the lesson this
    // lane paid for on 2026-08-29: mutation testing cannot see a guard that is GONE, so making a
    // guard CONDITIONAL is the same hazard wearing a smaller hat.
    //
    // ⚠ M57 WAS HERE AND WAS DELETED THE SAME DAY IT WAS WRITTEN, WHICH IS WORTH ONE LINE. It
    // forced the screens ALWAYS ON, and was killed by an arm that built a screens-OFF gate through
    // a construction option. Both review lenses returned HIGH on that option — a containment
    // opt-out — so it was removed, `windowsNameRules` now derives from `process.platform` alone,
    // and on a Windows host "always on" is simply the correct behaviour with nothing left to
    // mutate. Deleting it is honest; keeping it would have parked a permanently-surviving row that
    // says nothing about any guard. **The POSIX branch is consequently unmutated here, and that is
    // the same lost coverage `A47`'s comment names — not a gap this matrix can close on Windows.**
    { id: 'M58', file: 'fsgate', what: 'invert the host derivation (win32 gets POSIX rules)', plan: 'A39-not-filenames + A47-name-rules-host',
        from: "    const windowsNameRules = process.platform === 'win32';",
        to: "    const windowsNameRules = process.platform !== 'win32';" },
    // ⚠⚠ M59 IS THE ROW THAT PINS THE CREATE-PATH ASYMMETRY, AND IT IS THE ONE THAT MATTERS.
    //
    // `createScreens.stream` is TRUE on every host because on the create path the stream screen is
    // the ONLY guard — the leaf is joined lexically and never walked, so `realpathNative` is never
    // consulted for it and a `<link>:<stream>` leaf reaches `openExclusive`. Relaxing this one
    // field to the host derivation looks like a tidy-up (it makes the two sets symmetrical) and
    // reopens the escape that was REPRODUCED writing outside the grant on 2026-08-29.
    //
    // ⚠ THE ROW IT REPLACES COULD NOT DISTINGUISH ITS OWN STATE. The previous M59 inverted the host
    // derivation, which on a Windows host — the only host that runs this matrix — yields exactly
    // what the old M58 produced, so the two were behaviourally identical and died to the same arm
    // for the same reason. Counting them as two overstated coverage by one. Found by the
    // cross-vendor escalation lens; a matrix that cannot tell two of its own rows apart is the same
    // class of defect as a mutant that never applied.
    // ⚠⚠ AND IT SURVIVES ON WINDOWS, WHICH IS THE HONEST RESULT AND NOT A GAP TO PAPER OVER.
    // On win32 `windowsNameRules` is true, so `{ stream: true }` and `{ stream: windowsNameRules }`
    // are the SAME OBJECT behaviourally and no arm can distinguish them. The state this row pins is
    // observable only OFF win32 — which is precisely the host this suite cannot run.
    // ⚠ THE LABEL IS "NO KILLING ARM ON THIS HOST", NOT "EQUIVALENT". Those are different claims and
    // this lane has confused them before: an equivalent mutant means the guard could be deleted, and
    // this one means the guard's whole purpose lives on a platform we cannot exercise. Deleting the
    // row would delete the only written record that the create-path asymmetry is untested.
    { id: 'M59', file: 'fsgate', what: 'relax the CREATE-path stream screen to the host derivation (reopens the ADS create escape) — SURVIVES on win32, see note', plan: 'NO KILLING ARM ON WIN32 — observable only off-win32; NOT equivalent',
        // ⚠ THE ANCHOR IS THE COMPILED FORM. This matrix mutates `dist/`, where TypeScript strips
        // the `: NameScreens` annotation — an anchor copied from `src/` matches nothing and the row
        // reports ANCHOR-NOT-FOUND. Caught by the preflight added the same day, which is the first
        // thing it caught.
        from: '    const createScreens = { stream: true, device: windowsNameRules };',
        to: '    const createScreens = { stream: windowsNameRules, device: windowsNameRules };' },
    { id: 'M60', file: 'fsgate', what: 'drop the stream screen on BOTH paths', plan: 'A39-not-filenames',
        from: '        if (screens.stream && segment.includes(\':\')) {', to: '        if (false && segment.includes(\':\')) {' },

    /* ---------------------------------------------------------------- *
     * S1 — the write-failure outcome (ruled 2026-08-31, fork 3B + 3b).  *
     *                                                                   *
     * ⚠ NO ROW HERE DELETES A FILE, and none ever may. The ruling is    *
     * that a failed write RETAINS its target and REPORTS it; a mutant   *
     * that unlinked would be a mutant this harness cannot undo — it     *
     * restores the one file it edits and CANNOT restore a filesystem  *
     * victim.                                                           *
     * ---------------------------------------------------------------- */

    // ⚠ THE FIELD IS DROPPED AT ITS SINGLE CONSTRUCTION SITE, which is the only place it can be
    // dropped from — that is what putting the guard at the primitive bought.
    { id: 'M65', file: 'fsgate', what: 'drop the `retained` field from every write refusal', plan: 'A47-write-throws-retains / A48-short-write-retains',
        from: '        resolvedPath: base.resolvedPath,\n        retained: left',
        to: '        resolvedPath: base.resolvedPath' },

    // The inverse, and the reason the `null` rows are arms rather than a comment: a field that is
    // always populated carries no information, and every retention arm still passes.
    { id: 'M66', file: 'fsgate', what: 'populate `retained` unconditionally, pre-open refusals included', plan: 'A50-refusal-before-open-retains-nothing',
        from: 'function asWriteRefusal(base, left) {\n    return Object.freeze({',
        to: 'function asWriteRefusal(base, left) {\n    left = left ?? retained(\'\');\n    return Object.freeze({' },

    // Fork 3b, reverted: swallow the close error and report the success anyway.
    { id: 'M67', file: 'fsgate', what: 'restore the swallowed close error (revert fork 3b)', plan: 'A49-close-fails-after-write',
        from: "                return writeRefuse('IO_ERROR', `${target.rel} failed to close after writing`, retained(target.rel));",
        to: '                void 0;' },

    // ⚠ THE OBSERVABLE PROPERTY IS WHETHER THE CLOSE OUTCOME IS CONSULTED BEFORE THE SUCCESS IS
    // COMMITTED — not whether the success object is CONSTRUCTED early. Constructing it early and
    // returning it only after a good close is behaviourally identical to the correct code, so a
    // row worded that way would describe a mutant that survives and tests nothing.
    //
    // ⚠ AND IT IS MECHANICALLY DISTINCT FROM `M67`, which matters after the M58/M59 lesson. M67
    // swallows the error at the close site; this returns BEFORE the close, leaving the `finally`
    // safety net to close exactly once — so the descriptor accounting stays correct and only the
    // observation is missing. A52 still passes against it; A49 does not.
    { id: 'M68', file: 'fsgate', what: 'commit the success BEFORE observing the close outcome', plan: 'A49-close-fails-after-write',
        from: '            closeAttempted = true;\n            try {\n                prim.close(fd);',
        to: '            return Object.freeze({ ok: true, rel: target.rel, bytes: written });\n            closeAttempted = true;\n            try {\n                prim.close(fd);' },

    // ⚠ THE ROUND-1 DOUBLE-CLOSE, PRESERVED AS A ROW. With the flag set AFTER the call, a throwing
    // close leaves it false and the `finally` closes the same descriptor a second time — on one the
    // runtime may already have released and reused. `A49`'s `closeCalls === 1` is the only
    // assertion that sees it; a `>= 1` "did it reach close" check goes green, which is exactly how
    // this defect would have shipped.
    { id: 'M69', file: 'fsgate', what: 'set the close flag AFTER the call, reintroducing the double close', plan: 'A49-close-fails-after-write (the `=== 1` counter, and nothing else)',
        from: '            closeAttempted = true;\n            try {\n                prim.close(fd);\n            }',
        to: '            try {\n                prim.close(fd);\n                closeAttempted = true;\n            }' },
    // ⚠ NO `M61` FOR THE DEVICE SCREEN — `M46` IS THAT ROW and was re-anchored to the new form
    // instead. A second row with the same effect would have inflated the matrix's denominator while
    // measuring one guard twice, which is the bookkeeping defect the escalation lens found in the
    // first M58/M59 pair. One guard, one row.

    /* ------------------------------------------------------------------ *
     * ADDED AFTER THE MOVE — the contract's `mutationsAddedPostMove`.     *
     *                                                                     *
     * ⚠⚠ THESE TWO ARE OUTSIDE THE LOCKED 69, WHICH IS WHY THEY COULD     *
     * EXIST AT ALL. Until 2026-09-02 the contract had `mutations` and     *
     * nothing beside it, and the verifier asserts that array's length     *
     * from code — so the matrix could not grow, and the two arms added    *
     * after the move (`A54-writeall-loop`, `A55-same-path-replacement`)   *
     * were graded by measurements written into their own comments. A      *
     * comment is not re-run. `A55` pins open fork F8, so what had no      *
     * reader was the detector for a security gap.                        *
     *                                                                     *
     * ⚠ THE LOCKED FIGURES DID NOT MOVE. 69, and the 66/3 split, are      *
     * still asserted from code against `mutations` alone; these rows      *
     * join the live half only.                                            *
     * ------------------------------------------------------------------ */

    // ⚠ NOT THE MUTATION `A54`'s COMMENT RECORDS, AND THAT IS THE POINT. It records
    // `if (n <= 0) break` -> `if (n < 0) break`, measured green on 2026-09-01 — before the arm
    // existed. It cannot be a ROW now: `A54`'s first leg injects a `writeSync` returning 0 forever,
    // so a weakened break makes the loop non-terminating and the suite HANGS to `SUITE_TIMEOUT_MS`
    // instead of going red. A row whose only channel is a 240-second timeout measures the timeout.
    // Same branch, same arm, terminating form: the break still fires, and the loop lies about
    // having finished.
    { id: 'M70-writeall-no-progress', file: 'fsgate', what: 'report a no-progress write as a completed one — the `n <= 0` break of the shipped completion loop', plan: 'A54-writeall-loop',
        from: '        if (n <= 0)\n            break;',
        to: '        if (n <= 0) {\n            written = buffer.length;\n            break;\n        }' },

    /**
     * ⚠⚠ THIS ROW APPLIES THE F8 TIGHTENING AND DOES NOT TAKE F8. The open fork asks whether
     * `rootStillCanonical` should compare `dev`/`ino` unconditionally rather than only inside
     * `if (current !== root)`. This patches `dist/` for one suite run and restores it byte-for-byte;
     * `src/fsgate.ts` is untouched and nothing ships differently.
     *
     * What it buys is that the fence's CURRENT behaviour finally has a detector that RUNS. `A55`
     * measured the gap by hand on 2026-09-02 and nothing re-ran it, so a refactor that tightened
     * the branch — or a ruling taken quietly — would have left the arm red with no row saying which
     * change did it. Now the row goes SURVIVED and the run fails, which is the review event.
     *
     * ⚠ IT REDDENS TWO ARMS, MEASURED 2026-09-02, AND NEITHER IS WRONG. `META-no-outside-names`
     * asserts that a stage-(a) refusal touches the filesystem for nothing but the root re-check;
     * an unconditional comparison adds an `lstat` of the canonical root to every request, which
     * that arm sees. Worth stating rather than tidying away: because the harness gates on the
     * DISPOSITION and records the red set diagnostically, this row coming back KILLED does not by
     * itself prove `A55` was the arm that caught it. Narrowing the mutation to dodge META would
     * mean mutating something other than the F8 tightening, which is the one thing the row is for.
     */
    /* ⚠⚠ M71 WAS INVERTED ON 2026-09-03 WHEN F8 WAS CLOSED (option C), AND THE INVERSION
     * KEEPS THE ROW MEANINGFUL RATHER THAN RETIRING IT.
     *
     * It used to read `if (current !== root) {` -> `if (true) {`: with the gap OPEN, that mutation
     * SIMULATED the fix, and `A55` — which then pinned the gap — went red on it. The anchor no
     * longer exists, because the identity check is now unconditional in the source.
     *
     * So the row now mutates in the opposite direction: it RESTORES the old conditional, putting
     * the F8 gap back. `A55` asserts the refusal today, so it reddens on the reintroduced gap. The
     * row grades the same guard it always graded; only the direction of travel changed. */
    { id: 'M71-root-identity-unconditional', file: 'fsgate', what: 'restore the conditional root identity comparison (reintroduce the F8 gap)', plan: 'A55-same-path-replacement',
        from: '        let now;',
        to: '        if (current === root) return null;\n        let now;' },

    /* ------------------------------------------------------------------ *
     * THE APPEND PATH — `M72`+, added 2026-09-02 with `appendLineInGrant`. *
     *                                                                      *
     * ⚠⚠ EVERY GUARD ON THIS PATH NEEDS ITS OWN ROW, AND THE REASON IS     *
     * MECHANICAL. `appendLineInGrant` does NOT call `resolveNew` — that    *
     * function refuses EXISTS on any existing leaf, which is right for a   *
     * create and fatal for an append — so the parent resolution, the name  *
     * screens and the containment check are performed a SECOND time, in a  *
     * second body. A row that patches `resolveNew` says nothing about the  *
     * append path, and vice versa. The `from` anchors below are the append *
     * body's own text and were checked against the built output.           *
     * ------------------------------------------------------------------ */

    { id: 'M72-append-line-framing', file: 'fsgate', what: 'accept a line that is not exactly one LF-terminated record', plan: 'A56-append-core',
        from: 'if (firstLf !== line.length - 1) {',
        to: 'if (false) {' },

    /**
     * ⚠⚠ SURVIVES ON WIN32, AND IT IS `M59`'S TWIN RATHER THAN A WEAK ARM. `readScreens` and
     * `createScreens` differ in exactly one field, `stream`, and on win32 both are `true` — so on
     * this host the two sets are the same object by value and swapping them changes nothing that
     * runs. Off win32 they diverge and this mutation re-admits the alternate-data-stream leaf class
     * on the append path.
     *
     * ⚠ NOT EQUIVALENT, AND THE DISTINCTION MATTERS BECAUSE THIS LANE HAS CONFUSED THEM BEFORE. An
     * equivalent mutant means the guard could be deleted; this one means the guard's whole purpose
     * lives on a platform this suite cannot exercise. Deleting the row would delete the only
     * written record that the append path's screen-set choice is untested here. It folds into the
     * standing `POSIX is reasoned, never measured` row, beside `M59`.
     */
    { id: 'M73-append-read-screens', file: 'fsgate', what: 'run the READ name screens on an append instead of the create screens (reopens the ADS leaf class on every host) — SURVIVES on win32, see note', plan: 'NO KILLING ARM ON WIN32 — the two screen sets are identical on this host; observable only off-win32; NOT equivalent',
        from: 'const lexical = lexicalStage(root, request, createScreens);\n        if (isRefusal(lexical))\n            return asWriteRefusal(lexical, null);',
        to: 'const lexical = lexicalStage(root, request, readScreens);\n        if (isRefusal(lexical))\n            return asWriteRefusal(lexical, null);' },

    { id: 'M74-append-parent-lexical', file: 'fsgate', what: "resolve the append path's PARENT lexically, bypassing the fence", plan: 'A57-append-parent-containment',
        // ⚠ THE LOCAL IS `appendParent` IN THE SOURCE, AND THAT IS WHY. A copy spelled `parent`
        // made `M47`'s anchor ambiguous — the matrix's uniqueness preflight refused the whole run
        // rather than half-applying either row. See the note at the source's own declaration.
        from: 'const appendParent = resolveInGrant(root, prim, path.relative(root, parentSpelled), createScreens);\n            if (isRefusal(appendParent))\n                return asWriteRefusal(appendParent, null);',
        to: 'const appendParent = { ok: true, actual: parentSpelled, rel: path.relative(root, parentSpelled) };\n            if (isRefusal(appendParent))\n                return asWriteRefusal(appendParent, null);' },

    { id: 'M75-append-leaf-probe-deleted', file: 'fsgate', what: 'delete the append leaf probe entirely, taking the create branch unconditionally', plan: 'A58-append-leaf-no-follow / A59-append-probe-errors / A60-append-target-changed',
        from: '            const leafStats = prim.lstat(actual);\n            if (leafStats.isSymbolicLink() || !leafStats.isFile()) {',
        to: '            const leafStats = { isSymbolicLink: () => false, isFile: () => true };\n            if (leafStats.isSymbolicLink() || !leafStats.isFile()) {' },

    { id: 'M76-append-accepts-link-leaf', file: 'fsgate', what: 'accept a non-file or link leaf on the append path (the probe still runs, its verdict is ignored)', plan: 'A58-append-leaf-no-follow',
        from: 'if (leafStats.isSymbolicLink() || !leafStats.isFile()) {\n                return writeRefuse(\'NOT_A_FILE\', `${rel} is not a regular file`, null);',
        to: 'if (false) {\n                return writeRefuse(\'NOT_A_FILE\', `${rel} is not a regular file`, null);' },

    { id: 'M77-append-create-not-exclusive', file: 'fsgate', what: "open the append create branch NON-exclusively ('ax' -> 'a')", plan: 'A58-append-leaf-no-follow / A60-append-target-changed',
        from: "? fs.openSync(target, 'ax')",
        to: "? fs.openSync(target, 'a')" },

    { id: 'M78-append-existing-creates', file: 'fsgate', what: 'add O_CREAT to the append EXISTING branch (a leaf deleted after observation is silently recreated empty)', plan: 'A60-append-target-changed',
        from: ': fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_APPEND);',
        to: ': fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT);' },

    /**
     * ⚠ THE EXISTING BRANCH ONLY, DELIBERATELY. Dropping `O_APPEND` from `'ax'` as well is not
     * expressible — `ax` IS the append-create mode — and a row that mutated both would be two
     * changes under one id. The existing branch is where the flag is spelled out and where a
     * maintainer would plausibly drop it.
     */
    { id: 'M79-append-no-o-append', file: 'fsgate', what: 'drop O_APPEND from the existing branch, so an append overwrites from position 0', plan: 'A62-append-one-write',
        from: 'fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_APPEND)',
        to: 'fs.openSync(target, fs.constants.O_WRONLY)' },

    { id: 'M80-append-write-before-verify', file: 'fsgate', what: 'write BEFORE the pre-write identity verification (the whole check becomes decoration)', plan: 'A58-append-leaf-no-follow / A60-append-target-changed',
        from: '            let descriptorStats;\n            try {\n                descriptorStats = prim.fstat(fd);',
        to: '            prim.appendOnce(fd, line);\n            let descriptorStats;\n            try {\n                descriptorStats = prim.fstat(fd);' },

    { id: 'M81-append-drop-preopen-identity', file: 'fsgate', what: 'drop the PRE-OPEN-vs-descriptor identity comparison (a swap between probe and open is served)', plan: 'A60-append-target-changed',
        from: "if (mode === 'existing' && !sameObject(observed, descriptorIdentity)) {",
        to: 'if (false) {' },

    { id: 'M82-append-drop-postopen-identity', file: 'fsgate', what: 'drop the descriptor-vs-post-open identity comparison (a name re-pointed after the open is served)', plan: 'A58-append-leaf-no-follow / A60-append-target-changed',
        from: 'if (!sameObject(descriptorIdentity, postIdentity)) {',
        to: 'if (false) {' },

    { id: 'M83-append-skip-realpath-containment', file: 'fsgate', what: 'skip the post-open realpath containment check on the append path', plan: 'A58-append-leaf-no-follow / META-no-outside-names',
        from: 'const stillContained = _validateDerivedAbsolute(root, realPath);\n            if (stillContained)',
        to: 'const stillContained = null;\n            if (stillContained)' },

    /**
     * ⚠ THE RETRY IS THE DEFECT THIS PATH EXISTS TO REFUSE, and the row takes the terminating form
     * for `M70`'s reason: a loop that never completes hangs the suite to `SUITE_TIMEOUT_MS` and a
     * row whose only channel is a timeout measures the timeout. This one retries a BOUNDED number
     * of times, which is exactly the shape a maintainer would write.
     */
    { id: 'M84-append-retries-short-write', file: 'fsgate', what: 'retry after a short append (which under O_APPEND splices another writer\'s record between the fragments)', plan: 'A62-append-one-write',
        from: 'const written = prim.appendOnce(fd, line);',
        to: 'let written = prim.appendOnce(fd, line);\n            for (let attempt = 0; attempt < 8 && written < line.length; attempt += 1) {\n                written += prim.appendOnce(fd, line.subarray(written));\n            }' },

    { id: 'M85-append-short-write-is-success', file: 'fsgate', what: 'report a short append as a success with a reduced count', plan: 'A62-append-one-write / A63-append-retention',
        from: 'if (written !== line.length) {\n                return writeRefuse(\'IO_ERROR\', `${rel} appended ${written} of ${line.length} bytes`, retained(rel));',
        to: 'if (false) {\n                return writeRefuse(\'IO_ERROR\', `${rel} appended ${written} of ${line.length} bytes`, retained(rel));' },

    /**
     * ⚠ `retained` IS A REQUIRED FIELD, so it cannot be OMITTED without failing the build — which
     * is the type's whole point. What a dist patch CAN do is what a maintainer's mistake would do:
     * pass `null` everywhere, claiming nothing was left behind. That is the observable defect the
     * required field was introduced to make impossible to reach by forgetting.
     */
    { id: 'M86-append-retained-null', file: 'fsgate', what: 'claim retained: null on every append refusal, including the post-open ones', plan: 'A63-append-retention',
        from: 'return writeRefuse(\'IO_ERROR\', `${rel} appended ${written} of ${line.length} bytes`, retained(rel));',
        to: 'return writeRefuse(\'IO_ERROR\', `${rel} appended ${written} of ${line.length} bytes`, null);' },

    { id: 'M87-append-close-swallowed', file: 'fsgate', what: 'swallow a close failure on the append path and report success anyway', plan: 'A64-append-close',
        from: 'catch {\n                return writeRefuse(\'IO_ERROR\', `${rel} failed to close after appending`, retained(rel));\n            }',
        to: 'catch {\n                /* swallowed */\n            }' },

    { id: 'M88-append-returns-absolute', file: 'fsgate', what: 'return the RESOLVED ABSOLUTE path as the append result\'s rel', plan: 'A56-append-core / META-no-outside-names',
        from: 'return Object.freeze({ ok: true, rel, bytes: written });',
        to: 'return Object.freeze({ ok: true, rel: actual, bytes: written });' },

    /**
     * ⚠ THE ANCHOR IS THE APPEND PATH'S OWN RECHECK, NOT THE SHARED FUNCTION. `M30` deletes the
     * recheck at all three of its ORIGINAL sites; this row deletes only the fourth, so a row that
     * came back SURVIVED would mean the append path had stopped calling it independently.
     */
    { id: 'M89-append-no-root-recheck', file: 'fsgate', what: 'omit the root re-check on the append path only', plan: 'A35-root-moved / A45-root-identity',
        from: 'const moved = rootStillCanonical();\n        if (moved)\n            return asWriteRefusal(moved, null);',
        to: 'const moved = null;\n        if (moved)\n            return asWriteRefusal(moved, null);' },

    /**
     * ⚠ THE TWO NLINK ROWS ARE SEPARATE BECAUSE THE TWO CHECKS ANSWER DIFFERENT WINDOWS, and a
     * single row dropping both would be KILLED by either leg while proving neither is load-bearing
     * on its own. The pre-open reading catches a link that was there all along; the post-open one
     * catches a link created between the probe and the open. Deleting one leaves the other green,
     * which is exactly what makes each row a claim about its own check.
     *
     * ⚠ THE ANCHORS ARE THE `nlink` COMPARISONS, NOT THE REFUSALS THEY GUARD, because the two
     * refusals are textually identical apart from their retention argument — anchoring on the
     * `writeRefuse` call would make both rows ambiguous and the matrix's uniqueness preflight
     * would refuse them.
     */
    { id: 'M96-append-drop-preopen-nlink', file: 'fsgate', what: 'drop the PRE-OPEN link-count check (a pre-existing hard link aliasing an outside file is appended to)', plan: 'A65-append-hardlink-refused / A58-append-leaf-no-follow',
        from: 'if (observed.nlink > 1n) {',
        to: 'if (false) {' },

    { id: 'M97-append-drop-postopen-nlink', file: 'fsgate', what: 'drop the POST-OPEN link-count check (a hard link created between the probe and the open is appended through)', plan: 'A65-append-hardlink-refused',
        from: 'if (descriptorIdentity !== null && descriptorIdentity.nlink > 1n) {',
        to: 'if (false) {' },

    { id: 'M98-preflight-symlink-denial-misclassified', file: 'preflight', what: 'misclassify every symlink-creation failure as a privilege denial', plan: 'FP1-preflight',
        from: "if (error.code !== 'EPERM' && error.code !== 'EACCES') {", to: "if (error.code !== 'EPERM' || error.code !== 'EACCES') {" },
    { id: 'M99-preflight-nothing-was-run-dropped', file: 'preflight', what: 'drop NOTHING WAS RUN from the junction-preflight refusal', plan: 'FP2-junction-preflight',
        from: 'NOTHING WAS RUN, ', to: '' },
    { id: 'M100-readme-pointer-into-source', file: 'readme', what: 'point the README limits account into unshipped source', plan: 'PC1-pointers-resolve',
        from: 'The source header records how the limits were measured;', to: 'The source header in `src/fsgate.ts` records how the limits were measured;' },
    { id: 'M101-readme-completeness-overclaim', file: 'readme', what: 'claim the README lists every known limit', plan: 'PC2-retired-wordings',
        from: 'This section is the authoritative account.', to: 'The README lists every known limit.' },
    { id: 'M102-readme-limits-condensed', file: 'readme', what: 'condense the README limits section to its first three bullet paragraphs', plan: 'PC3-limits-section-live',
        anchors: ['## Security boundary and limits', 'This section is the authoritative account.'],
        replace: source => {
            const heading = '## Security boundary and limits';
            const closing = 'This section is the authoritative account.';
            const bodyStart = source.indexOf('\n\n', source.indexOf(heading)) + 2;
            const bodyEnd = source.indexOf(closing, bodyStart);
            const body = source.slice(bodyStart, bodyEnd);
            const bullets = [...body.matchAll(/^- /gm)].map(match => match.index);
            if (bullets.length !== 12) throw new Error(`M102 expected exactly 12 limits bullets, found ${bullets.length}`);
            return source.slice(0, bodyStart) + body.slice(0, bullets[3]) + source.slice(bodyEnd);
        } },

    // ⚠⚠ TWO ROWS FOR ONE COMPARISON, BECAUSE THERE ARE TWO COPIES OF IT AND NOT ONE. The append
    // path does not call `resolveNew` — that function refuses EXISTS the moment its leaf probe
    // finds anything, right for a create and fatal for an append — so the parent resolution, and
    // now the alias comparison with it, exist twice in two bodies. A row on one is not evidence
    // about the other, exactly as `M47`/`M74` are two rows for one lexical-parent defect.
    //
    // ⚠ THE ANCHORS ARE THE ARGUMENT SPELLINGS (`parent.actual` vs `appendParent.actual`), WHICH IS
    // WHY THE SOURCE KEEPS THE TWO LOCALS TEXTUALLY DISTINCT. A copy spelled `parent` in both
    // bodies made `M47`'s anchor ambiguous once already, and the matrix's uniqueness preflight
    // refused the whole run rather than half-applying either row.
    { id: 'M103-create-parent-alias-accepted', file: 'fsgate', what: 'accept an aliased parent on the create path (the comparison runs, its verdict is ignored)', plan: 'A66-parent-alias-refused / A40-create',
        from: 'if (_parentIsAliased(parentSpelled, parent.actual)) {',
        to: 'if (false && _parentIsAliased(parentSpelled, parent.actual)) {' },

    { id: 'M104-append-parent-alias-accepted', file: 'fsgate', what: 'accept an aliased parent on the append path (the comparison runs, its verdict is ignored)', plan: 'A66-parent-alias-refused / A57-append-parent-containment',
        from: 'if (_parentIsAliased(parentSpelled, appendParent.actual)) {',
        to: 'if (false && _parentIsAliased(parentSpelled, appendParent.actual)) {' },

    // ⚠ THE PREDICATE ITSELF, SEPARATE FROM ITS TWO CALL SITES. `M103`/`M104` delete the guard at a
    // site; this one leaves both sites calling and makes the comparison EXACT, which is the change
    // a maintainer makes by reasoning that case-folding is sloppy. It must redden the case-fold
    // legs and nothing else — the alias legs still refuse, because `Notes` and `Arc` differ under
    // an exact comparison too. That asymmetry is what makes this row a claim about the FOLD rather
    // than about the guard.
    { id: 'M105-parent-alias-compared-exactly', file: 'fsgate', what: 'compare the spelled and resolved parent EXACTLY, dropping the case fold', plan: 'A66-parent-alias-refused / A40-create',
        from: 'return path.normalize(spelled).toLowerCase() !== path.normalize(actual).toLowerCase();',
        to: 'return path.normalize(spelled) !== path.normalize(actual);' },

    { id: 'M106-baseline-byte-pin-dropped', file: 'attributes', what: 'enable Git text conversion for generated baselines', plan: 'E16-baseline-byte-pin',
        from: '*.baseline -text',
        to: '*.baseline text' },

    { id: 'M107-append-window-account-thinned', file: 'readme', what: 'remove the exact last-check-to-write timing from the authoritative append-window account', plan: 'PC4-append-window-single-home',
        from: "After the fence's last check, the real-path containment check that follows the descriptor's",
        to: "After the fence has opened the descriptor, its remaining checks run," },

    { id: 'M108-probe-kind-collapsed', file: 'fsgate', what: 'report every successful existence probe as a file', plan: 'A67-probe-directory / A70-probe-junction',
        from: 'return Object.freeze({ ok: true, kind: entryKind(stats) });',
        to: "return Object.freeze({ ok: true, kind: 'file' });" }
];

// ⚠ ROW IDS MUST BE UNIQUE, AND NOTHING CHECKED UNTIL 2026-08-29, WHEN A DUPLICATE WAS ADDED AND
// RAN. Two rows answered to `M29`; `--only M29` silently executed BOTH and printed two result lines
// under one id. Neither was wrong, but nothing said which row a line belonged to — and a REPORT
// that cannot identify its own subject is the failure class this lane keeps finding. The id is the
// key the matrix, the plan's §5a table and every `--only` invocation all join on, so a collision
// corrupts the join rather than the run.
{
    const seen = new Set();
    const duplicates = ROWS.map(row => row.id).filter(id => (seen.has(id) ? true : (seen.add(id), false)));
    if (duplicates.length > 0) {
        console.error(`⛔ duplicate mutation row id(s): ${[...new Set(duplicates)].join(', ')}`);
        console.error('   Ids are the key everything joins on. Renumber before running.');
        process.exit(1);
    }
}

/**
 * ⚠⚠ THE RELOCATION CONTRACT, BEFORE A SINGLE BYTE OF `dist/` IS TOUCHED.
 *
 * The duplicate check above proves the matrix agrees with itself. It cannot notice a row that is
 * simply gone, and the relocation is the operation that can take rows away: every row here arrived
 * from another package on 2026-09-01. `../../wyrd/test/relocation-contract.json` is the outside
 * referent, written before anything moved, with no generator that could bring it into agreement
 * with a shorter list. It is the Reader's file on purpose — one record, not two that can be
 * reconciled separately.
 *
 * ⚠ It is handed the LIVE `ROWS`, reduced to id, file and the row's own `what`. A row's `file` is
 * what decides which package it measures, so the contract cross-checks the declared destination
 * against it — the one destination field in the contract that has an independent oracle.
 *
 * ⚠⚠ `what` IS PASSED AS `mutates` AND WAS NOT PASSED AT ALL UNTIL 2026-09-02. The projection was
 * `{ id, file }`, so the contract's `mutates` text — the recorded transformation, in a record with
 * no generator — was compared against nothing on either side of the fence move. A row whose id and
 * file survive while its transformation changes measures something the contract never routed, and
 * that was invisible. Dropping the field again now REFUSES rather than skipping.
 *
 * ⚠⚠ `plan` IS PASSED TOO, AND IT IS THE THIRD FIELD IN A ROW TO HAVE HAD NO READER. Every row here
 * names the arm the design's §5a table claimed would kill it, and until 2026-09-02 nothing checked
 * that the name existed — true of all 71 rows across both matrices, not only the new ones. An arm
 * that is renamed or deleted leaves its rows pointing at nothing while they still run and still
 * report. ⚠ The check is REFERENTIAL ONLY: `plan` is allowed to be wrong about which arm bites, and
 * the summary printing "§5a claims" beside "actually red" is the whole point of keeping it that way.
 */
const CONTRACT = (() => {
    const { contract, problems } = loadContract();
    if (problems.length) refuse(problems, 'the contract is not internally consistent');
    const rowProblems = verifyMutationRows(contract, 'wyrd-fence', ROWS.map(row => ({ id: row.id, file: row.file ?? 'fsgate', mutates: row.what, plan: row.plan })));
    if (rowProblems.length) refuse(rowProblems, "wyrd-fence's mutation matrix does not match the relocation contract");
    // ⚠ ONE SENTENCE, ONE DENOMINATOR. This used to read "N rows declared here, of <locked> locked
    // pre-move plus <added> added since" — and those are DIFFERENT populations: the first counts
    // rows in THIS file, the second counts the contract's total across BOTH packages. 69 + 33 = 102
    // against 93 declared here reads as an internal inconsistency, and a dispatched lane reported it
    // as a defect on 2026-09-04 and could not investigate further. The numbers were always right;
    // the sentence was not. Both totals are still printed, each labelled with what it counts.
    console.log(
        `· relocation contract: ${ROWS.length} mutation rows declared here (wyrd-fence);`
        + ` the contract holds ${contract.totals.mutations + contract.mutationsAddedPostMove.length}`
        + ` across BOTH packages — ${contract.totals.mutations} locked pre-move plus`
        + ` ${contract.mutationsAddedPostMove.length} added since`
    );
    return contract;
})();

const args = process.argv.slice(2);
const jsonOut = args.includes('--json');
const onlyArg = args.find(a => a.startsWith('--only'));
const only = onlyArg ? (onlyArg.includes('=') ? onlyArg.split('=')[1] : args[args.indexOf(onlyArg) + 1]) : null;
const selected = only ? new Set(only.split(',').map(s => s.trim())) : null;
// ⚠ AN UNKNOWN `--only` ID USED TO SELECT NOTHING AND EXIT 0 — a run that mutated nothing, tested
// nothing and reported `0/0 killed` as success. Found by the close-side review 2026-09-03.
if (selected) {
    const known = new Set(ROWS.map(r => r.id));
    const unknown = [...selected].filter(id => !known.has(id));
    if (unknown.length) {
        console.error(`mutate: --only names ${unknown.length} row(s) this matrix does not have: ${unknown.join(', ')}`);
        process.exit(2);
    }
}

const ORIGINAL = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, fs.readFileSync(p, 'utf8')]));
const ORIGINAL_BYTES = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, fs.readFileSync(p)]));

// Refuse rather than overwrite a differing backup: after a killed run, either the target is
// damaged and `--restore` is required, or the target is intentional and the backup directory must
// be deleted. This harness cannot safely guess which set of bytes is authoritative.
{
    const conflicts = RECOVERABLE.filter(key => fs.existsSync(backupPathFor(key)) && !fs.readFileSync(backupPathFor(key)).equals(ORIGINAL_BYTES[key]));
    if (conflicts.length) {
        for (const key of conflicts) {
            console.error(`⛔ refusing to overwrite backup ${backupPathFor(key)}: it differs from on-disk target ${FILES[key]}.`);
        }
        console.error(`   If the tree is damaged, run \`${RESTORE_COMMAND}\`; if the on-disk file is intentional, delete ${BACKUP_DIR} and run again.`);
        process.exit(1);
    }
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    for (const key of RECOVERABLE) {
        if (!fs.existsSync(backupPathFor(key))) fs.writeFileSync(backupPathFor(key), ORIGINAL_BYTES[key]);
    }
    console.log(`· pristine backup of ${RECOVERABLE.map(key => path.basename(FILES[key])).join(' and ')}: ${BACKUP_DIR}`);
    console.log(`  If this run is killed, \`${RESTORE_COMMAND}\` restores them byte-for-byte.`);
}

/** What a row promises its source contains. A `replace` callback is opaque, so it must declare. */
function declaredAnchors(row) {
    return row.anchors ?? (row.edits ? row.edits.map(([from]) => from) : row.from ? [row.from] : []);
}

/**
 * ⚠⚠ AN ANCHOR THAT MATCHES TWICE IS AS BROKEN AS ONE THAT MATCHES NEVER, AND IT LOOKS FINE.
 *
 * `String.prototype.replace` with a string pattern substitutes the FIRST occurrence only. A row
 * whose anchor appears twice therefore mutates one site and leaves the other intact — a partial
 * mutant, which is the worst state in this file: it tests something nobody described and reports
 * under the id of the thing it did not test. The existing guard catches the absent case and cannot
 * see this one, because a partial mutation still changes the file.
 *
 * ⚠ PREFLIGHTED OVER EVERY ROW BEFORE ANY SUITE RUNS, not row by row. A run that discovers this on
 * row 60 has already spent an hour, and the plan lists "an anchor is absent or non-unique" as a
 * refusal condition — a refusal that arrives after the measurement is a report, not a gate.
 *
 * ⚠ A row that genuinely needs to hit several sites declares `replace` with a global regex (M23,
 * M24, M30 do). Those declare their anchors explicitly and are checked the same way; if one ever
 * legitimately needs a repeated anchor, the honest fix is a narrower anchor, never relaxing this.
 */
{
    const ambiguous = [];
    for (const row of ROWS) {
        const source = ORIGINAL[row.file ?? 'fsgate'];
        for (const anchor of declaredAnchors(row)) {
            const hits = source.split(anchor).length - 1;
            if (hits > 1) ambiguous.push(`${row.id} anchors on text occurring ${hits} times in \`${row.file ?? 'fsgate'}\` — a string replace would mutate only the first, leaving a partial mutant: ${JSON.stringify(anchor.slice(0, 70))}`);
        }
    }
    if (ambiguous.length) refuse(ambiguous, 'a mutation anchor is not unique in its source');
}

function restoreAll() {
    for (const [key, file] of Object.entries(FILES)) fs.writeFileSync(file, ORIGINAL[key]);
}

function runSuite() {
    try {
        const out = execFileSync(process.execPath, [...SUITE],
            { cwd: pkg, encoding: 'utf8', timeout: SUITE_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'pipe'] });
        return { failed: false, out };
    } catch (error) {
        if (error.killed || error.signal) return { failed: true, out: 'SUITE TIMED OUT OR WAS KILLED' };
        return { failed: true, out: (error.stdout ?? '') + (error.stderr ?? '') };
    }
}

/** Named tests that went red, as the runner printed them. */
function redTests(out) {
    return [...new Set([...out.matchAll(/^✖ (.+?) \([\d.]+ms\)$/gm)].map(m => m[1].split(' — ')[0].trim()))];
}

/**
 * ⚠⚠ THE UNMUTATED CONTROL, AND WITHOUT IT EVERY VERDICT BELOW IS UNCONDITIONAL.
 *
 * A row is KILLED when the suite goes red with its mutation applied. That sentence only carries
 * information if the suite is GREEN without one — against a suite that was already failing, all 69
 * rows come back KILLED and the matrix reports a perfect score for a measurement it never made.
 * Nothing checked this until 2026-09-01; the plan lists "the unmutated control is red" as a
 * refusal condition of the relocation contract, and this is where it can be observed.
 *
 * It costs one suite run at the top, against untouched `dist/`.
 */
{
    const control = runSuite();
    if (control.failed) {
        refuse(
            ['the suite is RED before any mutation is applied, so every KILLED verdict below would be unconditional',
                `the control run said: ${control.out.trim().split(String.fromCharCode(10)).slice(-6).join(' | ')}`],
            'the unmutated control run is not green'
        );
    }
    console.log('· unmutated control: green — the verdicts below are conditional on the mutation.');
}

/** Set in the `finally` below, read by the contract's result check. */
let restored = false;
const results = [];
try {
    for (const row of ROWS) {
        if (selected && !selected.has(row.id)) continue;
        const key = row.file ?? 'fsgate';
        const source = ORIGINAL[key];
        let mutated;

        // ⚠⚠ EVERY DECLARED ANCHOR IS PREFLIGHTED, NOT JUST "DID ANYTHING CHANGE". Both 2026-08-31
        // review lenses found the first version of this guard half-built: it only reported
        // ANCHOR-NOT-FOUND when NO edit applied, so an `edits` row whose refactored source still
        // matched ONE of its anchors mutated partially, ran as a valid mutant, and exited 0. A
        // partial mutant is the worst case in this file — it tests something nobody described, and
        // reports under the id of the thing it did not test.
        //
        // `anchors` lets a `replace` callback row declare what its source must contain, since a
        // callback's substitutions are opaque from here. A row that declares none keeps the older,
        // weaker check — the whole-file no-op below — and that limit is real rather than closed.
        const declared = declaredAnchors(row);
        const missing = declared.filter(a => !source.includes(a));
        if (missing.length) {
            results.push({ ...meta(row), status: 'ANCHOR-NOT-FOUND', red: [] });
            continue;
        }

        if (row.replace) {
            mutated = row.replace(source);
        } else if (row.edits) {
            mutated = row.edits.reduce((acc, [f, t]) => acc.replace(f, t), source);
        } else {
            mutated = source.replace(row.from, row.to);
        }
        if (mutated === source) {
            results.push({ ...meta(row), status: 'ANCHOR-NOT-FOUND', red: [] });
            continue;
        }

        fs.writeFileSync(FILES[key], mutated);
        const { failed, out } = runSuite();
        restoreAll();
        results.push({ ...meta(row), status: failed ? 'KILLED' : 'SURVIVED', red: failed ? redTests(out) : [] });
    }
} finally {
    restoreAll();
    const clean = Object.entries(FILES).every(([k, p]) => fs.readFileSync(p).equals(ORIGINAL_BYTES[k]));
    restored = clean;
    if (!clean) {
        console.error('\n⚠⚠ RESTORE FAILED — run `npm run build` before trusting dist/.');
        process.exitCode = 1;
    } else if (!jsonOut) {
        console.log('[restore] dist/ restored byte-for-byte: true\n');
    }
}

function meta(row) {
    return { id: row.id, file: row.file ?? 'fsgate', mutation: row.what, planClaims: row.plan };
}

if (jsonOut) {
    console.log(JSON.stringify(results, null, 2));
} else {
    const width = Math.max(...results.map(r => r.id.length));
    for (const r of results) {
        const mark = r.status === 'KILLED' ? 'KILLED  ' : r.status === 'SURVIVED' ? 'SURVIVED' : r.status;
        console.log(`${mark.padEnd(18)} ${r.id.padEnd(width)}  ${r.mutation}`);
        console.log(`${''.padEnd(18)} ${''.padEnd(width)}  §5a claims: ${r.planClaims}`);
        if (r.red.length) console.log(`${''.padEnd(18)} ${''.padEnd(width)}  actually red: ${r.red.join(' | ')}`);
        else if (r.status === 'SURVIVED') console.log(`${''.padEnd(18)} ${''.padEnd(width)}  ⚠ NO ARM WENT RED`);
        console.log('');
    }
    const killed = results.filter(r => r.status === 'KILLED').length;
    console.log(`${killed}/${results.length} killed.`);
    const survived = results.filter(r => r.status !== 'KILLED');
    if (survived.length) console.log(`NOT KILLED: ${survived.map(r => `${r.id} (${r.status})`).join(', ')}`);
}

/**
 * ⚠⚠ AN UNANCHORED MUTANT FAILS THE RUN. A SURVIVOR DOES NOT — AND THE ASYMMETRY IS THE POINT.
 *
 * `SURVIVED` is a reasoned state: M4 and M48 are documented above, each with why no arm can kill
 * it. `ANCHOR-NOT-FOUND` is a BROKEN INSTRUMENT — the mutation never applied, so the row tested
 * nothing and reported in the same breath as rows that did. It is the file's own lesson arriving
 * one level up: a mutation that does not reproduce its defect certifies the guard without testing
 * it, and this harness had no way to say so.
 *
 * ⚠ MEASURED HERE, 2026-08-31, WHICH IS WHY THIS EXISTS. Threading `windowsNameRules` through
 * `lexicalStage` and `resolveInGrant` changed two call sites that M10 and M47 anchor on. Both rows
 * silently stopped applying, the run printed `60/64` and `NOT KILLED: … (ANCHOR-NOT-FOUND)`, and
 * **exited 0**. It was caught only by comparing the total against a count written down in
 * `NEXT.md` the day before — a human noticing an arithmetic change, which is not a control.
 * A refactor that renames a mutated line is ordinary; disarming the matrix by doing it must not be.
 */
const unanchored = results.filter(r => r.status === 'ANCHOR-NOT-FOUND');
if (unanchored.length) {
    console.error(
        `\n⚠⚠ ${unanchored.length} MUTANT(S) NEVER APPLIED: ${unanchored.map(r => r.id).join(', ')}\n` +
        `   Their anchor text is no longer in the source, so they tested NOTHING and are not survivors.\n` +
        `   Repair the row's \`from\` against the current source — do not delete the row.`
    );
    process.exitCode = 1;
}

/**
 * ⚠ THE CONTRACT, ONCE MORE, ON THE RESULTS RATHER THAN THE ROWS.
 *
 * The pre-run check proved the matrix still declares every contracted row. This proves the run
 * PRODUCED one, which is a different claim: a row that is declared and silently never executed
 * reports nothing and reduces the denominator by one without touching a list. It also holds the
 * dispositions — a row contracted KILLED that comes back SURVIVED is an adequacy regression.
 *
 * ⚠ AN EXACT RED SET WHERE A ROW DECLARES ONE, AND ONLY THERE. `A35-root-moved` has a measured
 * noise floor, so a blanket rule would gate this matrix on a coin flip; a row carrying no
 * `expectedRed` in the contract is recorded diagnostically and never gated, exactly as every row
 * was before 2026-09-02. What a declared set buys is ATTRIBUTION, which a disposition cannot give:
 * `M71` reddens two arms, so KILLED alone never said which one caught it. See the verifier for the
 * exemption list, for why the survivor direction is a note rather than a failure, and for why
 * adding a set to a row you have not run is the one thing not to do.
 */
{
    const { problems, notes } = verifyMutationResults(CONTRACT, 'wyrd-fence', results, { full: !selected, restored });
    for (const note of notes) console.error(`  ⚠ STALE CONTRACT ROW — ${note}`);
    if (problems.length) refuse(problems, 'the mutation run does not match the pre-move contract');
    if (!jsonOut) {
        console.log('✔ relocation contract: every contracted row produced a result, and every contracted kill was a kill.');
    }
}
