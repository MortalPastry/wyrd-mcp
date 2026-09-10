#!/usr/bin/env node
/**
 * THE MUTATION MATRIX, EXECUTED.
 *
 * `designs/2026-08-27-s2-fence-plan.md` §5a is a table of claims: each row names a mutation and
 * the arm that must go red. A table is not evidence. This script applies each mutation to the
 * BUILT output, runs the whole suite, and records which named tests actually failed.
 *
 *   npm run build && npm run mutate            all rows
 *   npm run mutate -- --only M8,M13            selected rows
 *   npm run mutate -- --json                   machine-readable record
 *   npm run mutate -- --restore                put the non-built targets back from the on-disk backup
 *
 * ⚠ It edits the files in `FILES` in place and restores them in a `finally`, verifying the restore
 *   byte-for-byte. It never touches `src/`. Run `npm run build` afterwards if in doubt.
 *
 * ⚠⚠ A `finally` DOES NOT RUN WHEN THE PROCESS IS KILLED, and until 2026-09-02 that was the whole
 *   recovery story. `dist/` survives that because `npm run build` regenerates it; `server.json` and
 *   `package.json` DO NOT — they are product files `tsc` does not produce, so a hard kill mid-row
 *   left a mutated manifest on disk with no instrument able to put it back and a recovery note
 *   ("rebuild") that could not. `BACKUP_DIR` under `os.tmpdir()` now holds the pristine bytes of
 *   every non-built target, written before the first mutation and printed at the top of every run;
 *   `--restore` copies them back byte-exactly. See `BACKUP_DIR` below.
 *
 * ⚠ A row whose status is EQUIVALENT or NO-KILLING-ARM is the honest output, not a gap to be
 *   papered over by weakening an arm. §5a exists to surface exactly those.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { loadContract, verifyMutationRows, verifyMutationResults, refuse } from './verify-relocation-contract.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * ⚠⚠ `fsgate` IS GONE FROM THIS MAP AS OF 2026-09-01, AND ITS ABSENCE IS THE MOVE.
 *
 * It used to resolve `wyrd-fence` by package name and patch a SIBLING PACKAGE'S built output from
 * here — 66 of this file's 69 rows measured that package's adequacy, not this one's. Those rows and
 * that entry are now in `wyrd-fence/scripts/mutate.mjs`, where the mutated file and the arms that
 * kill it live together.
 *
 * ⚠ DO NOT ADD IT BACK "for coverage". The fence's matrix is run by root `mutate`, which now drives
 * both packages; a second copy here would measure the same guards twice and inflate a denominator
 * that exists precisely to be honest.
 *
 * ⚠ Every value below is read by an unconditional module-scope `readFileSync`, OUTSIDE the
 * try/finally — a wrong path does not fail one row, it throws ENOENT before a single row runs.
 */
const FILES = {
    main: path.join(repo, 'dist', 'main.js'),
    index: path.join(repo, 'dist', 'index.js'),
    // Added 2026-08-29 with M44. `server.js` was outside the matrix entirely, so the layer-detection
    // arms were unmeasured — E7-layers had been green since it was written without anything ever
    // showing it could go red. An arm nothing can kill is a claim.
    server: path.join(repo, 'dist', 'server.js'),
    /**
     * ⚠⚠ TWO NON-BUILT TARGETS, ADDED 2026-09-02, AND THE EXTENSION IS THE MAP ENTRY AND NOTHING
     * ELSE. Every mechanism below — the module-scope read, the exact-once anchor preflight, the
     * write, the `finally` restore and the byte-for-byte verification — is keyed off `FILES` and
     * says nothing about what a value points at. `MF1-manifest-schema` and
     * `MF2-manifest-cross-reference` assert `server.json` and `package.json`, which are PRODUCT
     * files that ship (`server.json` is what the MCP Registry reads; `package.json` is the packed
     * manifest) and are simply not produced by `tsc`. An arm on a shipped file that no row can
     * reach is the same ungraded claim `server.js` was in before M44.
     *
     * ⚠⚠ THE RESTORE IS THE ONLY THING THAT MADE THIS WORTH CHECKING TWICE, AND THE FIRST VERSION
     * OF THIS NOTE OVERSTATED IT. `ORIGINAL` captures both files before any row runs and
     * `restoreAll()` rewrites every key from a `finally` — which covers a thrown row and does NOT
     * cover a kill, and "a killed run leaves these two exactly as it found them" is what this said.
     * For `dist/` that gap is survivable (`npm run build` regenerates it); for these two it is not,
     * because nothing regenerates a product file. `BACKUP_DIR` below closes it on disk, outside the
     * process, before the first mutation.
     *
     * ⚠ They are read and restored as TEXT, never parsed and re-serialised — a JSON round-trip
     * would reformat the whole file and the restore-verification would be comparing a reflowed file
     * against itself. The verification itself compares BYTES (`Buffer#equals`), so an encoding that
     * decodes identically but differs on disk cannot pass.
     *
     * ⚠ `package.json` IS ALSO READ BY `scripts/run-tests.mjs` BEFORE THE SUITE, which gates on
     * `name`, `version`, `dependencies['wyrd-fence']` and `engines.node`. A row mutating any of
     * those would redden the harness gate rather than an arm, and would report as a kill that
     * measured nothing about the arm it names. `M95` mutates `mcpName`, which that gate does not
     * read.
     */
    serverjson: path.join(repo, 'server.json'),
    pkgjson: path.join(repo, 'package.json')
};
/**
 * ⚠⚠ THE FILES A KILL CANNOT UNDO, AND THE DIRECTORY THAT CAN.
 *
 * `dist/` is disposable: whatever state a killed run leaves it in, `npm run build` regenerates it
 * from `src/`, which this script never touches. `server.json` and `package.json` are NOT — they are
 * product files `tsc` does not produce, so a run killed between the write and the `finally` leaves
 * a MUTATED MANIFEST on disk that no build repairs. That state is quiet: the tree still parses,
 * `npm test` still runs, and the only tell is a manifest asserting `com.example/not-this-server`.
 *
 * ⚠ THE BACKUP IS WRITTEN OUTSIDE THE PROCESS, BEFORE THE FIRST MUTATION, and its path is printed
 * at the top of every run rather than only in the failure message — a recovery path a reader first
 * meets while recovering is one they have to trust sight unseen.
 *
 * ⚠ THE PATH IS STABLE ACROSS RUNS ON PURPOSE (no pid, no timestamp). The case it exists for is a
 * run that was killed, so the process that could have printed a unique name is the process that is
 * gone; a fixed name means the recovery command is the same one the previous run printed.
 *
 * ⚠⚠ AND THE STABLE PATH IS WHY THE REWRITE IS GUARDED. This comment used to end "it is rewritten
 * at the start of each run from the on-disk pristine bytes, so a stale backup cannot outlive the
 * file it backs" — which described the DEFECT as if it were the safeguard. The bytes on disk are
 * only pristine when the previous run finished. Kill a run mid-row and the tree holds a MUTANT;
 * the next ordinary run then read that mutant as `ORIGINAL_BYTES` and copied it over the one
 * pristine copy in existence, after which `--restore` "restored" the mutant and verified it
 * byte-for-byte against itself. The recovery path destroyed itself through the ordinary path, and
 * reported success doing it. Found by the close-side review 2026-09-03.
 */
const NON_BUILT = Object.freeze(['serverjson', 'pkgjson']);

/**
 * ⚠⚠ PER-CHECKOUT, AND IT WAS A FIXED GLOBAL PATH UNTIL 2026-09-04 — the same defect measured in
 * the fence's matrix and fixed there the same day. `os.tmpdir()` alone gave every checkout of this
 * repo the SAME backup directory, so a run in one left files a run in another refused to overwrite,
 * and the refusal reads as *"the tree is damaged"* rather than as *"you have two checkouts."*
 *
 * ⚠ THE REFUSAL IT WOULD TRIP IS CORRECT AND IS NOT WHAT CHANGED — it is the guard the comment
 * above describes, the one standing between a stale backup and a `--restore` that verifies a mutant
 * against itself. The defect was the SHARED path, so the path is what moved.
 *
 * ⚠ IT STAYS OUTSIDE THE CHECKOUT: these bytes exist to survive a KILLED process, so they cannot
 * live anywhere a clean could take them. Hashing the package's absolute path keeps it outside the
 * tree while making it unique per checkout.
 *
 * ⚠ Fixed here WITHOUT a measured failure in this package, because the shape is identical and
 * waiting for it to bite twice buys nothing. The Scribe's matrix has no `BACKUP_DIR` at all and
 * needs no change — checked, not assumed.
 */
const BACKUP_DIR = path.join(
    os.tmpdir(),
    `wyrd-mutate-backup-${createHash('sha256').update(repo).digest('hex').slice(0, 12)}`,
    'wyrd'
);
const RESTORE_COMMAND = 'npm --workspace wyrd-mcp run mutate -- --restore';
// The mutation record must measure exactly what `npm test` measures, so it goes through the
// same gate — including the zero-skipped and manifest assertions.
const SUITE = [path.join('scripts', 'run-tests.mjs')];
const SUITE_TIMEOUT_MS = 240_000;
/**
 * Every row carries the EXACT transformation. `plan` is what §5a claims kills it; the run records
 * what actually did. Where they differ, that is the finding.
 *
 * ⚠⚠ THERE ARE THREE ROWS HERE AND THERE USED TO BE SIXTY-NINE. The 66 that patch `fsgate` moved
 * to `wyrd-fence/scripts/mutate.mjs` on 2026-09-01 with the arms that kill them — they measured
 * another package's adequacy from inside this one. The three that remain are the three that
 * genuinely patch THIS package's built output: `main.js`, `index.js` and `server.js`.
 *
 * ⚠⚠ AND THIS IS EXACTLY THE SHAPE THAT SILENTLY SHRINKS A MATRIX. A run of three rows scoring 3/3
 * reads identically to a run of sixty-nine scoring 69/69 if nobody looks at the denominator, which
 * is why `verifyMutationRows` below is handed the LIVE `ROWS` and refuses unless they are exactly
 * the rows the relocation contract routes here — and why the root `mutate` runs the fence's matrix
 * as well as this one. Root `mutate` was Reader-only until 2026-09-01; left that way it would have
 * stopped exercising 66 of the 69 rows without a single gate going red.
 */
const ROWS = [
    { id: 'M25', file: 'main', what: 'delete CLI-over-env precedence', plan: 'startup CLI-overrides-env arm',
        from: "const rawGrant = fromArgv !== null ? fromArgv : (deps.env['WYRD_GRANT'] ?? null);",
        to: "const rawGrant = deps.env['WYRD_GRANT'] ?? fromArgv;" },
    // ⚠ `anchors` IS DECLARED HERE BECAUSE THIS ROW CAN MUTATE HALFWAY. The first substitution
    // (`installObserver();`) succeeds on its own, so the whole-file no-op check below would still
    // see a change even if the second anchor had gone stale — a PARTIAL mutant, which runs as a
    // valid row and reports under the id of a thing it did not test. The second anchor is exactly
    // the specifier that changed when the fence moved to `wyrd-fence`, so this row is the one that
    // would have gone quietly wrong.
    { id: 'M27', file: 'index', what: 'instrument AFTER importing the app modules', plan: 'import-time-touch arm',
        anchors: ['installObserver();', "const { createFsGate } = await import('wyrd-fence');"],
        replace: s => s.replace('installObserver();', '')
            .replace("const { createFsGate } = await import('wyrd-fence');",
                "const { createFsGate } = await import('wyrd-fence');\ninstallObserver();") },
    // ⚠ M44 RESTORES A BUG THAT WAS REAL, not a hypothetical one. Layer detection used to take the
    // FIRST case-insensitive match via `.find()`; on a case-sensitive filesystem holding both `arc`
    // and `Arc`, if the listing yielded the FILE first, the real directory beside it was never
    // detected and the disclosure omitted a layer that was there. `.slice(0, 1)` reproduces that
    // exactly — only the first match is considered — without reverting the surrounding rewrite.
    { id: 'M44', file: 'server', what: 'consider only the FIRST case-insensitive layer match', plan: '(added 2026-08-29)',
        from: 'const candidates = entries.filter(entry => entry.name.toLowerCase() === layer.toLowerCase());',
        to: 'const candidates = entries.filter(entry => entry.name.toLowerCase() === layer.toLowerCase()).slice(0, 1);' },

    /* ===========================================================================================
     * M90–M95, ADDED 2026-09-02: SIX ARMS THAT NOTHING GRADED.
     *
     * ⚠⚠ THE STATE THESE ROWS LEAVE. `S14-no-grant-claims`, `E13-read-description`,
     * `E14-surface-claims`, `E15-refusal-vocabulary`, `MF1-manifest-schema` and
     * `MF2-manifest-cross-reference` were all added after the fence move, every one of them
     * because a surface was found carrying a falsehood with no arm on it — and every one then sat
     * in exactly the position the surface had been in: asserted, green, and named by no mutation
     * row. `A54-writeall-loop` and `A55-same-path-replacement` were in that state until
     * `mutationsAddedPostMove` existed; these six were still in it after, because the array was
     * added on the fence side and the Reader's matrix was still the three rows it has held since
     * the move.
     *
     * ⚠ THE RED SETS OVERLAP BY DESIGN AND ARE NOT NARROWED TO LOOK CLEANER. `E14-surface-claims`
     * asserts that the SAME claim appears on every surface that carries it, so a claim deleted
     * from the refusal message reddens both the arm that pins the message and the arm that pins
     * the agreement. Narrowing a row to dodge E14 would mean mutating something no surface claims,
     * which is not a defect any of these arms exists to catch. Every set below was measured twice,
     * identically, on the real machine before it was written into the contract.
     *
     * ⚠⚠ TWO OF THE SIX WERE RETARGETED THE SAME DAY THEY WERE WRITTEN, AND THE SHARED DEFECT IS
     * WORTH MORE THAN EITHER ROW. `M90` and `M91` both went red on their first measurement, both
     * named the right arms, and both were grading the WRONG THING — a cold review lens asked of
     * each row not "does it kill" but "is the CLAIM lost under the mutant", and the answer was no
     * twice. `M91` deleted a qualifying phrase while the description still stated the refusal three
     * other ways, so the arms reddened because their regexes wanted the deleted WORDING; `M90`
     * deleted a clause its target arm pins only incidentally, not one the arm's contract row
     * registers it to assert. Both are the same failure with different faces: A ROW THAT KILLS IS
     * NOT YET A ROW THAT MEASURES. The falsifier that catches it is cheap and is now the standard
     * for anything added here — READ THE MUTATED STRING and ask whether a consumer could still
     * derive the claim from what survives. If they could, the row grades the test, not the product,
     * and a green matrix then certifies exactly the gap it was built to expose.
     */
    // ⚠⚠ RETARGETED 2026-09-02 AFTER A COLD LENS, AND WHAT IT WAS BEFORE IS THE FINDING. This row
    // used to drop `which is not checked` from the WYRD_OBSERVE clause. That does redden `S14`, but
    // `S14`'s CONTRACTED assertion — read the contract row, not the test body — is "both refusals,
    // the outside-reaching hard link, and the scoped read-only", and the observe clause is none of
    // the four; it is `E14`'s cross-surface `OBSERVE_DESTINATION_UNCHECKED` property, which S14
    // happens also to pin. A row that reddens an arm through a claim the arm was not registered for
    // grades the arm's incidental surface area, not its contract.
    //
    // ⚠ THE HARD-LINK WARNING IS THE ONE OF THE FOUR WITH THE MOST TO LOSE. Deleted, the refusal
    // message — the last surface a user reads BEFORE handing over a folder — no longer says that a
    // link already sitting in that folder reaches a file anywhere on the disk, and nothing else in
    // the message implies it: the remaining limits are the TOCTOU swap (needs write access) and the
    // reparse-point classification (explicitly says containment HOLDS). The whole sentence goes,
    // both halves, because the invisible-to-inspection half alone would leave a reader told a link
    // is hidden without being told what it reaches.
    { id: 'M90-no-grant-hardlink-warning', file: 'main',
        what: 'delete the outside-reaching hard-link warning from the no-grant refusal message',
        plan: 'S14-no-grant-claims, E14-surface-claims',
        from: "'Known limits: a hard link that already exists inside the folder makes the file it points at',\n    'readable wherever on the disk that file lives, and ordinary folder inspection will not show',\n    'it as a link. A path component swapped between validation and opening may be read instead of',",
        to: "'Known limits: a path component swapped between validation and opening may be read instead of'," },
    // ⚠⚠ RETARGETED 2026-09-02 AFTER A COLD LENS FOUND IT PROVING STRING MATCHING. It used to drop
    // only the bytes-not-extension QUALIFIER, and under that mutant the description still said the
    // refusal existed ("A requested slice that is not valid UTF-8 is refused with `NOT_TEXT`"),
    // still said reads are byte-oriented into the file's UTF-8 encoding, and still said there is no
    // extension filter — so a consumer could derive the rule from what remained. `E13` and `E14`
    // reddened because their regexes wanted the deleted WORDING, which grades the pin and not the
    // property. A row whose kill survives the claim surviving is measuring the test, not the claim.
    //
    // ⚠ THE WHOLE REFUSAL SENTENCE NOW GOES. Under this mutant nothing in `READ_DESCRIPTION` tells
    // the model that invalid UTF-8 is refused at all — checked against the mutated string rather
    // than assumed: the surviving UTF-8 mentions are the pagination contract (`offset`/`limit` are
    // byte counts into the UTF-8 encoding; a slice ends on a whole codepoint; following
    // `next_offset` reconstructs the text byte for byte), every one of which describes how a
    // SUCCESSFUL read is cut and none of which says a read can be refused for its bytes. The model
    // is left believing any in-scope path returns content, which is the consumer-visible falsehood
    // `NOT_TEXT` exists to prevent — a refused read read as a successful empty one.
    { id: 'M91-read-description-utf8-refusal', file: 'server',
        what: 'delete the invalid-UTF-8 refusal from the `read` tool description entirely',
        plan: 'E13-read-description, E14-surface-claims',
        from: "'are readable. A requested slice that is not valid UTF-8 is refused with',\n    '`NOT_TEXT` rather than returned with substituted characters — a file that comes back altered',\n    'but looks complete is worse than one that is refused. Note this is a property of the BYTES,',\n    'not the file extension: a `.bin` whose contents happen to be valid UTF-8 is returned, and a',\n    '`.md` saved in Latin-1 is refused. Nothing here is a filter on what may be reached.',",
        to: "'are readable. Nothing here is a filter on what may be reached.'," },
    // ⚠ `initialize.instructions` IS E14'S SURFACE AMONG THE THREE ARMS THIS SLICE GRADES — `S14`
    // reads the refusal message and `E13` the tool description — BUT NOT IN THE SUITE, and the
    // first measurement is what said so. `E5-disclosure`, a locked pre-move arm, reads the same
    // string and pins the same clause, so it reddens too. That is recorded rather than dodged: the
    // claim below names both, and the consequence is that no row in this matrix demonstrates E14
    // being reached alone at this surface.
    { id: 'M92-instructions-observe-content', file: 'server',
        what: 'drop the never-file-contents claim from the initialize.instructions disclosure',
        plan: 'E14-surface-claims, E5-disclosure (measured; not predicted)',
        from: "'    pathnames it touches, never file contents, to exactly the path that variable names,',",
        to: "'    pathnames it touches, to exactly the path that variable names,'," },
    // ⚠ A REFUSAL CODE THE TABLE HAS NEVER SEEN, WHICH IS THE DIRECTION THAT ACTUALLY HAPPENS. The
    // arm's other direction — a table row for a code the program no longer returns — is reachable
    // too, but a new refusal class arriving undocumented is the shape that produced this arm.
    { id: 'M93-undocumented-refusal-reason', file: 'server',
        what: 'return a refusal reason no disclosure surface accounts for',
        plan: 'E15-refusal-vocabulary',
        from: "content: [{ type: 'text', text: refusalText('BAD_INPUT', '`path` must be a string.') }]",
        to: "content: [{ type: 'text', text: refusalText('PATH_NOT_A_STRING', '`path` must be a string.') }]" },
    // ⚠ THE TRANSPORT IS CHOSEN BECAUSE `MF2` NEVER READS IT. MF2 cross-references name, version
    // and identifier; a mutation to any of those grades both arms and says nothing about whether
    // the SCHEMA validation ran at all. `anyOf` is also the constraint family MF1's in-arm bite
    // check exercises, so a row that came back SURVIVED here would mean the validator had stopped
    // reaching the manifest rather than that the constraint had gone.
    { id: 'M94-manifest-transport-invalid', file: 'serverjson',
        what: 'declare a transport type the registry schema admits no alternative for',
        plan: 'MF1-manifest-schema',
        from: '"transport": {\n        "type": "stdio"\n      }',
        to: '"transport": {\n        "type": "carrier-pigeon"\n      }' },
    // ⚠ `mcpName` IS THE ROW WITH TEETH AND THE ONE THE HARNESS GATE DOES NOT READ. The registry
    // proves npm ownership by reading it out of the PUBLISHED tarball and requiring it to equal
    // the manifest's `name`, so a disagreement refuses the submission AFTER the publish. Mutating
    // `name` or `version` here would instead redden `scripts/run-tests.mjs`'s own manifest gate,
    // which runs before a single arm does.
    { id: 'M95-manifest-mcpname-disagrees', file: 'pkgjson',
        what: 'break the mcpName the registry reads out of the published tarball',
        plan: 'MF2-manifest-cross-reference',
        from: '"mcpName": "com.wyrdmcp/wyrd",',
        to: '"mcpName": "com.example/not-this-server",' },
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

/** Where a given file key's pristine bytes are kept. Basename only — the keys are already unique. */
function backupPathFor(key) {
    return path.join(BACKUP_DIR, path.basename(FILES[key]));
}

/**
 * ⚠⚠ `--restore`, AND IT RUNS BEFORE EVERY OTHER GATE IN THIS FILE.
 *
 * The state it exists for is a tree whose `package.json` is mutated, and several things upstream of
 * a normal run read that file: `loadContract` parses the contract beside it, `scripts/run-tests.mjs`
 * gates on `name`/`version`/`dependencies`/`engines`. A recovery mode that first has to pass the
 * checks the damage breaks is not a recovery mode, so this exits before the contract block below.
 *
 * ⚠ IT RESTORES ONLY THE NON-BUILT TARGETS, WHICH IS THE WHOLE POINT AND IS SAID OUT LOUD. `dist/`
 * is not backed up and is not restored here; `npm run build` is its recovery and always was. This
 * closes the half that had none.
 */
if (process.argv.slice(2).includes('--restore')) {
    if (!fs.existsSync(BACKUP_DIR)) {
        console.error(`⛔ no backup directory at ${BACKUP_DIR} — nothing to restore from.`);
        console.error('   A backup is written at the start of every mutate run; if none exists, no run has been started since this tree was checked out.');
        process.exit(1);
    }
    const restoredNow = [];
    const missing = [];
    for (const key of NON_BUILT) {
        const from = backupPathFor(key);
        if (!fs.existsSync(from)) { missing.push(`${key} (${from})`); continue; }
        const pristine = fs.readFileSync(from);
        const onDisk = fs.existsSync(FILES[key]) ? fs.readFileSync(FILES[key]) : null;
        const changed = onDisk === null || !onDisk.equals(pristine);
        fs.writeFileSync(FILES[key], pristine);
        // ⚠ VERIFIED AFTER WRITING, not assumed from the write returning. The one thing this mode
        // must never do is report a repair it did not make.
        if (!fs.readFileSync(FILES[key]).equals(pristine)) {
            console.error(`⛔ ${FILES[key]} still differs from its backup after being rewritten.`);
            process.exit(1);
        }
        restoredNow.push(`${changed ? 'RESTORED ' : 'already ok'}  ${FILES[key]}`);
    }
    if (missing.length) {
        console.error(`⛔ the backup directory has no copy of: ${missing.join(', ')}`);
        process.exit(1);
    }
    console.log(`[restore] from ${BACKUP_DIR}`);
    for (const line of restoredNow) console.log(`[restore] ${line}`);
    console.log('[restore] byte-for-byte verified against the backup.');
    process.exit(0);
}

/**
 * ⚠⚠ THE RELOCATION CONTRACT, BEFORE A SINGLE BYTE OF `dist/` IS TOUCHED.
 *
 * The duplicate check above proves the matrix agrees with itself. It cannot notice a row that is
 * simply gone, and the fence relocation was exactly the operation that took rows away: 66 of the
 * 69 left for `wyrd-fence` on 2026-09-01. `test/relocation-contract.json` is the outside referent,
 * written before anything moved, with no generator that could bring it into agreement with a
 * shorter list — which is what makes a three-row matrix here provable rather than merely asserted.
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
    const rowProblems = verifyMutationRows(contract, 'wyrd', ROWS.map(row => ({ id: row.id, file: row.file ?? 'fsgate', mutates: row.what, plan: row.plan })));
    if (rowProblems.length) refuse(rowProblems, "this package's mutation matrix does not match the pre-move contract");
    console.log(`· relocation contract: ${ROWS.length} mutation rows declared here, of ${contract.totals.mutations} locked pre-move`);
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
/**
 * ⚠⚠ THE SAME FILES AS BYTES, AND THE DECODED COPY ABOVE IS NOT A SUBSTITUTE FOR THIS ONE.
 *
 * The rows do string surgery, so `ORIGINAL` has to be text. The restore VERIFICATION must not be:
 * comparing decoded strings passes a file whose bytes differ but whose decoding does not — a BOM
 * dropped or added, an invalid sequence normalised to U+FFFD on the way in and written back as the
 * replacement character's own encoding. Both are byte-level corruption of a file that ships, and
 * both read as a clean restore through `readFileSync(p, 'utf8')`. `Buffer#equals` cannot.
 */
const ORIGINAL_BYTES = Object.fromEntries(Object.entries(FILES).map(([k, p]) => [k, fs.readFileSync(p)]));

// ⚠ THE BACKUP, WRITTEN BEFORE ANY ROW RUNS AND PRINTED WHETHER OR NOT ANYTHING GOES WRONG.
// It is the only copy of the non-built targets that outlives a killed process; see `BACKUP_DIR`.
{
    fs.mkdirSync(BACKUP_DIR, { recursive: true });

    /**
     * ⚠⚠ A DIFFERING BACKUP IS A REFUSAL, NEVER AN OVERWRITE, AND THE REASON IS THAT THIS SCRIPT
     * CANNOT TELL THE TWO CAUSES APART.
     *
     * If a backup already exists and its bytes differ from what is on disk now, exactly one of two
     * things happened, and they want opposite repairs:
     *   · a previous run was KILLED mid-row, so the tree holds a mutant and the BACKUP is the good
     *     copy — `--restore` is the fix, and overwriting the backup destroys the only pristine bytes;
     *   · someone legitimately EDITED the file since the last run, so the tree is the good copy and
     *     the backup is merely old — deleting the backup directory is the fix.
     * Nothing available here distinguishes them: both look like "these bytes differ". Guessing gets
     * one of the two catastrophically wrong, silently, in the recovery path. So it refuses and hands
     * the operator both exits.
     */
    const conflicts = [];
    for (const key of NON_BUILT) {
        const backup = backupPathFor(key);
        if (!fs.existsSync(backup)) continue;
        if (!fs.readFileSync(backup).equals(ORIGINAL_BYTES[key])) conflicts.push({ key, backup });
    }
    if (conflicts.length) {
        console.error('⛔ REFUSING TO OVERWRITE A PRISTINE BACKUP THAT DISAGREES WITH THE TREE.');
        for (const { key, backup } of conflicts) {
            console.error(`   · ${FILES[key]}`);
            console.error(`     differs from its backup at ${backup}`);
        }
        console.error('\n   Either a run was killed mid-mutation (the TREE holds a mutant) or the file');
        console.error('   was edited since the last run (the BACKUP is merely stale). This script');
        console.error('   cannot tell which, and guessing wrong destroys the only pristine copy.');
        console.error(`\n   Tree is damaged  ->  ${RESTORE_COMMAND}`);
        console.error(`   Backup is stale  ->  delete ${BACKUP_DIR}`);
        process.exit(2);
    }

    for (const key of NON_BUILT) fs.writeFileSync(backupPathFor(key), ORIGINAL_BYTES[key]);
    console.log(`· pristine backup of ${NON_BUILT.map(k => path.basename(FILES[k])).join(' and ')}: ${BACKUP_DIR}`);
    console.log(`  If this run is killed, \`${RESTORE_COMMAND}\` puts them back; \`npm run build\` covers dist/.`);
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

/**
 * ⚠ RESTORES FROM THE PRISTINE BYTES, NOT THE DECODED TEXT. The verification below compares with
 * `Buffer#equals`, so writing back `ORIGINAL[key]` would mean the restore and its own check were
 * two different objects — a lossy decode would be written faithfully and then reported as a failed
 * restore, or worse, a byte difference the string comparison could not see would be written back.
 * One source of truth for both.
 */
function restoreAll() {
    for (const [key, file] of Object.entries(FILES)) fs.writeFileSync(file, ORIGINAL_BYTES[key]);
}

function runSuite() {
    try {
        const out = execFileSync(process.execPath, [...SUITE],
            { cwd: repo, encoding: 'utf8', timeout: SUITE_TIMEOUT_MS, stdio: ['ignore', 'pipe', 'pipe'] });
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
 * information if the suite is GREEN without one — against a suite that was already failing, every one of
 * row comes back KILLED and the matrix reports a perfect score for a measurement it never made.
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
            // ⚠ FUNCTION REPLACERS: a string `t` or `row.to` would expand `$&`, `$'`, `$n` and the backtick form,
            // and mutation text is JS source. A corrupted patch still differs from `source`, so the
            // ANCHOR-NOT-FOUND check below cannot see it.
            mutated = row.edits.reduce((acc, [f, t]) => acc.replace(f, () => t), source);
        } else {
            mutated = source.replace(row.from, () => row.to);
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
    // ⚠ BYTES, NOT DECODED TEXT — see `ORIGINAL_BYTES`. The string comparison this replaced passed
    // any corruption that survived a UTF-8 round trip, in files that ship.
    const dirty = Object.entries(FILES).filter(([k, p]) => !fs.readFileSync(p).equals(ORIGINAL_BYTES[k]));
    restored = dirty.length === 0;
    if (!restored) {
        // ⚠ THE RECOVERY LINE NAMES THE RIGHT INSTRUMENT PER FILE, AND IT USED TO NAME ONE FOR ALL.
        // "run `npm run build`" is the whole repair for `dist/` and NO repair at all for the two
        // manifests, which is exactly the pair this message is most likely to be printed about.
        console.error(`\n⚠⚠ RESTORE FAILED for: ${dirty.map(([k]) => path.relative(repo, FILES[k])).join(', ')}`);
        if (dirty.some(([k]) => NON_BUILT.includes(k))) {
            console.error(`   Product manifests do not rebuild. Run: ${RESTORE_COMMAND}`);
            console.error(`   (pristine bytes are at ${BACKUP_DIR})`);
        }
        if (dirty.some(([k]) => !NON_BUILT.includes(k))) {
            console.error('   Run `npm run build` before trusting dist/.');
        }
        process.exitCode = 1;
    } else if (!jsonOut) {
        console.log('[restore] every mutation target restored byte-for-byte: true\n');
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
    const { problems, notes } = verifyMutationResults(CONTRACT, 'wyrd', results, { full: !selected, restored });
    for (const note of notes) console.error(`  ⚠ STALE CONTRACT ROW — ${note}`);
    if (problems.length) refuse(problems, 'the mutation run does not match the pre-move contract');
    if (!jsonOut) {
        console.log('✔ relocation contract: every contracted row produced a result, and every contracted kill was a kill.');
    }
}
