#!/usr/bin/env node
/**
 * THE MUTATION MATRIX, EXECUTED.
 *
 * `designs/2026-08-27-s2-fence-plan.md` §5a is a table of claims: each row names a mutation and
 * the arm that must go red. A table is not evidence. This script applies each mutation to the
 * BUILT output, runs the whole suite, and records which named tests actually failed.
 *
 *   npm run mutate                             fresh build, then all rows
 *   node scripts/mutate.mjs                    fresh build, then all rows
 *   npm run mutate -- --only M8,M13            selected rows
 *   npm run mutate -- --json                   machine-readable record
 *   node scripts/mutate.mjs --selftest          write-free suite-result classifier self-test
 *   npm run mutate -- --restore                put the non-built targets back from the on-disk backup
 *
 * ⚠ It builds first, edits the files in `FILES` in place and restores them in a `finally`,
 *   verifying the restore byte-for-byte. It never touches `src/`.
 *
 * ⚠⚠ A `finally` DOES NOT RUN WHEN THE PROCESS IS KILLED, and until 2026-09-02 that was the whole
 *   recovery story. `dist/` survives that because `npm run build` regenerates it; `server.json` and
 *   `package.json` DO NOT — they are product files `tsc` does not produce, so a hard kill mid-row
 *   left a mutated manifest on disk with no instrument able to put it back and a recovery note
 *   ("rebuild") that could not. `BACKUP_DIR` under `os.tmpdir()` now holds the pristine bytes of
 *   every non-built target, written before the first mutation and printed at the top of every run;
 *   `--restore` copies them back byte-exactly. See `BACKUP_DIR` below.
 *
 * ⚠ A row contracted EQUIVALENT or NO-KILLING-ARM is the honest output, not a gap to be papered
 *   over by weakening an arm. §5a exists to surface exactly those.
 *
 * ⚠⚠ THOSE TWO ARE CONTRACT VALUES, NOT RUNNER STATUSES, AND THE DISTINCTION IS LOAD-BEARING.
 *   THIS RUNNER EMITS `KILLED`, `SURVIVED`, `ANCHOR-NOT-FOUND` AND THE INSTRUMENT ERRORS — it
 *   cannot emit either of them, because neither is observable: both are CLAIMS ABOUT WHY a mutant
 *   survived. They are declared in `relocation-contract.json` as `expectedDisposition` and graded
 *   by `verify-relocation-contract.mjs`, which requires a substantive `why` with each and REFUSES
 *   if such a row is ever killed — a kill falsifies the argument rather than merely staling it.
 *
 *   ⚠ Until 2026-09-15 this comment promised those two statuses and NOTHING implemented them:
 *   neither string appeared anywhere else in this file or at all in the verifier, so a maintainer
 *   who reached an honest non-kill had `SURVIVED` plus prose — the exact papering-over the line
 *   above warns against. Ruled 2026-09-15, option A: carry them for real. The lesson worth
 *   keeping is that a comment asserting a capability is read as the capability; nothing checked
 *   this claim for as long as it was false.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { ALL_ARMS } from '../test/arms.mjs';
import { loadContract, verifyMutationRows, verifyMutationResults, refuse } from './verify-relocation-contract.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const selftestMode = args.includes('--selftest');
const restoreMode = args.includes('--restore');
const jsonOut = args.includes('--json');
const onlyArg = args.find(a => a.startsWith('--only'));
const only = onlyArg ? (onlyArg.includes('=') ? onlyArg.split('=')[1] : args[args.indexOf(onlyArg) + 1]) : null;

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
 * ⚠ Every value below is read inside `runMatrix()` after its mandatory build, OUTSIDE the
 * try/finally — a wrong path does not fail one row, it throws ENOENT before a single row runs.
 */
const FILES = {
    auth: path.join(repo, 'dist', 'auth.js'),
    http: path.join(repo, 'dist', 'http.js'),
    main: path.join(repo, 'dist', 'main.js'),
    index: path.join(repo, 'dist', 'index.js'),
    /**
     * ⚠ TWO BUILT TLS TARGETS. `cert.js` is the certificate grammar, generation and write
     * implementation exercised by H25–H28; `tls-config.js` is the TLS argument, material-validation
     * and metadata implementation exercised by H28–H30. Without these keys, rows for those claims
     * cannot reach the code they are meant to grade. Both files come from `src/` through `tsc`, so a
     * rebuild recovers them; adding them to `NON_BUILT` would incorrectly treat disposable output as
     * an irreplaceable product file.
     */
    cert: path.join(repo, 'dist', 'cert.js'),
    tlsconfig: path.join(repo, 'dist', 'tls-config.js'),
    // Added 2026-08-29 with M44. `server.js` was outside the matrix entirely, so the layer-detection
    // arms were unmeasured — E7-layers had been green since it was written without anything ever
    // showing it could go red. An arm nothing can kill is a claim.
    server: path.join(repo, 'dist', 'server.js'),
    /**
     * ⚠⚠ TWO NON-BUILT TARGETS, ADDED 2026-09-02, AND THE EXTENSION IS THE MAP ENTRY AND NOTHING
     * ELSE. Every mechanism below — the post-build read, the exact-once anchor preflight, the
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
 * ⚠⚠ SIXTY-SIX OF THE ORIGINAL SIXTY-NINE ROWS MOVED. The rows that patch `fsgate` moved to
 * `wyrd-fence/scripts/mutate.mjs` on 2026-09-01 with the arms that kill them — they measured another
 * package's adequacy from inside this one. Reader-owned rows added since remain here and are held by
 * the post-move contract below.
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
    // M44 stays on the same Reader-owned layer decision after the listing was removed. Dropping the
    // conservative link case makes an unusual still-classified reparse point disappear from the
    // warning, which is the same wrong-direction disclosure failure this row has always graded.
    { id: 'M44', file: 'server', what: 'ignore a layer whose successful probe still classifies it as a link', plan: 'E7-shadow',
        from: "if (result.kind === 'directory' || result.kind === 'link')",
        to: "if (result.kind === 'directory')" },

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
     * added on the fence side while the Reader's matrix still held only the three rows retained at
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
    // ⚠⚠ THIS COMMENT'S PREMISE WENT STALE ON 2026-09-14 AND THE MEASUREMENT SAYS SO. It read:
    // "THE TRANSPORT IS CHOSEN BECAUSE `MF2` NEVER READS IT." MF2 reads it now — the Reader gaining
    // HTTP is exactly when that could start drifting, so `manifest-schema.test.js:177` asserts the
    // policy "this manifest advertises stdio and nothing else" across the WHOLE document: every
    // package transport, argument route and remote entry. The measured red set for this row is
    // `MF1` AND `MF2`, which is the reading the old comment predicted could not happen.
    //
    // ⚠ THE ROW IS STILL SOUND AND THE SELECTION REASONING SURVIVES, which is why this is a comment
    // repair rather than a retarget. `carrier-pigeon` violates schema conformance (MF1) and the
    // stdio-only policy (MF2) at once, so both reds are genuine claim losses rather than one arm
    // tripping on the other's wording. `anyOf` remains the constraint family MF1's in-arm bite
    // check exercises, so a SURVIVED here would still mean the validator had stopped reaching the
    // manifest rather than that the constraint had gone.
    //
    // ⚠ FOUND BY A COLD READ ASKING "IS THE CLAIM LOST?", NOT BY ANY SUITE — a comment stating why
    // a row was chosen is not re-run, so it can contradict the live behaviour indefinitely. Same
    // class as the surface claims this package instruments for PRESENCE rather than truth.
    { id: 'M94-manifest-transport-invalid', file: 'serverjson',
        what: 'declare a transport type the registry schema admits no alternative for',
        plan: 'MF1-manifest-schema',
        // ⚠ ONE LINE, BECAUSE A MULTI-LINE ANCHOR IN A CHECKED-IN JSON FILE IS LINE-ENDING
        // DEPENDENT. The original spanned three lines with `\n`; the committed blob is LF but
        // `core.autocrlf` gives every Windows checkout CRLF on disk, so the anchor could never
        // match here and the row reported ANCHOR-NOT-FOUND rather than a verdict. Measured
        // 2026-09-14. A single-line anchor has no separator in it and matches either way.
        from: '"type": "stdio"',
        to: '"type": "carrier-pigeon"' },
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

    { id: 'M109-layer-root-listing-restored', file: 'main',
        what: 'restore a grant-root listing before the three layer probes',
        plan: 'S16-layer-probes',
        from: 'const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name));',
        to: 'await gate.listGrantRoot();\n    const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name));' },

    { id: 'M110-auth-denial-bypassed', file: 'http',
        what: 'bypass the unauthenticated decision and continue to body collection and handler.fetch',
        plan: 'H15-auth-401-no-tool, H24-network-plain-http-auth',
        from: "if (authDecision.kind === 'unauthenticated') {\n        incoming.pause();",
        to: "if (false && authDecision.kind === 'unauthenticated') {\n        incoming.pause();" },
    { id: 'M111-auth-denial-is-403', file: 'http',
        what: 'map unauthenticated to 403 instead of the fixed 401',
        plan: 'H15-auth-401-no-tool, H24-network-plain-http-auth',
        // ⚠ The anchor is the BUILT output, not the source. The first version of this row carried
        // the four-space-indented multi-line source shape and came back ANCHOR-NOT-FOUND: `tsc`
        // emits this call on one line. A row that cannot find its anchor measures nothing, and the
        // runner reports that rather than a false KILLED — which is the only reason it was caught.
        from: "sendStatus(outgoing, 401, 'Authentication required. Send Authorization: Bearer <Reader token>.\\n'",
        to: "sendStatus(outgoing, 403, 'Authentication required. Send Authorization: Bearer <Reader token>.\\n'" },
    { id: 'M112-verifier-injection-ignored', file: 'main',
        what: 'ignore the injected verifier factory and install the production verifier directly',
        plan: 'H16-verifier-injection-real-socket',
        from: 'const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;',
        to: 'const makeReadAuthInfo = createReadTokenVerifier;' },
    { id: 'M113-query-routed-by-pathname', file: 'http',
        what: 'route by pathname and accept a query string on /mcp',
        plan: 'H17-no-query-token-or-leak',
        from: "if (incoming.url !== '/mcp') {",
        to: "if (new URL(incoming.url ?? '/', 'http://localhost').pathname !== '/mcp') {" },
    { id: 'M114-token-appended-to-disclosure', file: 'main',
        what: 'append the configured Reader token to the HTTP startup disclosure',
        plan: 'H17-no-query-token-or-leak',
        from: 'deps.stderr(httpDisclosure(handle, gate.disclosedRoot()));',
        to: "deps.stderr(`${httpDisclosure(handle, gate.disclosedRoot())}\\n${readToken.token.toString('base64url')}`);" },
    { id: 'M115-missing-token-listens', file: 'main',
        what: 'replace missing-token startup refusal with an unauthenticated listener',
        plan: 'H18-no-token-refuses-before-listen',
        from: "if (!readToken.ok) {\n            deps.stderr(`wyrd: refusing to start — ${readToken.detail}`);\n            deps.setExitCode(2);\n            return { started: false, reason: 'READ_TOKEN', http: null };\n        }\n        const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;\n        const readAuthInfo = makeReadAuthInfo(readToken.token);",
        to: "const readAuthInfo = readToken.ok\n            ? (deps.makeReadAuthInfo ?? createReadTokenVerifier)(readToken.token)\n            : () => ({\n                kind: 'authenticated',\n                authInfo: { token: '', clientId: 'unauthenticated', scopes: [] }\n            });" },
    { id: 'M116-cert-overwrite-not-exclusive', file: 'cert',
        what: 'open the certificate destinations for overwrite instead of exclusive creation',
        plan: 'H26-cert-exclusive-write',
        edits: [
            [
                'activeHandle = await fs.open(certificatePath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o644);',
                'activeHandle = await fs.open(certificatePath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC, 0o644);'
            ],
            [
                'activeHandle = await fs.open(privateKeyPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);',
                'activeHandle = await fs.open(privateKeyPath, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC, 0o600);'
            ]
        ] },
    { id: 'M117-requested-san-dropped', file: 'cert',
        what: 'drop the requested host from the generated certificate SAN extension',
        plan: 'H27-cert-content-and-freshness',
        from: "        { type: host.kind === 'dns' ? 2 : 7, value: host.canonical },\n",
        to: '' },
    { id: 'M118-tls-selects-http-server', file: 'http',
        what: 'select http.createServer while validated TLS material is present',
        plan: 'H28-generated-cert-trust-control',
        from: 'https.createServer(configuration.serverOptions, requestListener)',
        to: 'http.createServer(requestListener)' },
    { id: 'M119-tls-metadata-says-http', file: 'http',
        what: 'emit http scheme metadata for a TLS listener',
        plan: 'H30-tls-disclosure',
        from: '            scheme: tls.scheme,',
        to: "            scheme: 'http'," },
    { id: 'M120-cleartext-warning-unconditional', file: 'main',
        what: 'print the clear-text bearer-token warning unconditionally under TLS',
        plan: 'H30-tls-disclosure',
        from: '            `Certificate expires: ${handle.endpoint.certificate.validTo}.`',
        to: "            `Certificate expires: ${handle.endpoint.certificate.validTo}.`,\n            '  · TLS is off, so the bearer token travels in the clear and can be replayed by',\n            '    anyone who captures it.'" },
    { id: 'M121-tls-handshake-socket-untracked', file: 'http',
        what: 'skip listener-level tracking for sockets stalled during the TLS handshake',
        plan: 'H31-tls-handshake-shutdown',
        from: "    listener.on('connection', socket => {\n",
        to: "    listener.on('connection', socket => {\n        if (tls !== null) return;\n" },
    { id: 'M122-response-body-buffered', file: 'http',
        what: 'buffer the complete fetch response body before ending the HTTP response',
        plan: 'H19-response-stream',
        from: 'await pipeline(Readable.fromWeb(source.body), target);',
        to: 'target.end(await source.text());' },
    { id: 'M123-read-window-halved', file: 'server',
        what: 'halve the maximum read-window clamp',
        plan: 'H20-localhost-read-budget, H19-response-stream',
        from: 'const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES);',
        to: 'const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES / 2);' },
    { id: 'M124-read-offset-dropped', file: 'server',
        what: 'drop the requested offset forwarded to the fence read',
        plan: 'H20-localhost-read-budget, E17-v1-raw-baseline',
        from: 'const slice = await fsgate.readFileInGrant(target, offset, limit);',
        to: 'const slice = await fsgate.readFileInGrant(target, 0, limit);' },
    { id: 'M125-origins-manually-serialized', file: 'http',
        what: 'manually concatenate allowed origins instead of using URL serialization',
        plan: 'H21-origin-serialization',
        from: 'return Object.freeze(hosts.map(interfaceAddress => httpEndpointUrl(Object.freeze({ ...endpoint, interfaceAddress }), port).origin));',
        to: "return Object.freeze(hosts.map(interfaceAddress => `${endpoint.scheme}://${urlHost(interfaceAddress)}:${port}`));" },
    { id: 'M126-ipv6-url-host-unbracketed', file: 'http',
        what: 'return a bare IPv6 address instead of bracketing it for URL serialization',
        plan: 'H21-origin-serialization',
        from: "return bare.includes(':') ? `[${bare}]` : bare;",
        to: 'return bare;' },
    { id: 'M127-network-consent-disabled', file: 'main',
        what: 'disable refusal of a non-loopback HTTP address without public consent',
        plan: 'H22-consent-and-guards, H1-transport-selection',
        from: 'if (!publicRequested) {',
        to: 'if (false && !publicRequested) {' },
    { id: 'M128-bind-kind-host-mismatch-disabled', file: 'http',
        what: 'disable the pre-handler bind kind and host mismatch guard',
        plan: 'H22-consent-and-guards',
        from: "if ((requestedKind === 'loopback') !== requestedLoopback) {",
        to: "if (false && (requestedKind === 'loopback') !== requestedLoopback) {" },
    { id: 'M129-reported-address-mismatch-dropped', file: 'http',
        what: 'drop the reported-address mismatch from the post-bind guard',
        plan: 'H22-consent-and-guards',
        from: 'if (refusal !== null || reportedAddress !== requestedAddress) {',
        to: 'if (refusal !== null) {' },
    { id: 'M130-plain-http-disclosure-exposure-inverted', file: 'main',
        what: 'invert the loopback and network branches of the plain-HTTP disclosure',
        plan: 'H23-network-disclosure-honesty',
        from: "    if (handle.endpoint.exposure === 'loopback') {\n        return [\n            `wyrd Reader is listening only on this machine, through the loopback interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,\n            `Endpoint: ${endpoint.href}.`,\n            'Transport: plain HTTP. TLS is off.',",
        to: "    if (handle.endpoint.exposure !== 'loopback') {\n        return [\n            `wyrd Reader is listening only on this machine, through the loopback interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,\n            `Endpoint: ${endpoint.href}.`,\n            'Transport: plain HTTP. TLS is off.'," },
    { id: 'M131-cert-idna-canonicalization-dropped', file: 'cert',
        what: 'lowercase the raw certificate hostname without IDNA canonicalization',
        plan: 'H25-cert-host-grammar, H27-cert-content-and-freshness',
        from: 'const ascii = domainToASCII(raw).toLowerCase();',
        to: 'const ascii = raw.toLowerCase();' },
    { id: 'M132-cert-ipv4-wildcard-refusal-disabled', file: 'cert',
        what: 'disable refusal of the IPv4 wildcard certificate host',
        plan: 'H25-cert-host-grammar',
        from: "if (host === '0.0.0.0')",
        to: "if (false && host === '0.0.0.0')" },
    { id: 'M133-tls-key-match-check-disabled', file: 'tlsconfig',
        what: 'disable the TLS certificate and private-key match check',
        plan: 'H29-tls-startup-validation',
        from: 'if (!certificate.checkPrivateKey(privateKey)) {',
        to: 'if (false && !certificate.checkPrivateKey(privateKey)) {' },
    { id: 'M134-tls-expiry-boundary-exclusive', file: 'tlsconfig',
        what: 'accept a TLS certificate at its exact expiry boundary',
        plan: 'H29-tls-startup-validation',
        from: 'if (nowMs >= validToMs)',
        to: 'if (nowMs > validToMs)' },
    { id: 'M135-cert-serial-fixed', file: 'cert',
        what: 'replace the generated certificate serial number with a fixed valid serial',
        plan: 'H27-cert-content-and-freshness',
        from: 'certificate.serialNumber = randomSerial(serialRandomBytes);',
        to: "certificate.serialNumber = '01';" },
    // ⚠ This row exists because H32 was the one arm the selection round dropped: a cold redesign
    // proposed it under the id `M135`, the incumbent plan used that id for H27 freshness, and the
    // count delta was recorded as a numbering difference rather than a missing arm. Reconcile
    // candidate designs by ARM, never by id.
    { id: 'M136-transport-forced-stdio', file: 'main',
        what: 'report the stdio transport to the configured Reader factory even when HTTP is listening',
        // H1 is claimed as MEASURED collateral, not predicted: the first run reported it as an
        // unclaimed red with `'stdio' !== 'http'`. That is a real loss of H1's own selection claim
        // from the same one-line mutation, so it is named rather than narrowed around.
        plan: 'H32-network-instructions-truth, H1-transport-selection',
        from: "const transport = httpArg.present ? 'http' : 'stdio';",
        to: "const transport = 'stdio';" },
];

/** Named registered arms that went red, as the runner printed them. */
function redTests(out) {
    const named = [...out.matchAll(/^✖ (.+?) \([\d.]+ms\)\r?$/gm)]
        .map(match => match[1].split(' — ')[0].trim());
    return [...new Set(named.filter(id => Object.hasOwn(ALL_ARMS, id)))];
}

/**
 * The failing DETAIL behind each red arm, keyed by arm id.
 *
 * ⚠⚠ WHY THIS EXISTS, AND IT IS A MEASURED COST RATHER THAN A NICETY. `redTests` above keeps the
 * NAME and discards everything else, so when an arm reddens that no row declared, the run records
 * THAT it happened and never WHY. On 2026-09-15 that cost two full capture loops and left three
 * hypotheses unfalsifiable: `H29` under `M113` (twice, undiagnosed), `H27` under `M119`, and `H28`
 * under `M109` — the last at a measured 1 run in 10. Each time the arm name was all that survived,
 * and each time the next step was "run it again and hope", which is the most expensive way to
 * learn anything.
 *
 * ⚠ BOUNDED ON PURPOSE. A cap per arm and a cap on arms, because the alternative — keeping the
 * whole suite output — turns every refusal into a wall nobody reads, and this file already carries
 * the lesson that a refusal a reconciler learns to scroll past has stopped being a refusal.
 *
 * ⚠ This is DIAGNOSTIC ONLY. It never decides a disposition, never feeds `expectedRed`, and must
 * never become an input to grading: an arm's failure TEXT is not a claim about the product, and a
 * gate that read it would be gating on a message rather than on a property.
 */
// ⚠ 900, not 400. Raised once the bodies were actually located: a real node:test failure carries
// the AssertionError line, an expected/actual diff and a stack frame, and 400 cut the diff off
// mid-way — which would have shipped a diagnostic that truncates exactly the part worth reading.
const RED_DETAIL_CHARS = 900;
const RED_DETAIL_ARMS = 6;
function redDetails(out, ids) {
    const detail = {};
    for (const id of ids.slice(0, RED_DETAIL_ARMS)) {
        // node:test prints the failure body indented beneath the ✖ line, up to the next ✖/✔ at
        // column 0. Anchor on this arm's own line so a neighbour's failure is never attributed here.
        // ⚠⚠ ANCHOR IN THE `✖ failing tests:` SECTION, NOT ON THE FIRST OCCURRENCE OF THE ARM.
        // MEASURED 2026-09-15 with a deliberately failing probe test, after four wrong guesses:
        // `node --test` prints each failure TWICE on STDOUT. First an inline headline as the arm
        // runs — `✖ <name> (1.23ms)` and nothing else — then, AFTER the `ℹ` summary counts, a
        // `✖ failing tests:` section that repeats each headline followed by the real body: the
        // AssertionError, the expected/actual diff, the stack.
        //
        // ⚠ THE FIRST VERSION OF THIS FUNCTION ANCHORED ON `out.indexOf('✖ ' + id)`, which finds
        // the INLINE headline every time, so it captured exactly the one line that was never
        // missing and looked like it worked. The body was on stdout the whole time. (Neither was
        // stderr the culprit: the probe measured 0 bytes on stderr for a failing run.)
        const section = out.indexOf('✖ failing tests:');
        const hay = section === -1 ? out : out.slice(section);
        const start = hay.indexOf(`✖ ${id}`);
        if (start === -1) continue;
        const rest = hay.slice(start);
        // Boundary: the next failure's headline in this same section, anchored to a line start.
        const boundary = rest.slice(1).search(/\n✖ /);
        const body = (boundary === -1 ? rest : rest.slice(0, boundary + 1)).trim();
        if (body.length > RED_DETAIL_CHARS) {
            detail[id] = `${body.slice(0, RED_DETAIL_CHARS)}… [truncated at ${RED_DETAIL_CHARS} chars]`;
        } else {
            detail[id] = body;
        }
    }
    return detail;
}

/** Classify execution separately from mutation disposition. */
function classifySuiteResult({ error = null, out = '' } = {}) {
    if (error === null) return { outcome: 'GREEN', out, red: [] };

    const captured = [error.stdout, error.stderr]
        .filter(part => part !== undefined && part !== null)
        .map(part => typeof part === 'string' ? part : part.toString('utf8'))
        .join('');
    if (error.code === 'ETIMEDOUT' || error.killed) {
        return { outcome: 'TIMEOUT', out: captured, red: [] };
    }
    if (error.signal) return { outcome: 'SIGNAL', out: captured, red: [] };

    const red = redTests(captured);
    return {
        outcome: red.length > 0 ? 'ARM_RED' : 'NONZERO_NO_ARM',
        out: captured,
        red,
        redDetail: red.length > 0 ? redDetails(captured, red) : {}
    };
}

function runClassifierSelfTest() {
    const armLine = '✖ S1-no-grant — synthetic failure (1.25ms)\n';
    const cases = [
        ['clean exit', classifySuiteResult({ out: 'clean\n' }), 'GREEN'],
        ['registered arm failure', classifySuiteResult({ error: { stdout: armLine, stderr: '' } }), 'ARM_RED'],
        ['timeout', classifySuiteResult({ error: { code: 'ETIMEDOUT', signal: 'SIGTERM', stdout: armLine } }), 'TIMEOUT'],
        ['signal', classifySuiteResult({ error: { signal: 'SIGKILL', stdout: armLine } }), 'SIGNAL'],
        ['nonzero without an arm', classifySuiteResult({ error: { stdout: '✖ not-a-registered-arm — synthetic failure (2ms)\n', stderr: '' } }), 'NONZERO_NO_ARM']
    ];
    for (const [name, actual, expected] of cases) {
        if (actual.outcome !== expected) {
            throw new Error(`classifier self-test failed for ${name}: expected ${expected}, got ${actual.outcome}`);
        }
    }
    if (cases[1][1].red.join(',') !== 'S1-no-grant') {
        throw new Error(`classifier self-test failed to retain the registered arm: ${cases[1][1].red.join(',')}`);
    }
    console.log('✔ mutation suite classifier self-test: 5/5 outcomes correct (GREEN, ARM_RED, TIMEOUT, SIGNAL, NONZERO_NO_ARM).');
}

/** Where a given file key's pristine bytes are kept. Basename only — the keys are already unique. */
function backupPathFor(key) {
    return path.join(BACKUP_DIR, path.basename(FILES[key]));
}

/**
 * ⚠⚠ `--restore`, AND IT RUNS BEFORE EVERY MATRIX GATE IN THIS FILE.
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
function restoreNonBuiltTargets() {
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
 * ⚠⚠ CHECK THE KILL-SURVIVING BACKUP BEFORE BUILDING.
 *
 * `prebuild` deletes `dist/`, so a build destroys the built-file evidence left by a killed run
 * before compilation even starts. A differing non-built backup is the only durable signal this
 * harness has that such a run may have been killed. Refusing on that conflict before the build
 * preserves the entire scene for `--restore`; when no conflict exists, fresh output wins over
 * forensic retention because a stale-code measurement is worse than missing or replaced `dist/`.
 *
 * This reads only a non-built file that already has a backup. It does not capture matrix originals;
 * `ORIGINAL` and `ORIGINAL_BYTES` are created inside `runMatrix()` after a successful build. The
 * post-build call closes the smaller race where a build lifecycle itself changes a manifest.
 */
function refuseBackupConflicts(currentBytes = null) {
    const conflicts = [];
    for (const key of NON_BUILT) {
        const backup = backupPathFor(key);
        if (!fs.existsSync(backup)) continue;
        const current = currentBytes?.[key] ?? fs.readFileSync(FILES[key]);
        if (!fs.readFileSync(backup).equals(current)) conflicts.push({ key, backup });
    }
    if (!conflicts.length) return;

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

/**
 * Every ordinary entry point builds here, in this process's dispatcher, before matrix targets are
 * read. `npm run build` deliberately includes `prebuild`, whose clean removes all of `dist/` before
 * `tsc` runs. A compile failure therefore leaves formerly available output absent, and a successful
 * build overwrites a killed run's mutated built output. Both costs are intentional: neither stale
 * output nor forensic output may be presented as a measurement of the current source.
 */
function buildFreshOutput() {
    console.log('· fresh build: npm run build');
    const build = spawnSync('npm run build', { cwd: repo, stdio: 'inherit', shell: true });
    if (build.error) {
        console.error(`⛔ MUTATION MATRIX REFUSED — build could not be started: ${build.error.message}`);
        console.error('   prebuild may already have removed dist/; fix the build and rerun to regenerate it.');
        process.exit(1);
    }
    if (build.status !== 0) {
        console.error(`⛔ MUTATION MATRIX REFUSED — build exited ${build.status ?? `on signal ${build.signal}`}.`);
        console.error('   prebuild may already have removed dist/; fix the build and rerun to regenerate it.');
        process.exit(1);
    }
}

/** The private, same-process matrix worker. Only the dispatcher at EOF enters it. */
function runMatrix() {
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
 * ⚠⚠ THE RELOCATION CONTRACT, BEFORE A SINGLE BYTE OF `dist/` IS MUTATED BY THE MATRIX.
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
refuseBackupConflicts(ORIGINAL_BYTES);

// ⚠ THE BACKUP, WRITTEN BEFORE ANY ROW RUNS AND PRINTED WHETHER OR NOT ANYTHING GOES WRONG.
// It is the only copy of the non-built targets that outlives a killed process; see `BACKUP_DIR`.
{
    fs.mkdirSync(BACKUP_DIR, { recursive: true });

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
            /**
             * ⚠⚠ ABSENT IS CHECKED HERE TOO, AS OF 2026-09-15, AND THE OLD PREDICATE WAS `hits > 1`.
             *
             * An absent anchor was already a refusal — but only when its OWN ROW RAN, as
             * `ANCHOR-NOT-FOUND`. This block exists because "a refusal that arrives after the
             * measurement is a report, not a gate", and that reasoning covers the absent case
             * exactly as well as the duplicate one: a row whose anchor is gone is discovered on
             * row 60, an hour in, having spent the whole run to learn something readable from the
             * source before the first suite started.
             *
             * ⚠ THE TWO CASES STAY SEPARATE MESSAGES because they mean different things. Duplicate
             * = the anchor is too broad, and the fix is a narrower one. Absent = a source edit
             * moved out from under the row, and the fix is to repair the row's `from` — NEVER to
             * delete the row, which is what `verifyMutationResults` says about `ANCHOR-NOT-FOUND`
             * and is the same instruction one step earlier.
             *
             * ⚠ `ANCHOR-NOT-FOUND` IS NOT DEAD and must not be removed: `--only` runs a subset, a
             * row's anchor can be invalidated by an earlier row in the same run, and the
             * disposition is what the contract grades. This is a cheaper gate in front of it, not
             * a replacement for it.
             */
            if (hits === 0) ambiguous.push(`${row.id} anchors on text that does not occur in \`${row.file ?? 'fsgate'}\` — the row would report ANCHOR-NOT-FOUND after the run reaches it, having measured nothing. Repair the row's \`from\`, never delete the row: ${JSON.stringify(anchor.slice(0, 70))}`);
        }
    }
    if (ambiguous.length) refuse(ambiguous, 'a mutation anchor is absent or not unique in its source');
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
        return classifySuiteResult({ out });
    } catch (error) {
        return classifySuiteResult({ error });
    }
}

function instrumentError(outcome) {
    return outcome !== 'GREEN' && outcome !== 'ARM_RED';
}

function outputTail(out) {
    const tail = out.trim().split(/\r?\n/).slice(-6).join(' | ');
    return tail || '(no captured output)';
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
    if (control.outcome === 'ARM_RED') {
        refuse(
            ['the suite is RED before any mutation is applied, so every KILLED verdict below would be unconditional',
                `the control run named these red arms: ${control.red.join(', ')}`,
                `the control run said: ${outputTail(control.out)}`],
            'the unmutated control run is not green'
        );
    }
    if (instrumentError(control.outcome)) {
        console.error(`\n⛔ MUTATION MATRIX REFUSED — unmutated control instrument error: ${control.outcome}`);
        console.error(`   · the control run said: ${outputTail(control.out)}`);
        console.error('   No mutation verdict can be trusted, and no mutation was applied.');
        process.exit(1);
    }
    console.log('· unmutated control: green — the verdicts below are conditional on the mutation.');
}

/** Set in the `finally` below, read by the contract's result check. */
let restored = false;
const results = [];
let suiteInstrumentError = null;
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
        const suite = runSuite();
        restoreAll();
        if (instrumentError(suite.outcome)) {
            results.push({ ...meta(row), status: suite.outcome, red: [] });
            suiteInstrumentError = { row, suite };
            break;
        }
        results.push({
            ...meta(row),
            status: suite.outcome === 'ARM_RED' ? 'KILLED' : 'SURVIVED',
            red: suite.outcome === 'ARM_RED' ? suite.red : [],
            redDetail: suite.outcome === 'ARM_RED' ? (suite.redDetail ?? {}) : {}
        });
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

if (suiteInstrumentError) {
    const { row, suite } = suiteInstrumentError;
    const checked = verifyMutationResults(CONTRACT, 'wyrd', results, { full: false, restored });
    console.error(`\n⛔ MUTATION MATRIX REFUSED — instrument error on ${row.id}: ${suite.outcome}`);
    console.error(`   · the suite said: ${outputTail(suite.out)}`);
    for (const problem of checked.problems) console.error(`   · ${problem}`);
    console.error(`   Mutation targets restored byte-for-byte: ${restored}. No matrix score was produced.`);
    process.exit(1);
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
        // ⚠ THE DETAIL FOR ARMS `plan` DID NOT CLAIM — the surprises, and the only ones worth the
        // width. An arm the row expected to redden explains itself; an arm nobody predicted is the
        // one that costs a capture loop to see again. `plan` is the runner's own claim, so this
        // needs no contract read and stays honest if the contract is absent or stale.
        if (r.red.length && r.redDetail) {
            const claimed = String(r.planClaims ?? '');
            for (const id of r.red) {
                if (claimed.includes(id) || !r.redDetail[id]) continue;
                console.log(`${''.padEnd(18)} ${''.padEnd(width)}  ⚠ UNCLAIMED RED — ${id}, and this is the text that is otherwise lost:`);
                for (const line of r.redDetail[id].split('\n')) {
                    console.log(`${''.padEnd(18)} ${''.padEnd(width)}      ${line}`);
                }
            }
        }
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
}

// Mode dispatch is last so declaration evaluation stays write-free. At runtime selftest and restore
// exit before the build, matrix target reads and backup creation.
if (selftestMode) {
    runClassifierSelfTest();
    process.exit(0);
}
if (restoreMode) restoreNonBuiltTargets();
refuseBackupConflicts();
buildFreshOutput();
runMatrix();
