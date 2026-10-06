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
import { lineEndingOf, withLineEnding } from '../../wyrd-fence/scripts/mutation-text.mjs';
import { guardBattery, batteryLockFixture, registerBatteryTargets, recordBatteryMutant, assertNoBatteryLockRefusal } from '../../wyrd-fence/scripts/battery-lock.mjs';
import { loadContract, verifyMutationRows, verifyMutationResults, refuse } from './verify-relocation-contract.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
if (!process.argv.some(arg => ['--selftest', '--eol-fixture', '--restore-fixture'].includes(arg))) guardBattery('reader mutation');
batteryLockFixture();
const args = process.argv.slice(2);
const selftestMode = args.includes('--selftest');
const restoreMode = args.includes('--restore');
const jsonOut = args.includes('--json');
const onlyArg = args.find(a => a.startsWith('--only'));
const only = onlyArg ? (onlyArg.includes('=') ? onlyArg.split('=')[1] : args[args.indexOf(onlyArg) + 1]) : null;

/**
 * The shared fence slice is a target for Reader response integration arms. Fence-only arms and
 * their mutations remain in the fence matrix. Every target is read after the mandatory build;
 * an absent target refuses before any mutation is applied.
 */
const FILES = {
    fsgate: path.join(repo, '..', 'wyrd-fence', 'dist', 'fsgate.js'),
    auth: path.join(repo, 'dist', 'auth.js'),
    main: path.join(repo, 'dist', 'main.js'),
    index: path.join(repo, 'dist', 'index.js'),
    /**
     * The built certificate target stays in Reader for H25-H28. TLS argument and material
     * validation moved to HTTP with M133/M134; that matrix patches its own built output.
     */
    cert: path.join(repo, 'dist', 'cert.js'),
    // Added 2026-08-29 with M44. `server.js` was outside the matrix entirely, so the layer-detection
    // arms were unmeasured — E7-layers had been green since it was written without anything ever
    // showing it could go red. An arm nothing can kill is a claim.
    server: path.join(repo, 'dist', 'server.js'),
    search: path.join(repo, 'dist', 'search.js'),
    serverdts: path.join(repo, 'dist', 'server.d.ts'),
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
        replace: (s, ending) => s.replace('installObserver();', '')
            .replace("const { createFsGate } = await import('wyrd-fence');",
                withLineEnding("const { createFsGate } = await import('wyrd-fence');\ninstallObserver();", ending)) },
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
        from: "'Known limits: a hard link that already exists inside the folder makes the file it points at',\n    'readable and searchable wherever on the disk that file lives, and ordinary folder inspection will not show',\n    'it as a link. A path component swapped between validation and opening may be read instead of',",
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
        from: "content: [{ type: 'text', text: readRefusal('BAD_INPUT', '`path` must be a string.') }]",
        to: "content: [{ type: 'text', text: readRefusal('PATH_NOT_A_STRING', '`path` must be a string.') }]" },
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
        from: 'const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name), backendPath === \'\' ? undefined : () => gate.listGrantRoot());',
        to: 'await gate.listGrantRoot();\n    const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name), backendPath === \'\' ? undefined : () => gate.listGrantRoot());' },

    { id: 'M112-verifier-injection-ignored', file: 'main',
        what: 'ignore the injected verifier factory and install the production verifier directly',
        plan: 'H16-verifier-injection-real-socket',
        from: 'const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;',
        to: 'const makeReadAuthInfo = createReadTokenVerifier;' },
    { id: 'M114-token-appended-to-disclosure', file: 'main',
        what: 'append the configured Reader token to the HTTP startup disclosure',
        plan: 'H17-no-query-token-or-leak',
        from: 'deps.stderr(httpDisclosure(handle, gate.disclosedRoot(), searchBackendDisclosure));',
        to: "deps.stderr(`${httpDisclosure(handle, gate.disclosedRoot(), searchBackendDisclosure)}\\n${readToken.token.toString('base64url')}`);" },
    { id: 'M115-missing-token-listens', file: 'main',
        what: 'replace missing-token startup refusal with an unauthenticated listener',
        plan: 'H18-no-token-refuses-before-listen',
        from: "if (!readToken.ok) {\n            deps.stderr(`wyrd: refusing to start — ${readToken.detail}`);\n            deps.setExitCode(2);\n            return { started: false, reason: 'READ_TOKEN', http: null, closeSearchBackend };\n        }\n        const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;\n        const readAuthInfo = makeReadAuthInfo(readToken.token);",
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
    { id: 'M120-cleartext-warning-unconditional', file: 'main',
        what: 'print the clear-text bearer-token warning unconditionally under TLS',
        plan: 'H30-tls-disclosure',
        from: '            `Certificate expires: ${handle.endpoint.certificate.validTo}.`',
        to: "            `Certificate expires: ${handle.endpoint.certificate.validTo}.`,\n            '  · TLS is off, so the bearer token travels in the clear and can be replayed by',\n            '    anyone who captures it.'" },
    { id: 'M123-read-window-halved', file: 'server',
        what: 'halve the maximum read-window clamp',
        plan: 'H20-localhost-read-budget, H19-response-stream',
        from: 'const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES);',
        to: 'const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES / 2);' },
    { id: 'M124-read-offset-dropped', file: 'server',
        what: 'drop the requested offset forwarded to the fence read',
        plan: 'H20-localhost-read-budget, E17-v1-raw-baseline',
        from: 'const slice = await fsgate.readFileInGrant(target, offset, limit, hydrate);',
        to: 'const slice = await fsgate.readFileInGrant(target, 0, limit, hydrate);' },
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
    { id: 'M137-transport-unaccounted-websocket', file: 'serverdts',
        what: 'add an unaccounted websocket member to the ServerTransport declaration',
        plan: 'E19-transport-network-accounting',
        from: "export type ServerTransport = 'stdio' | 'http';",
        to: "export type ServerTransport = 'stdio' | 'http' | 'websocket';" },    { id: 'M178-read-default-hydrates', file: 'server', what: 'treat an omitted opt-in as true', plan: 'SR3-read-opt-in',
        from: "const hydrate = args['hydrate'] === true;", to: 'const hydrate = true;' },
    { id: 'M179-unavailable-as-available', file: 'server', what: 'label an unmeasured platform available with zero placeholders', plan: 'SR4-unsupported-platform',
        from: "placeholder_detection: 'unavailable', placeholder_count: null,", to: "placeholder_detection: 'available', placeholder_count: 0," },
    { id: 'M184-search-stale-walk', file: 'search', what: 'reuse the first grant walk on later queries', plan: 'SR10-fresh-add-delete, SR14-zero-files-vs-no-match',
        edits: [
            ['return async (query) => {', 'let priorWalk;\n    return async (query) => {'],
            ['const walk = await fsgate.walkGrant();', 'const walk = priorWalk ?? await fsgate.walkGrant();\n        priorWalk = walk;']
        ] },
    { id: 'M185-search-retain-source', file: 'search', what: 'retain raw source prefix in the lexical cache', plan: 'SR11-zero-maintenance-reads',
        from: 'return { key: changeKey(file), terms, typed };',
        to: 'return { key: changeKey(file), terms, typed, raw: prefix };' },
    { id: 'M186-search-extra-excerpt', file: 'search', what: 'read a second excerpt window per selected hit', plan: 'SR11-zero-maintenance-reads',
        from: 'const slice = await reads.read(candidate.path, candidate.excerpt_start, EXCERPT_BYTES);',
        to: 'await reads.read(candidate.path, candidate.excerpt_start, EXCERPT_BYTES);\n            const slice = await reads.read(candidate.path, candidate.excerpt_start, EXCERPT_BYTES);' },
    { id: 'M187-search-ten-truncated', file: 'search', what: 'infer truncation from exactly ten returned candidates', plan: 'SR13-large-file-utf8',
        from: 'let truncated = response.hasMore;',
        to: 'let truncated = response.hasMore || response.candidates.length === HIT_LIMIT;' },
    { id: 'M188-search-empty-states', file: 'search', what: 'collapse zero scope and zero searchable files into no matches', plan: 'SR10-fresh-add-delete, SR14-zero-files-vs-no-match',
        from: "state: filesInScope === 0 ? 'zero_files_in_scope' : filesInScope === null ? 'scope_unavailable' :\n                searchable === 0 ? 'zero_searchable_files' :",
        to: "state: filesInScope === null ? 'scope_unavailable' : searchable === 0 ? 'no_matches' :" },
    { id: 'M189-search-long-match-context', file: 'search', what: 'spend the excerpt window on leading context before a long match', plan: 'SR18-long-match-excerpt',
        from: 'const context = Math.min(leadingCount, Math.max(0, 200 - tokenCodepoints));',
        to: 'const context = leadingCount;' },
    { id: 'M190-search-prevalidated-truncation', file: 'search', what: 'declare truncation from candidate count before revalidation', plan: 'SR19-revalidated-truncation',
        from: 'let truncated = response.hasMore;',
        to: 'let truncated = response.hasMore || response.candidates.length > HIT_LIMIT;' },
    { id: 'M200-search-empty-query-accepted', file: 'server', what: 'allow an empty search query on the wire', plan: 'SR23-search-wire-shape',
        from: '[...query].length < 1', to: '[...query].length < 0' },
    { id: 'M201-search-wire-cap-bypassed', file: 'server', what: 'send duplicate hits beyond the ten-hit wire cap', plan: 'SR24-cap-and-truncation',
        from: 'const payload = { ...result, warnings };',
        to: 'const payload = { ...result, hits: [...result.hits, ...result.hits], warnings };' },
    { id: 'M202-search-cache-disclosure-false', file: 'server', what: 'claim search retains no cache in the model-facing disclosure', plan: 'SR26-disclosure, E14-surface-claims',
        from: 'Search builds a lazy in-memory cache of normalized terms and anchors; it holds no raw',
        to: 'Search keeps no cache of terms or anchors; it holds no raw' },
    { id: "M297-search-version-kind", file: 'search', what: "accept malformed version declarations", plan: "SR37-malformed-version",
        from: "(version.kind !== 'stat' && version.kind !== 'sha256')",
        to: "false" },
    { id: "M298-search-sha256-format", file: 'search', what: "accept malformed lowercase SHA-256 values", plan: "SR37-malformed-version",
        from: "if (version.kind === 'sha256' && !/^[a-f0-9]{64}(?![\\s\\S])/.test(version.value))",
        to: "if (false)" },
    { id: "M299-search-range-integer", file: 'search', what: "accept an unsafe integer passage end", plan: "SR38-source-range",
        from: "if (!Number.isSafeInteger(candidate.source_range_end))",
        to: "if (false)" },
    { id: "M300-search-range-order", file: 'search', what: "accept a passage end at or before its anchor", plan: "SR38-source-range",
        from: "if (!(candidate.byte_offset < candidate.source_range_end))",
        to: "if (false)" },
    { id: "M301-search-range-size", file: 'search', what: "accept a passage end beyond file size", plan: "SR38-source-range",
        from: "if (!(candidate.source_range_end <= file.size))",
        to: "if (false)" },
    { id: "M302-search-range-excerpt", file: 'search', what: "accept an excerpt starting after the passage", plan: "SR38-source-range",
        from: "candidate.excerpt_start <= candidate.byte_offset",
        to: "true" },
    { id: "M303-search-sha256-compare", file: 'search', what: "accept a candidate without comparing its digest", plan: "SR34-sha256-mismatch",
        from: "if (digests.get(candidate.path) !== version.value)",
        to: "if (false)" },
    { id: "M304-search-sha256-once", file: 'search', what: "rehash a file for every candidate", plan: "SR36-sha256-one-pass",
        from: "if (!digests.has(candidate.path))",
        to: "if (true)" },
    { id: "M305-search-sha256-window", file: 'search', what: "accept hash windows with invalid size or progress", plan: "SR39-sha256-window-refusal",
        edits: [
            ["if (!window || window.size !== file.size || window.nextOffset <= position)\n                    return null;", "if (!window)\n                    return null;"],
            ["position = window.nextOffset;", "position += window.bytes.length;"]
        ] },
    { id: "M306-search-sha256-before", file: 'search', what: "ignore SHA-256 candidate metadata changes before reading", plan: "SR35-sha256-backend-change",
        from: "changeKey(before) !== expectedKey",
        to: "(version.kind === 'stat' && changeKey(before) !== expectedKey)" },
    { id: "M307-search-sha256-after", file: 'search', what: "ignore SHA-256 candidate metadata changes after capturing the excerpt", plan: "SR40-sha256-read-change",
        from: "changeKey(after) !== expectedKey",
        to: "(version.kind === 'stat' && changeKey(after) !== expectedKey)" },
    { id: "M308-search-sha256-after-hash", file: 'search', what: "ignore post-hash metadata changes before truncation", plan: "SR43-sha256-withheld-change",
        from: "if (!afterHash || changeKey(afterHash) !== changeKey(file) || !maySearch(afterHash))",
        to: "if (false)" },
    {"id":"M309-search-sha256-separate-excerpt","file":"search","what":"read SHA-256 excerpts separately from the hashing pass","plan":"SR44-sha256-same-stat-swap","from":"excerptBytes = window.bytes.subarray(0, kept);","to":"excerptBytes = (await reads.read(candidate.path, candidate.excerpt_start, EXCERPT_BYTES)).bytes;"} ,
    {"id":"M310-search-byte-anchor","file":"search","what":"accept invalid byte offsets regardless of range presence","plan":"SR45-candidate-anchors","edits":[["Number.isSafeInteger(candidate.byte_offset) && Number.isSafeInteger(candidate.excerpt_start) &&","Number.isSafeInteger(candidate.excerpt_start) &&"],["0 <= candidate.byte_offset && candidate.byte_offset < size","true"],["candidate.excerpt_start <= candidate.byte_offset","true"]]} ,
    {"id":"M311-search-excerpt-anchor","file":"search","what":"accept unsafe excerpt offsets","plan":"SR45-candidate-anchors","edits":[["Number.isSafeInteger(candidate.excerpt_start)","true"],["0 <= candidate.excerpt_start","true"]]} ,
    {"id":"M312-search-sha256-early-limit","file":"search","what":"declare hash truncation before establishing a captured decodable excerpt","plan":"SR46-sha256-withheld-excerpt","from":"if (version.kind === 'stat' && hits.length === HIT_LIMIT)","to":"if (hits.length === HIT_LIMIT)"} ,
    {"id":"M313-search-sha256-cap","file":"search","what":"capture more than sixteen excerpt windows per file","plan":"SR47-sha256-window-cap","from":"windows.size < HASH_WINDOW_LIMIT","to":"true"} ,
    {"id": "M358-backend-result-copy", "file": "search", "what": "copy module candidates before asynchronous revalidation", "plan": "SR71-backend-retained-results", "from": "const response = { ...answer, candidates: answer.candidates.map(candidate => ({\n                ...candidate, version: candidate.version && { ...candidate.version }\n            })) };", "to": "const response = answer;"},
    {"id": "M359-backend-search-capture", "file": "main", "what": "capture selected search function at startup", "plan": "SR71-backend-retained-results", "from": "searchBackend = Object.freeze({ search: selectedBackend.search.bind(selectedBackend) });", "to": "searchBackend = selectedBackend;"},
    {"id": "M360-backend-close-force-exit", "file": "index", "what": "deadline shutdown terminates retained native handles", "plan": "SR67-backend-close-deadline", "from": "if (backendFailed)\n            process.exit();", "to": "if (backendFailed)\n            process.stdin.destroy();"},
    {"id": "M351-backend-private-inputs", "file": "search", "what": "keep backend references separate from revalidation", "plan": "SR65-backend-private-inputs", "from": "backend.search(backendSnapshot, query, backendReads)", "to": "backend.search(snapshot, query, reads)"},
    {"id": "M352-backend-stdio-close", "file": "index", "what": "stdio stream closure invokes module close", "plan": "SR66-backend-stdio-close SR67-backend-close-deadline", "from": "if (result.http === null) {", "to": "if (false) {"},
    {"id": "M353-backend-close-deadline", "file": "main", "what": "bound an unsettled module close", "plan": "SR67-backend-close-deadline", "from": "reject(new Error('deadline exceeded (10 seconds)'))", "to": "undefined"},
    {"id": "M354-backend-disclosure-copy", "file": "main", "what": "copy disclosure values once before validation", "plan": "SR68-backend-disclosure-copy", "from": "searchBackendDisclosure = Object.freeze({ path: backendPath, lines });", "to": "searchBackendDisclosure = Object.freeze({ path: backendPath, lines: Object.freeze(Array.from({ length: suppliedLines.length }, (_, index) => suppliedLines[index])) });"},
    {"id": "M355-backend-lexical-facade", "file": "main", "what": "hide mutable lexical backend behind frozen search facade", "plan": "SR69-backend-lexical-facade", "from": "lexical: Object.freeze({ search: lexical.search.bind(lexical) })", "to": "lexical"},
    {"id": "M356-backend-host-fields", "file": "main", "what": "provide process UUID and engine read bound", "plan": "SR70-backend-host-fields", "from": "grantId, maxSliceBytes: SCAN_BYTES,", "to": ""},
    {"id": "M357-backend-close-await", "file": "index", "what": "await module close before allowing process exit", "plan": "SR66-backend-stdio-close SR67-backend-close-deadline", "from": "await result.closeSearchBackend();", "to": "void result.closeSearchBackend();"},
    {"id": "M315-backend-absolute", "file": "main", "what": "absolute path guard", "plan": "SR53-backend-path", "from": "!isAbsolute(backendPath)", "to": "false"},
    {"id": "M316-backend-file", "file": "main", "what": "file kind guard", "plan": "SR53-backend-path", "from": "!(await stat(backendPath)).isFile()", "to": "false"},
    {"id": "M317-backend-export", "file": "main", "what": "factory export guard", "plan": "SR55-backend-export", "from": "typeof factory !== 'function'", "to": "false"},
    {"id": "M318-backend-return", "file": "main", "what": "object result guard", "plan": "SR57-backend-return", "from": "result === null || typeof result !== 'object'", "to": "false"},
    {"id": "M319-backend-search", "file": "main", "what": "search function guard", "plan": "SR58-backend-search-guard", "from": "typeof result.backend?.search !== 'function'", "to": "false"},
    {"id": "M320-backend-array", "file": "main", "what": "disclosure array guard", "plan": "SR59-backend-lines-guard", "from": "!Array.isArray(suppliedLines)", "to": "false"},
    {"id": "M321-backend-min-lines", "file": "main", "what": "disclosure minimum lines guard", "plan": "SR59-backend-lines-guard", "from": "suppliedLines.length < 1", "to": "false"},
    {"id": "M322-backend-max-lines", "file": "main", "what": "disclosure maximum lines guard", "plan": "SR59-backend-lines-guard", "from": "suppliedLines.length > 40", "to": "false"},
    {"id": "M323-backend-string-line", "file": "main", "what": "disclosure string guard", "plan": "SR60-backend-line-guard", "from": "typeof line !== 'string'", "to": "false"},
    {"id": "M324-backend-empty-line", "file": "main", "what": "disclosure empty line guard", "plan": "SR60-backend-line-guard", "from": "line.trim().length === 0", "to": "false"},
    {"id": "M325-backend-long-line", "file": "main", "what": "disclosure line length guard", "plan": "SR60-backend-line-guard", "from": "[...line].length > 200", "to": "false"},
    {"id": "M326-backend-controls", "file": "main", "what": "disclosure control character guard", "plan": "SR60-backend-line-guard", "from": "/[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]/.test(line)", "to": "false"},
    {"id": "M327-backend-close", "file": "main", "what": "optional close function guard", "plan": "SR61-backend-close-guard", "from": "result.close !== undefined && typeof result.close !== 'function'", "to": "false"},
    {"id": "M328-backend-refusal", "file": "main", "what": "backend refusal returns before transports", "plan": "SR53-backend-path SR54-backend-import SR55-backend-export SR56-backend-factory SR57-backend-return SR58-backend-search-guard SR59-backend-lines-guard SR60-backend-line-guard SR61-backend-close-guard", "from": "return { started: false, reason: 'SEARCH_BACKEND', http: null, closeSearchBackend: null };", "to": "searchBackend = undefined;"},
    {"id": "M329-backend-error-line", "file": "main", "what": "error diagnostics stay on one line", "plan": "SR54-backend-import", "from": "(error instanceof Error ? error.message : String(error)).replace(/[\\x00-\\x1f\\x7f-\\x9f\\u2028\\u2029]/g, ' ')", "to": "(error instanceof Error ? error.message : String(error))"},
    {"id": "M330-backend-precedence", "file": "main", "what": "command line wins over environment", "plan": "SR49-backend-default SR50-backend-selection", "from": "backendArg !== null ? backendArg : (deps.env['WYRD_SEARCH_BACKEND'] ?? '')", "to": "deps.env['WYRD_SEARCH_BACKEND'] ?? backendArg ?? ''"},
    {"id": "M331-backend-frozen-host", "file": "main", "what": "factory host is frozen", "plan": "SR51-backend-host", "from": "Object.freeze({ contractVersion: 1,", "to": "({ contractVersion: 1,"},
    {"id": "M332-backend-frozen-layers", "file": "main", "what": "host layer names are frozen", "plan": "SR51-backend-host", "from": "layers: Object.freeze([...layers]), listingFailed", "to": "layers: [...layers], listingFailed"},
    {"id": "M333-backend-layer-spelling", "file": "server", "what": "detected layer spelling follows disk", "plan": "SR51-backend-host", "from": "entries?.find(entry => entry.name.toLowerCase() === layer.toLowerCase())?.name ?? layer", "to": "layer"},
    {"id": "M334-backend-wire", "file": "server", "what": "selected backend reaches search engine", "plan": "SR52-backend-shared-search", "from": "createSearchEngine(fsgate, options.searchBackend)", "to": "createSearchEngine(fsgate)"},
    {"id": "M335-backend-model-disclosure", "file": "server", "what": "module disclosure reaches model", "plan": "SR62-backend-disclosure", "from": "disclosure(fsgate.disclosedRoot(), transport, layers, listingFailed, options.searchBackendDisclosure)", "to": "disclosure(fsgate.disclosedRoot(), transport, layers, listingFailed)"},
    {"id": "M336-backend-human-disclosure", "file": "main", "what": "module disclosure reaches human", "plan": "SR62-backend-disclosure", "from": "disclosure(gate.disclosedRoot(), context.transport, layers, listingFailed, searchBackendDisclosure)", "to": "disclosure(gate.disclosedRoot(), context.transport, layers, listingFailed)"},
    {"id": "M337-backend-http-disclosure", "file": "main", "what": "every HTTP disclosure branch includes module", "plan": "SR62-backend-disclosure", "from": "...searchBackendParagraph(module)", "to": "...searchBackendParagraph(undefined)"},
    {"id": "M338-backend-cache-claim", "file": "server", "what": "cache claims are scoped to built-in backend", "plan": "SR62-backend-disclosure", "from": "module ? \"  · wyrd's built-in search backend builds a lazy in-memory cache of normalized terms and anchors; it holds no raw\" :", "to": "false ? \"unused\" :"},
    {"id": "M339-backend-close-memo", "file": "main", "what": "module closes once under repeated signals", "plan": "SR63-backend-real-import-close SR64-backend-http-shutdown", "from": "closing ??= new Promise", "to": "closing = new Promise"},
    {"id": "M340-backend-close-shutdown", "file": "index", "what": "HTTP signals invoke module close", "plan": "SR64-backend-http-shutdown", "from": "if (result.closeSearchBackend !== null)", "to": "if (false)"},
    {"id": "M343-backend-production-wire", "file": "main", "what": "production server factory forwards the backend", "plan": "SR52-backend-shared-search SR62-backend-disclosure", "from": "{ searchBackend: configured.searchBackend }", "to": "{}"},
    {"id": "M344-backend-production-disclosure", "file": "main", "what": "production server factory forwards module disclosure", "plan": "SR62-backend-disclosure", "from": "{ searchBackendDisclosure: configured.searchBackendDisclosure }", "to": "{}"},
    {"id": "M345-backend-context-wire", "file": "main", "what": "process context retains the single backend", "plan": "SR52-backend-shared-search SR62-backend-disclosure", "from": "...(searchBackend === undefined ? {} : { searchBackend })", "to": "...{}"},
    {"id": "M348-backend-detection-warning", "file": "server", "what": "failed module structure detection describes incomplete detection", "plan": "SR51-backend-host", "from": "module ? 'Vault structure detection did not finish at startup, so no structure warning appears below.' :", "to": "false ? \"unused\" :"},
    {"id": "M350-backend-line-allocation-bound", "file": "main", "what": "iterate oversized disclosure before its codepoint limit", "plan": "SR60-backend-line-guard", "from": "line.length > 400", "to": "false"},
    {"id": "M349-backend-detection-read-claim", "file": "server", "what": "module detection does not claim no metadata was read", "plan": "SR51-backend-host", "from": "module ? 'That is not a statement that the folder has no sensitive layers — detection was incomplete.' :", "to": "false ? \"unused\" :"},
    {"id": "M347-backend-selection-guard", "file": "main", "what": "ignore a selected module and silently use the built-in backend", "plan": "SR50-backend-selection SR51-backend-host SR52-backend-shared-search SR53-backend-path SR54-backend-import SR55-backend-export SR56-backend-factory SR57-backend-return SR58-backend-search-guard SR59-backend-lines-guard SR60-backend-line-guard SR61-backend-close-guard SR62-backend-disclosure SR63-backend-real-import-close SR64-backend-http-shutdown", "from": "if (backendPath !== '')", "to": "if (false)"},
    {"id": "M346-backend-context-disclosure", "file": "main", "what": "process context retains module disclosure", "plan": "SR62-backend-disclosure", "from": "...(searchBackendDisclosure === undefined ? {} : { searchBackendDisclosure })", "to": "...{}"},
    {"id": "M342-backend-listing-failure", "file": "server", "what": "failed root listing stays unavailable", "plan": "SR51-backend-host", "from": "if (isRefusal(listed))", "to": "if (false)"},
    {"id": "M341-backend-close-exit", "file": "index", "what": "close failure preserves nonzero exit code", "plan": "SR64-backend-http-shutdown", "from": "if (process.exitCode === 0)\n                        process.exitCode = 1;", "to": "if (true)\n                        process.exitCode = 1;"},
    {"id":"M314-search-sha256-utf8-trim","file":"search","what":"decode a partial trailing codepoint in a captured window","plan":"SR48-sha256-utf8-window","from":"if (width > back)","to":"if (false)"} ,
    { id: 'M295-read-pre-read-size', file: 'fsgate', what: 'report the opened file size measured before reading', plan: 'SR31-read-observed-size',
        from: 'const observedSize = Math.max(prim.fstat(fd).size, nextOffset);',
        to: 'const observedSize = Math.max(size, nextOffset);' },
    { id: 'M296-read-forget-download', file: 'fsgate', what: 'replace the pre-open placeholder observation with the post-open state', plan: 'SR32-read-download-observation',
        from: 'dehydrated = dehydrated === true || now === true ? true : now;',
        to: 'dehydrated = now;' },
    { id: 'M255-search-revalidation-state-guard', file: 'search', what: 'report no_matches after revalidation withheld a candidate', plan: 'SR30-revalidation-dropped-count',
        from: "revalidationDropped > 0 || searchable === null ? 'search_coverage_unavailable' : 'no_matches'",
        to: "searchable === null ? 'search_coverage_unavailable' : 'no_matches'" },
    { id: 'M191-search-context-ring-off-by-one', file: 'search', what: 'move the saved excerpt context one codepoint forward', plan: 'SR21-mixed-anchor-parity',
        from: 'recent[(leadingEnd - context) % recent.length]',
        to: 'recent[(leadingEnd - context + 1) % recent.length]' },
];

/** What a row promises its source contains. A `replace` callback is opaque, so it must declare. */
function declaredAnchors(row) {
    return row.anchors ?? (row.edits ? row.edits.map(([from]) => from) : row.from ? [row.from] : []);
}

function missingMutationAnchors(row, source, ending) {
    return declaredAnchors(row).filter(anchor => !source.includes(withLineEnding(anchor, ending)));
}

function applyMutationRow(row, source, ending) {
    if (row.replace) return row.replace(source, ending);
    // Function replacers preserve JS source containing replacement-pattern characters.
    if (row.edits) return row.edits.reduce((acc, [from, to]) =>
        acc.replace(withLineEnding(from, ending), () => withLineEnding(to, ending)), source);
    return source.replace(withLineEnding(row.from, ending),
        () => withLineEnding(row.to, ending));
}

if (args.includes('--check-anchors')) {
    const problems = [];
    for (const row of ROWS) {
        const key = row.file ?? 'fsgate';
        const target = FILES[key];
        if (!target) {
            problems.push(`${row.id}: no mutation target is registered for file ${JSON.stringify(key)}`);
            continue;
        }
        const source = fs.readFileSync(target, 'utf8');
        const ending = lineEndingOf(source, target);
        for (const anchor of declaredAnchors(row)) {
            const hits = source.split(withLineEnding(anchor, ending)).length - 1;
            if (hits !== 1) problems.push(`${row.id}: ${key} (${target}) anchor matched ${hits} times: ${JSON.stringify(anchor)}`);
        }
    }
    if (problems.length) refuse(problems, 'mutation anchors are not applicable');
    console.log(`✔ Reader mutation anchors: ${ROWS.length} rows apply to their registered targets.`);
    process.exit(0);
}

if (args[0] === '--eol-fixture') {
    const [arm, target] = args.slice(1);
    const bytes = fs.readFileSync(target);
    const source = bytes.toString('utf8');
    try {
        if (arm === 'BH2-eol-mixed') {
            let refused = false;
            try { lineEndingOf(source, target); } catch (error) {
                refused = /mixed or unsupported line endings/.test(error.message);
            }
            if (!refused) throw new Error('mixed-ending target was accepted');
        } else {
            const ending = lineEndingOf(source, target);
            if (arm === 'BH1-eol-crlf') {
                const row = { edits: [['alpha\nbeta', 'alpha\ndelta']] };
                if (missingMutationAnchors(row, source, ending).length) throw new Error('CRLF anchor missing');
                fs.writeFileSync(target, applyMutationRow(row, source, ending));
                if (fs.readFileSync(target, 'utf8') !== 'alpha\r\ndelta\r\ngamma\r\n') throw new Error('CRLF edit did not land');
                const callback = ROWS.find(item => item.id === 'M27');
                const callbackSource = "installObserver();\r\nconst { createFsGate } = await import('wyrd-fence');\r\n";
                if (missingMutationAnchors(callback, callbackSource, ending).length) throw new Error('callback anchor missing');
                const callbackResult = applyMutationRow(callback, callbackSource, ending);
                if (!callbackResult.includes("import('wyrd-fence');\r\ninstallObserver();"))
                    throw new Error('callback added a bare LF');
            } else if (arm === 'BH3-eol-all-edits') {
                const row = { edits: [['alpha', 'delta'], ['absent\nsecond', 'nope']] };
                if (missingMutationAnchors(row, source, ending).length !== 1) throw new Error('second edit was not refused');
            } else throw new Error('unknown EOL fixture arm');
        }
    } finally {
        fs.writeFileSync(target, bytes);
        if (!fs.readFileSync(target).equals(bytes)) throw new Error('fixture restore changed bytes');
    }
    console.log(`fixture ${arm}: reader PASS`);
    process.exit(0);
}

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
    assertNoBatteryLockRefusal(captured);
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

if (args.includes('--bh6-spawn-fixture')) {
    const failed = spawnSync(path.join(repo, 'missing-executable'), [], { encoding: 'utf8' });
    const verdict = classifySuiteResult({ error: failed.error });
    if (verdict.outcome === 'GREEN' || verdict.outcome === 'ARM_RED') throw new Error('spawn failure received a mutation verdict');
    console.log(`INFRASTRUCTURE: ${verdict.outcome}`);
    process.exit(0);
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
registerBatteryTargets(Object.values(FILES));
const ENDINGS = Object.fromEntries(Object.entries(ORIGINAL).map(([key, source]) =>
    [key, lineEndingOf(source, FILES[key])]));
refuseBackupConflicts(ORIGINAL_BYTES);

// ⚠ THE BACKUP, WRITTEN BEFORE ANY ROW RUNS AND PRINTED WHETHER OR NOT ANYTHING GOES WRONG.
// It is the only copy of the non-built targets that outlives a killed process; see `BACKUP_DIR`.
{
    fs.mkdirSync(BACKUP_DIR, { recursive: true });

    for (const key of NON_BUILT) fs.writeFileSync(backupPathFor(key), ORIGINAL_BYTES[key]);
    console.log(`· pristine backup of ${NON_BUILT.map(k => path.basename(FILES[k])).join(' and ')}: ${BACKUP_DIR}`);
    console.log(`  If this run is killed, \`${RESTORE_COMMAND}\` puts them back; \`npm run build\` covers dist/.`);
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
        const key = row.file ?? 'fsgate';
        const source = ORIGINAL[key];
        for (const anchor of declaredAnchors(row)) {
            const adapted = withLineEnding(anchor, ENDINGS[key]);
            const hits = source.split(adapted).length - 1;
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
        const missing = missingMutationAnchors(row, source, ENDINGS[key]);
        if (missing.length) {
            results.push({ ...meta(row), status: 'ANCHOR-NOT-FOUND', red: [] });
            continue;
        }

        mutated = applyMutationRow(row, source, ENDINGS[key]);
        if (mutated === source) {
            results.push({ ...meta(row), status: 'ANCHOR-NOT-FOUND', red: [] });
            continue;
        }

        recordBatteryMutant(FILES[key], Buffer.from(mutated));
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
