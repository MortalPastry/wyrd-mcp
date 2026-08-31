/**
 * THE DESIGN INVENTORY of test arms.
 *
 * ⚠ This file is DECLARATIVE and deliberately separate from the registration path. A test that
 * is deleted leaves its row here, and `scripts/run-tests.mjs` fails the run because the union
 * of executed IDs no longer equals this list. A test that is added without a row here fails it
 * too. Each row carries what the arm is FOR, so removing one is a visible, reviewable edit
 * rather than a silent deletion of two adjacent lines.
 *
 * ⚠ HONEST LIMIT: deleting a test AND its row here still passes. Nothing machine-checkable
 * derives this list from `designs/2026-08-27-s2-fence-plan.md` §5 — that would need the design
 * to be machine-readable, which it is not. What this buys is that the deletion is two edits in
 * two files, one of which reads as an inventory.
 */

/** Fence arms — `test/fsgate.test.js`. */
export const FENCE_ARMS = {
    A1: '`..` traversal to an existing outside file',
    A2: 'absolute path to an existing outside file',
    A3: 'drive-relative `C:notes`',
    A4: 'cross-volume absolute path',
    A5: 'null byte, lexically not by errno',
    A6: 'the exact parent',
    A7: '`.` through listDirInGrant is IS_ROOT',
    A8: '`.` through readFileInGrant is IS_ROOT',
    A9: 'the sibling-prefix trap',
    A10: '`..` absorbed at the volume root is CLAMPED',
    A11: 'terminal file symlink, out and in',
    A12: 'symlink chain, out and in',
    A13: 'junction out, and the IN-GRANT junction that kills the real mutant',
    'A14-M': 'THE MIRROR ESCAPE — junction alias plus relative symlink out',
    'A14-T': 'the twin — same shape, in-grant target, must OPEN',
    A15: 'junction cycle, and the self-junction that must not false-positive',
    'A16-in': 'dangling IN-GRANT junction is MISSING',
    'A16-out': 'dangling junction pointing outside is ESCAPES',
    A17: 'missing in-grant file is MISSING',
    A18: 'relative-target symlink, out and in',
    A19: 'directory symlink to outside',
    A20: 'junction chain, out and in',
    A21: 'symlink cycle',
    'A21-rel': 'chain of RELATIVE targets, plus a relative cycle',
    A22: 'self-descending directory symlink — the OS refuses first',
    'A22-hops': 'FINITE acyclic chain above the hop bound, with a twin below it',
    'A23-dsym': 'the mirror shape with a DIRECTORY SYMLINK alias',
    'A24-hardlink-limit': 'the documented hardlink limit, not a fence arm',
    'A25-case': 'a case-only difference is accepted',
    'A26-pagination': 'next_offset reconstructs byte-for-byte',
    'A27-utf8': 'a slice never splits a codepoint',
    'A28-symlinked-root': 'disclosedRoot is canonical, not the name given',
    'A29-unc': 'a UNC link target — the only arm reaching !isAbsolute(rel)',
    'A30-no-arbitration': 'plain escapes refuse WITHOUT reaching the realpath arbitration',
    'A31-errno': 'every errno maps to its own reason, injected below the fence',
    'A32-hidden-intermediate': 'a reparse point hidden inside another link target — the oracle',
    'A33-guards': 'offset, limit, kind and shape guards, table-driven',
    'A34-listing': 'entry kinds and sizes, and a file given to listDirInGrant',
    'A35-root-moved': 'the root-identity re-check, stated as a narrowed window',
    'A36-defaults': 'the load-bearing arms re-run on the PRODUCTION primitives, uninjected',
    'A37-request-separators': 'request paths in every separator spelling reach the same file',
    'A38-both-contained': 'BOTH readings in-grant and DIFFERENT — where the walk\'s choice bites',
    'A39-not-filenames': 'stream syntax and reserved device names refuse in stage (a), on EVERY gate entry',
    'A40-create': 'a new file is created through the gate; escaping parents refuse and create nothing',
    'A41-exists-refuses': 'anything already at the name refuses EXISTS, unfollowed — hardlink and symlink included',
    'A42-hash': 'a source hashes through the gate, and NO result carries an absolute path',
    'A45-root-identity': 'a RE-SPELLED root is accepted, a REPLACED one refuses — case-folding fails both',
    'A43-probe-errors': 'only ENOENT reaches the open — every other leaf-probe failure refuses',
    'A44-short-write': 'a short write refuses IO_ERROR, never a success with a reduced count',
    'A47-name-rules-host': 'both name screens follow the HOST on read, the stream screen is unconditional on CREATE, and neither takes an override',
    // ⚠ THE WRITE-FAILURE OUTCOME — S1, ruled 2026-08-31. These arms assert RETENTION, never
    // absence: a failed write leaves its target and REPORTS that it did. An arm here asserting the
    // file is gone would be asserting the design that was ruled out.
    //
    // ⚠ THE `A47-` PREFIX IS SHARED WITH `A47-name-rules-host` AND THE TWO ARE UNRELATED. Ids are
    // full strings, so nothing collides mechanically; the number is the plan's and is kept so the
    // mutation table, the plan's acceptance list and this inventory all join on the same key.
    'A47-write-throws-retains': 'a throwing write refuses AND reports the file it left behind',
    'A48-short-write-retains': 'a short write refuses AND reports the truncated file it left behind',
    'A49-close-fails-after-write': 'a failed close is a refusal, not a footnote — and the descriptor closes EXACTLY once',
    'A50-refusal-before-open-retains-nothing': 'a pre-open refusal states retained: null — the other half of the check',
    'A51-nonexistent-errno-retains-indeterminate': 'a non-EEXIST open failure is indeterminate; the injectable primitive promises nothing',
    'A52-success-closes-once': 'a successful write closes exactly once — a regression guard, and it PASSES against main',
    'A53-post-probe-exists-retains-nothing': 'an EEXIST at the OPEN retains nothing, witnessed by having reached the open',
    'META-primitives': 'per-primitive: each injected implementation is called at its site',
    'META-this-unbound': 'an injected callback receives `this === undefined`',
    'META-no-outside-names': 'no arm, refusal OR pass, names a path outside the root',
    'META-guard-armed': 'the containment guard is armed and non-vacuous',
    'SHAPE-no-mutator': 'the gate is frozen, null-prototype, no setter'
};

/** Startup and observer arms — `test/startup.test.js`. */
export const STARTUP_ARMS = {
    'S1-no-grant': 'no grant: static message, non-zero exit, factory never runs',
    'S2-missing': 'non-existent absolute grant refuses AND prints the resolved path',
    'S3-file-grant': 'a grant that is a file refuses',
    'S4-config-shapes': 'relative, drive-relative, namespaced, malformed, empty, null byte',
    'S5-precedence': 'the command line overrides the environment',
    'S6-arg-forms': '`--grant=value` and `--grant value`',
    'S7-valid': 'a valid grant starts and discloses the canonical root',
    'S8-link-grants': 'a dangling grant link, and one resolving to a file',
    'S9-import-touch': 'an import-time filesystem touch IS detected',
    'S10-bootstrap-order': 'the bootstrap arms the instrument before importing',
    'S11-child-no-grant': 'the child exits non-zero and names no candidate vault',
    'S12-separator-spellings': 'every separator spelling of one folder is ACCEPTED, and the\n        genuine volume-changing manglings still refuse',
    'S13-grant-source-parity': '--grant X, --grant=X and WYRD_GRANT=X agree exactly'
};

/** End-to-end arms — `test/handshake.test.js`. */
export const E2E_ARMS = {
    'E1-handshake': 'initialize handshake over stdio',
    'E2-one-tool': 'exactly one tool, `read`, with a real description',
    'E3-read-and-refuse': 'serves in-grant, refuses an escape, end to end',
    'E4-export-inventory': 'the fence module exports no raw primitive',
    'E5-disclosure': 'initialize.instructions discloses the CANONICAL grant, and names no outside path',
    'E6-preflight': 'the suite preflight refuses on denied symlink privilege, and separates the probe stages',
    'E7-layers': 'Mage layers are named only when present, and a plain folder gets no vault paragraph',
    'E7-shadow': 'a same-named FILE listed before a real layer directory does not shadow it',
    'E8-not-text': 'a file that is not valid UTF-8 is refused NOT_TEXT, never returned altered',
    'E9-grant-injection': 'a grant carrying a control character or absurd length is refused at the door',
    'E10-junction-preflight': 'the tier-1 preflight refuses when a junction cannot be created',
    'E11-read-only-hint': '`read` declares readOnlyHint, so the guarantee is machine-readable',
    // ⚠ THE OTHER HALF OF `E4`. E4 pins the built JAVASCRIPT's exports; the shipped `.d.ts` — a
    // deep-importable public contract, since `files` ships all of `dist` and there is no `exports`
    // map — was pinned by nothing until S1.
    'E12-declaration-inventory': 'the shipped .d.ts matches its REVIEWED baseline, shapes and optionality included'
};

export const ALL_ARMS = { ...FENCE_ARMS, ...STARTUP_ARMS, ...E2E_ARMS };

/**
 * TIER 2 — the arms that cannot run without the Windows symlink privilege.
 *
 * ⚠ THIS LIST IS READ OFF THE FIXTURES, NOT OFF THE ARM NAMES, and the two disagree. `issuelog.md`
 * called `A14` "junction-shaped"; it is not — the mirror needs a junction alias AND a relative
 * SYMLINK (`esc`) as its escape, so it belongs here. An arm is tier 2 if the fixture it reads was
 * built with `fs.symlinkSync` in a mode the OS gates. Junctions and hard links are NOT gated and
 * do not put an arm here.
 *
 * ⚠ MEMBERSHIP IS MACHINE-CHECKED, NOT TRUSTED. `scripts/run-tests.mjs --portable` asserts that the
 * skipped set equals this set EXACTLY — no more, no fewer. A misclassification in either direction
 * fails the run rather than quietly shrinking what got tested. That assertion is what makes the
 * partial run honest: it reports a denominator it cannot misstate.
 */
export const SYMLINK_PRIVILEGE_ARMS = new Set([
    // Fence arms whose fixtures are symlinks.
    'A11',                  // s_out / s_in — terminal file symlinks
    'A12',                  // sc_a / sc_in_a — symlink chains
    'A14-M',                // alias\esc — junction alias, but `esc` itself is a symlink
    'A14-T',                // d2\escape — the twin's escape is a symlink
    'A18',                  // s_rel_out / s_rel_in — relative-target symlinks
    'A19',                  // ds_out — directory symlink
    'A21',                  // scyc_a — symlink cycle
    'A21-rel',              // rc_a / rcyc_a — relative chain and relative cycle
    'A22',                  // sd — self-descending directory symlink
    'A22-hops',             // hop70_* / hop20_* — 90 symlinks
    'A23-dsym',             // dsalias — the mirror with a DIRECTORY SYMLINK alias
    // ⚠ `A28-symlinked-root` IS DELIBERATELY ABSENT, and it was here until both review lenses
    // caught it on 2026-08-29. Its name says symlinked; its fixture is
    // `fs.symlinkSync(real, named, 'junction')` — a junction, which is ungated. It was classified
    // off the arm NAME, which is the one thing the note above this list says never to do. It runs
    // in tier 1 and passes there.
    'A41-exists-refuses',   // s_out / s_in — both are symlinks, and the arm needs them to EXIST
    'A29-unc',              // unc_out — the only arm reaching !isAbsolute(rel)
    'A30-no-arbitration',   // probes s_out, sc_a, unc_out
    'A34-listing',          // listing\a_link — a symlink, and the arm asserts kind === 'link'
    'A36-defaults',         // re-runs the load-bearing arms, several of them symlink-backed
    'A38-both-contained',   // Lsym — directory symlink alias, the whole point of the arm
    'META-primitives',      // drives readlink / realpathNative through s_in
    'META-no-outside-names', // sweeps s_in, dsalias, sc_in_a, rc_a
    // Startup and end-to-end.
    'S8-link-grants',       // a grant that is a dangling link, and one resolving to a file
    'E5-disclosure'         // the canonical-root arm reaches the grant through a dir symlink
]);

/** TIER 1 — everything else. Derived, never hand-listed, so the two can never drift apart. */
export const PORTABLE_ARMS = Object.keys(ALL_ARMS).filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
