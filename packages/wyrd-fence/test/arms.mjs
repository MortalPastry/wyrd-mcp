/**
 * THE FENCE'S DESIGN INVENTORY of test arms.
 *
 * ⚠ This file is DECLARATIVE and deliberately separate from the registration path. A test that
 * is deleted leaves its row here, and `scripts/run-tests.mjs` fails the run because the union
 * of executed IDs no longer equals this list. A test that is added without a row here fails it
 * too.
 *
 * ⚠⚠ AND IT IS CHECKED AGAINST AN OUTSIDE REFERENT. Every id below is in
 * `../../wyrd/test/relocation-contract.json`, which has no generator. Deleting an arm AND its row
 * here — the one edit an inventory cannot catch on its own — refuses in the contract instead.
 * ⚠ SINCE 2026-09-02 THE TEXT IS CHECKED TOO, not only the id: each description below is compared
 * against the `asserts` the contract locked for that arm, so rewording one here without the paired
 * hand-edit to the contract refuses. That comparison had no reader for its first day, and two of
 * these rows had already drifted by the time it got one.
 *
 * ⚠ SEVENTEEN OF THEM ARE THIS PACKAGE'S OWN ENTRIES IN THE CONTRACT'S `armsAddedPostMove`
 * ARRAY RATHER THAN ITS LOCKED 88 — the two `FP` rows and `A54-writeall-loop` (2026-09-01),
 * `A55-same-path-replacement`, the three `PC` rows, and the ten `A56`–`A65` append rows
 * (2026-09-02). The array's own total is twenty-four; the other seven belong to `wyrd`, the
 * Reader package, and are not inventoried here. Everything else below was declared by
 * `wyrd-mcp` before the move. The distinction
 * is about what the 88 is EVIDENCE of, not about whether a row is checked: the 88 measures the
 * pre-move suite and so cannot grow, while an addition is still contracted (deleting one refuses)
 * and still routed.
 * ⚠ THAT SENTENCE NAMED ONLY THE TWO `FP` ROWS UNTIL 2026-09-02. `A54` was added on the same day as
 * the other two and this hand-maintained exception did not grow with it — which is the whole failure
 * mode of a list that has to be remembered rather than derived, and it is why the count above is
 * spelled out rather than left at "the FP rows and the recent ones".
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
    'A37-request-separators': 'request paths reach the same file in every separator spelling the HOST recognises — measured on the fixture\'s own volume, with the backslash spellings held to safety and coherence where it is not one',
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
    // ⚠ A NEW ID, ADDED 2026-09-01, AND IT IS `A54` RATHER THAN `A46`. `A46` was DELETED
    // deliberately as real lost coverage; reusing the number would make a hole look like a fill.
    // Recorded in the contract's `armsAddedPostMove`, outside the locked 88.
    //
    // ⚠ GRADED BY `M70-writeall-no-progress`, in the contract's `mutationsAddedPostMove`. The row
    // is NOT the `n <= 0` -> `n < 0` patch this arm's own body comment records: with the arm in
    // place that mutation makes the loop non-terminating and the suite hangs to the harness
    // timeout, so the row keeps the branch and takes a terminating form. See the row for why.
    'A54-writeall-loop': 'the SHIPPED writeAll completion loop — its no-progress break, its resumption after a partial write, and a throwing syscall',
    // ⚠⚠ A PINNED GAP, NOT A GUARANTEE — ADDED 2026-09-02, AND IT IS THE ONE ROW HERE THAT IS
    // SUPPOSED TO GO RED. See the block below this inventory for why it pins the hole rather than
    // closing it, and read that before "fixing" either the arm or the fence.
    'A55-same-path-replacement': 'the PINNED F8 GAP, MEASURED: a different directory built at the IDENTICAL canonical path is served for read, list, hash and create — and what making the identity comparison unconditional would cost',
    // ⚠⚠ THE APPEND PATH — TEN ARMS, ADDED 2026-09-02, ALL IN `armsAddedPostMove`. They grade
    // `appendLineInGrant`, which is the SECOND write entry point and does NOT reuse `resolveNew`:
    // that function refuses `EXISTS` on any existing leaf, which is correct for a create and fatal
    // for an append. So the parent resolution and the containment check are performed again by the
    // same calls in the same order, and every guard `resolveNew` carries needs its own arm here —
    // an arm on the create path proves nothing about a code path that only LOOKS the same.
    'A56-append-core': 'the first append creates and the second appends; the result carries only rel and the exact byte count, and the fence creates no parent directory',
    'A57-append-parent-containment': 'missing, non-directory and escaping parents refuse; an in-grant junction parent refuses PARENT_ALIAS with nothing landing on the canonical parent; a real directory parent still creates and then appends',
    'A58-append-leaf-no-follow': 'a symlink, dangling link, junction or directory leaf refuses before any write and touches nothing outside; an ordinary file appends, and a hard-linked leaf refuses NOT_A_FILE with neither name written',
    'A59-append-probe-errors': 'only a leaf ENOENT selects create — every other probe errno maps and reaches no open',
    'A60-append-target-changed': 'absent-to-present, present-to-missing, and pre/open/post identity changes each refuse TARGET_CHANGED before the write',
    'A61-append-name-screens': 'the CREATE screens run on an append: stream syntax and reserved device names refuse before any I/O',
    'A62-append-one-write': 'on the PRODUCTION primitives: O_APPEND is in effect, appendOnce is called exactly once with the whole line, a short count is not retried, and concurrent appenders produce intact lines',
    'A63-append-retention': 'pre-open refusals state retained: null; open, write, short-count and identity failures state the conservative indeterminate retention',
    'A64-append-close': 'success and failure each close exactly once, and a close failure cannot become a success',
    'A65-append-hardlink-refused': 'a leaf whose link count exceeds one refuses NOT_A_FILE at the pre-open reading with nothing opened, the same leaf appends once single-named, and a link created between the probe and the open is caught by the post-open reading before appendOnce',
    'A66-parent-alias-refused': 'an in-grant junction parent refuses PARENT_ALIAS with retained: null on BOTH write paths and leaves the aliased directory unchanged, the comparison fires ahead of the leaf probe so an existing leaf cannot hide the alias, a DEEPER aliased ancestor refuses the same way, EVERY refusing leg — create, append, occupied leaf, the deeper pair and the symlink pair — is checked CASE-FOLDED to name the caller\'s own spelling and never the alias TARGET, a directory-SYMLINK alias refuses identically where the privilege allows the fixture, and a case-only spelling of a real directory still writes',
    'META-primitives': 'per-primitive: each injected implementation is called at its site',
    'META-this-unbound': 'an injected callback receives `this === undefined`',
    'META-no-outside-names': 'no arm, refusal OR pass, names a path outside the root',
    'META-guard-armed': 'the containment guard is armed and non-vacuous',
    'SHAPE-no-mutator': 'the gate is frozen, null-prototype, no setter'
};

/**
 * ⚠⚠ WHY `A55-same-path-replacement` PINS THE GAP RATHER THAN THE FIX — the argument, in the
 * inventory, because this is the row a later session would otherwise close on its own authority.
 *
 * `rootStillCanonical` compares the granted directory's captured `dev`/`ino` only inside
 * `if (current !== root)`. Remove the granted folder, build a DIFFERENT one under the identical
 * name, and the re-resolve returns the string it expects, the comparison never runs, and every
 * operation is served against the new directory. That was a source READING for three independent
 * readers and none of them ran it; this arm ran it, on the real filesystem with the shipped
 * primitives, on 2026-09-02. The read, the listing, the hash and `createFileInGrant` all went
 * through to the replacement.
 *
 * ⚠ WHETHER THE COMPARISON SHOULD BECOME UNCONDITIONAL IS AN OPEN FORK (F8) AND IS NOT THIS ARM'S
 * TO SETTLE. The arm's job is to make the fork DECIDABLE — to state what the fence does today so
 * that a change to it is a ruling and not a silent tightening. Two things the ruling has to weigh,
 * and the arm asserts both rather than describing them:
 *
 *   · WHAT THE GAP COSTS. The grant names a directory; what is served is whatever later occupies
 *     its name. Reaching it needs local write access after startup, which is outside the stated
 *     threat model — the same footing as TOCTOU and hard links, and it is documented beside them
 *     in README.md, "Security boundary and limits".
 *   · WHAT CLOSING IT COSTS. The identity branch FAILS CLOSED when either side cannot supply
 *     `dev`/`ino`; network shares and some filesystems report `ino === 0`. Today such a root is
 *     served normally, because on an unchanged spelling the branch never runs. Make the comparison
 *     unconditional under the same fail-closed rule and that gate refuses EVERY request from the
 *     first one. The arm's last leg asserts the current service, so the ruling cannot land without
 *     that cost being seen.
 *
 * ⚠ NEITHER `A35-root-moved` NOR `A45-root-identity` CAN REACH THIS, which is why nothing caught
 * it: A35 puts a JUNCTION at the old name, whose canonical path differs, and A45 stages its
 * "replaced" case through a `realpathNative` returning a different SPELLING. Both take the
 * changed-spelling branch — the one branch that does compare identity.
 *
 * ⚠ GRADED BY `M71-root-identity-unconditional`, in the contract's `mutationsAddedPostMove`. That
 * row applies the F8 tightening to the BUILT output for one suite run and restores it — it does not
 * take F8, and `src/fsgate.ts` is untouched. What it buys is that the measurement above stops being
 * a one-off: tighten the branch by accident or by ruling and the row comes back SURVIVED, which
 * fails the matrix and makes the change a review event instead of a quiet one.
 * Recorded in the contract's `armsAddedPostMove`, outside the locked 88.
 */

/**
 * GRANT-SHAPE arms — `test/grant.test.js`.
 *
 * ⚠ THESE THREE ARRIVED FROM `wyrd-mcp/test/startup.test.js`, AND THE CONTRACT RECORDED THEM AS
 * `undecided` RATHER THAN GUESSING. Every assertion in each is a direct `createFsGate` call with
 * no product involvement, so what they assert is fence source contract; what put them in a file
 * called `startup` was where the grant string comes FROM, which is the Reader's concern and not
 * the assertion's. The Reader keeps `S2-missing`, `S3-file-grant` and `S13-grant-source-parity` as
 * its integration coverage of the same refusals reaching `main()`.
 *
 * ⚠ THE IDS DID NOT CHANGE. One id lives in exactly one package's inventory; renumbering them here
 * would have broken the join between this file, the contract and the mutation matrix.
 */
export const GRANT_ARMS = {
    'S4-config-shapes': 'relative, drive-relative, namespaced, malformed, empty, null byte',
    'S8-link-grants': 'a dangling grant link, and one resolving to a file',
    'S12-separator-spellings': 'every separator spelling of one folder is ACCEPTED, and the\n        genuine volume-changing manglings still refuse'
};

/**
 * PUBLIC-SURFACE arms — `test/surface.test.js`.
 *
 * These arrived from `wyrd-mcp/test/handshake.test.js`, where they asserted this package's source
 * contract from the other side of a package boundary. `E5-disclosure` and `E3-read-and-refuse`
 * remain the Reader's integration coverage of the same fence, reached over the wire.
 */
export const SURFACE_ARMS = {
    'E4-export-inventory': 'the fence module exports no raw primitive',
    'E9-grant-injection': 'a grant carrying a control character or absurd length is refused at the door',
    'E12-declaration-inventory': 'the shipped .d.ts matches its REVIEWED baseline, shapes and optionality included',
    'E16-baseline-byte-pin': 'the reviewed generated declaration baseline matches a -text attribute, so Git checkout performs no line-ending conversion'
};

/**
 * SUITE-INFRASTRUCTURE arms — `test/preflight.test.js`.
 *
 * ⚠⚠ THESE TWO ARE NEW IDS, AND THAT IS THE RULING RATHER THAN AN OVERSIGHT. Their subject is
 * `scripts/preflight.mjs`, which BOTH packages need after the move and which is therefore
 * duplicated rather than shared — the fence cannot import a module out of the Reader and still be
 * a package. The contract forbids one id living in two inventories, so the Reader keeps `E6` and
 * `E10` for its own copy and the fence's copy is graded by `FP1` and `FP2`. They are recorded in
 * the contract's `armsAddedPostMove` array, outside the locked 88, so the pre-move denominator
 * cannot be inflated by adding arms.
 */
export const SUITE_ARMS = {
    'FP1-preflight': "the FENCE's own suite preflight refuses on denied symlink privilege, and separates the probe stages",
    'FP2-junction-preflight': "the FENCE's own tier-1 preflight refuses when a junction cannot be created"
};

/**
 * PUBLISHED-CLAIM arms — `test/published-claims.test.js`.
 *
 * ⚠⚠ THESE THREE CHECK STRUCTURE, NEVER TRUTH, and the distinction is the whole reason they are
 * worth having AND the reason they must not be read as more. The fence's published limits were
 * wrong three times in one night; these would have caught EXACTLY ONE — the description pointing a
 * reader at `src/fsgate.ts`, which the tarball does not contain. The other two were prose that had
 * been true and went false when the code moved, and nothing in this repo catches that class.
 *
 * ⚠ NOT A SECOND CLAIM MATRIX. The fence's limits live in ONE place by design, so there is no
 * cross-surface agreement to check; `E14` answers a question the fence deliberately does not have.
 * They share no engine with it either — a shared module would need a cross-package relative import
 * in a shipped file, which `importClosureProblems()` refuses.
 */
export const PUBLISHED_CLAIM_ARMS = {
    'PC1-pointers-resolve': 'every published pointer resolves to a heading and a file a stranger actually receives',
    'PC2-retired-wordings': 'a retired wording does not come back on any published fence artifact',
    'PC3-limits-section-live': 'the limits section is substantive and the source header still points at it rather than restating it'
};

export const ALL_ARMS = { ...FENCE_ARMS, ...GRANT_ARMS, ...SURFACE_ARMS, ...SUITE_ARMS, ...PUBLISHED_CLAIM_ARMS };

/**
 * TIER 2 — the arms that cannot run without the Windows symlink privilege.
 *
 * ⚠ READ OFF THE FIXTURES, NOT OFF THE ARM NAMES. An arm is tier 2 if the fixture it reads was
 * built with `fs.symlinkSync` in a mode the OS gates. Junctions and hard links are NOT gated and
 * do not put an arm here — `A28-symlinked-root` is the standing example: its name says symlinked
 * and its fixture is a junction, so it runs in tier 1 and passes there.
 *
 * ⚠ MEMBERSHIP IS MACHINE-CHECKED. `scripts/run-tests.mjs --portable` asserts the skipped set
 * equals this set EXACTLY — no more, no fewer.
 *
 * ⚠ `S8-link-grants` CAME WITH ITS TIER. It was tier 2 in the Reader and its fixture is unchanged;
 * `E5-disclosure` was the Reader's other tier-2 non-fence arm and stayed there with the arm.
 */
export const SYMLINK_PRIVILEGE_ARMS = new Set([
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
    'A41-exists-refuses',   // s_out / s_in — both are symlinks, and the arm needs them to EXIST
    // ⚠ TIER 2 FOR ITS SYMLINK LEAVES ONLY. Its junction and directory leaves need no privilege,
    // and `A57-append-parent-containment` deliberately stays in tier 1 for that reason — the
    // junction half of the append path is exercised on a machine without Developer Mode, which is
    // where an unattended fence is most likely to be running.
    'A58-append-leaf-no-follow', // s_out / s_in / dangle_out — the arm needs them to EXIST
    'A29-unc',              // unc_out — the only arm reaching !isAbsolute(rel)
    'A30-no-arbitration',   // probes s_out, sc_a, unc_out
    'A34-listing',          // listing\a_link — a symlink, and the arm asserts kind === 'link'
    'A36-defaults',         // re-runs the load-bearing arms, several of them symlink-backed
    'A38-both-contained',   // Lsym — directory symlink alias, the whole point of the arm
    'META-primitives',      // drives readlink / realpathNative through s_in
    'META-no-outside-names', // sweeps s_in, dsalias, sc_in_a, rc_a
    'S8-link-grants'        // a grant that is a dangling link, and one resolving to a file
]);

/** TIER 1 — everything else. Derived, never hand-listed, so the two can never drift apart. */
export const PORTABLE_ARMS = Object.keys(ALL_ARMS).filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
