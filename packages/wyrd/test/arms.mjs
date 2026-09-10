/**
 * THE DESIGN INVENTORY of test arms.
 *
 * ⚠ This file is DECLARATIVE and deliberately separate from the registration path. A test that
 * is deleted leaves its row here, and `scripts/run-tests.mjs` fails the run because the union
 * of executed IDs no longer equals this list. A test that is added without a row here fails it
 * too. Each row carries what the arm is FOR, so removing one is a visible, reviewable edit
 * rather than a silent deletion of two adjacent lines.
 *
 * ⚠⚠ THE FENCE'S ARMS LEFT ON 2026-09-01 AND THAT IS NOT A SHRUNKEN SUITE. 62 fence arms, the
 * three grant-shape arms (`S4`, `S8`, `S12`) and the three fence-surface arms (`E4`, `E9`, `E12`)
 * now live in `wyrd-fence`, which measures its own adequacy — see
 * `designs/2026-09-01-fence-test-relocation-plan.md`. What remains here is what this package is
 * FOR: product behaviour and integration coverage of the fence through the Reader's own paths.
 *
 * ⚠ THE HONEST LIMIT this file used to state — "deleting a test AND its row here still passes" —
 * IS NOW CLOSED FOR EVERY PRE-MOVE ID. `test/relocation-contract.json` is an outside referent with
 * no generator, and `scripts/run-tests.mjs` checks this inventory against it before it spawns
 * anything. The limit survives only for arms added after 2026-09-01 that nobody adds to the
 * contract's `armsAddedPostMove` list.
 */

/**
 * Startup and observer arms — `test/startup.test.js`.
 *
 * ⚠ `S2-missing` AND `S3-file-grant` ARE THE INTEGRATION HALF of refusals whose direct assertions
 * moved to the fence with `S4`/`S8`. They stay because what they assert is that `main()` surfaces
 * the reason and prints the resolved path, which is this package's disclosure behaviour and not
 * the gate's. Removing them because "the fence covers that now" would delete the only coverage of
 * the plumbing between them.
 */
export const STARTUP_ARMS = {
    'S1-no-grant': 'no grant: static message, non-zero exit, factory never runs',
    'S2-missing': 'non-existent absolute grant refuses AND prints the resolved path',
    'S3-file-grant': 'a grant that is a file refuses',
    'S5-precedence': 'the command line overrides the environment',
    'S6-arg-forms': '`--grant=value` and `--grant value`',
    'S7-valid': 'a valid grant starts and discloses the canonical root',
    'S9-import-touch': 'an import-time filesystem touch IS detected',
    'S10-bootstrap-order': 'the bootstrap arms the instrument before importing',
    'S11-child-no-grant': 'the child exits non-zero and names no candidate vault',
    'S13-grant-source-parity': '--grant X, --grant=X and WYRD_GRANT=X agree exactly',
    'S14-no-grant-claims': 'the no-grant refusal states both refusals, the outside-reaching hard link, and the scoped read-only',
    'S15-client-config-entrypoint': 'the example client config resolves to the real built entrypoint and its grant is still a placeholder'
};

/**
 * End-to-end arms — `test/handshake.test.js`.
 *
 * ⚠ `E3-read-and-refuse` AND `E5-disclosure` ARE WHAT THE PLAN ASKED THIS PACKAGE TO KEEP: the
 * fence exercised over the wire, through the Reader's normal server paths, rather than by direct
 * `createFsGate` calls. `E4`, `E9` and `E12` were the direct ones and went with the fence.
 *
 * ⚠ `E14-surface-claims` IS THE ONLY ARM HERE THAT OWNS A RELATIONSHIP RATHER THAN A STRING.
 * Every other surface arm — `S14`, `E13`, `E5` — validates ONE surface against ONE set of
 * patterns, which is why the disclosure surfaces disagreed three times on 2026-09-01 while the
 * battery stayed green. `E14` declares the claim set once and checks every surface against it, so
 * a new surface or a changed claim is one edit in one place. It lives in this file because the
 * runtime surfaces arrive over the wire. ⚠ Its surface LIST is derived as of 2026-09-02 — the
 * hand-written one was wrong four times running, which is the defect the arm exists to catch,
 * sitting inside the arm.
 *
 * ⚠⚠ `E15-refusal-vocabulary` IS THE ONE ARM HERE WHOSE TWO SIDES COME FROM DIFFERENT PLACES, and
 * that is the whole of it. `E14` compares prose to prose, so it makes the surfaces agree and cannot
 * make them true — it was found on 2026-09-02 pinning three false claims across every surface it
 * covers, green throughout. `E15` derives one side from the PROGRAM (the fence's enumerated refusal
 * unions plus the reason literals in this package's own build output) and requires the prose to
 * account for it. A new refusal class then forces a documentation decision rather than widening the
 * gap in silence.
 *
 * ⚠ `E6` AND `E10` STAYED, AND THE FENCE'S COPY OF THE SAME GUARD IS GRADED BY NEW IDS. Their
 * subject is `scripts/preflight.mjs`, suite infrastructure both packages need and neither can
 * import across the boundary. The contract forbids one id living in two inventories, so these two
 * keep grading this package's copy and `FP1`/`FP2` grade the fence's.
 */
export const E2E_ARMS = {
    'E1-handshake': 'initialize handshake over stdio',
    'E2-one-tool': 'exactly one tool, `read`, with a real description',
    'E3-read-and-refuse': 'serves in-grant, refuses an escape, end to end',
    'E5-disclosure': 'initialize.instructions discloses the CANONICAL grant, and names no outside path',
    'E6-preflight': 'the suite preflight refuses on denied symlink privilege, and separates the probe stages',
    'E7-layers': 'Mage layers are named only when present, and a plain folder gets no vault paragraph',
    'E7-shadow': 'a same-named FILE listed before a real layer directory does not shadow it',
    'E8-not-text': 'a file that is not valid UTF-8 is refused NOT_TEXT, never returned altered',
    'E10-junction-preflight': 'the tier-1 preflight refuses when a junction cannot be created',
    'E11-read-only-hint': '`read` declares readOnlyHint, so the guarantee is machine-readable',
    'E13-read-description': 'the `read` description states both refusals and the outside-reaching hard link, as the model receives it',
    'E14-surface-claims': 'every DERIVED disclosure surface carries one declared claim set, every claim either carried or explicitly exempt per surface, and no retired wording anywhere',
    'E15-refusal-vocabulary': 'every refusal the program can return — the fence\'s enumerated unions plus the Reader\'s own — is stated on a surface or exempted with a written reason'
};

/**
 * Registry-manifest arms — `test/manifest-schema.test.js`.
 *
 * ⚠ `server.json` DECLARED ITS OWN CONTRACT AND NOTHING READ THE DECLARATION. Its first line is a
 * `$schema` URL; until 2026-09-02 no schema was vendored and no arm validated the file against one,
 * so a malformed manifest was caught by the MCP Registry at SUBMISSION rather than here. That is
 * the worst place for it: the npm publish has already happened by then.
 *
 * ⚠ THE TWO ARMS ANSWER DIFFERENT QUESTIONS AND NEITHER SUBSUMES THE OTHER. `MF1` asks whether the
 * file is WELL-FORMED against the schema it names. `MF2` asks whether it is TRUE — a manifest can
 * satisfy every schema constraint and still advertise a version that is not what shipped, or a
 * `name` that `package.json`'s `mcpName` does not match, which is the pair the registry reads out
 * of the published tarball to prove ownership. Nothing cross-referenced them before.
 */
export const MANIFEST_ARMS = {
    'MF1-manifest-schema': 'the vendored MCP registry schema still spans the bounded validator, and server.json conforms to it',
    'MF2-manifest-cross-reference': 'server.json\'s declared $schema is the vendored copy\'s $id, and its name, version and npm identifier agree with package.json and with the built program'
};

export const ALL_ARMS = { ...STARTUP_ARMS, ...E2E_ARMS, ...MANIFEST_ARMS };

/**
 * TIER 2 — the arms that cannot run without the Windows symlink privilege.
 *
 * ⚠ READ OFF THE FIXTURES, NOT OFF THE ARM NAMES. An arm is tier 2 if the fixture it reads was
 * built with `fs.symlinkSync` in a mode the OS gates. Junctions and hard links are NOT gated and
 * do not put an arm here — `A28-symlinked-root`, now the fence's, was the standing example of that
 * mistake: its name says symlinked and its fixture is a junction.
 *
 * ⚠ MEMBERSHIP IS MACHINE-CHECKED, NOT TRUSTED. `scripts/run-tests.mjs --portable` asserts that
 * the skipped set equals this set EXACTLY — no more, no fewer. A misclassification in either
 * direction fails the run rather than quietly shrinking what got tested.
 *
 * ⚠ IT IS DOWN TO ONE ENTRY AND THAT IS NOT A WEAKENED GATE. Every other tier-2 arm was
 * fence-owned and moved; `S8-link-grants` moved with them. What is left is the one arm in this
 * package whose fixture is a symlink. The set is still asserted by identity, so a second arm that
 * quietly starts needing the privilege fails the portable run rather than joining it.
 */
export const SYMLINK_PRIVILEGE_ARMS = new Set([
    'E5-disclosure'         // the canonical-root arm reaches the grant through a dir symlink
]);

/** TIER 1 — everything else. Derived, never hand-listed, so the two can never drift apart. */
export const PORTABLE_ARMS = Object.keys(ALL_ARMS).filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
