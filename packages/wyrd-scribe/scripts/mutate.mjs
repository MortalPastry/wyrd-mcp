/**
 * THE SCRIBE'S MUTATION MATRIX — adequacy measurement for the span resolver's and stamp path's arms.
 *
 * Sibling of `packages/wyrd/scripts/mutate.mjs`. Same ordering, same discipline: build ONCE, then
 * patch the built artifact and drive the runner DIRECTLY.
 *
 * ⚠⚠ WHY THIS SCRIPT EXISTS RATHER THAN A COMMENT TELLING YOU TO BE CAREFUL. `npm test` is
 * `npm run build && node scripts/run-tests.mjs` — so a mutation run that shells out to `npm test`
 * RECOMPILES `dist/` FROM `src/` and erases the mutant before the suite ever sees it. Every mutant
 * then "survives", which reads as a weak guard and is actually a dead instrument. Measured
 * 2026-08-31: three mutants reported as survivors, all six killed once the runner was called
 * directly. A written warning had already been added and did not prevent the next person reaching
 * for `npm test` — which is why the rule is a script now.
 *
 * ⚠ A ROW WHOSE ANCHOR DOES NOT MATCH EXACTLY ONCE EXITS NON-ZERO. A stale anchor is a broken
 * instrument, not a survivor, and reporting it beside real survivors is how a matrix certifies
 * guards it never ran. Repair the row's `from`; never delete the row to make the run green.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { lineEndingOf, withLineEnding } from '../../wyrd-fence/scripts/mutation-text.mjs';
import { guardBattery, batteryLockFixture, registerBatteryTargets, recordBatteryMutant, restoreBatteryTarget, assertNoBatteryLockRefusal } from '../../wyrd-fence/scripts/battery-lock.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG = path.resolve(HERE, '..');
if (!process.argv.some(arg => ['--eol-fixture', '--restore-fixture'].includes(arg))) guardBattery('scribe mutation');
batteryLockFixture();
const RUNNER = path.join('scripts', 'run-tests.mjs');

/**
 * ⚠ EVERY ROW NAMES ITS OWN `file`, SINCE 2026-09-02. The matrix was pinned to `dist/span.js` by a
 * module-level constant, so a row anchored in any other module patched the wrong file, matched zero
 * times, and reported as an UNANCHORED BROKEN INSTRUMENT rather than as a survivor — which is the
 * right failure, but only for as long as someone reads it. Naming the file per row is what lets the
 * stamp path be measured at all.
 */
const distOf = (file) => path.join(PKG, 'dist', file);

const NL = '\n';

/**
 * Every row traces to a finding. None was invented to pad the matrix.
 *
 * `M1`/`M2` are code-gate round 1's two live defects. `M3`/`M4` are the extra-key and proxy legs of
 * the no-leak property. `M5`/`M6` are round 2's MEASURED SURVIVORS — a frozen own ACCESSOR, which
 * `Object.isFrozen` permits because freeze constrains the property and never the getter's return
 * value. M6 is the sharp one: `where` is documented "enumerated so it cannot carry a value", and
 * under M6 it carries the whole source to every reader after the third.
 */
const MUTANTS = [
    /**
     * ---- THE SPAN PATH -----------------------------------------------------
     *
     * ⚠⚠ THESE SIX PREDATE `killedBy` AND WERE NOT EXEMPT FROM IT — THE CONVENTION SIMPLY ARRIVED
     * AT THE STAMP SECTION BELOW AND NOBODY CAME BACK. Measured 2026-09-03, one mutant at a time
     * against the real suite, rather than reasoned:
     *
     *   M1 -> B1-request-inherited          (ONE arm)
     *   M2 -> B1-quote-match-unaligned      (ONE arm)
     *   M3 -> 27 arms · M4 -> 27 · M5 -> 27 · M6 -> 23
     *
     * So M1 and M2 name their arm like every row below. M3-M6 CANNOT, and the reason is
     * structural rather than sloppy: the no-leak property is asserted by a SHARED HELPER that
     * every span arm calls, and those four mutants break the envelope for every result the module
     * returns. Naming one arm out of 27 would be a coin toss dressed as attribution.
     *
     * ⚠ THEY DECLARE `killedByAll` INSTEAD, which the runner treats as "must redden broadly".
     * That still catches the failure mode attribution exists for — a row that goes red through
     * something incidental — because a mutant that stopped being a global leak would redden ONE
     * arm or none, and the floor refuses both.
     */
    {
        id: 'M1-read-inherited-unconditionally',
        file: 'span.js',
        note: 'own-key checks bind the DECISION but not the READ; an inherited accessor fires',
        killedBy: ['B1-request-inherited'],
        from: 'const offsetValue = hasOffset ? view.offset : undefined;',
        to: 'const offsetValue = view.offset;'
    },
    {
        id: 'M2-quote-only-alignment-blames-length',
        file: 'span.js',
        note: 'a quote-only request has no `length` member to blame',
        killedBy: ['B1-quote-match-unaligned'],
        from: `refuse('SPAN_NOT_ALIGNED', 'request');${NL}    return resolved(first, needle.length, quoteValue);`,
        to: `refuse('SPAN_NOT_ALIGNED', 'length');${NL}    return resolved(first, needle.length, quoteValue);`
    },
    {
        id: 'M3-success-carries-an-extra-key',
        file: 'span.js',
        note: 'the plain extra-key leg of the no-leak property',
        killedByAll: 20,
        from: 'return Object.freeze({ ok: true, offset, length, quote });',
        to: "return Object.freeze({ ok: true, offset, length, quote, sourceBytes: 'LEAK' });"
    },
    {
        id: 'M4-frozen-proxy-with-a-dynamic-tojson',
        file: 'span.js',
        note: 'a proxy passes every structural check and serves a leaking toJSON',
        killedByAll: 20,
        from: 'return Object.freeze({ ok: true, offset, length, quote });',
        to: 'return new Proxy(Object.freeze({ ok: true, offset, length, quote }), '
            + "{ get(t, k) { if (k === 'toJSON') return () => ({ ok: true, offset, length, quote, "
            + "sourceBytes: 'LEAK' }); return Reflect.get(t, k); } });"
    },
    {
        id: 'M5-own-accessor-leaks-from-the-fifth-read',
        file: 'span.js',
        note: 'round 2 SURVIVOR until the data-property assertion landed',
        killedByAll: 20,
        from: `function resolved(offset, length, quote) {${NL}    return Object.freeze({ ok: true, offset, length, quote });`,
        to: `function resolved(offset, length, quote) {${NL}    let n = 0;${NL}`
            + '    return Object.freeze({ ok: true, offset, length, '
            + "get quote() { n += 1; return n < 5 ? quote : 'LEAKED-SOURCE'; } });"
    },
    {
        id: 'M6-where-accessor-carries-the-source',
        file: 'span.js',
        note: 'round 2 SURVIVOR; `where` is documented as unable to carry a value',
        killedByAll: 20,
        from: `function refuse(reason, where) {${NL}    return Object.freeze({ ok: false, reason, where });`,
        to: `function refuse(reason, where) {${NL}    let n = 0;${NL}`
            + '    return Object.freeze({ ok: false, reason, '
            + "get where() { n += 1; return n < 4 ? where : 'LEAKED-SOURCE'; } });"
    },

    /**
     * ---- THE STAMP PATH ----------------------------------------------------
     *
     * ⚠ EACH ROW NAMES THE ARM(S) IT MUST REDDEN, and the naming is not decoration. A mutant killed
     * by a DIFFERENT arm than the one it was written for is measuring something other than what the
     * row claims — usually an incidental assertion — and the row would then certify a guard nobody
     * has. `killedBy` is checked against the runner's output, so a row killed only elsewhere fails
     * the matrix.
     *
     * ⚠ ONLY BRANCHES WITH AN EXACT ONE-TIME ANCHOR ARE HERE. Several load-bearing rules — the
     * source-cache key, the record's key order — compile to code with no unique textual anchor, and
     * a row that matches twice is a broken instrument rather than a measurement. They are left out
     * rather than anchored loosely.
     */
    {
        id: 'M7-arc-check-runs-after-the-sources',
        file: 'stamp.js',
        note: 'the Arc/ screen becomes an existence oracle if a source is read before it fires',
        killedBy: ['ST5-arc-immutable-before-sources'],
        // ⚠ RE-ANCHORED TWICE ON 2026-09-08, EACH TIME WITH THE DETAIL'S OWN REWRITE — which is
        // what an anchor quoting returned API text costs, and the cost is accepted because no
        // shorter unique anchor exists at this branch. The first rewrite narrowed a claim asserted
        // across every tier; the second dropped the still-CATEGORICAL "does not write into it" for
        // what the screen actually does, refuse what is ADDRESSED into `Arc/` (see `stamp.ts`'s note
        // there). The same day the site gained its `preConfigRefuse` wrapper, which is part of the
        // anchor. The mutation's meaning is unchanged through all of it: make the screen conditional
        // so a request carrying sources reads them before it fires.
        from: "return preConfigRefuse(scribeRefuse('ARC_IMMUTABLE', 'Arc/ is the provenance layer; this server refuses writes addressed into it'));",
        to: "if (request.derivedFrom.length === 0) return preConfigRefuse(scribeRefuse('ARC_IMMUTABLE', 'Arc/ is the provenance layer; this server refuses writes addressed into it'));"
    },
    {
        id: 'M8-arc-check-is-case-sensitive',
        file: 'stamp.js',
        note: "a lowercase `arc/` reaches the same file on this host; a case-sensitive screen stops only the polite half",
        killedBy: ['ST5-arc-immutable-before-sources'],
        // ⚠ RE-ANCHORED 2026-09-03. This row read `from: 'return /^arc(\\/|$)/i.test(folded);'`,
        // a PREFIX test over a folded path. The screen has since become a SEGMENT test over the
        // split path, so the anchor matched 0 times and the row reported as a broken instrument
        // rather than as a survivor — which is the honest failure, and is how it was caught. The
        // mutation's meaning is unchanged: drop the `i` flag so the screen stops only the polite
        // half. ⚠ The `?? ''` is part of the anchor; without it this matches nothing again.
        from: "return /^arc$/i.test(segments[0] ?? '');",
        to: "return /^Arc$/.test(segments[0] ?? '');"
    },
    {
        id: 'M9-source-digest-not-compared',
        file: 'source.js',
        note: 'without the comparison a chimera read passes and every span over it is silently mislocated',
        killedBy: ['ST7-source-changed'],
        from: 'if (bytes.length !== hashed.size || ours !== hashed.digest) {',
        to: 'if (false) {'
    },
    {
        id: 'M10-quote-truncated-on-a-byte-boundary',
        file: 'lineage.js',
        note: 'a byte cut through a multibyte sequence stores text that does not re-encode to its source bytes',
        killedBy: ['ST9-quote-truncated'],
        from: "const written = held.write(text, 0, QUOTE_BYTE_BUDGET, 'utf8');",
        to: "const written = full.copy(held, 0, 0, QUOTE_BYTE_BUDGET);"
    },
    {
        id: 'M11-quote-hash-over-the-stored-prefix',
        file: 'lineage.js',
        note: 'hashing the cut text makes a truncated span unverifiable against its source — healthy-looking, proves nothing',
        killedBy: ['ST9-quote-truncated'],
        from: `        text: stored.toString('utf8'),${NL}        original_utf8_bytes: full.length,${NL}        stored_utf8_bytes: written,${NL}        sha256,`,
        to: `        text: stored.toString('utf8'),${NL}        original_utf8_bytes: full.length,${NL}        stored_utf8_bytes: written,${NL}        sha256: hashText(stored),`
    },
    {
        id: 'M12-line-ceiling-not-enforced',
        file: 'lineage.js',
        note: 'B4 argues atomicity for a BOUNDED line; an unbounded one is the failure case the bound exists for',
        killedBy: ['ST10-line-too-large'],
        from: 'if (line.length > MAX_LINE_BYTES) {',
        to: 'if (false) {'
    },
    {
        id: 'M13-frontmatter-conflict-overwrites',
        file: 'frontmatter.js',
        note: 'replacing an existing key destroys either a prior stamp or the user\'s own data, and this module cannot tell which',
        killedBy: ['ST14-frontmatter-conflict'],
        from: 'if (keyOf(line) === FRONTMATTER_KEY) {',
        to: 'if (false) {'
    },
    {
        id: 'M14-frontmatter-conflict-matches-indented-keys',
        file: 'frontmatter.js',
        note: "an indented key belongs to someone else's mapping; matching it refuses legitimate documents forever",
        killedBy: ['ST14-frontmatter-conflict'],
        // ⚠ THE ANCHOR IS THE EMITTED SHAPE, NOT THE SOURCE SHAPE. `tsc` splits a single-line
        // `if (x) return y;` across two lines, so an anchor copied from `src/` matches ZERO times
        // and reports as a broken instrument. Anchors are read from `dist/`, which is what gets
        // patched.
        from: `    if (/^\\s/.test(body))${NL}        return null;`,
        to: `    if (false)${NL}        return null;`
    },

    /**
     * ---- THE PRODUCTION APPENDER -------------------------------------------
     *
     * ⚠ TWO ROWS, NOT MORE, AND THE LIMIT IS THE ANCHOR RULE RATHER THAN MODESTY. `gateAppender`
     * compiles to a single expression: the path it names and the result it returns. Those are the
     * two things it can get wrong, and each has an exact one-time anchor. The `createScribe`
     * default is deliberately NOT a row — nothing in this package's arms constructs a Scribe (the
     * entry point exports nothing), so a mutant there would survive and certify a gap rather than
     * measure one. That gap is real and named here rather than papered over: the default is
     * exercised by inspection and by `index.ts`'s type, not by an arm.
     */
    {
        id: 'M15-appender-reports-a-refusal-as-success',
        file: 'ledger.js',
        note: 'a refused append reported as ok is a page written with NO provenance and no way to know',
        killedBy: ['ST24-ledger-parent-missing-refuses-after-create'],
        from: 'appendLine: (line) => gate.appendLineInGrant(LINEAGE_PATH, line)',
        to: 'appendLine: async (line) => { await gate.appendLineInGrant(LINEAGE_PATH, line); '
            + 'return { ok: true, bytes: line.length }; }'
    },
    {
        id: 'M16-ledger-written-beside-the-config-not-to-it',
        file: 'ledger.js',
        note: 'a provenance log written to a path nobody reads is provenance that does not exist',
        killedBy: ['ST22-ledger-line-lands', 'ST23-ledger-accumulates', 'ST25-ledger-concurrent'],
        from: 'gate.appendLineInGrant(LINEAGE_PATH, line)',
        to: "gate.appendLineInGrant('.wyrd/lineage-2.jsonl', line)"
    },

    /**
     * ---- THE COLD-REVIEW ROUND, 2026-09-02 ---------------------------------
     *
     * ⚠ FIVE ROWS FOR FIVE FIXED BRANCHES, AND THE COUNT IS THE ANCHOR RULE AGAIN RATHER THAN
     * modesty. Each of these has an exact one-time textual anchor in `dist/`. The sixth fix — the
     * frontmatter projection dropping `page` — has NO such anchor: it is the ABSENCE of a key in an
     * object literal, and a mutant restoring it would have to insert rather than replace, which
     * this harness's `from`/`to` shape cannot express as a one-time match. It is left out and named
     * here rather than anchored loosely; `ST26` and the shape assertions in `ST12`/`ST13` are what
     * hold it, and they are three arms over two code paths rather than one.
     */
    {
        id: 'M17-draft-placeholder-narrower-than-the-real-line',
        file: 'stamp.js',
        note: 'a one-digit placeholder for a sixteen-digit field lets an over-size draft create the page, then reports a fabricated IO_ERROR',
        killedBy: ['ST27-line-limit-is-decided-before-create'],
        from: "pageContent: contentHash('0'.repeat(64), Number.MAX_SAFE_INTEGER),",
        to: "pageContent: contentHash('0'.repeat(64), 0),"
    },
    {
        id: 'M18-counts-checked-after-the-sources-are-read',
        file: 'stamp.js',
        note: 'a request over a documented cap reads every source first, leaking existence and timing through a refusal it had already earned',
        killedBy: ['ST28-guaranteed-refusals-read-nothing'],
        // ⚠ RE-ANCHORED 2026-09-08. It read `checkRequestCounts(view.derivedFrom.length, ...)`; both
        // counts now come off the SNAPSHOT rather than from a second walk of the caller's array, so
        // the anchor matched zero times. The mutation's meaning is unchanged: drop the cap so a
        // request over it reads every source before refusing for a reason it had already earned.
        from: 'const counted = checkRequestCounts(snapshot.length, requestedSpans);',
        to: 'const counted = null;'
    },
    {
        id: 'M19-span-shape-checked-after-the-source-is-read',
        file: 'stamp.js',
        note: 'a malformed span reads its source before the shape that refuses it is consulted — the same oracle, one entry at a time',
        killedBy: ['ST28-guaranteed-refusals-read-nothing'],
        from: 'const shape = spanShapeFault(spanRequest);',
        to: 'const shape = { ok: true };'
    },
    {
        id: 'M20-event-id-reminted-for-the-ledger-line',
        file: 'stamp.js',
        note: 'a second mint gives one write two identities and breaks the only join between the stamped page and its ledger line',
        killedBy: ['ST12-frontmatter-on-prepended', 'ST26-frontmatter-carries-no-page-identity'],
        from: 'eventId: draft.event_id,',
        to: 'eventId: newEventId(),'
    },
    {
        id: 'M21-any-first-line-rule-is-an-opening-fence',
        file: 'frontmatter.js',
        note: 'without the mapping-line check a key is spliced between two horizontal rules, into the middle of the user\'s prose',
        killedBy: ['ST30-horizontal-rule-is-not-frontmatter'],
        from: `            if (!looksLikeMapping(lines, 1, index)) {`,
        to: `            if (false) {`
    },
    {
        id: 'M22-inserted-line-ignores-the-document-ending',
        file: 'frontmatter.js',
        note: 'a lone LF inserted into a CRLF document produces mixed endings — a whole-file diff on the next normalisation',
        killedBy: ['ST31-crlf-preserved'],
        from: 'const spliced = [...lines.slice(0, index), keyLine + endingOf(line), ...lines.slice(index)];',
        to: 'const spliced = [...lines.slice(0, index), keyLine, ...lines.slice(index)];'
    },
    {
        /**
         * ⚠⚠ THE ORDER IS THE GUARD, AND THIS ROW IS WHAT MAKES THAT A CLAIM RATHER THAN A COMMENT.
         *
         * Option C's part 3 hoists `loadConfig`'s exclusive-create ahead of the config read. The
         * mutant restores the read-first order — which is a perfectly reasonable-looking shape, and
         * is what the code did until 2026-09-08 — and everything except the ordering property still
         * works: a missing config is still minted, an existing one is still read, the race is still
         * handled. What breaks is that `readFileInGrant` resolves THROUGH an in-grant junction and
         * asks nothing about where the parent landed, so a `.wyrd -> Arc` alias is never questioned:
         * the page is created and only the ledger append refuses, leaving an ORPHAN PAGE — which is
         * strictly the failure part 3 exists to prevent, arriving through the one change a
         * maintainer would make by tidying.
         *
         * ⚠ THE MUTANT IS THE PREVIOUS SHIPPED CODE, which is the strongest form a mutation row
         * takes: it cannot be dismissed as a shape nobody would write.
         *
         * ⚠⚠ RE-ANCHORED 2026-09-08 ON THE TWO OPENING LINES ONLY, AND THE SHORTENING IS THE FIX
         * RATHER THAN A CONVENIENCE. The previous anchor spanned the whole block, so the comments
         * `tsc` emits BETWEEN those statements were part of the match — and `config.ts` gained two
         * such comments the same day `config_created` landed, which would have made this row match
         * zero times and report as a broken instrument. Two adjacent statement lines are still a
         * one-time match in this file and carry no interleaved comment. The mutant reaches the same
         * read-first shape by making the create CONDITIONAL on the read having failed `MISSING`,
         * which is the previous order expressed against the current envelope: the `created` flag
         * stays truthful on both branches, so the row measures the ORDERING and nothing else.
         */
        id: 'M23-config-read-before-create',
        file: 'config.js',
        note: 'restore the read-first config load; an aliased .wyrd is then invisible until the ledger append, after the page exists',
        killedBy: ['ST39-config-parent-alias-refused'],
        from: '    const minted = mint(newUuid());\n    const created = await gate.createFileInGrant(CONFIG_PATH, serialiseConfig(minted));',
        to: '    const preread = await gate.readFileInGrant(CONFIG_PATH, 0, CONFIG_READ_LIMIT);\n'
            + '    if (!isRefusal(preread)) {\n'
            + '        const pre = readSlice(preread);\n'
            + "        if ('ok' in pre)\n"
            + '            return pre;\n'
            + '        return Object.freeze({ config: pre, created: false });\n'
            + '    }\n'
            + "    if (preread.reason !== 'MISSING')\n"
            + '        return preread;\n'
            + '    const minted = mint(newUuid());\n'
            + '    const created = await gate.createFileInGrant(CONFIG_PATH, serialiseConfig(minted));'
    },
    {
        /**
         * ⚠⚠ THE BRANCH `ST38`'s NOTE CALLED UNREACHABLE, AND THIS ROW IS WHY THAT MATTERED.
         *
         * When option C's part 1 landed, `ST38` was replaced and its note argued that the
         * post-create `checkLineSize` could no longer fire: the canonical parent must fold-equal the
         * spelled one, so — the argument went — the two can differ only in case, which changes no
         * byte count. **That is false.** `toLowerCase()` maps the Kelvin sign `U+212A` (three UTF-8
         * bytes) to a one-byte `k`, so two spellings can fold equal and differ in WIDTH; the fold is
         * the documented accepted cost, and `created.rel` can come back wider than the draft was
         * sized against. `ST41-post-create-size-branch-is-reachable` reaches it deterministically by
         * injecting `realpathNative`.
         *
         * ⚠ THE ROW EXISTS BECAUSE A BRANCH ARGUED UNREACHABLE AND LEFT UNTESTED IS THE SAME THING
         * AS A DELETED ONE, and nothing would have said so. Deleting the check makes the over-size
         * line reach the APPENDER, which writes it — a lineage line past the ceiling B4's atomicity
         * argument depends on, over a page that is already on disk. `M12` grades the DRAFT-side
         * ceiling and cannot reach here; without this row, this site is ungraded.
         */
        id: 'M24-post-create-size-check-deleted',
        file: 'stamp.js',
        note: 'the post-create ceiling is the last guard before an over-size line is appended; ST38 argued it unreachable and it is not',
        killedBy: ['ST41-post-create-size-branch-is-reachable'],
        from: '    const finalSize = checkLineSize(line);\n    if (finalSize)\n        return ledgerFailed(created, finalSize, configCreated);',
        to: '    const finalSize = null;\n    if (finalSize)\n        return ledgerFailed(created, finalSize, configCreated);'
    },

    {
        /**
         * ⚠ THE CEILING'S OWN SIZE CLAUSE, ADDED 2026-09-08. `truncated` alone accepted a config
         * of exactly 16,385 bytes against a documented 16,384 ceiling (a round-5 lens probed it
         * live); deleting the clause restores that acceptance, and only the exact-edge leg of
         * `ST4` can see it — the 17,000-byte leg is caught by `truncated` either way.
         */
        id: 'M28-config-ceiling-size-clause-deleted',
        file: 'config.js',
        note: 'a config of exactly CONFIG_CEILING + 1 bytes fits the read window, so truncated is false and only the size clause refuses it',
        killedBy: ['ST4-config-too-large'],
        from: '    if (slice.truncated || slice.size > CONFIG_CEILING) {',
        to: '    if (slice.truncated) {'
    },
    /**
     * ---- THE VALIDATED SNAPSHOT, 2026-09-08 --------------------------------
     *
     * ⚠⚠ EACH MUTANT REPRODUCES THE PREVIOUS SHIPPED BEHAVIOUR AT ONE SEAM, which is the strongest
     * form a mutation row takes: none can be dismissed as a shape nobody would write, because the
     * behaviour each restores is what `writePage` did until this round. They are not the previous
     * SOURCE shape — `M25` keeps the `Validated` envelope and re-reads the members into it, and
     * `M27` reads `request` beside the current split rather than making `preflight` hand it back —
     * because the current source has no seam where the old text would fit whole. What they restore:
     * `preflight` served the caller's own members, `resolveSpan` was handed the caller's own span,
     * and the refusal split was a `.ok === false` read that walked the prototype chain.
     */
    {
        id: 'M25-preflight-returns-the-callers-object',
        file: 'stamp.js',
        note: 'the snapshot carries the caller\'s LIVE members, so a getter serves one value to the validation and another to the write',
        killedBy: ['ST42-request-mutation-after-validation-is-not-observed'],
        // ⚠ THE MUTANT KEEPS THE `Validated` ENVELOPE AND EMPTIES IT. Returning `view` outright
        // would fail the outer `instanceof` and refuse everything, which reddens the whole suite and
        // measures nothing. Wrapping the caller's live members instead reproduces exactly the old
        // defect — a value the type system calls validated whose members are still the caller's.
        from: '    return new Validated(rawPath, rawContent, Object.freeze(snapshot));',
        to: '    return new Validated(request.path, request.content, request.derivedFrom);'
    },
    {
        id: 'M26-span-passed-through-not-rebuilt',
        file: 'stamp.js',
        note: 'the caller\'s span object reaches resolveSpan, which calls spanShapeFault AGAIN — the accessor fires a second time, after the source read',
        killedBy: ['ST42-request-mutation-after-validation-is-not-observed'],
        // ⚠ THE HALF A SHALLOW COPY MISSES. `derivedFrom` can be copied entry by entry and still
        // hand step 5 the caller's spans; this row is what makes the depth of the snapshot a
        // measurement rather than a claim in a comment.
        from: '            spans.push(snapshotSpan(shape));',
        to: '            spans.push(spanRequest);'
    },
    {
        /**
         * ⚠⚠ THIS ROW MUTATES BOTH HALVES, AND THE REASON IS A MEASUREMENT RATHER THAN A
         * CONVENIENCE. It was first written as the split alone — `instanceof Validated` restored to
         * `isRefusalLike(checked)` — and it SURVIVED, which is the honest and useful answer: with
         * the snapshot in place `preflight` returns an object of this module's own making, and a
         * `Validated` carries no `ok` on itself or on its prototype, so no caller can make the
         * `.ok === false` read answer true. **The snapshot SUBSUMES the discrimination defect.**
         *
         * ⚠ SO THE TWO GUARDS ARE NOT INDEPENDENT, and pretending otherwise with a row that cannot
         * fail would certify a guard nothing measures. The `instanceof` earns its place as the half
         * that does not depend on the snapshot staying deep — a later change that let ANY
         * caller-derived value back out of `preflight` reopens the prototype question, and this test
         * is what stands there. What the row measures is the PAIR: the old code, both halves of it,
         * which is the shape that actually shipped.
         */
        id: 'M27-preflight-passes-through-and-the-split-reads-a-caller-supplied-ok',
        file: 'stamp.js',
        note: 'the previous shipped shape, both halves: preflight hands back the caller\'s object and the split reads `.ok` off it through the prototype chain',
        killedBy: ['ST43-refusal-discrimination-is-not-caller-supplied'],
        from: '    if (!(checked instanceof Validated))\n        return checked;',
        to: '    if (isRefusalLike(request))\n'
            + '        return request;\n'
            + '    if (!(checked instanceof Validated))\n'
            + '        return checked;'
    },

    /** The MCP server and tier-plan guards, each anchored once in emitted JavaScript. */
    {
        id: 'M29-call-rechecks-tier-instead-of-using-the-registration-map',
        file: 'server.js',
        note: 'dispatch must use the same frozen registration map as tools/list; a second tier decision can disagree with the advertised surface',
        killedBy: ['SV3-b-positive-list', 'SV4-c-positive-list'],
        from: '        const registration = registrations[request.params.name];',
        to: "        const registration = plan.tier === 'A' ? registrations[request.params.name] : registrations['write_page'];"
    },
    {
        id: 'M30-empty-tier-treated-as-absence',
        file: 'server.js',
        note: 'an explicitly empty tier is a supplied unrecognised value, not the absent default',
        killedBy: ['SV5-invalid-tier-no-open'],
        from: "    const selected = rawTier ?? 'A';",
        to: "    const selected = rawTier || 'A';"
    },
    {
        id: 'M31-unavailable-tier-silently-capped-to-a',
        file: 'server.js',
        note: 'a recognised tier with an absent layer must refuse startup and name itself, never return a working A plan',
        killedBy: ['SV6-known-tier-unavailable'],
        from: "    if (needed.some(factory => factory === null)) {\n"
            + '        return Object.freeze({\n'
            + '            ok: false,\n'
            + "            reason: 'TIER_UNAVAILABLE',\n"
            + '            message: `TIER_UNAVAILABLE: tier ${tier} is recognised but unavailable in this build`\n'
            + '        });\n'
            + '    }',
        to: "    if (needed.some(factory => factory === null)) {\n"
            + '        return Object.freeze({\n'
            + '            ok: true,\n'
            + "            tier: 'A',\n"
            + '            factories: Object.freeze([layers.A])\n'
            + '        });\n'
            + '    }'
    },
    {
        id: 'M32-gate-opened-before-tier-plan',
        file: 'main.js',
        note: 'an invalid tier must be decided before even the grant factory is invoked',
        killedBy: ['SV5-invalid-tier-no-open'],
        from: "    const planned = planTier(deps.env['WYRD_SCRIBE_TIER'], PRODUCTION_LAYERS);",
        to: "    deps.makeFsGate({ rawGrant: deps.env['WYRD_GRANT'] ?? '' });\n"
            + "    const planned = planTier(deps.env['WYRD_SCRIBE_TIER'], PRODUCTION_LAYERS);"
    },
    {
        id: 'M33-schema-validator-bypassed',
        file: 'server.js',
        note: 'every tool call must cross the validator compiled from that registration\'s advertised inputSchema before its port is called',
        killedBy: ['SV12-schema-enforced-on-wire'],
        from: '        return callValidated(registration, args);',
        to: '        return registration.call(args);'
    },
    {
        id: 'M34-envelope-drops-nested-fields',
        file: 'main.js',
        note: 'the wire body must serialise the complete port result, including config_created and a ledger failure\'s nested cause and created',
        killedBy: ['SV13-rich-results-on-wire'],
        from: '            const serialised = JSON.stringify(result);',
        to: '            const serialised = JSON.stringify({ reason: result.reason, detail: result.detail });'
    },
    {
        id: 'M35-tier-value-trimmed',
        file: 'server.js',
        note: 'tier recognition is exact; leading, trailing, tab and newline padding remain part of the refused raw value',
        killedBy: ['SV5-invalid-tier-no-open'],
        from: "    const selected = rawTier ?? 'A';",
        to: "    const selected = (rawTier ?? 'A').trim();"
    },
    {
        id: 'M36-ledger-failed-prefixed-as-refusal',
        file: 'main.js',
        note: 'PAGE_WRITTEN_LEDGER_FAILED is discriminated as a created page whose lineage append was not confirmed and whose cause reports what may have been retained, not described as a refused page write',
        killedBy: ['SV13-rich-results-on-wire'],
        from: "            const prefix = result.ok\n"
            + "                ? 'wyrd-scribe completed write_page.'\n"
            + "                : result.reason === 'PAGE_WRITTEN_LEDGER_FAILED'\n"
            + "                    ? 'wyrd-scribe created the page, but no lineage append was confirmed; inspect `cause` and, when present, `cause.retained`, because the ledger may contain no new line, a fragment, or the complete line.'\n"
            + "                    : 'wyrd-scribe refused write_page.';",
        to: "            const prefix = result.ok\n"
            + "                ? 'wyrd-scribe completed write_page.'\n"
            + "                : 'wyrd-scribe refused write_page.';"
    },
    {
        id: 'M37-generated-version-disagrees',
        file: 'version.js',
        note: 'the generated runtime version diverges from package.json, including provenance consumers',
        killedBy: ['PK3-version-single-source', 'SV1-default-a-handshake', 'SV15-v1-raw-baseline'],
        from: 'export const SERVER_VERSION = "0.2.0";',
        to: 'export const SERVER_VERSION = "0.0.1";'
    },
    {
        id: 'M38-manifest-private-disabled',
        file: '../package.json',
        note: 'the active package is incorrectly withheld from publication',
        killedBy: ['PK1-manifest-surface'],
        from: '  "private": false,',
        to: '  "private": true,'
    },
    {
        id: 'M39-pack-admits-source',
        file: '../package.json',
        note: 'the package files declaration admits source alongside built output',
        measurementPending: true,
        from: `    "LICENSE"${NL}  ],`,
        to: `    "LICENSE",${NL}    "src"${NL}  ],`
    },
    {
        id: 'M40-overwrite-arc-screen', file: 'mutate.js',
        note: 'directly addressed Arc pages must refuse before config or source IO',
        killedBy: ['ST46-overwrite-arc-immutable'],
        from: 'if (/^arc$/i.test(firstComponent(path))) {',
        to: 'if (false) {'
    },
    {
        id: 'M41-overwrite-internal-screen', file: 'mutate.js',
        note: 'the internal subtree must be excluded before config or source IO',
        killedBy: ['ST49-overwrite-internal-subtree'],
        from: 'if (/^\\.wyrd$/i.test(firstComponent(path))) {',
        to: 'if (false) {'
    },
    {
        id: 'M42-overwrite-frontmatter-replace', file: 'frontmatter.js',
        note: 'a generated lineage line must be replaced rather than rejected as a conflict',
        killedBy: ['ST48-overwrite-frontmatter'],
        from: 'if (matches.length === 0)\n        return stamp(content, projection);',
        to: 'if (matches.length >= 0)\n        return stamp(content, projection);'
    },
    {
        id: 'M43-overwrite-precondition', file: 'mutate.js',
        note: 'a known mismatch must refuse before config creation',
        killedBy: ['ST50-overwrite-refusal-disk-invariance'],
        from: 'if (previous.digest !== expectedSha256) {',
        to: 'if (false) {'
    },
    {
        id: 'M44-overwrite-event-kind', file: 'mutate.js',
        note: 'the ledger event must name a replacement',
        killedBy: ['ST44-overwrite-success-lineage'],
        from: "event: 'page_overwritten', event_id: eventId,",
        to: "event: 'page_written', event_id: eventId,"
    },
    {
        id: 'M45-overwrite-ledger-cause', file: 'mutate.js',
        note: 'a failed append must carry its actual cause',
        killedBy: ['ST47-overwrite-ledger-failure'],
        from: 'overwritten, cause, config_created: created',
        to: "overwritten, cause: scribeRefuse('BAD_INPUT', 'fabricated'), config_created: created"
    },
    {
        id: 'M46-overwrite-production-registration', file: 'main.js',
        note: 'the production B layer must register overwrite_page',
        killedBy: ['SV19-production-b-list'],
        from: "name: 'overwrite_page',",
        to: "name: 'write_page',"
    },
    {
        id: 'M47-overwrite-resolved-arc-screen', file: 'mutate.js',
        note: 'a parent alias resolving into Arc must refuse before config creation',
        killedBy: ['ST51-overwrite-resolved-protected-namespaces'],
        from: "if (/^arc$/i.test(first))\n            return 'arc';",
        to: "if (false)\n            return 'arc';"
    },
    {
        id: 'M48-overwrite-resolved-internal-screen', file: 'mutate.js',
        note: 'a parent alias resolving into .wyrd must refuse before config creation',
        killedBy: ['ST51-overwrite-resolved-protected-namespaces'],
        from: "if (/^\\.wyrd$/i.test(first))\n            return 'internal';",
        to: "if (false)\n            return 'internal';"
    },
    {
        id: 'M49-overwrite-win32-name-normalization', file: 'mutate.js',
        note: 'Win32 trailing dots and spaces are included in the protected lexical screen',
        killedBy: ['ST51-overwrite-resolved-protected-namespaces'],
        from: "first.replace(/[. ]+$/g, '') : first",
        to: 'first : first'
    },
    {
        id: 'M50-overwrite-installed-byte-digest', file: 'mutate.js',
        note: 'frontmatter replacement ledger bytes describe the installed page',
        killedBy: ['ST48-overwrite-frontmatter'],
        from: 'hashText(pageBytes), pageBytes.length',
        to: "hashText(Buffer.from(content, 'utf8')), Buffer.byteLength(content, 'utf8')"
    },
    {
        id: 'M51-overwrite-wire-success-must-be-real', file: 'main.js',
        note: 'a success envelope without a replacement or ledger line must fail the production arm',
        killedBy: ['SV19-production-b-list'],
        from: 'context.scribe.overwritePage({',
        to: "(async () => ({ ok: true, overwritten: { effect: { target: 'replaced' } }, record: { event: 'page_overwritten' } }))({"
    },
    {
        id: 'M52-production-b-startup-available', file: 'main.js',
        note: 'the golden production B leg must initialise and list real tools',
        killedBy: ['SV15-v1-raw-baseline'],
        from: "    B: (context, activeTier) => Object.freeze([\n"
            + '        overwritePageRegistration(context, activeTier)\n'
            + '    ]),',
        to: '    B: null,'
    },
    {
        id: 'M168-scribe-close-skips-admitted-write', file: 'write-completion.js',
        note: 'close must await every write registered at admission',
        killedBy: ['SH4-disconnect-drain'],
        from: 'pending.add(settled);',
        to: 'void settled;'
    },
    {
        id: 'M169-scribe-abort-cancels-admitted-write', file: 'write-completion.js',
        note: 'socket abort must not cancel an already admitted Scribe mutation',
        killedBy: ['SH4-disconnect-drain'],
        from: 'const result = Promise.resolve().then(operation);',
        to: 'const result = Promise.resolve().then(() => _signal?.aborted ? undefined : operation());'
    },
    {
        id: 'M170-scribe-network-tls-before-listen', file: 'main.js',
        note: 'non-loopback Scribe writes must refuse without TLS before listener construction',
        killedBy: ['SH6-http-refusals-no-disk-effects'],
        from: "if (httpArg.bind.kind === 'network' && tlsArg.paths === null) {",
        to: 'if (false) {'
    },
    {
        id: 'M171-scribe-auth-refusal', file: 'http-policy.js',
        note: 'wrong Scribe bearer tokens must refuse before a write reaches the vault',
        killedBy: ['SH6-http-refusals-no-disk-effects'],
        from: 'if (!bearerTokenMatches(bytes, authorization))',
        to: 'if (false)'
    },
    {
        id: 'M172-scribe-http-close-skips-tracker', file: 'http.js',
        note: 'HTTP shutdown must wait for the Scribe write tracker',
        killedBy: ['SH9-http-close-awaits-tracker'],
        from: 'closing ??= runtimeShutdown ?? handle.close().finally(() => writes.close());',
        to: 'closing ??= runtimeShutdown ?? handle.close();'
    },
    {
        id: 'M174-scribe-runtime-error-skip-write-drain', file: 'http.js',
        note: 'the runtime server error path must wait for admitted Scribe writes',
        killedBy: ['SH10-runtime-server-error-drain'],
        from: 'closing ?? listenerShutdown.finally(() => writes.close())',
        to: 'closing ?? listenerShutdown'
    },
    {
        id: 'M176-scribe-tls-shutdown-tracks-raw-socket', file: '../../wyrd-http/dist/http.js',
        note: 'HTTPS shutdown must preserve the TLS socket of an admitted write',
        killedBy: ['SH11-https-admitted-write-response-during-close'],
        from: '        trackSocket(secureSocket);',
        to: '        if (raw !== undefined) sockets.add(raw);'
    }
];

function prepareMutationRows(rows, baselineFor) {
    for (const m of rows) {
        const { text, ending } = baselineFor(m);
        const from = withLineEnding(m.from, ending);
        const hits = text.split(from).length - 1;
        if (hits !== 1) throw new Error(`${m.id}: anchor matched ${hits} times before mutation`);
    }
}

function applyMutationRow(m, source, ending) {
    return source.replace(withLineEnding(m.from, ending),
        () => withLineEnding(m.to, ending));
}

if (process.argv.includes('--check-anchors')) {
    const problems = [];
    for (const row of MUTANTS) {
        const target = distOf(row.file);
        if (!fs.existsSync(target)) {
            problems.push(`${row.id}: ${row.file} (${target}) does not exist`);
            continue;
        }
        const source = fs.readFileSync(target, 'utf8');
        const ending = lineEndingOf(source, target);
        const hits = source.split(withLineEnding(row.from, ending)).length - 1;
        if (hits !== 1) problems.push(`${row.id}: ${row.file} (${target}) anchor matched ${hits} times: ${JSON.stringify(row.from)}`);
    }
    if (problems.length) throw new Error(`mutation anchors are not applicable:\n${problems.join('\n')}`);
    console.log(`✔ Scribe mutation anchors: ${MUTANTS.length} rows apply to their registered targets.`);
    process.exit(0);
}

const onlyArg = process.argv.find((value, index) => process.argv[index - 1] === '--only');
const SELECTED_MUTANTS = onlyArg === undefined ? MUTANTS : MUTANTS.filter(row => onlyArg.split(',').includes(row.id));
if (SELECTED_MUTANTS.length === 0 || (onlyArg !== undefined && SELECTED_MUTANTS.length !== onlyArg.split(',').length)) {
    throw new Error('--only must name existing Scribe mutation rows exactly once');
}

if (process.argv[2] === '--eol-fixture') {
    const [arm, target] = process.argv.slice(3);
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
                const row = { id: 'fixture', from: 'alpha\nbeta', to: 'alpha\ndelta' };
                prepareMutationRows([row], () => ({ text: source, ending }));
                fs.writeFileSync(target, applyMutationRow(row, source, ending));
                if (fs.readFileSync(target, 'utf8') !== 'alpha\r\ndelta\r\ngamma\r\n') throw new Error('CRLF edit did not land');
            } else if (arm === 'BH3-eol-all-edits') {
                const rows = [{ id: 'first', from: 'alpha', to: 'delta' },
                    { id: 'second', from: 'absent\nsecond', to: 'nope' }];
                let refused = false;
                try { prepareMutationRows(rows, () => ({ text: source, ending })); }
                catch (error) { refused = /second: anchor matched 0 times/.test(error.message); }
                if (!refused) throw new Error('second row was not refused before mutation');
            } else throw new Error('unknown EOL fixture arm');
        }
    } finally {
        fs.writeFileSync(target, bytes);
        if (!fs.readFileSync(target).equals(bytes)) throw new Error('fixture restore changed bytes');
    }
    console.log(`fixture ${arm}: scribe PASS`);
    process.exit(0);
}

const sha = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');
const runSuite = (executable = process.execPath) => spawnSync(executable, [RUNNER], { cwd: PKG, encoding: 'utf8' });
if (process.argv.includes('--bh6-spawn-fixture')) {
    const result = runSuite(path.join(PKG, 'missing-executable'));
    if (!result.error || result.status !== null) throw new Error('spawn failure received a mutation verdict');
    console.log('INFRASTRUCTURE: suite did not start');
    process.exit(0);
}

/**
 * Build ONCE, before anything is patched. Never between rows.
 *
 * ⚠ `tsc` IS DRIVEN DIRECTLY, NOT THROUGH npm, AND THAT IS DELIBERATE ON TWO COUNTS.
 * `spawnSync('npm', [...], { shell: true })` is DEP0190 — an args array under a shell is
 * concatenated rather than escaped — and it is already an open row against the Reader's release
 * script, so using it here would reproduce a defect this repo has recorded. But dropping
 * `shell: true` does not work either: Node refuses to spawn a `.cmd` without a shell
 * (CVE-2024-27980). Resolving the compiler's own entry point sidesteps both — no shell, no npm,
 * no warning.
 */
const TSC = ['node_modules/typescript/bin/tsc', '../../node_modules/typescript/bin/tsc']
    .map((rel) => path.resolve(PKG, rel))
    .find((p) => fs.existsSync(p));
if (!TSC) {
    console.error('⛔ cannot locate typescript/bin/tsc from ' + PKG + ' — is the workspace installed?');
    process.exit(1);
}
// ⚠ `--build`, NOT `--project`, SINCE 2026-08-31. This package references `wyrd-fence`, and in
// project mode the compiler type-checks against whatever that package's `dist` happens to hold
// without ever bringing it up to date — which is the silent stale-fence case the whole reference
// graph exists to close, reopened in the one script that measures guard adequacy.
const built = spawnSync(process.execPath, [TSC, '--build', PKG], { cwd: PKG, encoding: 'utf8' });
if (built.status !== 0) {
    console.error('⛔ build failed; refusing to mutate\n' + (built.stdout || '') + (built.stderr || ''));
    process.exit(1);
}
const generated = spawnSync(process.execPath, ['scripts/generate-version.mjs'], { cwd: PKG, encoding: 'utf8' });
if (generated.status !== 0) {
    console.error('⛔ version generation failed; refusing to mutate\n'
        + (generated.stdout || '') + (generated.stderr || ''));
    process.exit(1);
}

/**
 * The baseline of EVERY file any row targets, read once before anything is patched.
 *
 * ⚠ RESTORE IS BY HASH, PER FILE. A single-file matrix could restore from one string; a multi-file
 * one that restored the wrong file would leave a mutant resident in `dist/` and every subsequent
 * row would measure a doubly-mutated build. The per-file hash assertion after each restore is what
 * makes that impossible rather than unlikely.
 */
const BASELINES = new Map();
for (const m of SELECTED_MUTANTS) {
    if (BASELINES.has(m.file)) continue;
    const target = distOf(m.file);
    if (!fs.existsSync(target)) {
        console.error(`⛔ ${m.id} targets dist/${m.file}, which the build did not produce`);
        process.exit(1);
    }
    const bytes = fs.readFileSync(target);
    const text = bytes.toString('utf8');
    BASELINES.set(m.file, { bytes, text, ending: lineEndingOf(text, target), hash: sha(bytes) });
}
prepareMutationRows(SELECTED_MUTANTS, m => BASELINES.get(m.file));
registerBatteryTargets([...BASELINES.keys()].map(distOf));

/**
 * ⚠⚠ EVERY ROW MUST DECLARE HOW IT IS ATTRIBUTED, AND THIS REFUSES BEFORE ANY MUTANT RUNS.
 * `M1`-`M6` sat undeclared for the life of this file — not by exemption, but because `killedBy`
 * arrived at the stamp-path section and nobody went back for the span rows. An undeclared row
 * reports KILLED without proving WHICH guard killed it, which is the exact claim the matrix
 * exists to make. Nothing detected that, because "no declaration" and "declaration satisfied"
 * both left `attributed` true.
 *
 * ⚠ IT FAILS AT LOAD RATHER THAN PER-ROW: a new row that forgets this should stop the run, not
 * pass quietly inside it.
 */
const undeclared = SELECTED_MUTANTS.filter(
    (m) => !Array.isArray(m.killedBy) && typeof m.killedByAll !== 'number'
        && m.measurementPending !== true
);
if (undeclared.length) {
    console.error('⛔ ROWS WITH NO ATTRIBUTION DECLARED — each needs `killedBy: [...]` (the arms it must');
    console.error('   redden) or `killedByAll: <n>` (a floor, for a mutant that breaks the envelope');
    console.error('   globally and so reddens most of the suite):');
    for (const m of undeclared) console.error(`   · ${m.id}`);
    process.exit(2);
}

const control = runSuite();
if (control.status !== 0) {
    console.error('⛔ UNMUTATED CONTROL IS RED — every result below would be meaningless.');
    console.error((control.stdout || '').slice(-2000));
    process.exit(1);
}
console.log(`✔ unmutated control green — ${SELECTED_MUTANTS.length} mutants to run\n`);

let survived = 0;
let unanchored = 0;
let misattributed = 0;
let measurementsPending = 0;

for (const m of SELECTED_MUTANTS) {
    const target = distOf(m.file);
    const { bytes, text: original, ending, hash: baseline } = BASELINES.get(m.file);
    const from = withLineEnding(m.from, ending);

    const hits = original.split(from).length - 1;
    if (hits !== 1) {
        console.log(`⛔ ${m.id} — ANCHOR MATCHED ${hits} TIMES in dist/${m.file}, not 1. BROKEN INSTRUMENT, not a survivor.`);
        unanchored += 1;
        continue;
    }
    const mutated = applyMutationRow(m, original, ending);
    assert.notEqual(mutated, original, `${m.id}: mutant is identical to the original`);
    recordBatteryMutant(target, Buffer.from(mutated));
    fs.writeFileSync(target, mutated, 'utf8');
    assert.equal(fs.readFileSync(target, 'utf8'), mutated, `${m.id}: mutant did not land on disk`);

    const result = runSuite();
    const output = `${result.stdout || ''}${result.stderr || ''}`;
    try { assertNoBatteryLockRefusal(output); }
    catch (error) {
        restoreBatteryTarget(target);
        assert.ok(fs.readFileSync(target).equals(bytes), `${m.id}: restore failed after lock refusal`);
        throw error;
    }
    if (result.signal || result.error ||
        (result.status !== 0 && !/(?:not ok \d+ - |✖ )\s*[A-Z]+\d+[\w-]*/.test(output))) {
        restoreBatteryTarget(target);
        assert.ok(fs.readFileSync(target).equals(bytes), `${m.id}: restore failed after infrastructure error`);
        throw new Error(`${m.id}: suite infrastructure error: ${output.slice(-1000)}`);
    }
    const killed = result.status !== 0;
    if (!killed) survived += 1;

    /**
     * ⚠⚠ A KILL BY THE WRONG ARM IS NOT A KILL, and this is the check the single-file matrix never
     * needed. A row states which arm must redden; if the suite goes red because some OTHER arm
     * tripped over the mutant incidentally, the row certifies a guard that does not exist. The
     * named arm's own failure line has to appear in the output.
     */
    let attributed = true;
    let attributionNote = '';
    if (m.measurementPending === true) {
        measurementsPending += 1;
        const observed = [...new Set(
            [...output.matchAll(/(?:not ok \d+ - |✖ )\s*([A-Z]+\d+[\w-]*)/g)].map((match) => match[1])
        )].sort();
        console.log(`⚠ MEASURE ${m.id}: observed red set ${observed.length ? observed.join(', ') : '(none)'}`);
    }
    if (killed && Array.isArray(m.killedBy)) {
        const absent = m.killedBy.filter((id) => !output.includes(id));
        if (absent.length) {
            attributed = false;
            attributionNote = `it went red, but not through ${m.killedBy.join(', ')}`;
            misattributed += 1;
        }
    } else if (killed && typeof m.killedByAll === 'number') {
        /**
         * ⚠⚠ A FLOOR, NOT A NAMED ARM, AND ONLY FOR A MUTANT THAT BREAKS THE ENVELOPE GLOBALLY.
         * `M3`-`M6` make every span result leak, and the no-leak property is asserted by a SHARED
         * HELPER every arm calls — so they redden 23-27 arms and naming one would be a coin toss
         * dressed as attribution.
         *
         * ⚠ IT STILL CATCHES WHAT ATTRIBUTION EXISTS FOR. The failure mode is a row that goes red
         * through something incidental; a mutant that stopped being a global leak would redden ONE
         * arm or none, and this floor refuses both. What it deliberately does NOT do is pin the
         * exact count — that would turn ordinary arm churn into a false regression.
         */
        const distinct = new Set(
            [...output.matchAll(/(?:not ok \d+ - |✖ )\s*([A-Z]+\d+[\w-]*)/g)].map((match) => match[1])
        );
        if (distinct.size < m.killedByAll) {
            attributed = false;
            attributionNote = `it reddened ${distinct.size} distinct arm(s); a global envelope leak must redden at least ${m.killedByAll}`;
            misattributed += 1;
        }
    }

    const verdict = !killed ? '✖ SURVIVED' : attributed ? '✔ KILLED  ' : '⛔ MIS-ATTR';
    console.log(`${verdict} ${m.id}  — ${m.note}`);
    if (!attributed) console.log(`           ${attributionNote}`);

    restoreBatteryTarget(target);
    assert.ok(fs.readFileSync(target).equals(bytes), `${m.id}: RESTORE FAILED — dist/${m.file} is not back at baseline (${baseline})`);
}

const after = runSuite();
console.log(`\nrestored, hash verified; post-restore suite ${after.status === 0 ? 'GREEN' : 'RED'}`);
console.log(
    `${SELECTED_MUTANTS.length - survived - unanchored - misattributed}/${SELECTED_MUTANTS.length} killed by the arms they name`
    + ` · ${survived} survived · ${unanchored} unanchored · ${misattributed} killed by the wrong arm`
);

if (measurementsPending > 0) {
    console.error(`⛔ ${measurementsPending} mutation row(s) have measured attribution pending; `
        + 'the matrix reported their observed red sets but will not bless an unrecorded expectation.');
}

if (unanchored > 0 || survived > 0 || misattributed > 0 || measurementsPending > 0 || after.status !== 0) process.exit(1);
