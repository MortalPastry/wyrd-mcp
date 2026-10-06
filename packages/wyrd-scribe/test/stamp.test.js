import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { createFsGate } from 'wyrd-fence';

import { writePage } from '../dist/stamp.js';
import { gateAppender, refusingAppender } from '../dist/ledger.js';
import { MAX_PAGE_PATH_BYTES } from '../dist/lineage.js';
import { SourceCache, readSource } from '../dist/source.js';
import { declare as arm } from './manifest.mjs';

/**
 * THE STAMP PATH's ARMS.
 *
 * ⚠⚠ THE GRANT IS REAL AND THE FENCE IS REAL. Every arm builds a temp directory, grants it through
 * `createFsGate`, and lets the fence produce its own refusals — because D8's claim is about the
 * IDENTICAL code path, and a hand-written stub gate proves nothing about it. The pattern is copied
 * from `packages/wyrd-fence/test/fixtures.mjs` (build in the OS temp dir, never in the repo; tear
 * down after) rather than the code, since the Scribe's fixtures need none of the reparse-point
 * machinery that file exists for.
 *
 * ⚠ NO SYMLINKS ANYWHERE IN HERE. That is what keeps every arm portable — escapes are exercised
 * with an absolute outside path and a `..` traversal, both refused by the fence with no privilege
 * required. See the note in `arms.mjs`.
 *
 * ⚠ SKIPS FAIL THE BUILD. Nothing here may skip and nothing may be `todo`; the runner asserts both
 * counts are zero and that the executed set EQUALS the declared inventory.
 */

const VERSION = '0.0.0-test';
const FIXED_NOW = () => new Date('2026-09-02T19:42:17.114Z');
const FIXED_UUID = '11111111-2222-4333-8444-555555555555';

/** Every fixture this file builds, torn down after the last arm. */
const built = [];
process.on('exit', () => {
    for (const base of built) fs.rmSync(base, { recursive: true, force: true });
});

/**
 * A vault, plus an `outside` sibling holding a real file and a real non-file.
 *
 * ⚠ THE OUTSIDE FILE EXISTS ON PURPOSE (AC1a). A refusal over a path that does not exist proves
 * nothing about the existence-oracle property; the interesting case is a source that IS there and
 * is still refused with no read.
 */
function vault(options = {}) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-scribe-'));
    built.push(base);
    const grant = path.join(base, 'vault');
    const outside = path.join(base, 'outside');
    fs.mkdirSync(path.join(grant, 'Mage'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'Arc'), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.md'), 'OUTSIDE-SECRET-CANARY');
    if (options.wyrd !== false) fs.mkdirSync(path.join(grant, '.wyrd'), { recursive: true });
    if (options.config !== undefined) {
        fs.writeFileSync(path.join(grant, '.wyrd', 'scribe.json'), options.config);
    }
    return { base, grant, outside };
}

/**
 * The primitive spy. Instrumented at the FENCE's own injection seam, so the gate under test is the
 * production gate — see `packages/wyrd-fence/test/fsgate.test.js`, which explains why `writeAll` is
 * deliberately NOT supplied (a spy that replaces the completion loop tests the spy, not the code).
 */
function spy(sink, overrides = {}) {
    const record = (name, argument) => {
        sink.push({ name, argument: typeof argument === 'string' ? argument : `<${typeof argument}>` });
    };
    return {
        open: (t, f) => { record('open', t); return fs.openSync(t, f); },
        close: fd => fs.closeSync(fd),
        read: (fd, b, o, l, p) => fs.readSync(fd, b, o, l, p),
        fstat: fd => fs.fstatSync(fd),
        lstat: t => { record('lstat', t); return fs.lstatSync(t); },
        readlink: t => fs.readlinkSync(t, 'utf8'),
        realpathNative: t => fs.realpathSync.native(t),
        readdir: t => fs.readdirSync(t, { withFileTypes: true }),
        openExclusive: t => { record('openExclusive', t); return fs.openSync(t, 'wx'); },
        ...overrides
    };
}

/** An appender that records what it was handed and succeeds. */
function capturingAppender(lines) {
    return {
        appendLine: async line => {
            assert.ok(Buffer.isBuffer(line), 'the appender is handed a fully-serialised Buffer, never a record');
            assert.equal(line[line.length - 1], 0x0a, 'a lineage line is LF-terminated');
            lines.push(line);
            return { ok: true, bytes: line.length };
        }
    };
}

/** An appender that must never be called. Its assertion IS the arm in several tests below. */
function forbiddenAppender(label) {
    return {
        appendLine: async () => {
            assert.fail(`the appender was called during ${label}, and nothing may be appended there`);
        }
    };
}

function gateFor(grant, primitives) {
    const gate = createFsGate(primitives ? { rawGrant: grant, primitives } : { rawGrant: grant });
    assert.ok(gate.ok !== false, `the grant must be accepted: ${JSON.stringify(gate)}`);
    return gate;
}

function stamp(gate, request, options = {}) {
    return writePage(request, {
        gate,
        appender: options.appender ?? forbiddenAppender('a refusing path'),
        version: VERSION,
        now: options.now ?? FIXED_NOW,
        newUuid: options.newUuid ?? (() => FIXED_UUID),
        ...(options.cache ? { cache: options.cache } : {})
    });
}

/**
 * ⚠⚠ THE NO-OUTSIDE-NAMES CHECK, APPLIED TO EVERY SCRIBE-ORIGINATED REFUSAL IN THIS FILE.
 *
 * The fence returns `rel` and never `actual` so a refusal cannot become a filesystem oracle. That
 * property is worth nothing if the layer above it echoes the request back — so every refusal that
 * passes through here is checked against the absolute paths that exist in this test's world. The
 * collected list is re-asserted as a whole by `ST18`, which is what makes the property a claim
 * about the SURFACE rather than about whichever refusals someone remembered to check.
 */
const seenRefusals = [];
function refusal(result, reason, world) {
    assert.equal(result.ok, false, `expected a refusal, got ${JSON.stringify(result)}`);
    assert.equal(result.reason, reason, `expected ${reason}, got ${result.reason}: ${result.detail}`);
    assert.equal(typeof result.detail, 'string');
    seenRefusals.push({ reason: result.reason, detail: result.detail, world });
    if (world) assertNoOutsideNames(result.detail, world);
    return result;
}

function assertNoOutsideNames(detail, world) {
    for (const forbidden of [world.base, world.grant, world.outside]) {
        assert.ok(
            !detail.includes(forbidden),
            `a Scribe refusal detail may not carry an absolute path: ${JSON.stringify(detail)}`
        );
    }
    assert.ok(
        !/[A-Za-z]:[\\/]/.test(detail),
        `a Scribe refusal detail may not carry a drive-absolute path: ${JSON.stringify(detail)}`
    );
}

const SOURCE_TEXT = 'The interview began at noon. Rowan said the thing about foundations.';

function withSource(world, rel = 'Arc/interview.md', text = SOURCE_TEXT) {
    fs.mkdirSync(path.dirname(path.join(world.grant, rel)), { recursive: true });
    fs.writeFileSync(path.join(world.grant, rel), text);
    return rel;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

test('ST1-not-initialised — no .wyrd/ refuses, names the directory, and creates nothing', async () => {
    arm('ST1-not-initialised');
    const world = vault({ wyrd: false });
    const gate = gateFor(world.grant);

    const result = await stamp(gate, {
        path: 'Mage/answer.md',
        content: 'body',
        derivedFrom: []
    });

    refusal(result, 'SCRIBE_NOT_INITIALISED', world);
    assert.match(result.detail, /\.wyrd/, 'the refusal must name the directory the user has to create');
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'nothing is created');
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd')), false, 'and the Scribe does NOT create it itself');

    // The pair: a `.wyrd` that is a FILE rather than a directory reaches the same refusal, because
    // the user's action is identical. A fence `NOT_A_DIRECTORY` passed through raw would tell them
    // to create something that already exists.
    const second = vault({ wyrd: false });
    fs.writeFileSync(path.join(second.grant, '.wyrd'), 'not a directory');
    const result2 = await stamp(gateFor(second.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    });
    refusal(result2, 'SCRIBE_NOT_INITIALISED', second);
});

test('ST2-config-minted — a minted id is ADOPTED once; a later mint is discarded, and counted', async () => {
    arm('ST2-config-minted');
    const world = vault();
    const gate = gateFor(world.grant);
    const lines = [];

    let firstMints = 0;
    const first = await stamp(gate, {
        path: 'Mage/one.md', content: 'one', derivedFrom: []
    }, {
        appender: capturingAppender(lines),
        newUuid: () => { firstMints += 1; return FIXED_UUID; }
    });
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.equal(firstMints, 1, 'the first stamp mints exactly once — one config load, one speculative id');

    const onDisk = JSON.parse(fs.readFileSync(path.join(world.grant, '.wyrd', 'scribe.json'), 'utf8'));
    assert.deepEqual(Object.keys(onDisk).sort(), ['schema', 'vault_id', 'write_frontmatter']);
    assert.equal(onDisk.schema, 'wyrd.scribe/v1');
    assert.equal(onDisk.vault_id, FIXED_UUID);
    assert.equal(onDisk.write_frontmatter, false, 'the safe default: the visible stamp is opted INTO');

    /**
     * ⚠⚠ THE CLAIM CHANGED ON 2026-09-08 AND THE COUNTER IS WHY THE CHANGE IS VISIBLE. This
     * paragraph read: *"THE SECOND CALL MUST NOT MINT AGAIN, and the mint function proves it by
     * being one that would produce a DIFFERENT id."* Option C's part 3 hoists `loadConfig`'s
     * exclusive-create ahead of the config read — so the second call DOES mint, hits `EXISTS`,
     * re-reads, and adopts the id on disk. Every assertion below still passed, because they check
     * the id that was RECORDED and not how many times the minter ran: **the arm survived while the
     * guarantee it named disappeared.** That is the silently-repurposed shape, one step subtler
     * than a deleted arm, and it still shows green.
     *
     * ⚠ THE HONEST CLAIM IS NARROWER AND IS ASSERTED IN BOTH HALVES: a speculative mint IS
     * performed (`secondMints === 1`, so the cost is stated rather than hidden) and it is NOT
     * ADOPTED (`vault.id` is still the first id, so one vault keeps one identity). A minter
     * returning a DIFFERENT value is what separates "read the existing config" from "minted a
     * fresh one that happens to match", and it is kept for exactly that reason.
     */
    let secondMints = 0;
    const second = await stamp(gate, {
        path: 'Mage/two.md', content: 'two', derivedFrom: []
    }, {
        appender: capturingAppender(lines),
        newUuid: () => { secondMints += 1; return '99999999-9999-4999-8999-999999999999'; }
    });
    assert.equal(second.ok, true, JSON.stringify(second));
    assert.equal(secondMints, 1,
        'the second stamp mints ONCE speculatively — more than one would mean a second config load per write');
    assert.equal(second.record.vault.id, FIXED_UUID,
        'and the speculative id is DISCARDED: the vault keeps the identity already on disk');
    assert.equal(second.record.page.identity.vault_id, FIXED_UUID);
    assert.equal(
        JSON.parse(fs.readFileSync(path.join(world.grant, '.wyrd', 'scribe.json'), 'utf8')).vault_id,
        FIXED_UUID,
        'the file on disk is untouched by the discarded mint'
    );

    // A real v4 UUID is what the default minter produces; the strict shape is asserted here so the
    // pinned test id is not the only thing the validator has ever seen.
    assert.match(crypto.randomUUID(), /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    /**
     * ⚠⚠ THE THROWING MINTER, DECIDED DELIBERATELY RATHER THAN DISCOVERED. Because the minter now
     * runs on EVERY load, an injected `newUuid` that THROWS turns a stamp against a VALID EXISTING
     * config into an uncaught throw, where before it threw only when the config was missing. It is
     * NOT caught, and the arm pins that: there is no honest reason to convert it to.
     * `SCRIBE_CONFIG_INVALID` would blame a config that is perfectly valid, and a fence reason
     * would attribute a Scribe-side fault to the fence. Catching it behind a fallback to the
     * read-first order would be worse — a containment check that switches itself off when an
     * injected function misbehaves is not a check.
     *
     * ⚠ AND THE BEHAVIOUR IS NOT NEW IN KIND. `writePage` has no try/catch anywhere, so a throwing
     * injected `newUuid` ALREADY produced an uncaught throw on a missing config; part 3 widens
     * WHEN it fires, not what it does. Both halves are asserted so the widening is a recorded fact
     * and not an inference from one of them.
     */
    const throwing = () => { throw new Error('ST2: the injected minter refuses'); };
    await assert.rejects(
        () => stamp(gate, { path: 'Mage/three.md', content: 'three', derivedFrom: [] },
            { appender: forbiddenAppender('a throwing minter'), newUuid: throwing }),
        /the injected minter refuses/,
        'a throwing minter propagates over a VALID EXISTING config — widened by part 3, and not caught'
    );
    const fresh = vault();
    await assert.rejects(
        () => stamp(gateFor(fresh.grant), { path: 'Mage/four.md', content: 'four', derivedFrom: [] },
            { appender: forbiddenAppender('a throwing minter'), newUuid: throwing }),
        /the injected minter refuses/,
        'and over a MISSING config, which it already did before part 3'
    );
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'three.md')), false, 'nothing was created either time');
    assert.equal(fs.existsSync(path.join(fresh.grant, 'Mage', 'four.md')), false);
});

test('ST3-config-invalid — four independent shapes each refuse', async () => {
    arm('ST3-config-invalid');
    const cases = [
        ['{"schema":"wyrd.scribe/v1","vault_id":"11111111-2222-4333-8444-555555555555","write_frontmatter":false,"extra":1}', 'an unknown key'],
        ['{"schema":"wyrd.scribe/v2","vault_id":"11111111-2222-4333-8444-555555555555","write_frontmatter":false}', 'a wrong schema'],
        ['{"schema":"wyrd.scribe/v1","vault_id":"not-a-uuid","write_frontmatter":false}', 'a non-UUID vault_id'],
        ['{"schema":"wyrd.scribe/v1","vault_id":"11111111-2222-4333-8444-555555555555","write_frontmatter":"yes"}', 'a non-boolean flag'],
        ['not json at all', 'unparseable text'],
        ['[]', 'a JSON array rather than an object']
    ];
    for (const [config, why] of cases) {
        const world = vault({ config });
        const result = await stamp(gateFor(world.grant), {
            path: 'Mage/answer.md', content: 'body', derivedFrom: []
        });
        refusal(result, 'SCRIBE_CONFIG_INVALID', world);
        assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, `${why}: nothing is created`);
        /**
         * ⚠⚠ THE FLAG IS PINNED `false`, AND IT WAS ABSENT ENTIRELY UNTIL 2026-09-08. This refusal
         * is the Scribe's own and it comes back from step 4, so the rule at `WritePageResult` binds
         * it — but the return site handed it back BARE, so the documentation promised a field the
         * caller never received. `false` is the honest value here rather than a default: a config
         * already EXISTS (that is what makes it invalid), so the exclusive create refused `EXISTS`
         * and this invocation minted nothing.
         */
        assert.equal(result.config_created, false,
            `${why}: an existing-but-invalid config means this call minted nothing, and the refusal says so`);
    }

    // The pair: the valid shape succeeds, so a validator that refused everything could not pass.
    const good = vault({ config: '{"schema":"wyrd.scribe/v1","vault_id":"11111111-2222-4333-8444-555555555555","write_frontmatter":false}' });
    const ok = await stamp(gateFor(good.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
});

test('ST4-config-too-large — a config past the read window refuses', async () => {
    arm('ST4-config-too-large');
    // ⚠ VALID JSON, AND THAT IS THE POINT. An over-size file full of garbage would refuse INVALID
    // too, so the arm would pass without the size check existing at all. This one parses.
    const padding = 'x'.repeat(17_000);
    const world = vault({
        config: JSON.stringify({
            schema: 'wyrd.scribe/v1',
            vault_id: FIXED_UUID,
            write_frontmatter: false,
            note: padding
        })
    });
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    });
    refusal(result, 'SCRIBE_CONFIG_TOO_LARGE', world);
    // ⚠ THE SAME PIN AS `ST3`, AND FOR THE SAME REASON: a Scribe-shaped refusal from step 4 carries
    // `config_created`, and an over-size config is one that EXISTS, so this call minted nothing.
    // Returned bare until 2026-09-08.
    assert.equal(result.config_created, false,
        'an over-size EXISTING config means this call minted nothing, and the refusal says so');

    // The pair, well under the ceiling: it is read whole and then refuses on the unknown key,
    // proving the size branch is a SIZE branch and not a catch-all for large files.
    const justUnder = JSON.stringify({
        schema: 'wyrd.scribe/v1', vault_id: FIXED_UUID, write_frontmatter: false, note: 'x'.repeat(200)
    });
    const near = vault({ config: justUnder });
    const nearResult = await stamp(gateFor(near.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    });
    refusal(nearResult, 'SCRIBE_CONFIG_INVALID', near);
    assert.equal(nearResult.config_created, false, 'and the near case carries it too');

    // ⚠⚠ THE TWO EDGES BY EXACT BYTE COUNT, ADDED 2026-09-08 AFTER A LENS PROBED THE GAP. The
    // documented ceiling is 16,384 bytes and the read window is one byte wider so the gate can
    // answer `truncated`; a file of EXACTLY 16,385 bytes fits the window, so `truncated` was
    // false and the file was ACCEPTED one byte past the ceiling. The 17,000-byte case above
    // never reached that edge. Both files below are valid JSON with an unknown key, so the
    // 16,384 one proves "read whole, then refused on the KEY" and the 16,385 one proves "refused
    // on SIZE" — the reason is what separates them, and the byte counts are asserted, not
    // described.
    const exactly = (bytes) => {
        const base = JSON.stringify({
            schema: 'wyrd.scribe/v1', vault_id: FIXED_UUID, write_frontmatter: false, note: ''
        });
        const doc = JSON.stringify({
            schema: 'wyrd.scribe/v1', vault_id: FIXED_UUID, write_frontmatter: false,
            note: 'x'.repeat(bytes - Buffer.byteLength(base, 'utf8'))
        });
        assert.equal(Buffer.byteLength(doc, 'utf8'), bytes, `the fixture is exactly ${bytes} bytes`);
        return doc;
    };
    const atCeiling = vault({ config: exactly(16_384) });
    const atResult = await stamp(gateFor(atCeiling.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    });
    refusal(atResult, 'SCRIBE_CONFIG_INVALID', atCeiling);
    const overByOne = vault({ config: exactly(16_385) });
    const overResult = await stamp(gateFor(overByOne.grant), {
        path: 'Mage/answer.md', content: 'body', derivedFrom: []
    });
    refusal(overResult, 'SCRIBE_CONFIG_TOO_LARGE', overByOne);
    assert.equal(overResult.config_created, false, 'one byte over is an EXISTING config; nothing minted');
});

// ---------------------------------------------------------------------------
// The ordering property
// ---------------------------------------------------------------------------

test('ST5-arc-immutable-before-sources — Arc/ refuses with NO source read', async () => {
    arm('ST5-arc-immutable-before-sources');
    const world = vault();
    const sink = [];
    const gate = gateFor(world.grant, spy(sink));
    // ⚠ THE BOOTSTRAP SEAM RUNS TWO PRIMITIVES OF ITS OWN — `lstat` then `realpathNative` on the
    // grant, at `createFsGate` time, before `writePage` is ever called. Asserting an EMPTY sink
    // would fail on the gate's own construction and say nothing about the ordering under test, so
    // the baseline is taken here and the arm asserts nothing ran AFTER it.
    const bootstrap = sink.length;

    const result = await stamp(gate, {
        path: 'Arc/x.md',
        content: 'body',
        // ⚠⚠ THE SOURCE IS AN ABSOLUTE OUTSIDE PATH THAT REALLY EXISTS. If the Arc/ check ran after
        // the sources, this request would report the outside file's existence and hash through the
        // refusal it got back — the existence oracle D8 exists to close, arriving through a
        // doctrine check.
        derivedFrom: [{ source: path.join(world.outside, 'secret.md'), spans: [{ quote: 'OUTSIDE' }] }]
    });

    refusal(result, 'ARC_IMMUTABLE', world);
    assert.equal(
        sink.length,
        bootstrap,
        `no primitive ran after the gate was built, and one did: ${JSON.stringify(sink.slice(bootstrap))}`
    );
    assert.equal(fs.existsSync(path.join(world.grant, 'Arc', 'x.md')), false);

    // Every spelling of the same target, since a case-sensitive or backslash-blind screen would
    // pass the arm above and be bypassed by typing one character differently.
    // ⚠ The dot-segment spellings are the ones a caller who knows about the screen would choose:
    // the fence normalises `Mage/../Arc/x.md` to `Arc/x.md` before it resolves, so a screen that
    // reads the caller's spelling admits exactly them. Added 2026-09-03 from the close-side review.
    for (const target of ['arc/x.md', 'ARC/x.md', 'Arc\\x.md', '/Arc/x.md', 'Arc/deep/x.md',
        'Mage/../Arc/x.md', './Arc/x.md', 'Arc/./x.md', 'Mage\\..\\Arc\\x.md']) {
        const each = await stamp(gate, { path: target, content: 'b', derivedFrom: [] });
        refusal(each, 'ARC_IMMUTABLE', world);
    }

    // The pair: a path merely STARTING with the letters is not Arc/ and must not be refused.
    const notArc = await stamp(gate, {
        path: 'Archive/x.md', content: 'b', derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.notEqual(notArc.reason, 'ARC_IMMUTABLE', 'Archive/ is not Arc/');
});

test('ST6-source-escape-reads-nothing-appends-nothing — the fence\'s own reason, passed through', async () => {
    arm('ST6-source-escape-reads-nothing-appends-nothing');
    const world = vault();
    const gate = gateFor(world.grant);

    /**
     * ⚠ THE TWO ESCAPE SHAPES REFUSE UNDER DIFFERENT FENCE REASONS, AND THAT IS THE FENCE BEING
     * STRICTER RATHER THAN INCONSISTENT. An ABSOLUTE request is refused LEXICALLY as `BAD_INPUT`
     * before any resolution happens at all — the strongest possible outcome, since nothing about
     * the named path is ever consulted. A `..` traversal has to be resolved to be judged, so it
     * comes back `ESCAPES`. What matters for the Scribe is that BOTH are the fence's own words,
     * passed through unchanged; a Scribe-invented `SOURCE_ESCAPED` would be a second vocabulary for
     * one outcome and would force every consumer to learn both.
     */
    for (const [escape, reason] of [
        [path.join(world.outside, 'secret.md'), 'BAD_INPUT'],
        ['../outside/secret.md', 'ESCAPES']
    ]) {
        const result = await stamp(gate, {
            path: 'Mage/answer.md',
            content: 'body',
            derivedFrom: [{ source: escape, spans: [{ quote: 'OUTSIDE' }] }]
        });
        assert.equal(result.ok, false);
        assert.equal(result.reason, reason, `expected the fence's own reason, got ${result.reason}`);
        // ⚠ THE FENCE'S REFUSAL, NOT THE SCRIBE'S — it carries `resolvedPath`, which a Scribe
        // refusal never has. That field is what proves this came through untranslated.
        assert.equal(typeof result.resolvedPath, 'string');
        assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'the target is not created');
    }

    // ⚠ AC1a: THE REFUSAL IS IDENTICAL WHETHER THE OUTSIDE PATH EXISTS OR NOT. `outside/secret.md`
    // above is a real file; this one is not, and both give the same reason and the same detail —
    // so `derived_from` cannot be used to ask whether a path outside the grant exists.
    const existing = await stamp(gate, {
        path: 'Mage/answer.md', content: 'body',
        derivedFrom: [{ source: path.join(world.outside, 'secret.md'), spans: [{ quote: 'x' }] }]
    });
    const missing = await stamp(gate, {
        path: 'Mage/answer.md',
        content: 'body',
        derivedFrom: [{ source: path.join(world.outside, 'does-not-exist.md'), spans: [{ quote: 'x' }] }]
    });
    assert.equal(missing.reason, existing.reason, 'same reason whether or not the outside path exists');
    assert.equal(missing.detail, existing.detail, 'same detail too — a differing message is the oracle');

    // The traversal pair, same property one resolution deeper.
    const relExisting = await stamp(gate, {
        path: 'Mage/answer.md', content: 'body',
        derivedFrom: [{ source: '../outside/secret.md', spans: [{ quote: 'x' }] }]
    });
    const relMissing = await stamp(gate, {
        path: 'Mage/answer.md', content: 'body',
        derivedFrom: [{ source: '../outside/nope.md', spans: [{ quote: 'x' }] }]
    });
    assert.equal(relMissing.reason, relExisting.reason, 'a traversal refuses identically either way');

    // The Scribe source path hashes before reading. A cloud placeholder must stop both opens.
    const cloudWorld = vault();
    fs.writeFileSync(path.join(cloudWorld.grant, 'Mage', 'cloud.md'), 'cloud bytes');
    fs.writeFileSync(path.join(cloudWorld.grant, 'Mage', 'local.md'), 'local bytes');
    const opens = [];
    const cloudGate = createFsGate({ rawGrant: cloudWorld.grant, primitives: {
        open: (target, flags) => { opens.push(target); return fs.openSync(target, flags); },
        placeholderAttributes: async target => ({
            attributes: path.basename(target) === 'cloud.md' ? 0x1000 : 0,
            reparseTag: 0
        })
    } });
    const blocked = await readSource(cloudGate, 'Mage/cloud.md', new SourceCache());
    assert.equal(blocked.reason, 'PLACEHOLDER');
    assert.equal(opens.length, 0);
    const local = await readSource(cloudGate, 'Mage/local.md', new SourceCache());
    assert.equal(local.rel, 'Mage/local.md');
    assert.equal(local.bytes.toString(), 'local bytes');
    assert.ok(opens.length >= 2, 'the local counterpart hashes and reads');
});

test('ST7-source-changed — bytes that differ between the loop and the hash refuse', async () => {
    arm('ST7-source-changed');
    const world = vault();
    const rel = withSource(world);
    const target = path.join(world.grant, rel);

    // ⚠ THE SWAP HAPPENS AT THE PRIMITIVE SEAM, which is the only place a mid-read edit can be
    // staged deterministically. `hashInGrant` runs first and reads the file as it is; the window
    // loop that follows is served DIFFERENT bytes of the same length, so the size check cannot be
    // what catches it and the digest comparison has to.
    let opens = 0;
    const primitives = spy([], {
        open: (t, f) => {
            const fd = fs.openSync(t, f);
            if (t === fs.realpathSync.native(target)) opens += 1;
            return fd;
        },
        read: (fd, b, o, l, p) => {
            const read = fs.readSync(fd, b, o, l, p);
            // The first open is the hash's; the second is the window loop's.
            if (opens >= 2 && read > 0) b[o] = b[o] === 0x58 ? 0x59 : 0x58;
            return read;
        }
    });

    const result = await stamp(gateFor(world.grant, primitives), {
        path: 'Mage/answer.md',
        content: 'body',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    });

    refusal(result, 'SOURCE_CHANGED_DURING_READ', world);
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'no PAGE is created');

    /**
     * ⚠⚠ "NOTHING IS CREATED" WAS THE OLD MESSAGE ON THE LINE ABOVE AND IT WAS FALSE, corrected
     * 2026-09-08. This vault had no config, so step 4 MINTED `.wyrd/scribe.json` before the source
     * loop that refuses here ever ran — the invocation is not a no-op, and an arm whose message says
     * it is teaches the next reader the wrong model of the ordering. The claim that holds is about
     * the PAGE.
     *
     * ⚠ AND THE REFUSAL REPORTS THE MINT. `SOURCE_CHANGED_DURING_READ` is the Scribe's own shape
     * from step 5, so the rule at `WritePageResult` binds it: it carries `config_created`, and until
     * 2026-09-08 it was returned bare while the documentation promised the field.
     */
    assert.equal(result.config_created, true,
        'the refusal reports the config THIS call minted at step 4, rather than leaving it to be inferred from disk');
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd', 'scribe.json')), true,
        'and the mint really happened — the flag above is measured against disk, not asserted alone');
});

// ---------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------

test('ST8-record-shape — the appended line matches the wire shape key-for-key', async () => {
    arm('ST8-record-shape');
    const world = vault();
    const rel = withSource(world);
    const lines = [];

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'foundations' }, { offset: 4, length: 9 }] }]
    }, { appender: capturingAppender(lines) });

    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(lines.length, 1, 'exactly one line per write');

    const raw = lines[0].toString('utf8');
    assert.equal(raw.split('\n').length, 2, 'a lineage line contains exactly one LF, at the end — never split');
    const line = JSON.parse(raw);

    // ⚠⚠ THE OWN-KEY ENVELOPE, AS `span.test.js` DOES IT. A property is worth what the check
    // FORBIDS: `assert.equal(line.schema, ...)` passes while an extra key carries the whole source
    // into the permanent record, and this record is the thing that gets written to disk forever.
    assert.deepEqual(Object.keys(line).sort(), ['event', 'event_id', 'page', 'recorded_at', 'schema', 'sources', 'vault', 'writer']);
    assert.equal(line.schema, 'wyrd.lineage/v1');
    assert.equal(line.event, 'page_written');
    assert.equal(line.recorded_at, '2026-09-02T19:42:17.114Z');
    assert.match(line.recorded_at, /Z$/, 'the one server-generated timestamp is UTC');
    // ⚠ THE PER-WRITE IDENTIFIER. `ST29` proves two writes differ in it; this pins its SHAPE — a v4
    // UUID, server-minted, and distinct from the vault id, which is the collision a single injected
    // UUID seam would have produced.
    assert.match(line.event_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(line.event_id, FIXED_UUID, 'the event id is not the vault id');

    assert.deepEqual(Object.keys(line.writer).sort(), ['server', 'tool', 'version']);
    assert.deepEqual(line.writer, { server: 'wyrd-scribe', version: VERSION, tool: 'write_page' });
    // ⚠ NO ACTOR FIELD, ANYWHERE. MCP stdio supplies no authenticated caller, and an unauthenticated
    // assertion recorded as fact is worse than recording nothing: a later reader cannot tell them
    // apart. The check is over the WHOLE serialised line, not just the writer block.
    assert.ok(!/"actor"|"user"|"agent"|"caller"/.test(raw), 'no caller-supplied actor field may exist');

    assert.deepEqual(line.vault, { kind: 'uuid', id: FIXED_UUID });

    assert.deepEqual(Object.keys(line.page).sort(), ['content', 'identity']);
    assert.deepEqual(line.page.identity, { kind: 'path', vault_id: FIXED_UUID, path: 'Mage/answer.md' });
    assert.deepEqual(Object.keys(line.page.content).sort(), ['algorithm', 'bytes', 'digest']);
    assert.equal(line.page.content.algorithm, 'sha256');
    assert.equal(line.page.content.bytes, Buffer.byteLength('the answer', 'utf8'));
    assert.equal(
        line.page.content.digest,
        crypto.createHash('sha256').update(Buffer.from('the answer', 'utf8')).digest('hex'),
        'the page digest is over the bytes actually written'
    );

    assert.equal(line.sources.length, 1, 'sources are GROUPED BY RESOLVED PATH — two spans, one entry');
    const source = line.sources[0];
    assert.deepEqual(Object.keys(source).sort(), ['content', 'identity', 'spans']);
    assert.deepEqual(source.identity, { kind: 'path', vault_id: FIXED_UUID, path: 'Arc/interview.md' });
    assert.ok(!source.identity.path.includes('\\'), 'a ledger path uses forward slashes on every host');
    assert.equal(source.content.bytes, Buffer.byteLength(SOURCE_TEXT, 'utf8'));
    assert.equal(
        source.content.digest,
        crypto.createHash('sha256').update(Buffer.from(SOURCE_TEXT, 'utf8')).digest('hex')
    );

    assert.equal(source.spans.length, 2);
    for (const span of source.spans) {
        assert.deepEqual(Object.keys(span).sort(), ['length', 'offset', 'quote']);
        assert.deepEqual(Object.keys(span.quote).sort(), ['original_utf8_bytes', 'sha256', 'stored_utf8_bytes', 'text', 'truncated']);
        assert.equal(span.quote.truncated, false);
        assert.equal(
            span.quote.sha256,
            crypto.createHash('sha256').update(Buffer.from(span.quote.text, 'utf8')).digest('hex'),
            'an untruncated quote hashes to its own stored text'
        );
        // ⚠ D4's CENTRAL CLAIM, ASSERTED DIRECTLY: the recorded offsets locate the recorded text in
        // the recorded source. A span that resolves to different text than it recorded is the one
        // failure this whole lane exists to prevent.
        const bytes = fs.readFileSync(path.join(world.grant, rel));
        assert.equal(
            bytes.subarray(span.offset, span.offset + span.length).toString('utf8'),
            span.quote.text,
            'the span resolves to exactly the text it recorded'
        );
    }
    assert.equal(source.spans[0].quote.text, 'foundations');
    assert.equal(source.spans[1].quote.text, SOURCE_TEXT.slice(4, 13));
});

test('ST9-quote-truncated — a long multibyte quote is cut on a boundary and still hashes whole', async () => {
    arm('ST9-quote-truncated');
    const world = vault();
    // ⚠ MULTIBYTE, AND SIZED SO THE BUDGET LANDS MID-CHARACTER. '☃' is 3 bytes, so 1000 of them is
    // 3,000 bytes and byte 1024 falls INSIDE a character — a naive `slice(0, 1024)` would store
    // text that does not re-encode to the bytes it came from, which is the identity-destroying cut
    // every other path in this package refuses.
    const quote = '☃'.repeat(1000);
    const rel = withSource(world, 'Arc/snow.md', `head ${quote} tail`);
    const lines = [];

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: 'x', derivedFrom: [{ source: rel, spans: [{ quote }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(result.ok, true, JSON.stringify(result));

    const stored = JSON.parse(lines[0].toString('utf8')).sources[0].spans[0].quote;
    assert.equal(stored.truncated, true);
    assert.equal(stored.original_utf8_bytes, 3000);
    assert.ok(stored.stored_utf8_bytes <= 1024, `stored ${stored.stored_utf8_bytes} bytes`);
    assert.equal(stored.stored_utf8_bytes, Buffer.byteLength(stored.text, 'utf8'));
    assert.equal(stored.stored_utf8_bytes % 3, 0, '1024 is not a multiple of 3, so a boundary cut lands at 1023');
    assert.ok(!stored.text.includes('�'), 'a boundary cut never produces a replacement character');
    assert.equal(Buffer.from(stored.text, 'utf8').toString('utf8'), stored.text, 'the stored text round-trips losslessly');

    // ⚠⚠ THE HASH IS OVER THE FULL QUOTE, NOT THE STORED PREFIX. This is the whole value of the
    // truncation design: a truncated span stays REPAIRABLE against its source. Hashing the prefix
    // would make the record look healthy while proving nothing.
    assert.equal(stored.sha256, crypto.createHash('sha256').update(Buffer.from(quote, 'utf8')).digest('hex'));
    assert.notEqual(stored.sha256, crypto.createHash('sha256').update(Buffer.from(stored.text, 'utf8')).digest('hex'));

    // The span itself still locates the WHOLE quote, not the stored prefix.
    const span = JSON.parse(lines[0].toString('utf8')).sources[0].spans[0];
    assert.equal(span.length, 3000);
});

test('ST10-line-too-large — an over-size record refuses before any page is created', async () => {
    arm('ST10-line-too-large');
    const world = vault();
    // 300 distinct sources, each under the source cap? No — the SPAN cap is what a large citation
    // list hits first, so this drives the SIZE ceiling with many sources each carrying a bounded
    // quote, and the two count caps are asserted beside it.
    const many = [];
    for (let index = 0; index < 60; index += 1) {
        const rel = withSource(world, `Arc/s${index}.md`, `${'z'.repeat(900)}-${index}`);
        many.push({ source: rel, spans: [{ quote: 'z'.repeat(900) }, { quote: `${'z'.repeat(899)}-${index}` }] });
    }
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: 'x', derivedFrom: many
    });
    refusal(result, 'LINEAGE_LINE_TOO_LARGE', world);
    // ⚠ "NO PAGE", NOT "NOTHING". This assertion said `'NOTHING is created'` until 2026-09-08, and
    // it was already overclaiming before option C: the same call MINTS `.wyrd/scribe.json` on the
    // way past, because a vault with no config gets one at its first stamp. Part 3 moved that mint
    // earlier still — ahead of the config read — so the wording went from imprecise to plainly
    // false about the invocation it describes. The property the arm actually owns, and the one that
    // matters, is that the PAGE does not exist: an over-size record refuses before the first page
    // write. The config's creation is `ST2-config-minted`'s claim and is asserted there.
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'NO PAGE is created');
    // ⚠⚠ READ OFF THE RESULT, NOT OFF THE DISK, SINCE 2026-09-08. The disk answers a DIFFERENT
    // question: "does a config exist here now?" — which is true whether this call minted it, an
    // earlier call did, or a concurrent process did. `config_created` answers the question the arm
    // is actually making, which is what THIS INVOCATION did, and it is the field's whole reason for
    // existing. The disk check is kept beside it as the corroborating half, so a result claiming a
    // mint that never landed cannot pass.
    assert.equal(result.config_created, true,
        'the refusal reports that this same call minted the vault config — the outer side effect a bare refusal hides');
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd', 'scribe.json')), true,
        'and it really is on disk — stated rather than left as a silent exception to the line above');

    // The count caps, each on its own.
    const overSources = [];
    for (let index = 0; index < 65; index += 1) {
        overSources.push({ source: withSource(world, `Arc/t${index}.md`, `t${index}`), spans: [{ quote: `t${index}` }] });
    }
    refusal(await stamp(gateFor(world.grant), {
        path: 'Mage/b.md', content: 'x', derivedFrom: overSources
    }), 'LINEAGE_LINE_TOO_LARGE', world);

    const spanText = Array.from({ length: 300 }, (_, i) => `q${i}q`).join(' ');
    const spanRel = withSource(world, 'Arc/spans.md', spanText);
    refusal(await stamp(gateFor(world.grant), {
        path: 'Mage/c.md',
        content: 'x',
        derivedFrom: [{ source: spanRel, spans: Array.from({ length: 300 }, (_, i) => ({ quote: `q${i}q` })) }]
    }), 'LINEAGE_LINE_TOO_LARGE', world);

    // The pair: a record just inside every bound succeeds, so a refuser could not pass.
    const okRel = withSource(world, 'Arc/small.md', 'small source');
    const ok = await stamp(gateFor(world.grant), {
        path: 'Mage/ok.md', content: 'x', derivedFrom: [{ source: okRel, spans: [{ quote: 'small' }] }]
    }, { appender: capturingAppender([]) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
});

// ---------------------------------------------------------------------------
// Frontmatter (B2)
// ---------------------------------------------------------------------------

const OPTED_IN = `{"schema":"wyrd.scribe/v1","vault_id":"${FIXED_UUID}","write_frontmatter":true}`;
const OPTED_OUT = `{"schema":"wyrd.scribe/v1","vault_id":"${FIXED_UUID}","write_frontmatter":false}`;

test('ST11-frontmatter-off-bytes-untouched — the opt-out writes exactly what it was given', async () => {
    arm('ST11-frontmatter-off-bytes-untouched');
    const world = vault({ config: OPTED_OUT });
    const content = '---\ntitle: existing\n---\n\nbody with a --- in it\n';
    const lines = [];

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content, derivedFrom: []
    }, { appender: capturingAppender(lines) });
    assert.equal(result.ok, true, JSON.stringify(result));

    const written = fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'));
    assert.ok(written.equals(Buffer.from(content, 'utf8')), 'with the opt-in false the bytes are untouched');
    assert.equal(JSON.parse(lines[0].toString('utf8')).page.content.bytes, written.length);
});

test('ST12-frontmatter-on-prepended — content with no block gains one', async () => {
    arm('ST12-frontmatter-on-prepended');
    const world = vault({ config: OPTED_IN });
    const rel = withSource(world);
    const lines = [];

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'just a body\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(result.ok, true, JSON.stringify(result));

    const written = fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8');
    const rows = written.split('\n');
    assert.equal(rows[0], '---');
    assert.equal(rows[2], '---');
    assert.equal(rows[3], 'just a body', 'the original content follows the block, unmodified');
    assert.ok(rows[1].startsWith('wyrd_lineage: '), rows[1]);
    assert.equal(written.split('wyrd_lineage:').length - 1, 1, 'exactly one key is inserted');

    const projection = JSON.parse(rows[1].slice('wyrd_lineage: '.length));
    // ⚠⚠ THE PROJECTION CARRIES NO `page` KEY AT ALL. The digest was never computable here — it is
    // over bytes that do not exist until the projection is inserted — and the IDENTITY is worse
    // than uncomputable: it would be the CALLER'S spelling, while the ledger records the fence's
    // canonical path, so a junction write put two disagreeing identities on one event. `ST26` is
    // that case; this is the shape assertion that makes it structural.
    assert.equal('page' in projection, false, 'a page does not name itself inside itself');
    assert.deepEqual(Object.keys(projection).sort(), ['event', 'event_id', 'recorded_at', 'schema', 'sources', 'vault', 'writer']);
    assert.equal(projection.vault.id, FIXED_UUID, 'the vault is still named — only the PAGE is not');
    assert.equal(projection.sources[0].identity.vault_id, FIXED_UUID, 'every SOURCE identity survives');
    assert.equal(projection.sources[0].spans[0].quote.text, 'noon');
    // ⚠ THE JOIN TO THE LEDGER. Without `event_id` a reader holding a stamped page and a ledger of
    // many lines has only the timestamp to match on, which `ST29` shows does not distinguish writes.
    const ledgerRecord = JSON.parse(lines[0].toString('utf8'));
    assert.equal(projection.event_id, ledgerRecord.event_id, 'the page and its ledger line name the same event');

    // The ledger's digest is over the STAMPED bytes, not the caller's content.
    const line = JSON.parse(lines[0].toString('utf8'));
    assert.equal(line.page.content.bytes, Buffer.byteLength(written, 'utf8'));
    assert.equal(line.page.content.digest, crypto.createHash('sha256').update(Buffer.from(written, 'utf8')).digest('hex'));
});

test('ST13-frontmatter-on-inserted — an existing block gains the key before its closing fence', async () => {
    arm('ST13-frontmatter-on-inserted');
    const world = vault({ config: OPTED_IN });
    const lines = [];
    const content = '---\ntitle: existing\ntags: [a, b]\n---\nbody\n';

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content, derivedFrom: []
    }, { appender: capturingAppender(lines) });
    assert.equal(result.ok, true, JSON.stringify(result));

    const rows = fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8').split('\n');
    assert.deepEqual(rows.slice(0, 3), ['---', 'title: existing', 'tags: [a, b]']);
    assert.ok(rows[3].startsWith('wyrd_lineage: '), rows[3]);
    assert.equal(rows[4], '---', 'the key goes BEFORE the closing fence');
    assert.equal(rows[5], 'body', 'the body is untouched');

    // ⚠ THE INSERTED KEY NAMES NO PAGE, HERE TOO. `ST12` pins the projection's shape on the
    // PREPEND path; this is the INSERT path, which composes the same value through a different
    // branch, and an assertion on one is not an assertion on the other.
    const projection = JSON.parse(rows[3].slice('wyrd_lineage: '.length));
    assert.equal('page' in projection, false, 'a page does not name itself inside itself');
    assert.deepEqual(Object.keys(projection).sort(), ['event', 'event_id', 'recorded_at', 'schema', 'sources', 'vault', 'writer']);

    // ⚠ CRLF MOVED TO `ST31` AND GREW A SECOND HALF. The check that used to sit here proved a CRLF
    // document was not mistaken for an unclosed block; it never asked what ENDING the inserted line
    // got, and the answer was a lone LF in a CRLF file.
});

test('ST14-frontmatter-conflict — an existing top-level key refuses; an indented one does not', async () => {
    arm('ST14-frontmatter-conflict');
    const world = vault({ config: OPTED_IN });
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: '---\ntitle: x\nwyrd_lineage: {"already":"here"}\n---\nbody\n',
        derivedFrom: []
    });
    refusal(result, 'FRONTMATTER_CONFLICT', world);
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'nothing is created');

    // ⚠ THE PAIR THAT MAKES THE RULE A RULE: an INDENTED key belongs to someone else's mapping and
    // is not ours to collide with. A conflict check matching anywhere in the line would refuse this
    // legitimate document forever, with no way for the user to know why.
    const nested = vault({ config: OPTED_IN });
    const ok = await stamp(gateFor(nested.grant), {
        path: 'Mage/answer.md',
        content: '---\nmeta:\n  wyrd_lineage: not ours\n---\nbody\n',
        derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
});

test('ST32-quoted-key-is-the-same-key — a quoted wyrd_lineage refuses as a conflict', async () => {
    arm('ST32-quoted-key-is-the-same-key');
    /**
     * ⚠⚠ WHAT THIS CATCHES IS NOT A MISSED REFUSAL, IT IS A DESTROYED RECORD. Measured before the
     * fix: a page carrying `"wyrd_lineage": {...}` did not refuse — it WROTE, and the result was a
     * document with TWO top-level `wyrd_lineage` keys. That is invalid YAML; the ordinary parser
     * response is to keep one and silently drop the other, so the user's existing provenance is
     * gone with no refusal, no error and nothing visible in the page. `ST14` could not see this:
     * its fixture spells the key bare, which was the one spelling that already worked.
     */
    for (const spelling of ['"wyrd_lineage"', "'wyrd_lineage'"]) {
        const world = vault({ config: OPTED_IN });
        const result = await stamp(gateFor(world.grant), {
            path: 'Mage/answer.md',
            content: `---\ntitle: x\n${spelling}: {"already":"here"}\n---\nbody\n`,
            derivedFrom: []
        });
        refusal(result, 'FRONTMATTER_CONFLICT', world);
        assert.equal(
            fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false,
            `nothing is created for ${spelling}`
        );
    }

    // ⚠ THE PAIR, AND IT IS THE HALF THAT KEEPS THE FIX HONEST. Stripping quotes must not make the
    // module refuse documents it should write: a DIFFERENT quoted key is still someone else's key,
    // and an unmatched quote is not a quoted key at all. Without this, `unquote` returning the
    // whole line's prefix — or matching one quote — would pass the loop above and break real pages.
    for (const innocent of ['"title"', "'author'", '"wyrd_lineage', "wyrd_lineage'"]) {
        const world = vault({ config: OPTED_IN });
        const ok = await stamp(gateFor(world.grant), {
            path: 'Mage/answer.md',
            content: `---\n${innocent}: x\n---\nbody\n`,
            derivedFrom: []
        }, { appender: capturingAppender([]) });
        assert.equal(ok.ok, true, `${innocent} must still be written: ${JSON.stringify(ok)}`);
    }
});

test('ST15-frontmatter-invalid — an unclosed block refuses rather than being prepended to', async () => {
    arm('ST15-frontmatter-invalid');
    const world = vault({ config: OPTED_IN });
    // ⚠ EVERY LINE IS MAPPING-SHAPED, AND THAT IS WHAT MAKES THIS THE UNCLOSED-BLOCK CASE RATHER
    // THAN THE HORIZONTAL-RULE ONE. The fixture used to end in a bare `body`, which since the
    // mapping-line check reads as prose under a rule — `ST30`'s case, which is PREPENDED to, not
    // refused. Two different outcomes hang on this fixture's shape, so it states which it is.
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: '---\ntitle: never closed\nauthor: rowan\n', derivedFrom: []
    });
    refusal(result, 'FRONTMATTER_INVALID', world);
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false);

    // A block that closes only past the 200-line ceiling refuses too — the bound is what stops an
    // unbounded scan of caller-supplied bytes, and treating it as "no frontmatter" would prepend a
    // SECOND block and hand back a document with two.
    const long = vault({ config: OPTED_IN });
    const far = `---\n${'k: v\n'.repeat(250)}---\nbody\n`;
    refusal(await stamp(gateFor(long.grant), {
        path: 'Mage/answer.md', content: far, derivedFrom: []
    }), 'FRONTMATTER_INVALID', long);
});

// ---------------------------------------------------------------------------
// The write and the ledger
// ---------------------------------------------------------------------------

test('ST16-exists-is-tier-a — the fence\'s EXISTS is tier A\'s rule, and the ledger stays untouched', async () => {
    arm('ST16-exists-is-tier-a');
    const world = vault();
    fs.writeFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'ALREADY HERE');

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: 'replacement', derivedFrom: []
    }, { appender: forbiddenAppender('an EXISTS refusal') });

    assert.equal(result.ok, false);
    // ⚠ THE FENCE'S REASON, ARRIVING FOR FREE. Tier A's "may not overwrite" needs no Scribe check at
    // all: `createFileInGrant` opens `wx`, so the refusal is ATOMIC against anything appearing
    // between a would-be pre-check and the open. A pre-check would be the TOCTOU window itself.
    assert.equal(result.reason, 'EXISTS', `expected the fence's EXISTS, got ${result.reason}`);
    // ⚠ `retained` IS THE FENCE'S WORD ABOUT THE PAGE PATH, AND ITS MESSAGE SAID MORE THAN THAT
    // UNTIL 2026-09-08. It read `'nothing was created by this invocation'`, which was already
    // false: the same call MINTS `.wyrd/scribe.json`, because this vault had no config. `retained`
    // has never made a claim about the whole invocation — it answers "did the fence leave anything
    // at THIS target?" — and the wording is corrected to say so rather than the check being
    // changed. Part 3 moved the mint earlier, which made an imprecise sentence a plainly wrong one.
    assert.equal(result.retained, null, 'the fence left nothing at the page target');
    assert.equal(fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8'), 'ALREADY HERE', 'the existing file is untouched');

    /**
     * ⚠⚠ THIS OUTCOME IS THE **D8 EXCLUSION**, AND THAT IS THE WHOLE OF WHY IT CARRIES NO
     * `config_created`. The rule at `WritePageResult` is one sentence with one exception: every
     * result after `loadConfig` carries the field EXCEPT a fence refusal passed through unchanged
     * under D8. `EXISTS` is the fence's own refusal, returned unwrapped because D8 forbids a second
     * vocabulary for one containment implementation, so the Scribe adds no field to it. This arm
     * pins the exclusion rather than leaving it to be discovered.
     *
     * ⚠ EVERY OTHER SHAPE FROM STEP 4 DOWN DOES CARRY IT, INCLUDING THE SPAN REFUSALS SINCE
     * 2026-09-08 (`ST20`). So an `undefined` here is a statement about D8's boundary and not about
     * the field being optional.
     *
     * The consequence is real and is what the assertions below measure together: the invocation DID
     * mint the vault's config, and the result it hands back does not say so. Anyone closing that
     * gap later should see this arm go red on the `undefined` assertion, which is why it is written
     * as an assertion rather than a comment.
     */
    assert.equal(result.config_created, undefined,
        'a fence pass-through is the D8 exclusion and carries no outer summary — see ConfigCreated in stamp.ts for why, and what it costs');
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd', 'scribe.json')), true,
        'and the config WAS minted by this same call — the invocation is not a no-op, and the result above cannot tell you that');
});

test('ST17-ledger-failed-after-create — the page stays, and the refusal says so', async () => {
    arm('ST17-ledger-failed-after-create');
    const world = vault();
    const rel = withSource(world);

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: refusingAppender() });

    assert.equal(result.ok, false);
    assert.equal(result.reason, 'PAGE_WRITTEN_LEDGER_FAILED');
    assertNoOutsideNames(result.detail, world);
    seenRefusals.push({ reason: result.reason, detail: result.detail, world });

    // ⚠⚠ THE `Created` IS CARRIED, and it is what makes the outcome actionable. Without it the
    // caller cannot tell "nothing happened" from "a page exists with no provenance" — opposite
    // situations demanding opposite repairs.
    assert.equal(result.created.ok, true);
    assert.equal(result.created.rel, path.join('Mage', 'answer.md'));
    assert.equal(result.created.bytes, Buffer.byteLength('the answer', 'utf8'));
    assert.equal(result.cause.ok, false, 'the underlying refusal is passed through, not summarised away');

    // ⚠ NO ROLLBACK. The fence has no delete, and deleting by PATH would reopen the TOCTOU the `wx`
    // create closes. The page is on disk and stays there.
    assert.equal(
        fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8'),
        'the answer',
        'the page IS on disk and is NOT removed'
    );
});

test('ST18-no-outside-names — no Scribe refusal in this file carries an absolute or outside path', () => {
    arm('ST18-no-outside-names');
    // ⚠⚠ THIS IS A CLAIM ABOUT THE SURFACE, NOT ABOUT REMEMBERED CASES, which is why it asserts a
    // COUNT before it asserts the property. Every refusal above routed through `refusal()` and was
    // collected; if a later edit stops routing them, this arm goes green over an empty list and
    // certifies nothing. The count makes that a failing state.
    assert.ok(seenRefusals.length >= 15, `expected the collected refusals, found ${seenRefusals.length}`);
    for (const seen of seenRefusals) {
        assert.equal(typeof seen.detail, 'string');
        assert.ok(seen.detail.length > 0, `${seen.reason} carries an empty detail`);
        if (seen.world) assertNoOutsideNames(seen.detail, seen.world);
    }
});

test('ST19-request-shape — a malformed request refuses before anything is read', async () => {
    arm('ST19-request-shape');
    const world = vault();
    const sink = [];
    const gate = gateFor(world.grant, spy(sink));
    const bootstrap = sink.length; // the gate's own lstat + realpathNative, before any request

    const bad = [
        [{ path: 'Mage/a.md', content: 'x', derivedFrom: [], extra: 1 }, 'BAD_INPUT'],
        [{ path: 'Mage/a.md', content: 'x' }, 'BAD_INPUT'],
        [{ path: '', content: 'x', derivedFrom: [] }, 'BAD_INPUT'],
        [{ path: 'Mage/a.md', content: 5, derivedFrom: [] }, 'BAD_INPUT'],
        [{ path: 'Mage/a.md', content: 'x', derivedFrom: 'nope' }, 'DERIVED_FROM_INVALID'],
        [{ path: 'Mage/a.md', content: 'x', derivedFrom: [{ source: 'Arc/i.md' }] }, 'DERIVED_FROM_INVALID'],
        [{ path: 'Mage/a.md', content: 'x', derivedFrom: [{ source: 'Arc/i.md', spans: [] }] }, 'DERIVED_FROM_INVALID'],
        [{ path: 'Mage/a.md', content: 'x', derivedFrom: [{ source: 'Arc/i.md', spans: [{ quote: 'x' }], oops: 1 }] }, 'DERIVED_FROM_INVALID']
    ];
    for (const [request, reason] of bad) {
        refusal(await stamp(gate, request), reason, world);
    }

    // ⚠ AN INHERITED KEY IS NOT A SUPPLIED ONE. `derivedFrom` on a prototype read leniently is a
    // page written with NO provenance while the caller believes it has some — the product's whole
    // value silently absent. `Reflect.ownKeys` is what forbids it; `in` would not.
    const inherited = Object.create({ derivedFrom: [] });
    inherited.path = 'Mage/a.md';
    inherited.content = 'x';
    refusal(await stamp(gate, inherited), 'BAD_INPUT', world);

    assert.equal(
        sink.length,
        bootstrap,
        `the shape is checked before ANY primitive runs: ${JSON.stringify(sink.slice(bootstrap))}`
    );
});

test('ST20-span-refusal-passed-through — a SPAN_* refusal keeps its own reason and where', async () => {
    arm('ST20-span-refusal-passed-through');
    const world = vault();
    const rel = withSource(world, 'Arc/dup.md', 'aaa bbb aaa');

    const ambiguous = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: 'x', derivedFrom: [{ source: rel, spans: [{ quote: 'aaa' }] }]
    }, { appender: forbiddenAppender('a span refusal') });
    // ⚠ VERBATIM, NOT TRANSLATED. `span.ts` spent four gate rounds making `reason` and `where` name
    // exactly which member is at fault; folding them into one Scribe reason would throw that away.
    assert.equal(ambiguous.ok, false);
    assert.equal(ambiguous.reason, 'SPAN_AMBIGUOUS');
    assert.equal(ambiguous.where, 'quote');

    /**
     * ⚠⚠ THE ENVELOPE GREW BY ONE DOCUMENTED KEY ON 2026-09-08, AND THIS ASSERTION IS WIDENED
     * RATHER THAN RELAXED. It read `['ok', 'reason', 'where']` — the shape `span.ts` returns — and
     * that is still exactly what `span.ts` returns; `test/span.test.js` asserts it there and is
     * untouched. What changed is the shape `writePage` hands BACK: a `SPAN_*` refusal reaching a
     * `writePage` caller is Scribe-originated at step 5 and fires AFTER step 4 may have minted the
     * config, so the rule at `WritePageResult` binds it exactly as it binds every other own shape,
     * and it now carries `config_created`.
     *
     * ⚠ WHY WIDENING IS NOT WEAKENING, WHICH IS THE ONLY QUESTION THIS ASSERTION EXISTS TO ANSWER.
     * The check is here to stop UNDOCUMENTED keys reaching a caller — a leaked source buffer, a
     * resolution, an offset (see `M3`-`M6`, which are exactly that failure). `config_created` is
     * documented on the type, in the same words on every shape that carries it, and is a boolean
     * that can hold nothing else. The assertion stays EXACT, so a fifth key still reddens it; only
     * the enumeration moved. ⚠ Round 1 backed this out and left the class open on the reasoning
     * that the envelope was another module's contract; the parent ruled it in, because the value at
     * this boundary is `writePage`'s result and not `span.ts`'s.
     */
    assert.deepEqual(Reflect.ownKeys(ambiguous).sort(), ['config_created', 'ok', 'reason', 'where']);
    assert.equal(ambiguous.config_created, true,
        'the span refusal reports the config step 4 minted on the way past');
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false);

    const missing = await stamp(gateFor(world.grant), {
        path: 'Mage/b.md', content: 'x', derivedFrom: [{ source: rel, spans: [{ quote: 'zzz' }] }]
    });
    assert.equal(missing.reason, 'SPAN_NOT_FOUND');
    assert.equal(missing.where, 'quote');
    assert.deepEqual(Reflect.ownKeys(missing).sort(), ['config_created', 'ok', 'reason', 'where']);
    /**
     * ⚠⚠ `false` IS THE DISCRIMINATING HALF, AND WITHOUT IT THIS ARM PINNED ONLY A KEY SET. Every
     * post-config assertion above reads `true`, because each was the FIRST stamp into a fresh
     * vault — so a `config_created` hard-wired to `true` satisfied all of them and the arm still
     * went green. This second stamp goes into the SAME `world`, whose config the first stamp
     * already minted, so the honest answer is `false`: nothing was minted on this pass. Added
     * 2026-09-08 after the round-3 review measured the hard-wired mutant surviving.
     *
     * ⚠ THE VALUE IS THE ASSERTION, NOT THE PRESENCE. The key-set check above proves the field
     * travels; only this proves it carries what THIS invocation did rather than a constant.
     */
    assert.equal(missing.config_created, false,
        'the config already existed, so this span refusal minted nothing and must report exactly that');

    /**
     * ⚠⚠ THE SHAPE-ONLY FAULT AT STEP 3 CARRIES NOTHING, AND THE PAIR IS WHAT MAKES THE RULE A LINE
     * RATHER THAN A BLANKET. `{}` is refused by `spanShapeFault` BEFORE `loadConfig` runs — that
     * ordering is `ST28`'s property — so there is no answer to report and the envelope is the
     * original three keys. A round that added the field everywhere would pass every assertion above
     * and quietly claim a mint that had not happened.
     */
    const shapeOnly = await stamp(gateFor(vault().grant), {
        path: 'Mage/c.md', content: 'x', derivedFrom: [{ source: rel, spans: [{}] }]
    });
    assert.equal(shapeOnly.ok, false);
    assert.equal(shapeOnly.reason, 'SPAN_INVALID_RANGE');
    assert.deepEqual(Reflect.ownKeys(shapeOnly).sort(), ['ok', 'reason', 'where'],
        'a step-3 shape fault precedes the config load, so it carries no summary at all');
});

test('ST21-source-cache-one-window-loop — the second stamp skips the loop and records identically', async () => {
    arm('ST21-source-cache-one-window-loop');
    const world = vault();
    const rel = withSource(world, 'Arc/big.md', `${'a'.repeat(5000)}NEEDLE${'b'.repeat(5000)}`);
    const cache = new SourceCache();
    const lines = [];

    // ⚠ THE COUNTER IS SCOPED TO THE SOURCE PATH, AND THE UNSCOPED VERSION WAS WRONG IN A WAY THAT
    // LOOKED RIGHT. Counting every `open` also counts the CONFIG read, which happens once per call
    // and is not cached by design — so both stamps reported the same total while the source cache
    // was working perfectly. A counter measuring the wrong file cannot detect the thing it names.
    const sourceReal = fs.realpathSync.native(path.join(world.grant, rel));
    let sourceOpens = 0;
    const primitives = spy([], {
        open: (t, f) => { if (t === sourceReal) sourceOpens += 1; return fs.openSync(t, f); }
    });
    const gate = gateFor(world.grant, primitives);

    const first = await stamp(gate, {
        path: 'Mage/one.md', content: 'one', derivedFrom: [{ source: rel, spans: [{ quote: 'NEEDLE' }] }]
    }, { appender: capturingAppender(lines), cache });
    assert.equal(first.ok, true, JSON.stringify(first));
    const afterFirst = sourceOpens;
    assert.equal(afterFirst, 2, 'a cold stamp opens the source twice: once to hash it, once for the window loop');

    const second = await stamp(gate, {
        path: 'Mage/two.md', content: 'two', derivedFrom: [{ source: rel, spans: [{ quote: 'NEEDLE' }] }]
    }, { appender: capturingAppender(lines), cache });
    assert.equal(second.ok, true, JSON.stringify(second));

    // ⚠⚠ THE CLAIM IS NARROW AND IS ASSERTED AS SUCH. A cache hit STILL HASHES — the digest is the
    // cache key and cannot be known without reading — so this is NOT AC7's "reads the source's
    // bytes once", and pretending otherwise would be a cost claim the code cannot back. What the
    // cache buys is the WINDOW LOOP: one open instead of two, one resident buffer instead of two.
    assert.equal(sourceOpens - afterFirst, 1, 'a cached stamp hashes but skips the window loop');
    assert.equal(cache.size, 1, 'one entry for one source');

    // AC6's shape: the cache does not change the record.
    const one = JSON.parse(lines[0].toString('utf8'));
    const two = JSON.parse(lines[1].toString('utf8'));
    assert.deepEqual(one.sources, two.sources, 'the cached stamp records byte-identical source provenance');
});

// ---------------------------------------------------------------------------
// The END-TO-END ledger — the production appender, over a real `.wyrd/lineage.jsonl`
//
// ⚠⚠ EVERY ARM BELOW USES `gateAppender`, NOT A STUB, AND THAT IS THE WHOLE POINT OF THE GROUP.
// The arms above hand `writePage` an appender that keeps the Buffer in memory, which is exactly
// right for asserting the SHAPE crossing the seam and proves nothing about a file. These four
// close the debt `arms.mjs` carried as `ST-OWED-end-to-end` until 2026-09-02: a line landing, the
// log accumulating, the failure direction over a real fence refusal, and B4's atomicity claim.
// ---------------------------------------------------------------------------

const LEDGER_REL = path.join('.wyrd', 'lineage.jsonl');

/** The vault's real lineage log, read whole. Absent is distinguished from empty on purpose. */
function ledgerText(world) {
    const at = path.join(world.grant, LEDGER_REL);
    return fs.existsSync(at) ? fs.readFileSync(at, 'utf8') : null;
}

/**
 * ⚠ SPLIT ON LF WITH THE TRAILING EMPTY DISCARDED, AND THE DISCARD IS CHECKED RATHER THAN ASSUMED.
 * A JSONL file of N records ends WITH a newline, so splitting yields N+1 members whose last is
 * empty. A helper that silently dropped a NON-empty last member would hide the one defect these
 * arms exist to catch — a final record written without its terminator, which is a torn line.
 */
function ledgerLines(world) {
    const raw = ledgerText(world);
    assert.notEqual(raw, null, 'the ledger file must exist');
    const parts = raw.split('\n');
    assert.equal(parts[parts.length - 1], '', 'the ledger must end with its terminating LF — a missing one is a torn record');
    return parts.slice(0, -1);
}

test('ST22-ledger-line-lands — one real write puts exactly one line in .wyrd/lineage.jsonl', async () => {
    arm('ST22-ledger-line-lands');
    const world = vault();
    const rel = withSource(world);
    const gate = gateFor(world.grant);

    // ⚠ THE LOG DOES NOT EXIST YET, ASSERTED BEFORE THE WRITE. Without this the arm cannot tell a
    // line it appended from a file the fixture happened to leave behind.
    assert.equal(ledgerText(world), null, 'the fixture creates .wyrd/ but never the log inside it');

    const result = await stamp(gate, {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'foundations' }, { offset: 4, length: 9 }] }]
    }, { appender: gateAppender(gate) });

    assert.equal(result.ok, true, JSON.stringify(result));

    const lines = ledgerLines(world);
    assert.equal(lines.length, 1, 'exactly one line per write — never zero, never two');

    // ⚠ THE REPORTED COUNT IS CHECKED AGAINST THE FILE'S OWN SIZE, which is the assertion a
    // capturing appender structurally cannot make. `appended` comes from the fence's `Appended`;
    // if it ever reported a short write as a success, THIS is where the two disagree.
    const onDisk = fs.statSync(path.join(world.grant, LEDGER_REL)).size;
    assert.equal(result.appended, onDisk, 'the reported byte count is the whole line, terminator included');
    assert.equal(result.appended, Buffer.byteLength(lines[0], 'utf8') + 1);

    // ⚠⚠ THE LINE PARSES TO THE RECORD `ST8` PINS, AND IT IS COMPARED TO `result.record` RATHER
    // THAN RE-DESCRIBED. `ST8` owns the wire shape key-for-key; duplicating those forty assertions
    // here would give two places to update and one of them would rot. What THIS arm adds is that
    // the bytes ON DISK are the record the call returned — the step `ST8` takes on faith.
    const parsed = JSON.parse(lines[0]);
    assert.deepEqual(parsed, JSON.parse(JSON.stringify(result.record)), 'the line on disk IS the record returned');
    assert.equal(parsed.schema, 'wyrd.lineage/v1');
    assert.equal(parsed.event, 'page_written');
    assert.deepEqual(parsed.page.identity, { kind: 'path', vault_id: FIXED_UUID, path: 'Mage/answer.md' });
    assert.equal(parsed.sources.length, 1);
    assert.equal(parsed.sources[0].spans.length, 2);
    assert.equal(parsed.sources[0].spans[0].quote.text, 'foundations');

    // And the page itself is on disk beside it — a ledger line whose page is missing is the false
    // provenance claim `stamp.ts`'s ordering exists to prevent.
    assert.equal(fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8'), 'the answer');
});

test('ST23-ledger-accumulates — three writes leave three intact lines, in order, nothing truncated', async () => {
    arm('ST23-ledger-accumulates');
    const world = vault();
    const rel = withSource(world);
    const gate = gateFor(world.grant);
    const appender = gateAppender(gate);

    const sizes = [];
    for (const name of ['one', 'two', 'three']) {
        const result = await stamp(gate, {
            path: `Mage/${name}.md`,
            content: `page ${name}`,
            derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
        }, { appender });
        assert.equal(result.ok, true, `${name}: ${JSON.stringify(result)}`);
        // ⚠ THE FILE ONLY EVER GROWS, CHECKED AFTER EACH WRITE RATHER THAN AT THE END. A path that
        // truncated and rewrote would end with three lines too; only the running size can tell the
        // difference between appending and starting over.
        const size = fs.statSync(path.join(world.grant, LEDGER_REL)).size;
        if (sizes.length) {
            assert.ok(size > sizes[sizes.length - 1], `${name}: the log shrank or stalled — a truncating write, not an append`);
        }
        sizes.push(size);
    }

    const lines = ledgerLines(world);
    assert.equal(lines.length, 3, 'three writes, three lines');

    // ⚠ ORDER IS ASSERTED BY THE PAGE PATH, NOT BY THE TIMESTAMP. `FIXED_NOW` pins `recorded_at`
    // identically on all three, so a timestamp ordering assertion would pass over any permutation.
    const paths = lines.map(line => JSON.parse(line).page.identity.path);
    assert.deepEqual(paths, ['Mage/one.md', 'Mage/two.md', 'Mage/three.md'], 'the lines are in call order');

    // Each line is INDEPENDENTLY intact: a complete JSON document, carrying its own span. A splice
    // landing on a record boundary would still count three; parsing each is what makes "intact"
    // mean intact.
    for (const line of lines) {
        assert.ok(line.length > 0, 'no empty line may appear in the log');
        const record = JSON.parse(line);
        assert.equal(record.schema, 'wyrd.lineage/v1');
        assert.equal(record.sources[0].spans[0].quote.text, 'noon');
    }
});

test('ST24-ledger-parent-missing-refuses-after-create — .wyrd/ deleted mid-write refuses with the fence\'s own reason', async () => {
    arm('ST24-ledger-parent-missing-refuses-after-create');
    const world = vault();
    const rel = withSource(world);

    /**
     * ⚠⚠ THE DELETION IS STAGED AT THE PAGE'S OWN CREATE, WHICH IS THE ONLY WINDOW THAT EXISTS.
     * `stamp.ts` loads the config, resolves the sources, creates the page, THEN appends — so the
     * `openExclusive` that creates `Mage/answer.md` is the one primitive call firing after the
     * config has been read and before the append is attempted. Removing `.wyrd/` from inside it
     * reproduces the real race (a user or another process clearing the directory mid-write) rather
     * than simulating it with a hand-written refusal.
     *
     * ⚠ IT FIRES ONCE, AND ONLY ON THE PAGE. A spy deleting on every `openExclusive` would also
     * fire during the CONFIG's minting create, which happens earlier and would refuse the write
     * long before the ledger — a different arm wearing this one's name.
     */
    let staged = false;
    const primitives = spy([], {
        openExclusive: target => {
            const fd = fs.openSync(target, 'wx');
            if (!staged && target.endsWith(`${path.sep}answer.md`)) {
                staged = true;
                fs.rmSync(path.join(world.grant, '.wyrd'), { recursive: true, force: true });
            }
            return fd;
        }
    });
    const gate = gateFor(world.grant, primitives);

    const result = await stamp(gate, {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: gateAppender(gate) });

    assert.equal(staged, true, 'the deletion must actually have been staged, or this arm proves nothing');
    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.reason, 'PAGE_WRITTEN_LEDGER_FAILED');
    assertNoOutsideNames(result.detail, world);
    seenRefusals.push({ reason: result.reason, detail: result.detail, world });

    // ⚠⚠ THE FENCE'S OWN REFUSAL IS CARRIED THROUGH, NOT SUMMARISED — and it is a REAL one this
    // time. `ST17` proves the passthrough with a hand-written refusal from `refusingAppender`;
    // this proves the PRODUCTION appender does not repackage what the gate returned. `MISSING` is
    // the fence's answer to an absent parent (`A56`), and `retained: null` is its statement that
    // nothing was left behind AT THE TARGET THAT CALL WAS GIVEN — the LEDGER file, not the page.
    // ⚠ THAT SCOPING IS THE WHOLE OF THE FIELD'S MEANING AND IS EASY TO MISREAD HERE, because the
    // `retained: null` sits one key away from a `created` saying the PAGE exists. `retained`
    // describes the fence call that produced the refusal it sits on; on `LedgerFailed` that call
    // addressed the ledger. The page's own outcome is `created`, asserted below.
    assert.equal(result.cause.ok, false);
    assert.equal(result.cause.reason, 'MISSING', `expected the fence's MISSING, got ${result.cause.reason}: ${result.cause.detail}`);
    assert.equal(result.cause.retained, null,
        'a pre-open refusal retains nothing at the LEDGER target, and the passthrough keeps the field');
    assert.equal(result.created.ok, true,
        'and the PAGE is a separate question, answered by `created` rather than by the cause\'s `retained`');
    assertNoOutsideNames(result.cause.detail, world);

    // ⚠ AND NOTHING RECREATED THE DIRECTORY. If anything had, this arm would go green while the
    // Scribe quietly restored vault metadata a user deleted.
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd')), false, 'nothing recreated .wyrd/');

    // The page STAYS. No rollback, by ruling — see `stamp.ts`'s header.
    assert.equal(result.created.ok, true);
    assert.equal(
        fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8'),
        'the answer',
        'the page is on disk and is NOT removed'
    );
});

test('ST25-ledger-concurrent — eight concurrent writes leave eight intact lines, none torn', async () => {
    arm('ST25-ledger-concurrent');
    const world = vault();
    const rel = withSource(world);
    const gate = gateFor(world.grant);

    /**
     * ⚠⚠ ONE SCRIBE, EIGHT IN-FLIGHT CALLS, REAL DESCRIPTORS. This is B4's atomicity claim measured
     * rather than argued — and it is measured IN PROCESS, which is what this suite can honestly do.
     * `O_APPEND` makes offset selection and the write one operation against competing appenders;
     * the honest limit, which `fsgate.ts` states and this arm does not overreach past, is that it
     * is NOT a promise of all-or-nothing against a device error.
     *
     * ⚠ THE PAGES DIFFER, AND THEIR BODIES ARE LONG. Eight identical records would leave a splice
     * invisible — any interleaving of identical bytes still parses — and short lines would rarely
     * be split by a write the runtime chose to break up.
     */
    const names = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'];

    /**
     * ⚠⚠ THE ARM MEASURES THAT THE CONCURRENCY IT CLAIMS ACTUALLY HAPPENED, AND UNTIL 2026-09-03
     * IT DID NOT. `Promise.all` puts eight CALLS in flight; that is not the same fact as two
     * appends being simultaneously between their open and their write, which is the only thing
     * `O_APPEND` is being trusted for here. If the runtime happened to serialise them — a change
     * in the appender, a lock, an await moved one line — every assertion below would still pass,
     * and the arm would be measuring the event loop while reading as a contention proof. A test
     * whose subject can quietly stop occurring is the shape this suite exists to refuse.
     *
     * ⚠ THE GATE IS FROZEN, deliberately, so the counter cannot be attached by re-pointing its
     * primitive. It wraps instead: a delegating object the scribe cannot tell from the real gate.
     * Measured on this machine when written — 7 simultaneously in flight, 21 overlapping pairs.
     * The floor asserted below is 2, because the CLAIM is "appends overlap", not "seven do".
     */
    const spans = [];
    let live = 0;
    let peakLive = 0;
    const counting = {
        readFileInGrant: (...args) => gate.readFileInGrant(...args),
        listDirInGrant: (...args) => gate.listDirInGrant(...args),
        hashInGrant: (...args) => gate.hashInGrant(...args),
        createFileInGrant: (...args) => gate.createFileInGrant(...args),
        appendLineInGrant: async (request, line) => {
            live += 1;
            peakLive = Math.max(peakLive, live);
            const entered = spans.push(null) - 1;
            const start = process.hrtime.bigint();
            try {
                return await gate.appendLineInGrant(request, line);
            } finally {
                spans[entered] = [start, process.hrtime.bigint()];
                live -= 1;
            }
        }
    };

    const appender = gateAppender(counting);
    const results = await Promise.all(names.map(name => stamp(counting, {
        path: `Mage/${name}.md`,
        content: `page ${name} ${name.repeat(400)}`,
        derivedFrom: [{ source: rel, spans: [{ quote: 'foundations' }] }]
    }, { appender })));

    assert.equal(spans.length, 8, 'every write must have reached the append');
    assert.ok(
        peakLive >= 2,
        `the appends were SERIALISED (peak in flight ${peakLive}) — this arm would then be `
        + 'measuring the event loop rather than O_APPEND, and every assertion below would still pass'
    );

    for (const [index, result] of results.entries()) {
        assert.equal(result.ok, true, `${names[index]}: ${JSON.stringify(result)}`);
    }

    const lines = ledgerLines(world);
    assert.equal(lines.length, 8, `eight writes must leave eight lines, found ${lines.length}`);

    // ⚠ EVERY LINE PARSES AND EVERY PAGE APPEARS EXACTLY ONCE. A torn record fails the parse; a
    // SPLICED pair — one record's bytes landing inside another's — shows as a duplicate or a
    // missing path even when both halves happen to parse.
    const seen = new Set();
    for (const line of lines) {
        const record = JSON.parse(line);
        assert.equal(record.schema, 'wyrd.lineage/v1');
        const pagePath = record.page.identity.path;
        assert.equal(seen.has(pagePath), false, `${pagePath} appears twice — records were spliced`);
        seen.add(pagePath);
        // ⚠ THE RECORD IS CHECKED AGAINST ITS OWN PAGE ON DISK. A record assembled from the halves
        // of two different writes can still parse; a digest that does not match the page it names
        // is what catches that.
        const bytes = fs.readFileSync(path.join(world.grant, pagePath.split('/').join(path.sep)));
        assert.equal(record.page.content.bytes, bytes.length, `${pagePath}: the recorded byte count is not the page's`);
        assert.equal(
            record.page.content.digest,
            crypto.createHash('sha256').update(bytes).digest('hex'),
            `${pagePath}: the recorded digest is not the page's — this record is a splice of two writes`
        );
    }
    assert.deepEqual([...seen].sort(), names.map(name => `Mage/${name}.md`).sort(), 'every page is recorded exactly once');

    // ⚠ THE TOTAL SIZE IS THE SUM OF THE REPORTED COUNTS. A lost or overwritten append shows here
    // as a shortfall even in the unlikely case that every surviving line parses.
    const total = results.reduce((sum, result) => sum + result.appended, 0);
    assert.equal(fs.statSync(path.join(world.grant, LEDGER_REL)).size, total, 'no append was lost or overwritten');
});

// ---------------------------------------------------------------------------
// The cold-review round, 2026-09-02
//
// ⚠⚠ EVERY ARM BELOW PINS A DEFECT THAT WAS LIVE IN THE BUILT PATH. None is a hypothetical, and
// each says which disagreement or which leak it holds shut — an arm whose stated reason is
// "coverage" is one a later session deletes without learning what it was for.
// ---------------------------------------------------------------------------

test('ST26-frontmatter-carries-no-page-identity — the page names no page; the ledger names the canonical one', async () => {
    arm('ST26-frontmatter-carries-no-page-identity');
    const world = vault({ config: OPTED_IN });
    const rel = withSource(world);
    const lines = [];

    /**
     * ⚠⚠ THE JUNCTION LEG WAS INVERTED ON 2026-09-08 AND THE PROTECTED PROPERTY MOVED TO A DIRECT
     * FIXTURE, RATHER THAN BEING DELETED WITH IT. This arm used to stamp through
     * `Alias/ -> Mage/` and assert the write SUCCEEDED, because the resolution is what made the
     * page record and the ledger record able to DISAGREE: `created.rel` was `Mage\answer.md` while
     * the request said `Alias/answer.md`, so under the old shape the page carried the caller's
     * spelling and the ledger the canonical one — two provenance records for one write, with the
     * wrong one embedded in the bytes that travel with the file.
     *
     * Option C refuses that write (`PARENT_ALIAS`), so the aliased leg can no longer produce a
     * page at all. ⚠ AN ARM MERELY DELETED IS A LOST GUARANTEE, so the two claims are separated:
     * the projection's page-identity ABSENCE is asserted below against a direct `Mage/answer.md`
     * fixture — it is a property of the PROJECTION, not of the junction — and the junction leg
     * stays, now asserting the refusal and that nothing was written through it.
     *
     * ⚠ A JUNCTION NEEDS NO WINDOWS PRIVILEGE — that is what keeps this arm portable, and it is why
     * the fence's own fixtures use junctions for their in-grant alias cases (`A13`). A symlink here
     * would break `test:portable` on an unprivileged machine with no gate going red.
     */
    fs.symlinkSync(path.join(world.grant, 'Mage'), path.join(world.grant, 'Alias'), 'junction');

    const aliased = await stamp(gateFor(world.grant), {
        path: 'Alias/answer.md',
        content: 'MUST NOT LAND\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: forbiddenAppender('a stamp through an aliased page parent') });
    refusal(aliased, 'PARENT_ALIAS', world);
    assert.equal(aliased.retained, null, 'nothing was opened on the aliased path');
    assert.equal(
        fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false,
        '⚠ the stamp LANDED A PAGE on the canonical parent and refused afterwards'
    );

    // ---- the projection's page-identity absence, on a DIRECT path -----------
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'the answer\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(result.created.rel, path.join('Mage', 'answer.md'));

    const written = fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8');
    const rows = written.split('\n');
    assert.ok(rows[1].startsWith('wyrd_lineage: '), rows[1]);
    const projection = JSON.parse(rows[1].slice('wyrd_lineage: '.length));

    // ⚠⚠ THE PROPERTY, STATED AS AN ABSENCE. Not "the page key holds the canonical path" — page
    // identity has ONE home and it is the ledger, so the projection carries no `page` key at all
    // and there is nothing left that CAN disagree.
    assert.equal('page' in projection, false, 'the projection carries no page identity');
    assert.deepEqual(
        Object.keys(projection).sort(),
        ['event', 'event_id', 'recorded_at', 'schema', 'sources', 'vault', 'writer']
    );
    // ⚠ AND THE PAGE'S OWN PATH APPEARS NOWHERE IN ITS BYTES. The key-absence check above would
    // still pass if the path leaked through some other member; this asks the whole document.
    //
    // ⚠ THIS ASKED FOR `'Alias'` UNTIL 2026-09-08, when the aliased leg became a refusal and the
    // request stopped carrying that spelling — an assertion nothing could violate any more, which
    // is the silently-repurposed shape this build swept for. It asks about the path the request
    // ACTUALLY named, which is the property either spelling was ever evidence for.
    assert.ok(!written.includes('answer.md'), `the page path must not appear in the page: ${rows[1]}`);

    // The SOURCES are what the projection is for, and they are untouched by the removal.
    assert.equal(projection.sources.length, 1);
    assert.deepEqual(projection.sources[0].identity, { kind: 'path', vault_id: FIXED_UUID, path: 'Arc/interview.md' });
    assert.equal(projection.sources[0].spans[0].quote.text, 'noon');

    // ⚠ THE LEDGER IS THE SINGLE HOME OF PAGE IDENTITY, AND IT CARRIES THE FENCE'S CANONICAL PATH —
    // forward-slashed, as every ledger path is on every host.
    const line = JSON.parse(lines[0].toString('utf8'));
    assert.deepEqual(line.page.identity, { kind: 'path', vault_id: FIXED_UUID, path: 'Mage/answer.md' });
    assert.equal(line.page.content.bytes, Buffer.byteLength(written, 'utf8'));
    assert.equal(
        line.page.content.digest,
        crypto.createHash('sha256').update(Buffer.from(written, 'utf8')).digest('hex'),
        'the ledger digest is over the STAMPED bytes'
    );
    assert.equal(projection.event_id, line.event_id, 'the page and its ledger line name the same event');
});

test('ST27-line-limit-is-decided-before-create — an over-size line refuses BEFORE the page exists', async () => {
    arm('ST27-line-limit-is-decided-before-create');

    /**
     * ⚠⚠ THE DEFECT THIS PINS, BECAUSE THE ARM IS MEANINGLESS WITHOUT IT. The draft record is
     * size-checked with a PLACEHOLDER page digest and byte count, because the real ones are not
     * known until the page bytes are composed. The placeholders used to be `'0'.repeat(64)` and
     * `0` — and `0` is ONE character where a real byte count can be sixteen. So a draft could pass
     * this check while the FINAL line, carrying the real count, was over the ceiling: the page was
     * CREATED, and the call then returned `PAGE_WRITTEN_LEDGER_FAILED` carrying a FABRICATED
     * `IO_ERROR` cause. The caller was told a page existed whose provenance was lost to an I/O
     * failure; the truth was that the request crossed a documented bound and nothing should have
     * been created at all.
     *
     * The fix: the placeholders are the WIDEST values their fields can hold — a fixed-width 64-hex
     * digest and `Number.MAX_SAFE_INTEGER` — so the fields they stand in for can no longer put a
     * passing draft over the ceiling, and the ORDINARY over-size request is decided here, before
     * anything is created. That is what this arm measures.
     *
     * ⚠⚠ THAT SENTENCE READ "a draft that passes GUARANTEES the final line passes, and the final
     * check becomes a defensive assertion that can no longer trip" UNTIL 2026-09-08, AND BOTH
     * CLAUSES ARE FALSE. The widening bounds only the fields it replaced; the CANONICAL PAGE PATH is
     * not one of them, and `created.rel` can come back materially wider in bytes than the request
     * the draft was sized against — `_parentIsAliased` compares FOLDED, and `toLowerCase()` maps the
     * Kelvin sign `K` (three UTF-8 bytes) to `k` (one). `ST41-post-create-size-branch-is-reachable`
     * drives exactly that and reaches the post-create check deterministically, over a page that is
     * already on disk. So the final check is a LIVE branch, and when it fires the outcome is an
     * ORPHAN page that nothing rolls back.
     *
     * ⚠⚠ THE TAIL LENGTH IS A FIXED, MEASURED CONSTANT AND NOT A SEARCH, AND THE FIRST VERSION OF
     * THIS ARM GOT THAT WRONG IN AN INSTRUCTIVE WAY. A fixture that TUNES itself against the
     * implementation under test is self-correcting: each build finds a tail that suits its own
     * arithmetic, so the fixed and the broken code both land somewhere comfortable and the arm
     * never sees a difference. Measured on 2026-09-02 by patching `dist/` between runs:
     *
     *     tail 880-883    WIDE: LINEAGE_LINE_TOO_LARGE, nothing created
     *                   NARROW: PAGE_WRITTEN_LEDGER_FAILED, the page ON DISK  ← the defect
     *     tail 884+       both refuse — the line is over the ceiling either way, so the
     *                         placeholder's width is no longer what decides
     *     tail <= 879     both succeed — the line fits either way
     *
     * `882` sits in the middle of that four-byte band. Only inside it does the placeholder's WIDTH
     * decide the outcome; a fixture outside it passes under BOTH implementations and certifies a
     * guard nobody has.
     *
     * ⚠ THE BAND IS NARROW, SO THE ARM ASSERTS ITS OWN FIXTURE. If a schema change moves the line
     * size, the control below stops behaving as recorded and says so, rather than the arm quietly
     * going green over a request that is simply too big for ordinary reasons.
     */
    const CEILING = 65_536;
    const BULK = 44;
    const TAIL = 882;

    // ⚠ LARGE, SO THE REAL BYTE COUNT IS WIDE. With a short page the old narrow placeholder and the
    // real value are the same width, the defect does not reproduce, and this arm would go green
    // over the broken code — which is exactly how the defect survived the existing size arm.
    const bigContent = 'x'.repeat(2_000_000);
    assert.equal(String(Buffer.byteLength(bigContent, 'utf8')).length, 7, 'the real byte count must be far wider than "0"');

    const build = world => {
        const entries = [];
        for (let index = 0; index < BULK; index += 1) {
            const rel = withSource(world, `Arc/b${index}.md`, `${'q'.repeat(1100)}${index}`);
            entries.push({ source: rel, spans: [{ offset: 0, length: 1024 }] });
        }
        const tailRel = withSource(world, 'Arc/tail.md', 'q'.repeat(1100));
        entries.push({ source: tailRel, spans: [{ offset: 0, length: TAIL }] });
        return entries;
    };

    /**
     * ⚠⚠ THE REQUEST REFUSES, AND IT REFUSES FOR THE RIGHT REASON. `PAGE_WRITTEN_LEDGER_FAILED`
     * here IS the defect — a fabricated I/O cause standing in for a bound the caller crossed, over
     * a page that should never have been created.
     */
    const real = vault();
    const result = await stamp(gateFor(real.grant), {
        path: 'Mage/answer.md',
        content: bigContent,
        derivedFrom: build(real)
    }, { appender: forbiddenAppender('an over-size line') });

    refusal(result, 'LINEAGE_LINE_TOO_LARGE', real);
    // ⚠ "NO PAGE", NOT "NOTHING", CORRECTED 2026-09-08 FOR `ST10`/`ST16`'s REASON. The line said
    // `'NOTHING is created'` and the same call mints `.wyrd/scribe.json`; the property the arm
    // owns is that the PAGE does not exist, because the limit is decided before the first PAGE
    // write. The config's mint is `ST2-config-minted`'s claim.
    assert.equal(
        fs.existsSync(path.join(real.grant, 'Mage', 'answer.md')),
        false,
        'NO PAGE is created — the limit is decided before the first page write'
    );
    assert.equal(ledgerText(real), null, 'and no ledger line was written either');
    // ⚠ AND THE MINT IS READ OFF THE RESULT SINCE 2026-09-08, for `ST10`'s reason: the disk says
    // only that a config exists, while `config_created` says THIS call made it. The pair is what
    // makes the exception to "NO PAGE" a stated fact rather than a footnote.
    assert.equal(result.config_created, true,
        'the refusal reports the config this same call minted, so the caller is not left inferring it');
    assert.equal(fs.existsSync(path.join(real.grant, '.wyrd', 'scribe.json')), true,
        'and it really is on disk');

    /**
     * ⚠⚠ THE CONTROL, AND IT IS WHAT KEEPS THE FIXTURE HONEST RATHER THAN MERELY BIG. The identical
     * citation list with a SMALL page must still refuse under the fixed code — the draft carries
     * the widest possible count either way, so the page's size cannot rescue it — but its line, had
     * it been allowed to serialise, would have FIT. That is the asymmetry the whole finding is
     * about, and it is asserted by measuring one tail lower, where the request succeeds.
     *
     * ⚠ ONE BYTE OF SLACK IS ALL IT TAKES, which is the point: the fixture sits exactly one byte
     * inside the boundary rather than comfortably past it. A fixture that refused by a wide margin
     * would refuse under the broken code too.
     */
    let control = null;
    for (let tail = TAIL; tail >= TAIL - 60 && control === null; tail -= 1) {
        const under = vault();
        const underEntries = [];
        for (let index = 0; index < BULK; index += 1) {
            const rel = withSource(under, `Arc/b${index}.md`, `${'q'.repeat(1100)}${index}`);
            underEntries.push({ source: rel, spans: [{ offset: 0, length: 1024 }] });
        }
        const underTail = withSource(under, 'Arc/tail.md', 'q'.repeat(1100));
        underEntries.push({ source: underTail, spans: [{ offset: 0, length: tail }] });
        const underLines = [];
        const underResult = await stamp(gateFor(under.grant), {
            path: 'Mage/answer.md', content: 'small', derivedFrom: underEntries
        }, { appender: capturingAppender(underLines) });
        if (underResult.ok) control = { tail, size: underLines[0].length };
    }
    assert.notEqual(control, null, 'a nearby smaller citation list must fit, or the fixture is simply over-size');

    /**
     * ⚠⚠ THE TWO NUMBERS TOGETHER ARE THE CLAIM. The control fits with room to spare measured in
     * BYTES, and the fixture above — a few bytes of quote larger — refuses. That closeness is what
     * makes the refusal attributable to the page's byte-count WIDTH rather than to the request
     * being large in general, and it is why a fixture chosen for comfort would prove nothing.
     */
    assert.ok(
        control.size <= CEILING && control.size > CEILING - 24,
        `the control must sit hard against the ceiling, got ${control.size}`
    );
    assert.ok(
        TAIL - control.tail <= 24,
        `the refusing fixture must sit close to the fitting one, got a gap of ${TAIL - control.tail} bytes of quote`
    );
});

test('ST28-guaranteed-refusals-read-nothing — the count caps and span shapes refuse with zero source opens', async () => {
    arm('ST28-guaranteed-refusals-read-nothing');
    const world = vault();

    /**
     * ⚠⚠ THE ORACLE LEG, AS `ST5` IS FOR `Arc/`. A request with 65 `derived_from` entries is over a
     * documented cap and can never succeed — the answer is knowable from `derivedFrom.length`
     * alone. It nonetheless used to READ every one of those sources first: every existence probe,
     * every hash, every window loop, and only then `checkCounts`. So an existing in-grant source
     * and a missing one produced different reasons and visibly different timings for a request that
     * was always going to refuse, which is the existence oracle D8 closed at the front door
     * arriving at the side one.
     *
     * ⚠ THE SOURCES REALLY EXIST, WHICH IS WHAT MAKES THE ARM MEAN ANYTHING. Over paths that are
     * absent, "nothing was read" is indistinguishable from "the read failed".
     */
    const many = [];
    for (let index = 0; index < 65; index += 1) {
        const rel = withSource(world, `Arc/c${index}.md`, `content ${index}`);
        assert.equal(fs.existsSync(path.join(world.grant, rel)), true, 'the source must exist');
        many.push({ source: rel, spans: [{ quote: `content ${index}` }] });
    }

    const sink = [];
    const gate = gateFor(world.grant, spy(sink));
    const bootstrap = sink.length; // the gate's own lstat + realpathNative at construction

    const counted = await stamp(gate, {
        path: 'Mage/answer.md', content: 'x', derivedFrom: many
    }, { appender: forbiddenAppender('a count-cap refusal') });
    refusal(counted, 'LINEAGE_LINE_TOO_LARGE', world);
    assert.equal(
        sink.length,
        bootstrap,
        `the count cap is decided before ANY primitive runs: ${JSON.stringify(sink.slice(bootstrap))}`
    );

    // The span cap, same property — 300 spans over one existing source.
    const spanRel = withSource(world, 'Arc/spans.md', Array.from({ length: 300 }, (_, i) => `q${i}q`).join(' '));
    const spanned = await stamp(gate, {
        path: 'Mage/b.md',
        content: 'x',
        derivedFrom: [{ source: spanRel, spans: Array.from({ length: 300 }, (_, i) => ({ quote: `q${i}q` })) }]
    }, { appender: forbiddenAppender('a span-cap refusal') });
    refusal(spanned, 'LINEAGE_LINE_TOO_LARGE', world);
    assert.equal(sink.length, bootstrap, 'the span cap is decided before any primitive runs too');

    /**
     * ⚠⚠ AND THE MALFORMED SPAN, WHICH IS THE SHARPER HALF. `{ }` is refused by `resolveSpan` on
     * SHAPE ALONE — it needs no bytes to know an empty request names no span — but the shape was
     * not consulted until after that entry's source had been read and hashed.
     *
     * ⚠ THE REFUSAL IS THE RESOLVER'S OWN, VERBATIM. Deciding it earlier must not change what the
     * caller is told: a different `reason` or `where` depending on WHEN the fault was noticed is a
     * second vocabulary for one outcome.
     */
    const okRel = withSource(world, 'Arc/fine.md', 'perfectly fine source text');
    for (const [spanRequest, reason, where] of [
        [{}, 'SPAN_INVALID_RANGE', 'request'],
        [{ offset: 0 }, 'SPAN_INVALID_RANGE', 'length'],
        [{ length: 4 }, 'SPAN_INVALID_RANGE', 'offset'],
        [{ offset: 1.5, length: 2 }, 'SPAN_INVALID_RANGE', 'offset'],
        [{ offset: 0, length: 0 }, 'SPAN_INVALID_RANGE', 'length'],
        [{ offset: 0, length: 2, nope: 1 }, 'SPAN_INVALID_RANGE', 'request'],
        [{ quote: '' }, 'SPAN_INVALID_QUOTE', 'quote'],
        [{ quote: '\uD800' }, 'SPAN_INVALID_QUOTE', 'quote']
    ]) {
        const before = sink.length;
        const result = await stamp(gate, {
            path: 'Mage/never.md', content: 'x', derivedFrom: [{ source: okRel, spans: [spanRequest] }]
        }, { appender: forbiddenAppender('a malformed span') });
        assert.equal(result.ok, false, JSON.stringify(result));
        assert.equal(result.reason, reason, `${JSON.stringify(spanRequest)}: ${result.reason}`);
        assert.equal(result.where, where, `${JSON.stringify(spanRequest)}: where=${result.where}`);
        assert.equal(
            sink.length,
            before,
            `${JSON.stringify(spanRequest)} was decided AFTER a read: ${JSON.stringify(sink.slice(before))}`
        );
    }

    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false, 'nothing was created');

    /**
     * ⚠⚠ THE PAIR THAT KEEPS THE PRE-CHECK FROM BEING A REFUSE-EVERYTHING. A span whose fault is a
     * property of the BYTES must still be read and still refuse from the resolver — the pre-check
     * predicts what `resolveSpan` will do without the source, it does not replace it.
     */
    const after = sink.length;
    const needsBytes = await stamp(gate, {
        path: 'Mage/never2.md',
        content: 'x',
        derivedFrom: [{ source: okRel, spans: [{ offset: 0, length: 999_999 }] }]
    }, { appender: forbiddenAppender('an out-of-range span') });
    assert.equal(needsBytes.reason, 'SPAN_INVALID_RANGE');
    assert.equal(needsBytes.where, 'length');
    assert.ok(sink.length > after, 'a fault that needs the bytes still reads the source');

    // And a well-formed request over the same source still succeeds, so a blanket refuser could not
    // have passed any of the above.
    const fine = await stamp(gate, {
        path: 'Mage/fine.md', content: 'x', derivedFrom: [{ source: okRel, spans: [{ quote: 'fine source' }] }]
    }, { appender: capturingAppender([]) });
    assert.equal(fine.ok, true, JSON.stringify(fine));
});

test('ST29-event-id-unique — two writes differ in event_id and in nothing else that should not differ', async () => {
    arm('ST29-event-id-unique');
    const world = vault();
    const rel = withSource(world);
    const lines = [];
    const gate = gateFor(world.grant);

    /**
     * ⚠⚠ THE CLOCK IS PINNED, WHICH IS THE WHOLE CONSTRUCTION. `FIXED_NOW` gives both writes the
     * same `recorded_at`, reproducing the real case the field exists for: write a page, delete it
     * outside this server, write identical content again within the same millisecond. Every other
     * member — page path, digest, sources, spans — is identical by construction, so before
     * `event_id` the two lines were BYTE-IDENTICAL and a ledger holding both could not say whether
     * it had recorded two events or duplicated one.
     */
    const request = {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    };

    const first = await stamp(gate, request, { appender: capturingAppender(lines) });
    assert.equal(first.ok, true, JSON.stringify(first));

    // ⚠ DELETED OUTSIDE THIS SERVER, NOT OVERWRITTEN. Tier A is create-only, so the second write
    // reaches the same path only because the name became free again — which is precisely the
    // sequence that produces two genuine events with identical content.
    fs.rmSync(path.join(world.grant, 'Mage', 'answer.md'));

    const second = await stamp(gate, request, { appender: capturingAppender(lines) });
    assert.equal(second.ok, true, JSON.stringify(second));

    assert.equal(lines.length, 2);
    const a = JSON.parse(lines[0].toString('utf8'));
    const b = JSON.parse(lines[1].toString('utf8'));

    // ⚠ THE LINES ARE NOT IDENTICAL, WHICH IS THE PROPERTY. Asserted on the raw bytes first, so it
    // holds regardless of which member turns out to carry the difference.
    assert.notEqual(lines[0].toString('utf8'), lines[1].toString('utf8'), 'two events must not produce one line');

    assert.notEqual(a.event_id, b.event_id, 'two writes get two event ids');
    for (const id of [a.event_id, b.event_id]) {
        assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/, `not a v4 UUID: ${id}`);
        assert.notEqual(id, FIXED_UUID, 'the event id is minted separately from the vault id');
    }

    // ⚠⚠ AND NOTHING ELSE MOVED. Without this the arm would pass over an implementation that
    // re-randomised the whole record — `event_id` must be the ONLY difference between two writes
    // whose content, sources and clock are identical.
    const stripped = record => { const { event_id, ...rest } = record; return rest; };
    assert.deepEqual(stripped(a), stripped(b), 'everything except event_id is identical across the two writes');

    // The returned record and the appended line agree about the id.
    assert.equal(first.record.event_id, a.event_id);
    assert.equal(second.record.event_id, b.event_id);
});

test('ST30-horizontal-rule-is-not-frontmatter — a rule over prose is prepended to, never spliced', async () => {
    arm('ST30-horizontal-rule-is-not-frontmatter');

    /**
     * ⚠⚠ TWO CASES, AND THEY USED TO FAIL IN OPPOSITE DIRECTIONS. Any first-line `---` was treated
     * as an opening fence, so:
     *
     *   · A DOCUMENT WITH A SECOND RULE inside the 200-line ceiling SUCCEEDED, and the key was
     *     inserted between two horizontal rules — YAML spliced into the middle of the user's prose,
     *     which is the worse half because it looks like it worked.
     *   · A DOCUMENT WITH NO SECOND RULE was refused `FRONTMATTER_INVALID`, telling the user their
     *     frontmatter had no closing fence when they had written no frontmatter at all. An ordinary
     *     Markdown file, permanently unwritable through this server.
     */
    const spliceable = vault({ config: OPTED_IN });
    const prose = '---\nA thought about foundations.\n\nAnother paragraph entirely.\n---\nAnd the rest.\n';
    const linesA = [];
    const a = await stamp(gateFor(spliceable.grant), {
        path: 'Mage/answer.md', content: prose, derivedFrom: []
    }, { appender: capturingAppender(linesA) });
    assert.equal(a.ok, true, JSON.stringify(a));

    const writtenA = fs.readFileSync(path.join(spliceable.grant, 'Mage', 'answer.md'), 'utf8');
    const rowsA = writtenA.split('\n');
    // ⚠ A BLOCK ON TOP, AND THE USER'S DOCUMENT ENTIRELY INTACT BENEATH IT.
    assert.equal(rowsA[0], '---');
    assert.ok(rowsA[1].startsWith('wyrd_lineage: '), rowsA[1]);
    assert.equal(rowsA[2], '---');
    assert.equal(writtenA.slice(writtenA.indexOf('\n', writtenA.indexOf('\n', writtenA.indexOf('\n') + 1) + 1) + 1), prose,
        'the caller\'s document follows the inserted block byte-for-byte');
    // ⚠ AND THE KEY IS NOT INSIDE THE PROSE. The defect put it on the line before the second rule.
    assert.equal(rowsA.indexOf('A thought about foundations.'), 4, 'the prose starts after the inserted block');
    assert.ok(!rowsA[5].includes('wyrd_lineage'), 'no key was spliced into the body');
    assert.equal(writtenA.split('wyrd_lineage:').length - 1, 1, 'exactly one key exists in the document');

    const unclosed = vault({ config: OPTED_IN });
    const linesB = [];
    const b = await stamp(gateFor(unclosed.grant), {
        path: 'Mage/answer.md', content: '---\nJust a rule, then prose, and no second rule.\n', derivedFrom: []
    }, { appender: capturingAppender(linesB) });
    // ⚠ IT SUCCEEDS. This is the ordinary file that used to be refused.
    assert.equal(b.ok, true, JSON.stringify(b));
    const rowsB = fs.readFileSync(path.join(unclosed.grant, 'Mage', 'answer.md'), 'utf8').split('\n');
    assert.equal(rowsB[0], '---');
    assert.ok(rowsB[1].startsWith('wyrd_lineage: '), rowsB[1]);
    assert.equal(rowsB[2], '---');
    assert.equal(rowsB[3], '---', 'the user\'s own rule is still their first line');
    assert.equal(rowsB[4], 'Just a rule, then prose, and no second rule.');

    /**
     * ⚠⚠ THE PAIRS THAT KEEP THE RECOGNISER FROM BEING A REFUSE-EVERYTHING. Real frontmatter must
     * still be INSERTED into, in every shape a mapping block legitimately takes — comments, nested
     * mappings, sequence members, blank lines. A recogniser that only admits `key: value` would
     * quietly start prepending second blocks to documents that already have one.
     */
    for (const [label, content] of [
        ['comments', '---\n# a comment\ntitle: x\n---\nbody\n'],
        ['nested', '---\nmeta:\n  a: 1\n  b: 2\n---\nbody\n'],
        ['sequence', '---\ntags:\n  - one\n  - two\n---\nbody\n'],
        ['blank lines', '---\ntitle: x\n\nauthor: rowan\n---\nbody\n'],
        ['empty block', '---\n---\nbody\n']
    ]) {
        const w = vault({ config: OPTED_IN });
        const r = await stamp(gateFor(w.grant), {
            path: 'Mage/answer.md', content, derivedFrom: []
        }, { appender: capturingAppender([]) });
        assert.equal(r.ok, true, `${label}: ${JSON.stringify(r)}`);
        const text = fs.readFileSync(path.join(w.grant, 'Mage', 'answer.md'), 'utf8');
        // ⚠ INSERTED, NOT PREPENDED — asserted by counting the fences, which a prepend would raise
        // from two to four.
        assert.equal(text.split('\n').filter(row => row === '---').length, 2, `${label}: the block was prepended, not inserted`);
        assert.equal(text.split('wyrd_lineage:').length - 1, 1, `${label}: exactly one key`);
    }
});

test('ST31-crlf-preserved — a CRLF document gets a CRLF key line and stays single-ending', async () => {
    arm('ST31-crlf-preserved');

    /**
     * ⚠⚠ THE INSERTED LINE MUST MATCH THE DOCUMENT'S OWN ENDING. The scan tolerated `\r` so a
     * Windows-authored file was not mistaken for an unclosed block — that half was already right —
     * but the line it INSERTED ended with a lone `\n`, producing a document with mixed endings:
     * git reports a whole-file change on the next normalisation, and some Windows editors render
     * the run as one long line. The old arm asserted the key was found at the right INDEX, which a
     * mixed-ending document satisfies perfectly.
     */
    const world = vault({ config: OPTED_IN });
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content: '---\r\ntitle: x\r\n---\r\nbody\r\n', derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(result.ok, true, JSON.stringify(result));

    // ⚠ READ AS BYTES. Reading as a string and splitting on '\n' is exactly the blindness that let
    // the defect through — the endings are the subject, so they are never normalised away.
    const raw = fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8');
    const rows = raw.split('\n');
    assert.ok(rows[2].startsWith('wyrd_lineage: '), rows[2]);
    assert.ok(rows[2].endsWith('\r'), `the inserted line must carry the document's CRLF: ${JSON.stringify(rows[2].slice(-40))}`);

    // ⚠⚠ THE WHOLE-DOCUMENT PROPERTY, NOT JUST THE ONE LINE. Every LF in the file is preceded by a
    // CR, so the document has ONE ending throughout — which is the claim, and which a per-line
    // check on the inserted row alone would not make.
    const loneLf = [...raw.matchAll(/\n/g)].filter(match => raw[match.index - 1] !== '\r');
    assert.deepEqual(loneLf.map(m => m.index), [], 'a CRLF document must contain no lone LF after stamping');
    assert.equal(raw.split('wyrd_lineage:').length - 1, 1, 'exactly one key');

    // ⚠ THE PAIR: AN LF DOCUMENT MUST NOT ACQUIRE A CR. The fix is "match the document", not
    // "always emit CRLF", and only the pair distinguishes the two.
    const lf = vault({ config: OPTED_IN });
    const lfResult = await stamp(gateFor(lf.grant), {
        path: 'Mage/answer.md', content: '---\ntitle: x\n---\nbody\n', derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(lfResult.ok, true, JSON.stringify(lfResult));
    const lfRaw = fs.readFileSync(path.join(lf.grant, 'Mage', 'answer.md'), 'utf8');
    assert.equal(lfRaw.includes('\r'), false, 'an LF document must not acquire a CR');
    // ⚠ INDEX 2, BECAUSE THIS DOCUMENT HAS REAL FRONTMATTER AND THE KEY IS INSERTED INTO IT — after
    // `---` and `title: x`, before the closing fence. Index 1 is the PREPEND path's position, and
    // asserting it here would pass only if the insert had silently become a prepend.
    assert.equal(lfRaw.split('\n')[1], 'title: x', 'the user\'s own key stays first');
    assert.ok(lfRaw.split('\n')[2].startsWith('wyrd_lineage: '), lfRaw.split('\n')[2]);

    // ⚠ AND THE PREPEND PATH, WHICH COMPOSES ITS BLOCK THROUGH A DIFFERENT BRANCH. A CRLF document
    // with no frontmatter at all is a case the insert-path fix does not reach.
    const crlfPrepend = vault({ config: OPTED_IN });
    const p = await stamp(gateFor(crlfPrepend.grant), {
        path: 'Mage/answer.md', content: 'plain body\r\nsecond line\r\n', derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(p.ok, true, JSON.stringify(p));
    const pRaw = fs.readFileSync(path.join(crlfPrepend.grant, 'Mage', 'answer.md'), 'utf8');
    assert.ok(pRaw.split('\n')[1].startsWith('wyrd_lineage: '), pRaw.split('\n')[1]);
    assert.ok(pRaw.includes('plain body\r\n'), 'the caller\'s own CRLF body is untouched');
});

/**
 * ⚠⚠ THE THREE PREPEND SHAPES, AND THEY ARE THREE SEPARATE `return`s IN `frontmatter.ts` RATHER
 * THAN ONE BEHAVIOUR SEEN THREE WAYS. Each of the four arms below drives all three, because the
 * defect being pinned is precisely a fix applied to one exit and missed at the others — which is
 * how this survived `ST31`, whose prepend leg asserted only that the caller's BODY was untouched
 * and never asked what ending the inserted BLOCK got.
 */
const PREPEND_SHAPES = (eol) => [
    ['plain prose, no frontmatter', `# Title${eol}Some prose.${eol}`],
    ['rules around prose', `---${eol}Just prose here.${eol}---${eol}More.${eol}`],
    ['opening rule, no close', `---${eol}prose that is not a mapping${eol}`]
];

async function prependedRaw(content) {
    const world = vault({ config: OPTED_IN });
    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md', content, derivedFrom: []
    }, { appender: capturingAppender([]) });
    assert.equal(result.ok, true, JSON.stringify(result));
    // ⚠ READ AS BYTES, per ST31: the endings are the subject, so nothing normalises them away.
    return fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8');
}

test('ST33-prepend-crlf-all-three-exits — every prepend exit gives a CRLF document a CRLF block', async () => {
    arm('ST33-prepend-crlf-all-three-exits');
    for (const [label, content] of PREPEND_SHAPES('\r\n')) {
        const raw = await prependedRaw(content);
        // ⚠ THE WHOLE-DOCUMENT PROPERTY. Measured before the fix, each of these three injected
        // exactly THREE lone LFs — the block's two internal separators plus the seam between the
        // closing fence and the user's first line. The seam is the one a partial fix leaves behind.
        const loneLf = [...raw.matchAll(/\n/g)].filter(m => raw[m.index - 1] !== '\r');
        assert.deepEqual(loneLf.map(m => m.index), [], `${label}: a CRLF document must contain no lone LF`);
        assert.ok(raw.startsWith('---\r\n'), `${label}: the opening fence carries CRLF`);
        assert.ok(raw.includes(`---\r\n${content.split('\r\n')[0]}\r\n`), `${label}: the SEAM below the closing fence carries CRLF`);
        assert.ok(raw.endsWith(content), `${label}: the caller's bytes are an exact suffix`);
    }
});

test('ST34-prepend-lf-introduces-no-cr — the same three shapes in LF acquire no CR', async () => {
    arm('ST34-prepend-lf-introduces-no-cr');
    // ⚠ THE PAIR THAT MAKES ST33 A RULE RATHER THAN A DIRECTION. Without this, "always emit CRLF"
    // passes ST33 completely while breaking every LF note in the vault.
    for (const [label, content] of PREPEND_SHAPES('\n')) {
        const raw = await prependedRaw(content);
        assert.equal(raw.includes('\r'), false, `${label}: an LF document must not acquire a CR`);
        assert.ok(raw.endsWith(content), `${label}: the caller's bytes are an exact suffix`);
    }
});

test('ST35-prepend-first-break-wins-on-mixed — an already-mixed document keeps its own bytes', async () => {
    arm('ST35-prepend-first-break-wins-on-mixed');
    /**
     * ⚠⚠ THIS IS THE ARM THAT REJECTS THE ALTERNATIVES. A majority rule, a last-ending rule and a
     * whole-file normalisation all pass ST33 and ST34 and all fail here, in one direction or the
     * other. The rule is the FIRST physical line's ending, because our block touches the document
     * at exactly one seam — above its first line — and that line is the only nearby evidence.
     *
     * ⚠ AND THE DOCUMENT STAYS MIXED. We did not cause it. This module's whole justification for
     * writing into someone else's notes is that the act is minimal; normalising their endings is
     * not, and would be a whole-file diff the user never asked for.
     */
    const firstCrlf = 'a\r\nb\nc\n';
    const rawCrlf = await prependedRaw(firstCrlf);
    assert.ok(rawCrlf.startsWith('---\r\n'), 'first break CRLF -> CRLF block, even though the body is mostly LF');
    assert.ok(rawCrlf.endsWith(firstCrlf), 'every original byte survives, mixed and all');

    const firstLf = 'a\nb\r\nc\r\n';
    const rawLf = await prependedRaw(firstLf);
    assert.ok(rawLf.startsWith('---\n'), 'first break LF -> LF block, even though the body is mostly CRLF');
    assert.equal(rawLf.slice(0, rawLf.length - firstLf.length).includes('\r'), false, 'the inserted block carries no CR');
    assert.ok(rawLf.endsWith(firstLf), 'every original byte survives, mixed and all');
});

test('ST36-prepend-without-evidence-defaults-lf — no break to read means LF, and nothing throws', async () => {
    arm('ST36-prepend-without-evidence-defaults-lf');
    // ⚠ AN ENDING DETECTOR THAT INDEXES OFF THE FRONT OF THE STRING BREAKS HERE RATHER THAN
    // SOMEWHERE VISIBLE: `content[-1]` on an empty document, or a first-line slice on a document
    // that has no first line. Both cases are ordinary — a new note, and a one-line capture.
    for (const [label, content] of [['empty', ''], ['one unterminated line', 'just one line']]) {
        const raw = await prependedRaw(content);
        assert.equal(raw.includes('\r'), false, `${label}: no evidence means LF, never a stray CR`);
        assert.ok(raw.startsWith('---\nwyrd_lineage: '), `${label}: the block is still well-formed`);
        assert.ok(raw.endsWith(content), `${label}: the caller's bytes are an exact suffix`);
    }
});

test('ST37-page-path-is-bounded — the last unbounded field in a bounded line now has a ceiling', async () => {
    arm('ST37-page-path-is-bounded');
    /**
     * ⚠⚠ WHAT THIS PINS. `MAX_LINE_BYTES` bounds the serialised line, and every field that feeds it
     * was bounded EXCEPT the page path: quotes by `QUOTE_BYTE_BUDGET`, sources by `MAX_SOURCES`,
     * spans by `MAX_SPANS`, the digest fixed at 64 hex characters, the byte count by
     * `Number.MAX_SAFE_INTEGER`. So one field could consume the entire budget on its own and
     * starve every other — a line whose citations were well within their limits still refusing,
     * for a reason no bound in the module named.
     *
     * ⚠ THE REFUSAL MUST COME BEFORE ANY WRITE, which is the half that makes the bound worth
     * having rather than merely present. A path bound enforced after the create would produce
     * exactly the orphan page the ceiling exists to prevent.
     */
    const world = vault();
    const rel = withSource(world);

    // ⚠ 4,096 IS ASSERTED, NOT ASSUMED. If the constant moves, this arm must be re-reasoned rather
    // than silently re-tuned — the fixture below is built from the number, so a changed bound with
    // an unchanged arm would test nothing.
    assert.equal(MAX_PAGE_PATH_BYTES, 4_096, 'the fixture is built from this bound');

    // One byte over, and comfortably under `MAX_LINE_BYTES` — so ONLY the path bound can refuse
    // this. Without it the line serialises well within its ceiling and the page is created.
    // ⚠ THE FILLER IS COMPUTED FROM THE FIXED PARTS, never hand-counted: the first version of this
    // arm hardcoded the offset and was wrong by two, which the assertion below caught.
    const PREFIX = 'Mage/';
    const SUFFIX = '/answer.md';
    const filler = MAX_PAGE_PATH_BYTES + 1 - PREFIX.length - SUFFIX.length;
    const overLong = `${PREFIX}${'d'.repeat(filler)}${SUFFIX}`;
    assert.equal(Buffer.byteLength(overLong, 'utf8'), MAX_PAGE_PATH_BYTES + 1, 'exactly one byte over');
    assert.ok(Buffer.byteLength(overLong, 'utf8') < 65_536, 'and far under the LINE ceiling, so the path bound is what fires');

    const result = await stamp(gateFor(world.grant), {
        path: overLong,
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: forbiddenAppender('an over-long page path') });

    refusal(result, 'LINEAGE_LINE_TOO_LARGE', world);
    assert.match(result.detail, /page path is \d+ bytes/, 'the detail names the PATH, not the line — the two bounds are distinguishable');
    assert.equal(ledgerText(world), null, 'nothing was appended');

    /**
     * ⚠⚠ THE CONTROL, AND WITHOUT IT THIS ARM WOULD PASS OVER A SCRIBE THAT REFUSES EVERY LONG
     * PATH. A path just under the bound must SUCCEED — that is what separates a bound from a
     * blanket refusal, and it is the assertion that would redden if someone "tightened" the
     * ceiling.
     *
     * ⚠⚠ THE CONTROL IS NOT AT THE BOUND EXACTLY, AND THE REASON IS A MEASUREMENT RATHER THAN A
     * CONVENIENCE. Windows caps a real path far below `MAX_PAGE_PATH_BYTES`, so a 4,096-byte path
     * cannot be CREATED on this machine at all — the fence refuses `MISSING` at the parent walk,
     * which is a true refusal about the filesystem and says nothing about the Scribe's bound. A
     * control that reddens for the OS's reason would certify a guard nobody has. So the control
     * uses a path the machine can really hold, and the ARITHMETIC above is what pins the bound's
     * exact position.
     */
    const nested = `${PREFIX}${'d'.repeat(60)}${SUFFIX}`;
    assert.ok(Buffer.byteLength(nested, 'utf8') < MAX_PAGE_PATH_BYTES, 'the control sits under the bound');

    const under = vault();
    const underRel = withSource(under);
    fs.mkdirSync(path.join(under.grant, PREFIX, 'd'.repeat(60)), { recursive: true });
    const gate = gateFor(under.grant);
    const ok = await stamp(gate, {
        path: nested,
        content: 'the answer',
        derivedFrom: [{ source: underRel, spans: [{ quote: 'noon' }] }]
    }, { appender: gateAppender(gate) });

    assert.equal(ok.ok, true, `under the bound, the stamp succeeds: ${JSON.stringify(ok)}`);
});

test('ST38-ledger-failed-carries-the-real-cause — a cause is passed through, never fabricated', async () => {
    arm('ST38-ledger-failed-carries-the-real-cause');
    /**
     * ⚠⚠ THE DEFECT, AND IT IS A TYPE-SHAPED ONE. `LedgerFailed.cause` was typed `FenceRefusal`,
     * whose `reason` is the fence's own closed union. The post-create size re-check fires on a
     * SCRIBE-side fault — a line over `MAX_LINE_BYTES` — and had nothing in that union it could
     * honestly use, so it fabricated `IO_ERROR`. A caller who crossed a documented bound was told
     * a filesystem error had lost their provenance: a different problem, with a different repair,
     * and one they would have gone looking for on the disk.
     *
     * **A too-narrow cause type does not prevent the wrong cause; it compels one.** The fix widened
     * `cause` to `FenceRefusal | ScribeRefusal` and passes the real refusal through.
     *
     * ⚠⚠ THIS ARM WAS REPLACED AND RENAMED ON 2026-09-08, NOT RE-EXPECTED, AND THE REASON IS A
     * FINDING RATHER THAN A REPAIR. Until that day it was
     * `ST38-post-create-size-failure-names-its-real-cause`, and it reached the post-create
     * `checkLineSize` by overriding `realpathNative` for the page's parent so the CANONICAL path
     * was 70,000 characters longer than the request — the real-world shape being an in-grant
     * junction. Option C's part 1 refuses exactly that: `resolveNew` now compares the resolved
     * parent against the spelled one and returns `PARENT_ALIAS` before the leaf is even joined, so
     * the old fixture never reached `openExclusive` and its own first assertion (`created === true`)
     * failed. Flipping the expectation would have left an arm that proved nothing about the branch
     * it names, so the arm's claim was rewritten and its id with it.
     *
     * ⚠⚠ AND THE POST-CREATE SITE IS MUCH HARDER TO REACH THROUGH THE RESOLUTION PATH, BUT IT IS
     * NOT UNREACHABLE — AND THIS COMMENT CLAIMED IT WAS UNTIL 2026-09-08. The retired sentence
     * argued that `parentActual` must FOLD-EQUAL `parentSpelled`, "so the canonical path can differ
     * from the request only in CASE, which changes no byte count." **The last clause is false.**
     * JavaScript's `toLowerCase()` maps the Kelvin sign `K` (U+212A, THREE UTF-8 bytes) to an
     * ordinary `k` (ONE byte), and the Ohm and Angstrom signs behave the same way. So two spellings
     * can fold equal and differ in WIDTH, `_parentIsAliased` accepts the pair by design, and
     * `created.rel` at `stamp.ts` can come back longer than the pre-create draft — which makes the
     * post-create size branch REACHABLE.
     *
     * ⚠ ON A CASE-FOLDING VOLUME LIKE THIS ONE THE PAIR CANNOT ARISE FROM THE FILESYSTEM: Windows
     * does not hand back a Kelvin-sign spelling for a `k` directory. The branch is reachable only
     * through a fold-equal alias of different byte width, which this volume cannot produce — so
     * `ST41-post-create-size-branch-is-reachable` reaches it deterministically by injecting
     * `realpathNative`, and that arm rather than this one is what holds the branch.
     *
     * ⚠ WHAT THE ARM ASSERTS INSTEAD IS THE PROPERTY THE TYPE WIDENING BOUGHT, at the one site that
     * still reaches `ledgerFailed`: the appender's refusal arrives in `cause` UNCHANGED — reason
     * AND detail — rather than being translated into something else the union happens to hold. The
     * detail comparison is what catches a fabricating site even when the reason coincides, and it
     * is why the fixture's detail is a sentence nothing else in this file could produce.
     *
     * ⚠⚠ WHAT THIS ARM DOES **NOT** CLAIM. The orphan page is still created — this outcome is
     * `PAGE_WRITTEN_LEDGER_FAILED` and the page IS on disk. B was ruled as the honest-refusal fix,
     * not as a fix for the orphan, and option C does not close it either: parts 1-2 refuse the
     * LEDGER APPEND after the page exists, deliberately (D4 — a ledger line for a page that may not
     * exist is a FALSE provenance claim, worse than a missing one). The arm asserts the page's
     * PRESENCE on purpose, so nobody reads a green suite as meaning the orphan is gone.
     */
    const world = vault();
    const rel = withSource(world);

    // ⚠ A DISTINCTIVE DETAIL, so the assertion below cannot pass on a coincidence of reason alone.
    const CAUSE_DETAIL = 'ST38: the appender refused, and this exact sentence must survive';

    const result = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'the answer',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: refusingAppender(CAUSE_DETAIL) });

    assert.equal(result.ok, false, JSON.stringify(result));
    assert.equal(result.reason, 'PAGE_WRITTEN_LEDGER_FAILED');

    // ⚠⚠ THE WHOLE POINT: the cause is the refusal that actually occurred, passed through.
    assert.equal(result.cause.reason, 'IO_ERROR', 'the appender refused IO_ERROR and that is what the cause says');
    assert.equal(result.cause.detail, CAUSE_DETAIL,
        'the cause carries the refusal VERBATIM — a re-wrapped or summarised detail is the fabrication this arm exists to catch');

    // ⚠ AND THE CREATED PAGE TRAVELS WITH IT, because a caller told their provenance was lost needs
    // to know what exists on disk.
    assert.equal(result.created.rel, path.join('Mage', 'answer.md'));

    assertNoOutsideNames(result.detail, world);
    seenRefusals.push({ reason: result.reason, detail: result.detail, world });

    assert.equal(
        fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')),
        true,
        'the orphan page IS still on disk — B made the refusal honest, and C did not close the orphan either'
    );
    assert.equal(ledgerText(world), null, 'and no lineage line was written for it');
});

test('ST39-config-parent-alias-refused — an aliased .wyrd refuses before any page exists', async () => {
    arm('ST39-config-parent-alias-refused');
    /**
     * ⚠⚠ THE SECOND MEASURED ROUTE INTO `Arc/`, AND IT NEEDS NO PAGE-PATH TRICKERY AT ALL.
     * `LINEAGE_PATH` is the fixed `.wyrd/lineage.jsonl`, so making `.wyrd` a junction to `Arc`
     * turns every ordinary stamp into a write inside the user's immutable provenance layer.
     * Measured 2026-09-04 against the shipped build: `mklink /J .wyrd Arc` (no privilege needed),
     * then an ordinary `Mage/answer.md` stamp returned `stamp_ok: true` with `lineage.jsonl`
     * written INTO `Arc/`.
     *
     * ⚠⚠ PARTS 1-2 ALONE WOULD LEAVE AN ORPHAN, WHICH IS WHY PART 3 EXISTS. They refuse the LEDGER
     * APPEND, and that happens AFTER the page is created — deliberately, because a ledger line for
     * a page that may not exist is a FALSE provenance claim and D4 names that as the failure that
     * matters. So the `Arc/` write would be traded for an orphaned page. Part 3 hoists
     * `loadConfig`'s exclusive-create ahead of the config read, so the refusal arrives at step 4 of
     * the stamp path — before any source is read and long before anything is written.
     *
     * ⚠ A JUNCTION NEEDS NO WINDOWS PRIVILEGE, which is what keeps this arm portable alongside
     * every other fixture in this file.
     */
    const world = vault({ wyrd: false });
    const rel = withSource(world);
    fs.symlinkSync(path.join(world.grant, 'Arc'), path.join(world.grant, '.wyrd'), 'junction');

    /**
     * ⚠⚠ THE ORDERING CLAIM IS PINNED WITH THE PRIMITIVE SPY, NOT ASSERTED IN PROSE — the same
     * mechanism `ST5-arc-immutable-before-sources` and `ST28` use. Until 2026-09-08 this arm SAID
     * the refusal arrives "before any source is read" and measured nothing of the kind: a
     * `loadConfig` that refused after the source loop would have satisfied every assertion here,
     * because the loop leaves no trace on disk. What makes the claim falsifiable is watching the
     * primitives.
     *
     * ⚠ THE SOURCE IS AN EXISTING, READABLE IN-GRANT FILE. A source that could not be read would
     * make "no read happened" true for the wrong reason.
     *
     * ⚠ THE BASELINE IS TAKEN AFTER `createFsGate`, for `ST5`'s reason: the bootstrap seam runs
     * `lstat` and `realpathNative` on the grant at construction time, so an empty-sink assertion
     * would fail on the gate's own construction and say nothing about the ordering under test.
     */
    const sink = [];
    const gate = gateFor(world.grant, spy(sink));
    const bootstrap = sink.length;

    let mints = 0;
    const result = await stamp(gate, {
        path: 'Mage/answer.md',
        content: 'the answer\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, {
        appender: forbiddenAppender('a stamp into an aliased .wyrd'),
        newUuid: () => { mints += 1; return FIXED_UUID; }
    });

    // ⚠⚠ ZERO SOURCE READS. `open` is the primitive `readSource` reaches the bytes through, so an
    // `open` naming the source file is the signature of a source that was read. The config load's
    // own primitives are allowed and expected — this asserts what step 5 did, not that step 4 was
    // silent.
    const sourceOpens = sink.slice(bootstrap).filter(
        entry => entry.name === 'open' && String(entry.argument).includes('interview.md')
    );
    assert.deepEqual(sourceOpens, [],
        `the refusal arrives BEFORE any source is read, and a source was opened: ${JSON.stringify(sourceOpens)}`);

    // ⚠ THE FENCE'S OWN REASON, PASSED THROUGH UNWRAPPED. `PARENT_ALIAS` is a containment reason
    // like `MISSING` or `EXISTS`; wrapping it in a `ScribeReason` would be a second vocabulary for
    // one containment implementation, which is what D8's pass-through rule exists to prevent.
    refusal(result, 'PARENT_ALIAS', world);
    assert.equal(result.retained, null, 'nothing was opened on the config path');
    assert.equal(mints, 1, 'exactly one speculative mint, and it bought the refusal');
    // ⚠⚠ `retained: null` AND `config_created` ANSWER DIFFERENT QUESTIONS, AND THIS ARM IS WHERE THE
    // DIFFERENCE IS SHARPEST. `retained` is the fence's word about ONE call's target — here the
    // CONFIG target, because this refusal came from step 4's create. `config_created` answers only
    // whether this invocation MINTED THE CONFIG. It is NOT a summary of whether the vault changed at
    // all, and reading it as one is the mistake to avoid: the second stamp at the end of this same
    // arm reports `config_created: false` while creating a page AND a ledger line. Here the honest
    // answer to both questions happens to be "no", and the disk assertions below are what prove the
    // vault was left alone — this outcome is a fence PASS-THROUGH, so it carries no `config_created`
    // field of its own (see `ConfigCreated` in `stamp.ts`). Pinned as an assertion so a later change
    // that starts stamping the field on pass-throughs has to come here and say so.
    assert.equal(result.config_created, undefined,
        'the fence refusal is passed through unwrapped, so it carries no outer summary — the absences below are the proof');

    // ⚠⚠ THE ASSERTIONS THAT MATTER ARE THE ABSENCES, and there are three of them. No config in
    // `Arc/`, no page anywhere, and no ledger line — a refusal returned after any of those had
    // landed would satisfy the reason check above and still be the defect.
    assert.equal(fs.existsSync(path.join(world.grant, 'Arc', 'scribe.json')), false,
        '⚠ THE CONFIG WAS WRITTEN INTO THE PROTECTED DIRECTORY AND THE REFUSAL CAME AFTERWARDS');
    assert.equal(fs.existsSync(path.join(world.grant, 'Arc', 'lineage.jsonl')), false,
        '⚠ THE LEDGER WAS WRITTEN INTO THE PROTECTED DIRECTORY');
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'answer.md')), false,
        '⚠ THE PAGE WAS CREATED AND ORPHANED — that is the outcome part 3 exists to prevent');
    assert.deepEqual(fs.readdirSync(path.join(world.grant, 'Arc')).sort(), ['interview.md'],
        'the protected directory holds exactly what the fixture put there');

    /**
     * ⚠⚠ THE SECOND WORLD IS THE ORDERING CLAIM, AND IT IS THE HALF A READ-FIRST `loadConfig`
     * FAILS. `Arc/scribe.json` ALREADY EXISTS here, so a read-first load would open it happily
     * through the junction, validate it, proceed to create the page, and refuse only at the ledger
     * append — leaving the orphan. The create-first order reaches `PARENT_ALIAS` ahead of `EXISTS`
     * because `resolveNew` compares the parent BEFORE it probes the leaf, so an existing config
     * cannot hide the alias.
     */
    const occupied = vault({ wyrd: false });
    const occupiedRel = withSource(occupied);
    fs.writeFileSync(path.join(occupied.grant, 'Arc', 'scribe.json'), OPTED_IN);
    fs.symlinkSync(path.join(occupied.grant, 'Arc'), path.join(occupied.grant, '.wyrd'), 'junction');

    const hidden = await stamp(gateFor(occupied.grant), {
        path: 'Mage/answer.md',
        content: 'the answer\n',
        derivedFrom: [{ source: occupiedRel, spans: [{ quote: 'noon' }] }]
    }, { appender: forbiddenAppender('a stamp into an aliased .wyrd holding a valid config') });

    refusal(hidden, 'PARENT_ALIAS', occupied);
    assert.equal(fs.existsSync(path.join(occupied.grant, 'Mage', 'answer.md')), false,
        '⚠ AN EXISTING CONFIG HID THE ALIAS AND THE PAGE WAS ORPHANED');
    assert.equal(
        fs.readFileSync(path.join(occupied.grant, 'Arc', 'scribe.json'), 'utf8'), OPTED_IN,
        'and the existing config is byte-identical afterwards'
    );

    /**
     * ⚠ THE POSITIVE CONTROL, or the arm proves only "a vault with a junction refuses". A REAL
     * `.wyrd/` directory beside a real `Arc/` must still stamp, mint its config and write its
     * ledger — which is the same vault shape, differing only in whether `.wyrd` is a directory or
     * a link to one.
     */
    const ordinary = vault();
    const ordinaryRel = withSource(ordinary);
    const lines = [];
    const ok = await stamp(gateFor(ordinary.grant), {
        path: 'Mage/answer.md',
        content: 'the answer\n',
        derivedFrom: [{ source: ordinaryRel, spans: [{ quote: 'noon' }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(lines.length, 1, 'the ordinary vault records its one lineage line');
    assert.equal(fs.existsSync(path.join(ordinary.grant, '.wyrd', 'scribe.json')), true,
        'and its config was minted in the real .wyrd/, not in Arc/');
    assert.equal(fs.existsSync(path.join(ordinary.grant, 'Arc', 'scribe.json')), false);
    // ⚠ THE SUCCESS SHAPE CARRIES THE SUMMARY TOO, AND THAT IS THE POINT OF PUTTING IT ON BOTH. A
    // field present only on refusals would answer the question exactly where a caller is least
    // likely to ask it. This vault had no config, so the successful stamp minted one and says so.
    assert.equal(ok.config_created, true, 'a successful stamp against a fresh vault reports the mint it performed');

    // ⚠ AND THE SECOND STAMP INTO THE SAME VAULT REPORTS `false` — the discriminating half. Without
    // it, a field hard-wired to `true` would satisfy every assertion above.
    const again = await stamp(gateFor(ordinary.grant), {
        path: 'Mage/second.md',
        content: 'the second answer\n',
        derivedFrom: [{ source: ordinaryRel, spans: [{ quote: 'noon' }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(again.ok, true, JSON.stringify(again));
    assert.equal(again.config_created, false,
        'the config already existed, so this invocation minted nothing and reports exactly that');
});

test('ST40-planted-page-refused — the measured Arc/ escape, driven end-to-end through writePage', async () => {
    arm('ST40-planted-page-refused');
    /**
     * ⚠⚠ THE EXACT REPRODUCTION, NOT A MODEL OF IT. Measured 2026-09-04 against the shipped build
     * and recorded at `7c2d096`: `mklink /J Notes Arc` inside a granted vault — needing no
     * privilege — then `writePage({path:'Notes/planted.md'})` returned **`ok: true`** and the file
     * landed at `vault/Arc/planted.md`. `Arc/` is the user's immutable provenance layer; every
     * containment predicate the fence owns said yes, because `Notes` resolves INSIDE the grant.
     *
     * ⚠ THIS NOTE SAID "D7 SAYS NO WYRD WRITE PATH MAY WRITE INTO IT" UNTIL 2026-09-08, WHICH IS
     * MORE THAN THE CODE KEEPS. The guarantee as ruled is narrower and is the one this arm actually
     * measures: `Arc/` is never written through a DIRECT SPELLING or a STATICALLY RESOLVABLE ALIAS
     * below the grant root — the Scribe's lexical screen catches the first, the fence's
     * `PARENT_ALIAS` the second. Three concurrent-writer races stay OPEN and named in the fence (a
     * dangling reparse leaf followed between probe and create, its twin on the append create branch,
     * and a post-check rename), and an ALIASED GRANT ROOT is adopted as canonical by the fence on
     * purpose (`A28`), so the claim starts one level below it. The escape below is an ALIAS, which
     * is inside the guarantee — which is why it must refuse.
     *
     * ⚠ `ST5-arc-immutable-before-sources` CANNOT CATCH THIS AND THAT IS THE WHOLE POINT. The
     * Scribe's `Arc/` screen is LEXICAL — it reads the request's own first segment — and the
     * request here says `Notes`. A screen on the spelling cannot see where the spelling leads, so
     * the guard has to live where the resolution happens, in the fence.
     *
     * ⚠ THE FENCE'S REASON REACHES THE CALLER UNWRAPPED, and it is `PARENT_ALIAS` rather than
     * `ARC_IMMUTABLE`: the fence knows nothing about `Arc/`, and the property it enforces is the
     * general one — a write goes where it was SPELLED. Translating it into the Scribe's doctrine
     * reason would claim a check the fence did not perform.
     */
    const world = vault();
    const rel = withSource(world);
    fs.symlinkSync(path.join(world.grant, 'Arc'), path.join(world.grant, 'Notes'), 'junction');

    const before = fs.readdirSync(path.join(world.grant, 'Arc')).sort();

    const result = await stamp(gateFor(world.grant), {
        path: 'Notes/planted.md',
        content: 'MUST NOT LAND\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: forbiddenAppender('a page planted through an aliased parent') });

    refusal(result, 'PARENT_ALIAS', world);
    assert.equal(result.retained, null, 'nothing was opened on the page path');
    // ⚠ THE **D8 EXCLUSION** — a fence refusal passed through unchanged, which is the one shape the
    // rule at `WritePageResult` exempts, and the same pin `ST39` carries for the same reason. Here
    // the config was minted at step 4 before the page refused at step 6, so the absence of the field
    // is a real cost and not a technicality; see `ConfigCreated` in `stamp.ts`.
    assert.equal(result.config_created, undefined,
        'the fence refusal is the D8 exclusion: unwrapped, carrying no outer summary, even though step 4 minted the config');
    assert.equal(fs.existsSync(path.join(world.grant, '.wyrd', 'scribe.json')), true,
        'and the mint really happened — which is exactly what the refusal above cannot tell the caller');

    // ⚠⚠ THE ASSERTION THE 2026-09-04 MEASUREMENT FAILED: the planted file must not exist.
    assert.equal(fs.existsSync(path.join(world.grant, 'Arc', 'planted.md')), false,
        '⚠ THE PAGE LANDED IN Arc/ — this is the reproduced escape, unfixed');
    assert.deepEqual(fs.readdirSync(path.join(world.grant, 'Arc')).sort(), before,
        'and Arc/ is otherwise unchanged');
    assert.equal(ledgerText(world), null, 'no lineage line was written for a page that does not exist');

    /**
     * ⚠⚠ THE DETAIL MUST NOT NAME WHERE THE ALIAS POINTS. The refusal reports the caller's own
     * spelling (`Notes`), never the canonical `parent.rel` (`Arc`) — the fence's comment at the
     * comparison states this as a legibility rule, and this is the assertion that makes it one.
     * Echoing the target would tell a caller who probed with a junction what the alias resolves to,
     * which is a fact about the vault's shape they did not have before the probe.
     *
     * ⚠⚠ COMPARED CASE-FOLDED SINCE 2026-09-08, AND THE CASE-SENSITIVE VERSION WAS A HOLE RATHER
     * THAN A STYLE CHOICE. This host's filesystem folds case, so the fence can legitimately hand
     * back `arc` or `ARC` for the same directory — and `includes('Arc')` passes over every spelling
     * but one. A check that only catches the polite spelling of a leak is not a check. The helper
     * folds BOTH sides so neither the detail's casing nor the target's decides the answer.
     */
    const namesTarget = (detail, target) => detail.toLowerCase().includes(target.toLowerCase());
    assert.ok(!namesTarget(result.detail, 'Arc'),
        `the refusal must not name the alias TARGET: ${JSON.stringify(result.detail)}`);
    assert.ok(namesTarget(result.detail, 'Notes'),
        `and it must name the spelling the caller wrote: ${JSON.stringify(result.detail)}`);

    /**
     * ⚠⚠ A DEEPER ANCESTOR, NOT JUST THE IMMEDIATE PARENT. `Notes -> Arc` with a request for
     * `Notes/sub/x.md` puts the alias one level ABOVE the write's own parent, so the comparison has
     * to catch it through the resolved walk rather than at the final segment. A check that only
     * compared the last component would pass this and land the page in `Arc/sub/`.
     */
    fs.mkdirSync(path.join(world.grant, 'Arc', 'sub'), { recursive: true });
    const deep = await stamp(gateFor(world.grant), {
        path: 'Notes/sub/x.md',
        content: 'MUST NOT LAND EITHER\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: forbiddenAppender('a page planted through a deeper aliased ancestor') });

    refusal(deep, 'PARENT_ALIAS', world);
    assert.equal(fs.existsSync(path.join(world.grant, 'Arc', 'sub', 'x.md')), false,
        '⚠ A DEEPER-ANCESTOR ALIAS LANDED THE PAGE IN THE PROTECTED DIRECTORY');
    // ⚠ THE CHECK APPLIES ON EVERY REFUSING LEG, not only the first — a leak on the deeper leg is
    // the same disclosure, and an arm that checks one leg certifies the property for one shape.
    assert.ok(!namesTarget(deep.detail, 'Arc'),
        `the deeper refusal must not name the alias TARGET either: ${JSON.stringify(deep.detail)}`);
    assert.ok(namesTarget(deep.detail, 'Notes'),
        `and it must name the caller's own spelling too: ${JSON.stringify(deep.detail)}`);

    // ⚠ THE POSITIVE CONTROL: the same vault, the same source, a directly-spelled page — must stamp.
    // Without it the arm proves only that this vault refuses everything.
    const lines = [];
    const ok = await stamp(gateFor(world.grant), {
        path: 'Mage/answer.md',
        content: 'the answer\n',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }, { appender: capturingAppender(lines) });
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.created.rel, path.join('Mage', 'answer.md'));
    assert.equal(lines.length, 1);
});

test('ST41-post-create-size-branch-is-reachable — a fold-equal alias of different byte width reaches it', async () => {
    arm('ST41-post-create-size-branch-is-reachable');
    /**
     * ⚠⚠ THIS ARM EXISTS BECAUSE `ST38`'s REPLACEMENT CARRIED A FALSE CLAIM, AND THE CLAIM IS THE
     * FINDING. When option C's part 1 landed, `ST38` was rewritten and its note argued that the
     * post-create `checkLineSize` in `stamp.ts` had become UNREACHABLE: `parentActual` must
     * fold-equal `parentSpelled`, so — the argument went — the canonical path can differ from the
     * request "only in CASE, which changes no byte count".
     *
     * **The last clause is false.** JavaScript's `toLowerCase()` maps the KELVIN SIGN `U+212A`
     * (three UTF-8 bytes) to an ordinary `k` (one byte); the Ohm sign `U+2126` and the Angstrom
     * sign `U+212B` do the same. `_parentIsAliased` compares folded, so a parent spelled with
     * Kelvin signs and one spelled with `k`s are ACCEPTED AS THE SAME DIRECTORY — which is the
     * documented accepted cost of case folding, stated at `PARENT_ALIAS`'s declaration and at
     * `_parentIsAliased` itself. The two spellings differ by TWO BYTES PER CHARACTER, so
     * `created.rel` can be materially longer than the path the draft was sized against, and the
     * post-create branch fires.
     *
     * ⚠⚠ WHY THE INJECTION IS THE FIXTURE AND NOT A SHORTCUT. This volume FOLDS CASE, and Windows
     * will not hand back a Kelvin-sign spelling for a directory created with `k`s — so the shape
     * cannot be built out of real directories here. It is reachable on a case-SENSITIVE volume,
     * where the two names are genuinely different directories that fold equal. Injecting
     * `realpathNative` reproduces exactly the value such a volume would return and nothing else:
     * every other primitive maps the wide spelling back to the real directory, so the FILESYSTEM
     * behaves normally and only the arbitration's answer is substituted. The alternative — a
     * case-sensitive-volume arm — cannot run on this machine and would be dead code.
     *
     * ⚠ THE FIXTURE IS SIZED SO THE DRAFT PASSES AND THE REAL LINE DOES NOT, which is the whole
     * point: a request that refused at the DRAFT would never create a page and would exercise
     * `ST27`'s branch instead. Measured 2026-09-08 by driving this fixture through `writePage` at
     * each tail and reading the EXACT SERIALISATION's outcome — never by arithmetic over the
     * ceiling, which is how the previous band got written:
     *
     *     tail <= 287     both fit — the stamp SUCCEEDS
     *     tail 288-673    draft fits, real line does NOT  ← the branch under test
     *     tail >= 674     the draft itself is over the ceiling — `ST27`'s branch, not this one
     *
     * ⚠⚠ THIS BAND READ `286-675` UNTIL THE RE-MEASUREMENT, AND BOTH EDGES WERE WRONG BY TWO. The
     * stated edges were never driven; the true ones are: 287 accepts (final line exactly 65,536),
     * 288 refuses (65,537), 673 still reaches the branch, 674 refuses at the draft. A band nobody
     * ran is a description rather than a measurement, which is why the controls below now sit ON the
     * true edges instead of comfortably outside a stated one.
     *
     * `480` sits in the middle of that band. The band is wide because the widening is 400 bytes
     * (200 characters at two extra bytes each), unlike `ST27`'s four-byte band — so this fixture
     * needs no tuning to stay inside it, and the controls below assert both edges anyway.
     */
    const KELVIN = 'K';
    const WIDTH = 200;
    const PLAIN = 'k'.repeat(WIDTH);
    const WIDE = KELVIN.repeat(WIDTH);

    // ⚠ THE ARM ASSERTS ITS OWN PREMISE. If a future runtime stops folding these equal, or stops
    // changing their width, this fixture proves nothing and must say so rather than going green.
    assert.equal(PLAIN.toLowerCase(), WIDE.toLowerCase(), 'the two spellings must fold EQUAL');
    assert.equal(Buffer.byteLength(PLAIN), WIDTH, 'the plain spelling is one byte per character');
    assert.equal(Buffer.byteLength(WIDE), WIDTH * 3, 'and the Kelvin spelling is three');

    const TAIL = 480;

    /**
     * The gate, with ONE substituted answer.
     *
     * ⚠ `unwide` IS APPLIED TO EVERY PATH-TAKING PRIMITIVE, not only to the one being substituted.
     * Once `realpathNative` answers with the wide spelling, the fence carries that spelling forward
     * into `lstat` and `openExclusive` — so without the mapping those calls would fail ENOENT and
     * the arm would refuse for a reason that has nothing to do with the branch under test.
     */
    const build = () => {
        const world = vault();
        const realParent = path.join(world.grant, PLAIN);
        const fakeParent = path.join(world.grant, WIDE);
        fs.mkdirSync(realParent, { recursive: true });
        const unwide = target => String(target).split(WIDE).join(PLAIN);
        const primitives = spy([], {
            open: (t, f) => fs.openSync(unwide(t), f),
            lstat: t => fs.lstatSync(unwide(t)),
            readlink: t => fs.readlinkSync(unwide(t), 'utf8'),
            readdir: t => fs.readdirSync(unwide(t), { withFileTypes: true }),
            openExclusive: t => fs.openSync(unwide(t), 'wx'),
            // ⚠⚠ THE ONE SUBSTITUTION. The real filesystem is asked first and its answer is
            // replaced ONLY for the page's parent — every other resolution, the sources and the
            // config included, gets the truth.
            realpathNative: t => {
                const real = fs.realpathSync.native(unwide(t));
                return real === realParent ? fakeParent : real;
            }
        });
        return { world, realParent, primitives };
    };

    // The citation list, borrowed in shape from `ST27`: bulk sources plus one tunable tail.
    const cite = (world, tail) => {
        const entries = [];
        for (let index = 0; index < 44; index += 1) {
            const rel = withSource(world, `Arc/k${index}.md`, `${'q'.repeat(1100)}${index}`);
            entries.push({ source: rel, spans: [{ offset: 0, length: 1024 }] });
        }
        entries.push({ source: withSource(world, 'Arc/ktail.md', 'q'.repeat(1100)), spans: [{ offset: 0, length: tail }] });
        return entries;
    };

    const { world, realParent, primitives } = build();
    const lines = [];
    const result = await stamp(gateFor(world.grant, primitives), {
        path: `${PLAIN}/page.md`,
        content: 'the answer',
        derivedFrom: cite(world, TAIL)
    }, { appender: capturingAppender(lines) });

    // ⚠⚠ THE BRANCH. `PAGE_WRITTEN_LEDGER_FAILED` whose cause is the Scribe's own
    // `LINEAGE_LINE_TOO_LARGE` — the exact outcome `ST38`'s widened `cause` type made expressible,
    // now driven by the site that fires on a Scribe-side fault AFTER the page exists.
    assert.equal(result.ok, false, JSON.stringify(result).slice(0, 400));
    assert.equal(result.reason, 'PAGE_WRITTEN_LEDGER_FAILED',
        `expected the post-create outcome, got ${result.reason}: ${result.detail}`);
    assert.equal(result.cause.reason, 'LINEAGE_LINE_TOO_LARGE',
        'the cause is the Scribe\'s own refusal, not a fabricated fence reason');

    // ⚠ THE CANONICAL PATH REALLY IS WIDER THAN THE REQUEST — the mechanism, asserted rather than
    // assumed. Without this the arm could pass on a line that was over the ceiling for some other
    // reason entirely.
    assert.equal(
        Buffer.byteLength(result.created.rel),
        Buffer.byteLength(path.join(PLAIN, 'page.md')) + WIDTH * 2,
        'created.rel carries the byte-wider canonical spelling, two extra bytes per character'
    );

    // ⚠⚠ THE PAGE IS PRESENT, ASSERTED ON PURPOSE. This branch fires AFTER the create, so the
    // orphan is the outcome — exactly as `ST38` states for the appender site. A green suite must
    // never be read as meaning the orphan is closed; option C did not close it.
    assert.equal(fs.existsSync(path.join(realParent, 'page.md')), true,
        'the orphan page IS on disk — this branch fires after the create, and nothing rolls back');
    assert.equal(lines.length, 0, 'and NO ledger line was appended for it');
    assert.equal(ledgerText(world), null);

    /**
     * ⚠⚠ THE TWO CONTROLS SIT **ON** THE BAND'S EDGES, NOT COMFORTABLY OUTSIDE THEM, AND THE MOVE
     * IS THE POINT RATHER THAN A TIGHTENING. They were `200` and `800` — a couple of hundred bytes
     * clear of a band that was itself never driven — so the pair proved only "small succeeds, large
     * refuses at the draft", which is true of any ceiling anywhere and says nothing about WHERE this
     * one sits. Sitting one byte outside each true edge makes the band ASSERTED: `287` and `674` are
     * the first tails on either side that leave the branch, so a change of one byte in the record's
     * serialisation reddens this arm instead of sliding quietly inside the old slack.
     *
     * Without the pair the arm certifies a branch it never pinned: the low control proves the
     * fixture is not simply too big, and the high control proves the outcome above is not just "any
     * over-size request" but specifically the post-create one. Together they prove the WIDENING is
     * what decided it.
     */
    const under = build();
    const smallOk = await stamp(gateFor(under.world.grant, under.primitives), {
        path: `${PLAIN}/page.md`,
        content: 'the answer',
        derivedFrom: cite(under.world, 287)
    }, { appender: capturingAppender([]) });
    assert.equal(smallOk.ok, true,
        `one byte below the band the same shape SUCCEEDS — the final line is exactly at the ceiling: ${JSON.stringify(smallOk).slice(0, 300)}`);

    const over = build();
    const tooBig = await stamp(gateFor(over.world.grant, over.primitives), {
        path: `${PLAIN}/page.md`,
        content: 'the answer',
        derivedFrom: cite(over.world, 674)
    }, { appender: forbiddenAppender('a draft over the ceiling') });
    assert.equal(tooBig.reason, 'LINEAGE_LINE_TOO_LARGE',
        'one byte above the band the DRAFT refuses, which is ST27\'s branch and not this one');
    assert.equal(tooBig.created, undefined, 'and no page was created at all');
    assert.equal(fs.existsSync(path.join(over.realParent, 'page.md')), false);

    /**
     * ⚠ AND THE TWO EDGES **INSIDE** THE BAND, WHICH IS WHAT MAKES "BOTH EDGES" TRUE RATHER THAN A
     * TURN OF PHRASE. `288` is the first tail that reaches the branch and `673` the last; with only
     * the outside controls, a band that had drifted inward by a byte at either end would still pass
     * everything above. All four together pin the band exactly.
     */
    for (const [tail, label] of [[288, 'the first tail in the band'], [673, 'the last tail in the band']]) {
        const edge = build();
        const atEdge = await stamp(gateFor(edge.world.grant, edge.primitives), {
            path: `${PLAIN}/page.md`,
            content: 'the answer',
            derivedFrom: cite(edge.world, tail)
        }, { appender: forbiddenAppender('a post-create size refusal') });
        assert.equal(atEdge.reason, 'PAGE_WRITTEN_LEDGER_FAILED',
            `${label} (${tail}) must reach the post-create branch, got ${atEdge.reason}`);
        assert.equal(atEdge.cause.reason, 'LINEAGE_LINE_TOO_LARGE',
            `${label} (${tail}) must fail on the line ceiling, not something else`);
        assert.equal(fs.existsSync(path.join(edge.realParent, 'page.md')), true,
            `${label} (${tail}) leaves the orphan page, exactly as the middle of the band does`);
    }
});

// ---------------------------------------------------------------------------
// The validated snapshot — 2026-09-08
// ---------------------------------------------------------------------------

/**
 * ⚠⚠ THE SUBSTITUTION LIVES IN A GETTER, NOT IN A HOOK, AND THE DISTINCTION IS WHAT THIS ARM
 * MEASURES. `writePage` is async, so a caller holding the request can change it between the
 * validation and the write without any cooperation from this suite — but a test that mutated the
 * object after calling `writePage` would be racing the implementation and would pass or fail on
 * scheduling. So each member is a getter that serves the honest value to its FIRST read and a
 * substitute to every read after it, and counts its reads. If the module reads a member twice, the
 * second read fetches the substitute deterministically, whatever the scheduling.
 *
 * The option hooks do NOT mutate anything (they return fixed values). They are named here because
 * they mark the steps at which the OLD code's second read happened, so the reader can place the
 * defect in the step list:
 *
 *   · `newUuid` runs inside `loadConfig` at STEP 4 — after `preflight`, after the first `await`,
 *     and BEFORE the source loop. The old code re-read `derivedFrom` and every span after this.
 *   · `now` runs at STEP 6 — after the whole source loop. The old code re-read `content` at step 7.
 *
 * ⚠ THE ASSERTIONS ARE ON THE BYTES ON DISK AND ON THE LEDGER RECORD, never on a return value. A
 * result object could carry the validated values while the page carried the changed ones; only the
 * page and the line say what was actually written. `content` is asserted on both; `derivedFrom`
 * and the span are asserted on the ledger record only, because nothing on the page carries them.
 */
test('ST42-request-mutation-after-validation-is-not-observed — the write uses what was validated', async () => {
    arm('ST42-request-mutation-after-validation-is-not-observed');

    /**
     * ---- content, changed at step 6 -------------------------------------
     *
     * ⚠ A GETTER RATHER THAN A REASSIGNMENT, because a getter is the shape a plain snapshot of the
     * OBJECT would still miss: the property is `readonly` on the type and the caller never assigns
     * to it, so nothing about the request looks mutated. The getter below returns the validated
     * content to the FIRST read and the substitute to every read after it, and counts its reads.
     */
    const contentWorld = vault();
    const contentRel = withSource(contentWorld, 'Arc/c.md', SOURCE_TEXT);
    const HONEST = 'the content the caller validated';
    const SUBSTITUTE = 'THE-SUBSTITUTED-CONTENT-THAT-MUST-NEVER-LAND';
    let contentReads = 0;
    const mutatingContent = {
        path: 'Mage/content.md',
        get content() {
            contentReads += 1;
            return contentReads === 1 ? HONEST : SUBSTITUTE;
        },
        derivedFrom: [{ source: contentRel, spans: [{ quote: 'noon' }] }]
    };
    const contentLines = [];
    const contentResult = await stamp(gateFor(contentWorld.grant), mutatingContent, {
        appender: capturingAppender(contentLines),
        // ⚠ THE HOOK ONLY HAS TO EXIST FOR THE GETTER TO HAVE BEEN CROSSED BY IT — `now` runs at
        // step 6, so by the time `content` is read at step 7 the request has been through both
        // awaits. The getter counts its own reads, which is the assertion below.
        now: FIXED_NOW
    });
    assert.equal(contentResult.ok, true, JSON.stringify(contentResult).slice(0, 300));

    // ⚠⚠ THE BYTES ON DISK, WHICH IS THE ONLY PLACE THIS CAN BE ANSWERED. The old code read
    // `request.content` at step 7 — the SECOND read — so the substitute is what landed in the page
    // while every returned value looked correct.
    const contentBytes = fs.readFileSync(path.join(contentWorld.grant, 'Mage', 'content.md'), 'utf8');
    assert.equal(contentBytes, HONEST, 'the page carries the VALIDATED content, never the substituted one');
    assert.ok(!contentBytes.includes(SUBSTITUTE), 'and no trace of the substitute reached the page');

    // ⚠ THE LEDGER LINE HASHES THE SAME BYTES. A page written from the validated value while the
    // record hashed the substituted one would be a false provenance claim, which is the failure D4
    // ranks worst.
    const contentRecord = JSON.parse(contentLines[0].toString('utf8'));
    assert.equal(
        contentRecord.page.content.digest,
        crypto.createHash('sha256').update(Buffer.from(HONEST, 'utf8')).digest('hex'),
        'the ledger line hashes the bytes that were written'
    );
    assert.equal(contentRecord.page.content.bytes, Buffer.byteLength(HONEST),
        'and the recorded byte count is the validated content\'s, not the substitute\'s');

    // ⚠ THE GETTER REALLY WAS READ EXACTLY ONCE. Without this the arm passes on an implementation
    // that reads twice and happens to get the same answer — which is what a non-mutating fixture
    // would have proved, and is not the property.
    assert.equal(contentReads, 1, 'content is read ONCE, at validation, and never again');

    /**
     * ---- derivedFrom, changed at step 4 ---------------------------------
     *
     * ⚠⚠ THE SUBSTITUTE CITES A DIFFERENT SOURCE, so if the second read won, the page's provenance
     * would name a file the caller never validated a citation to. Both sources exist and both are
     * in-grant, which is deliberate: a substitute that simply failed to read would refuse and the
     * arm would go green for the wrong reason. This one would SUCCEED and record the wrong lineage.
     */
    const derivedWorld = vault();
    const honestRel = withSource(derivedWorld, 'Arc/honest.md', SOURCE_TEXT);
    const otherRel = withSource(derivedWorld, 'Arc/other.md', 'A completely different transcript entirely.');
    const honestFrom = [{ source: honestRel, spans: [{ quote: 'noon' }] }];
    const otherFrom = [{ source: otherRel, spans: [{ quote: 'transcript' }] }];
    let derivedReads = 0;
    const mutatingDerived = {
        path: 'Mage/derived.md',
        content: 'the body',
        get derivedFrom() {
            derivedReads += 1;
            return derivedReads === 1 ? honestFrom : otherFrom;
        }
    };
    const derivedLines = [];
    const derivedResult = await stamp(gateFor(derivedWorld.grant), mutatingDerived, {
        appender: capturingAppender(derivedLines),
        // ⚠ `newUuid` IS CALLED INSIDE `loadConfig` AT STEP 4 — after preflight and before the
        // source loop. Nothing here needs the hook to do anything; the seam is where it sits.
        newUuid: () => FIXED_UUID
    });
    assert.equal(derivedResult.ok, true, JSON.stringify(derivedResult).slice(0, 300));

    const derivedRecord = JSON.parse(derivedLines[0].toString('utf8'));
    assert.equal(derivedRecord.sources.length, 1);
    assert.equal(
        derivedRecord.sources[0].identity.path,
        honestRel.split(path.sep).join('/'),
        'the ledger records the source that was VALIDATED, never the one substituted after'
    );
    assert.equal(derivedReads, 1, 'derivedFrom is read ONCE, at validation, and never again');

    /**
     * ---- one SPAN inside derivedFrom, changed at step 4 ------------------
     *
     * ⚠⚠ THE SPAN IS THE HALF A SHALLOW COPY MISSES, AND IT IS WHY THE SNAPSHOT GOES ALL THE WAY
     * DOWN. `derivedFrom` could be copied entry by entry and still hand step 5 the caller's own
     * span objects — and `resolveSpan` calls `spanShapeFault` AGAIN, so a span accessor fires a
     * second time there, after the config load and after the source read. The substitute quote is
     * present in the source and would resolve happily to a DIFFERENT range, so the recorded span
     * would point somewhere the caller never validated.
     */
    const spanWorld = vault();
    const spanRel = withSource(spanWorld, 'Arc/s.md', SOURCE_TEXT);
    let spanReads = 0;
    const mutatingSpan = {
        get quote() {
            spanReads += 1;
            return spanReads === 1 ? 'noon' : 'foundations';
        }
    };
    const spanLines = [];
    const spanResult = await stamp(gateFor(spanWorld.grant), {
        path: 'Mage/span.md',
        content: 'the body',
        derivedFrom: [{ source: spanRel, spans: [mutatingSpan] }]
    }, { appender: capturingAppender(spanLines), newUuid: () => FIXED_UUID });
    assert.equal(spanResult.ok, true, JSON.stringify(spanResult).slice(0, 300));

    const spanRecord = JSON.parse(spanLines[0].toString('utf8'));
    const recorded = spanRecord.sources[0].spans[0];
    assert.equal(recorded.quote.text, 'noon', 'the recorded quote is the one validated at step 3');
    assert.equal(
        recorded.offset,
        SOURCE_TEXT.indexOf('noon'),
        'and it is located at the VALIDATED quote\'s offset, not the substitute\'s'
    );
    assert.equal(spanReads, 1, 'a span member is read ONCE, at validation, and never again');
});

/**
 * ⚠⚠ THE REFUSAL/VALIDATED SPLIT MUST NOT BE ANSWERABLE BY A PROPERTY THE CALLER SUPPLIES.
 *
 * `writePage` used to ask `isRefusalLike(checked)` — `value.ok === false` — of what `preflight`
 * returned, which was the caller's own object. `.ok` reads through the prototype chain, so a
 * request whose PROTOTYPE carried `{ ok: false }` passed validation and was then read as a refusal
 * and handed straight back to the caller: an object the caller minted, returned as this module's
 * verdict. The own-property leg is the other direction of the same question — a request carrying a
 * real own `ok: false` that is not a refusal shape at all.
 *
 * ⚠ NEITHER LEG CAN USE `ownKeysOnly` AS ITS EXPLANATION. The inherited leg supplies `ok` on the
 * PROTOTYPE, which the own-key screen does not see at all; the own leg is caught by that screen and
 * refuses `BAD_INPUT`, which is the right refusal for the right reason and is asserted as such. The
 * two legs prove the discrimination is not answerable EITHER way.
 */
test('ST43-refusal-discrimination-is-not-caller-supplied — an inherited `ok: false` is not a refusal', async () => {
    arm('ST43-refusal-discrimination-is-not-caller-supplied');
    const world = vault();
    const rel = withSource(world, 'Arc/i.md', SOURCE_TEXT);

    // ---- the inherited leg: `{ ok: false }` on the prototype ----------------
    const inherited = Object.create({ ok: false, reason: 'FORGED_REFUSAL', detail: 'minted by the caller' });
    inherited.path = 'Mage/inherited.md';
    inherited.content = 'the body';
    inherited.derivedFrom = [{ source: rel, spans: [{ quote: 'noon' }] }];

    const lines = [];
    const result = await stamp(gateFor(world.grant), inherited, { appender: capturingAppender(lines) });

    // ⚠⚠ THE OLD CODE RETURNED THE CALLER'S OWN OBJECT HERE, reason `FORGED_REFUSAL` and all. It is
    // a REQUEST, so it is treated as one: the page is written and the line is appended.
    assert.equal(result.ok, true, `an inherited ok:false is not a refusal: ${JSON.stringify(result).slice(0, 300)}`);
    assert.notEqual(result.reason, 'FORGED_REFUSAL', 'and the caller\'s forged reason never comes back');
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'inherited.md')), true);
    assert.equal(lines.length, 1, 'the ledger line was appended, as for any other valid request');

    // ---- the own-property leg: a real own `ok: false` that is not a refusal --
    // ⚠ THIS ONE REFUSES, AND FOR THE STRICT-SHAPE REASON RATHER THAN THE DISCRIMINATION ONE. `ok`
    // is an unknown own key, so step 1's own-key screen refuses BAD_INPUT before anything is read.
    // Asserting the REASON is what keeps the two legs from being one arm wearing two hats.
    refusal(await stamp(gateFor(world.grant), {
        ok: false,
        path: 'Mage/own.md',
        content: 'the body',
        derivedFrom: [{ source: rel, spans: [{ quote: 'noon' }] }]
    }), 'BAD_INPUT', world);
    assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'own.md')), false);
});
