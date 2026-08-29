import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

import { createFsGate, isRefusal } from '../dist/fsgate.js';
import { buildFixture, CANARY, teardown } from './fixtures.mjs';
import { declare as arm, tier2 } from './manifest.mjs';

/**
 * ⚠ SKIPS FAIL THE BUILD. Arms are declared in `test/arms.mjs` and reconciled across every test
 * file by `scripts/run-tests.mjs`, which requires a globally zero skipped/cancelled count in the
 * FULL suite. A fixture that cannot be created throws inside `before`, failing every arm loudly.
 *
 * ⚠ ONE SANCTIONED EXCEPTION: `--portable` skips exactly the declared `SYMLINK_PRIVILEGE_ARMS`, and
 * the runner checks that set BY IDENTITY rather than by count. An unexpected skip still fails, and
 * so does a declared tier-2 arm that failed to skip. Nothing else may skip, ever.
 *
 * ⚠ EVERY ARM RUNS THROUGH AN INSTRUMENTED GATE, pass arms included. The shared gate's
 * primitives throw on any path argument outside the canonical root, so §6(1) is asserted where
 * paths actually OPEN, not only where they are refused.
 */

let FX = null;
let gate = null;
let root = null;
let ROOT_GUARD = null;
const GATE_SINK = [];
/**
 * ⚠ THE SINK ALONE CANNOT WITNESS A VIOLATION. The guard threw BEFORE recording, so an
 * out-of-grant argument never reached GATE_SINK and the `offenders` filter over it was
 * decoration: always empty, whatever the fence did. Worse, the thrown Error carried no `.code`,
 * so a violation that did occur was swallowed by `mapFsError` into an IO_ERROR refusal rather
 * than surfacing as a crash. Violations are now recorded here, in the throwing branch, and this
 * array is what the assertion reads.
 */
const VIOLATIONS = [];

function outsideRoot(canonicalRoot, candidate) {
    if (typeof candidate !== 'string' || !path.isAbsolute(candidate)) return false;
    const rel = path.relative(canonicalRoot, path.normalize(candidate));
    return rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel);
}

/** Records every primitive call, below the fence, on a REAL gate. */
function spyPrimitives(sink) {
    const record = (name, argument) => {
        sink.push({ name, argument: typeof argument === 'string' ? argument : `<${typeof argument}>` });
    };
    return {
        open: (t, f) => { record('open', t); return fs.openSync(t, f); },
        close: fd => { record('close', fd); return fs.closeSync(fd); },
        read: (fd, b, o, l, p) => { record('read', fd); return fs.readSync(fd, b, o, l, p); },
        fstat: fd => { record('fstat', fd); return fs.fstatSync(fd); },
        lstat: t => { record('lstat', t); return fs.lstatSync(t); },
        readlink: t => { record('readlink', t); return fs.readlinkSync(t, 'utf8'); },
        realpathNative: t => { record('realpathNative', t); return fs.realpathSync.native(t); },
        readdir: t => { record('readdir', t); return fs.readdirSync(t, { withFileTypes: true }); }
    };
}

/** Spy plus a hard containment assertion on every path-bearing argument. */
function guardingPrimitives(sink) {
    const spy = spyPrimitives(sink);
    const guarded = {};
    for (const [name, fn] of Object.entries(spy)) {
        guarded[name] = (...args) => {
            if (ROOT_GUARD !== null && typeof args[0] === 'string' && outsideRoot(ROOT_GUARD, args[0])) {
                // Record BEFORE throwing, and into an array the fence cannot swallow.
                VIOLATIONS.push({ primitive: name, argument: args[0] });
                sink.push({ name, argument: args[0] });
                const error = new Error(`FENCE VIOLATION: ${name} named ${args[0]}, outside ${ROOT_GUARD}`);
                error.code = 'WYRD_FENCE_VIOLATION';
                throw error;
            }
            return fn(...args);
        };
    }
    return guarded;
}

async function text(request, offset = 0, limit = 1 << 16) {
    const slice = await gate.readFileInGrant(request, offset, limit);
    assert.ok(!isRefusal(slice), `expected ${request} to open, got ${slice.reason}: ${slice.detail}`);
    return slice.bytes.toString('utf8');
}

async function refusal(request) {
    const result = await gate.readFileInGrant(request, 0, 4096);
    assert.ok(isRefusal(result), `expected ${request} to refuse, it returned content`);
    return result;
}

before(() => {
    FX = buildFixture();
    const made = createFsGate({ rawGrant: FX.grant, primitives: guardingPrimitives(GATE_SINK) });
    assert.ok(!isRefusal(made), `the fixture grant should be accepted: ${JSON.stringify(made)}`);
    gate = made;
    root = gate.disclosedRoot();
    ROOT_GUARD = root;
});

after(() => {
    if (FX) {
        const result = FX.teardown();
        assert.equal(result.removed, true, 'the fixture tree must be removed');
    }
});

/* ---------------- stage (a): lexical, nothing touched ---------------- */

test('A1 — `..` traversal to an existing outside file refuses; an in-grant file still opens', async () => {
    arm('A1');
    const r = await refusal('../outside/secret.md');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

test('A2 — an absolute path to an existing outside file refuses', async () => {
    arm('A2');
    const r = await refusal(path.join(FX.outside, 'secret.md'));
    assert.equal(r.reason, 'BAD_INPUT');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

test('A3 — drive-relative `C:notes` refuses; ordinary relative `notes` opens', async () => {
    arm('A3');
    const r = await refusal('C:notes');
    assert.equal(r.reason, 'BAD_INPUT');
    assert.equal(await text('notes'), CANARY.plainNotes);
});

test('A4 — a cross-volume absolute path refuses', async () => {
    arm('A4');
    const r = await refusal('D:\\y');
    assert.equal(r.reason, 'BAD_INPUT');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

test('A5 — a null byte refuses lexically, as BAD_INPUT and not as an errno', async () => {
    arm('A5');
    const r = await refusal('subdir\\note.md\u0000x');
    assert.equal(r.reason, 'BAD_INPUT');
    assert.match(r.detail, /null byte/);
    assert.equal(await text('subdir\\note.md'), CANARY.inGrantNote);
});

test('A6 — the exact parent refuses; a subdirectory still lists', async () => {
    arm('A6');
    const r = await refusal('..');
    assert.equal(r.reason, 'ESCAPES');
    const listed = await gate.listDirInGrant('subdir');
    assert.ok(!isRefusal(listed));
    assert.deepEqual(listed.map(e => e.name), ['note.md']);
});

test('A7 — `.` through listDirInGrant is IS_ROOT; listGrantRoot is the supported path', async () => {
    arm('A7');
    const r = await gate.listDirInGrant('.');
    assert.ok(isRefusal(r));
    assert.equal(r.reason, 'IS_ROOT');
    const listed = await gate.listGrantRoot();
    assert.ok(!isRefusal(listed));
    assert.ok(listed.some(e => e.name === 'subdir'), 'the grant root must list its own children');
});

test('A8 — `.` through readFileInGrant is IS_ROOT', async () => {
    arm('A8');
    const r = await refusal('.');
    assert.equal(r.reason, 'IS_ROOT');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

test('A9 — the sibling-prefix trap refuses; the in-grant lookalike opens', async () => {
    arm('A9');
    const r = await refusal('../vault-secrets/x.md');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('secrets/x.md'), CANARY.inGrantSecret);
});

test('A10 — `..` absorbed at the volume root refuses as CLAMPED, not merely as ESCAPES', async () => {
    arm('A10');
    const depth = root.slice(path.parse(root).root.length).split(path.sep).filter(Boolean).length;
    const r = await refusal('../'.repeat(depth + 2) + 'foo');
    assert.equal(r.reason, 'CLAMPED');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

/* ---------------- stage (b): links ---------------- */

test('A11 — a terminal file symlink to outside refuses; one to in-grant opens', { ...tier2('A11') }, async () => {    arm('A11');
    const r = await refusal('s_out');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('s_in'), CANARY.inGrantNote);
});

test('A12 — a symlink chain ending outside refuses; one ending in-grant opens', { ...tier2('A12') }, async () => {    arm('A12');
    const r = await refusal('sc_a');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('sc_in_a'), CANARY.inGrantNote);
});

test('A13 — a junction to outside refuses; an IN-GRANT junction opens', async () => {
    arm('A13');
    const r = await refusal('j_out\\secret.md');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('j_in\\note.md'), CANARY.inGrantNote);
});

test('A14-M — THE MIRROR ESCAPE: junction alias + relative symlink out. Must refuse', { ...tier2('A14-M') }, async () => {    arm('A14-M');
    const served = fs.readFileSync(path.join(FX.grant, 'alias', 'esc'), 'utf8');
    assert.equal(served, CANARY.outsideSecret, 'precondition: the OS serves the outside file here');
    const r = await refusal('alias\\esc');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('alias\\plain.md'), CANARY.viaJunctionPlain);
});

test('A14-T — the twin: same shape, in-grant target. Must OPEN and return the traversal answer', { ...tier2('A14-T') }, async () => {    arm('A14-T');
    const served = fs.readFileSync(path.join(FX.grant, 'x', 'alias', 'escape'), 'utf8');
    assert.equal(served, CANARY.twinTraversal, 'precondition: the OS serves the in-grant file here');
    assert.equal(await text('x\\alias\\escape'), CANARY.twinTraversal);
});

test('A15 — a junction cycle refuses as a detected cycle; a self-junction to the root opens', async () => {
    arm('A15');
    const r = await refusal('cyca\\note.md');
    assert.equal(r.reason, 'ELOOP');
    assert.match(r.detail, /cycle/);
    assert.equal(
        await text('j_self\\j_self\\j_self\\j_self\\j_self\\subdir\\note.md'),
        CANARY.inGrantNote
    );
});

test('A16-in — a dangling IN-GRANT junction is MISSING, never ESCAPES', async () => {
    arm('A16-in');
    const r = await refusal('j_dangle_in\\x.md');
    assert.equal(r.reason, 'MISSING');
    assert.equal(await text('j_in\\note.md'), CANARY.inGrantNote);
});

test('A16-out — a dangling junction pointing OUTSIDE is ESCAPES, refused without following', async () => {
    arm('A16-out');
    const r = await refusal('j_dangle_out\\x.md');
    assert.equal(r.reason, 'ESCAPES');
});

test('A17 — a missing in-grant file is MISSING', async () => {
    arm('A17');
    const r = await refusal('no-such-note.md');
    assert.equal(r.reason, 'MISSING');
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

test('A18 — a RELATIVE-target symlink out refuses; a relative-target symlink in-grant opens', { ...tier2('A18') }, async () => {    arm('A18');
    const r = await refusal('s_rel_out');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('s_rel_in'), CANARY.inGrantNote);
});

test('A19 — a DIRECTORY symlink to outside refuses', { ...tier2('A19') }, async () => {    arm('A19');
    const r = await refusal('ds_out\\secret.md');
    assert.equal(r.reason, 'ESCAPES');
});

test('A20 — a junction chain ending outside refuses; one ending in-grant opens', async () => {
    arm('A20');
    const r = await refusal('j_chain\\secret.md');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('j_chain_in\\note.md'), CANARY.inGrantNote);
});

test('A21 — a symlink cycle refuses', { ...tier2('A21') }, async () => {    arm('A21');
    const r = await refusal('scyc_a');
    assert.equal(r.reason, 'ELOOP');
});

test('A21-rel — a chain of RELATIVE-target symlinks opens; a relative cycle refuses', { ...tier2('A21-rel') }, async () => {    arm('A21-rel');
    assert.equal(await text('rc_a'), CANARY.inGrantNote);
    const r = await refusal('rcyc_a');
    assert.equal(r.reason, 'ELOOP');
    assert.match(r.detail, /cycle/);
});

test('A22 — a self-descending directory symlink is refused by the OS, exactly as measured', { ...tier2('A22') }, async () => {    arm('A22');
    // ⚠ This arm does NOT exercise the walk's own bounds. Measurement §9.5: Windows returns
    // ELOOP immediately at every tested depth, so the OS refuses before the walk gets far. The
    // hop bound needs a FINITE chain, which is A22-hops.
    const r = await refusal('sd\\note.md');
    assert.equal(r.reason, 'ELOOP', 'the OS answer for this shape is ELOOP, per measurement §9.5');
});

test('A22-hops — a FINITE acyclic chain past the hop bound refuses; a shorter one opens', { ...tier2('A22-hops') }, async () => {    arm('A22-hops');
    const r = await refusal('hop70_0');
    assert.equal(r.reason, 'ELOOP');
    // The hop limit, not a cycle: nothing here repeats, so only the bound can stop it.
    assert.match(r.detail, /hop limit/);
    // The pass twin is what stops the bound being set absurdly low.
    assert.equal(await text('hop20_0'), CANARY.inGrantNote);
});

test('A23-dsym — the mirror shape with a DIRECTORY SYMLINK alias resolves as the OS resolves it', { ...tier2('A23-dsym') }, async () => {    arm('A23-dsym');
    const served = fs.readFileSync(path.join(FX.grant, 'dsalias', 'esc'), 'utf8');
    assert.equal(served, CANARY.mirrorDecoy, 'precondition: a dir symlink alias serves the in-grant file');
    assert.equal(await text('dsalias\\esc'), CANARY.mirrorDecoy);
});

test('A24-hardlink-limit — a hardlink to an outside file is served, and that is the DOCUMENTED limit', async () => {
    arm('A24-hardlink-limit');
    assert.equal(fs.lstatSync(path.join(FX.grant, 'h_out.md')).isSymbolicLink(), false);
    assert.equal(await text('h_out.md'), CANARY.outsideSecret);
});

test('A25-case — a case-only difference is accepted', async () => {
    arm('A25-case');
    assert.equal(await text('SUBDIR\\NOTE.MD'), CANARY.inGrantNote);
});

test('A32-hidden-intermediate — a reparse point hidden inside a link target closes no oracle', async () => {
    arm('A32-hidden-intermediate');
    // `hop`'s target is lexically in-grant but reaching it traverses `hidden`, which is not.
    // Both requests must refuse IDENTICALLY: if the present one and the absent one differ, the
    // errno has reported whether an out-of-grant file exists.
    const present = await refusal('hop\\exists.md');
    const absent = await refusal('hop\\absent.md');
    assert.equal(present.reason, 'ESCAPES');
    assert.equal(absent.reason, present.reason, 'presence outside the grant must not be observable');
    assert.equal(absent.detail, present.detail, 'nor through the message');
});

/* ---------------- pagination ---------------- */

test('A26-pagination — following next_offset to exhaustion reconstructs the file byte-for-byte', async () => {
    arm('A26-pagination');
    const expected = fs.readFileSync(path.join(FX.grant, 'big.md'));
    const chunks = [];
    let offset = 0;
    let guard = 0;
    for (;;) {
        if (guard++ > 1000) throw new Error('pagination did not terminate');
        const slice = await gate.readFileInGrant('big.md', offset, 4096);
        assert.ok(!isRefusal(slice), `pagination refused at ${offset}`);
        chunks.push(slice.bytes);
        if (!slice.truncated) break;
        assert.ok(slice.nextOffset > offset, 'next_offset must advance');
        offset = slice.nextOffset;
    }
    assert.ok(Buffer.concat(chunks).equals(expected), 'the reassembled file must match byte-for-byte');
});

test('A27-utf8 — a slice never splits a codepoint, and the offsets still reconstruct', async () => {
    arm('A27-utf8');
    const expected = fs.readFileSync(path.join(FX.grant, 'utf8.md'));
    const slice = await gate.readFileInGrant('utf8.md', 0, 8);
    assert.ok(!isRefusal(slice));
    assert.equal(slice.bytes.length, 7, 'the slice must stop before the partial codepoint');
    assert.equal(slice.truncated, true);
    assert.equal(slice.nextOffset, 7);
    assert.equal(Buffer.from(slice.bytes.toString('utf8'), 'utf8').length, slice.bytes.length, 'valid UTF-8');

    const chunks = [slice.bytes];
    let offset = slice.nextOffset;
    for (let guard = 0; guard < 100; guard += 1) {
        const next = await gate.readFileInGrant('utf8.md', offset, 8);
        assert.ok(!isRefusal(next));
        chunks.push(next.bytes);
        if (!next.truncated) break;
        offset = next.nextOffset;
    }
    assert.ok(Buffer.concat(chunks).equals(expected));
});

/* ---------------- guards, listing, and the root identity ---------------- */

test('A33-guards — offset, limit, type and kind guards, table-driven', async () => {
    arm('A33-guards');
    const cases = [
        [() => gate.readFileInGrant(42, 0, 100), 'BAD_INPUT', 'a non-string request'],
        [() => gate.readFileInGrant(null, 0, 100), 'BAD_INPUT', 'a null request'],
        [() => gate.readFileInGrant('subdir/note.md', -1, 100), 'BAD_INPUT', 'a negative offset'],
        [() => gate.readFileInGrant('subdir/note.md', 1.5, 100), 'BAD_INPUT', 'a fractional offset'],
        [() => gate.readFileInGrant('subdir/note.md', Number.NaN, 100), 'BAD_INPUT', 'a NaN offset'],
        [() => gate.readFileInGrant('subdir/note.md', 0, 0), 'BAD_INPUT', 'a zero limit'],
        [() => gate.readFileInGrant('subdir/note.md', 0, -5), 'BAD_INPUT', 'a negative limit'],
        [() => gate.readFileInGrant('subdir/note.md', 1e6, 100), 'BAD_INPUT', 'an offset past EOF'],
        [() => gate.readFileInGrant('subdir', 0, 100), 'NOT_A_FILE', 'a directory given to read'],
        [() => gate.listDirInGrant('subdir/note.md'), 'NOT_A_DIRECTORY', 'a file given to list']
    ];
    for (const [run, expected, label] of cases) {
        const result = await run();
        assert.ok(isRefusal(result), `${label} must refuse`);
        assert.equal(result.reason, expected, `${label} refused as ${result.reason}`);
    }
    // The internal window cap holds even when the caller asks for more.
    const huge = await gate.readFileInGrant('big.md', 0, Number.MAX_SAFE_INTEGER);
    assert.ok(!isRefusal(huge));
    assert.ok(huge.bytes.length <= 1 << 20, `the window cap must hold; got ${huge.bytes.length}`);
    // A non-string grant is a config refusal, not a crash.
    const bad = createFsGate({ rawGrant: 42 });
    assert.ok(isRefusal(bad));
    assert.equal(bad.reason, 'CONFIG_EMPTY');
});

test('A34-listing — entry kinds and sizes, and errors from readdir map to their own reason', { ...tier2('A34-listing') }, async () => {    arm('A34-listing');
    const listed = await gate.listDirInGrant('listing');
    assert.ok(!isRefusal(listed));
    const byName = Object.fromEntries(listed.map(e => [e.name, e]));
    assert.equal(byName['a.md'].kind, 'file');
    assert.equal(byName['a.md'].size, 4);
    assert.equal(byName['nested'].kind, 'directory');
    assert.equal(byName['nested'].size, null);
    assert.equal(byName['a_link'].kind, 'link');
    assert.equal(byName['a_link'].size, null, 'a link is not sized as a file');

    const rootListing = await gate.listGrantRoot();
    assert.ok(!isRefusal(rootListing));
    assert.ok(rootListing.some(e => e.name === 'listing' && e.kind === 'directory'));

    // Injected failures on the read and list legs each map to their own reason.
    for (const [primitive, code, expected] of [['readdir', 'EACCES', 'DENIED'], ['open', 'EPERM', 'DENIED'], ['fstat', 'EIO', 'IO_ERROR']]) {
        const real = spyPrimitives([]);
        const primitives = {
            ...real,
            [primitive]: (...args) => {
                const error = new Error(`injected ${code}`);
                error.code = code;
                throw error;
            }
        };
        const made = createFsGate({ rawGrant: FX.grant, primitives });
        assert.ok(!isRefusal(made));
        const result = primitive === 'readdir'
            ? await made.listDirInGrant('listing')
            : await made.readFileInGrant('subdir/note.md', 0, 10);
        assert.ok(isRefusal(result), `${primitive}/${code} must refuse`);
        assert.equal(result.reason, expected, `${primitive}/${code} mapped to ${result.reason}`);
    }
});

test('A35-root-moved — swapping the granted folder after startup is CAUGHT, not closed', async () => {
    arm('A35-root-moved');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-rootswap-'));
    try {
        const vault = path.join(base, 'vault');
        const evil = path.join(base, 'evil');
        fs.mkdirSync(vault);
        fs.mkdirSync(evil);
        fs.writeFileSync(path.join(vault, 'note.md'), 'REAL-VAULT');
        fs.writeFileSync(path.join(evil, 'note.md'), 'SWAPPED-CONTENT');

        const made = createFsGate({ rawGrant: vault });
        assert.ok(!isRefusal(made));
        assert.equal((await made.readFileInGrant('note.md', 0, 100)).bytes.toString('utf8'), 'REAL-VAULT');

        // Move the real folder aside and put a junction to elsewhere in its place.
        fs.renameSync(vault, path.join(base, 'vault-real'));
        fs.symlinkSync(evil, vault, 'junction');

        const after = await made.readFileInGrant('note.md', 0, 100);
        assert.ok(isRefusal(after), 'the swapped root must not serve content');
        assert.equal(after.reason, 'ROOT_MOVED');
        // ⚠ This NARROWS a window, it does not close one: a swap landing between the check and
        // the open is still unhandled, and no Node-only fix exists without handle-relative APIs.
        // It belongs beside TOCTOU and hardlinks in the not-covered list.
    } finally {
        teardown(base);
    }
});

// ⚠ TIER 1 DESPITE THE NAME. The grant root here is reached through a JUNCTION, which needs no
// privilege — see the fixture below. The arm is about disclosing the canonical root, not about
// symlink semantics.
test('A28-symlinked-root — disclosedRoot is the CANONICAL root, not the name given', async () => {
    arm('A28-symlinked-root');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-rootlink-'));
    try {
        const real = path.join(base, 'real');
        fs.mkdirSync(real);
        fs.writeFileSync(path.join(real, 'note.md'), 'ROOTLINK');
        const named = path.join(base, 'named');
        fs.symlinkSync(real, named, 'junction');

        const made = createFsGate({ rawGrant: named });
        assert.ok(!isRefusal(made), 'a symlinked grant root is accepted');
        assert.equal(made.disclosedRoot(), fs.realpathSync.native(real));
        assert.notEqual(made.disclosedRoot(), named);
        const slice = await made.readFileInGrant('note.md', 0, 100);
        assert.ok(!isRefusal(slice));
        assert.equal(slice.bytes.toString('utf8'), 'ROOTLINK');
    } finally {
        teardown(base);
    }
});

test('A29-unc — a link target on a UNC share refuses', { ...tier2('A29-unc') }, async () => {    arm('A29-unc');
    // `path.relative` returns a UNC target unchanged, so it is neither `..` nor `..`-prefixed:
    // the only containment clause that refuses it is `!path.isAbsolute(rel)`. Without this arm
    // that clause has no killing mutation on a machine with a single volume.
    const r = await refusal('unc_out');
    assert.equal(r.reason, 'ESCAPES');
    assert.equal(await text('s_in'), CANARY.inGrantNote);
});

test('A30-no-arbitration — a plainly-escaping link is refused WITHOUT asking realpath', { ...tier2('A30-no-arbitration') }, async () => {    arm('A30-no-arbitration');
    // The screening walk exists to refuse before anything follows the link. That property is
    // invisible in the outcome — the arbitration would refuse these too — so it is asserted as
    // a call count. Walking one level only makes these reach the arbitration instead.
    for (const request of ['s_out', 'sc_a', 'j_out\\secret.md', 'j_chain\\secret.md', 'unc_out', 'hop\\exists.md']) {
        const sink = [];
        const made = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives(sink) });
        assert.ok(!isRefusal(made));
        const canonical = made.disclosedRoot();
        sink.length = 0;
        const result = await made.readFileInGrant(request, 0, 100);
        assert.ok(isRefusal(result), `${request} must refuse`);
        assert.equal(result.reason, 'ESCAPES');
        const arbitrations = sink.filter(c => c.name === 'realpathNative' && c.argument !== canonical);
        assert.deepEqual(arbitrations, [], `${request} reached the realpath arbitration`);
    }
});

test('A31-errno — every errno maps to its own reason, injected below the fence', async () => {
    arm('A31-errno');
    const table = [
        ['ENOENT', 'MISSING'],
        ['ENOTDIR', 'NOT_A_DIRECTORY'],
        ['EISDIR', 'NOT_A_FILE'],
        ['EACCES', 'DENIED'],
        ['EPERM', 'DENIED'],
        ['ELOOP', 'ELOOP'],
        ['ENAMETOOLONG', 'NAME_TOO_LONG'],
        ['ERR_INVALID_ARG_VALUE', 'BAD_INPUT'],
        ['ERR_INVALID_ARG_TYPE', 'BAD_INPUT'],
        ['EIO', 'IO_ERROR'],
        [undefined, 'IO_ERROR']
    ];
    for (const [code, expected] of table) {
        const real = spyPrimitives([]);
        const primitives = {
            ...real,
            lstat: target => {
                if (typeof target === 'string' && target.endsWith('note.md')) {
                    const error = new Error(`injected ${String(code)}`);
                    if (code !== undefined) error.code = code;
                    throw error;
                }
                return real.lstat(target);
            }
        };
        const made = createFsGate({ rawGrant: FX.grant, primitives });
        assert.ok(!isRefusal(made), `gate construction must survive the ${String(code)} injection`);
        const result = await made.readFileInGrant('subdir/note.md', 0, 100);
        assert.ok(isRefusal(result), `${String(code)} must refuse`);
        assert.equal(result.reason, expected, `${String(code)} mapped to ${result.reason}`);
    }
});

test('A36-defaults — the load-bearing arms hold on the PRODUCTION primitives, uninjected', { ...tier2('A36-defaults') }, async () => {    arm('A36-defaults');
    // ⚠ THE INSTRUMENTED GATE OVERRIDES EVERY PRIMITIVE, so arms running on it do not exercise
    // the module's own defaults at all. Swapping `realpathSync.native` for the banned bare form
    // then changes nothing any spied arm can see — measured: that mutation went from KILLED to
    // SURVIVED the moment the shared gate became instrumented. This arm re-runs the arms that
    // discriminate the realpath forms against a gate built with no primitives argument.
    const made = createFsGate({ rawGrant: FX.grant });
    assert.ok(!isRefusal(made));

    const mirror = await made.readFileInGrant('alias\\esc', 0, 4096);
    assert.ok(isRefusal(mirror), 'the mirror escape must refuse on the production primitives');
    assert.equal(mirror.reason, 'ESCAPES');

    const cases = [
        ['x\\alias\\escape', CANARY.twinTraversal],
        ['dsalias\\esc', CANARY.mirrorDecoy],
        ['alias\\plain.md', CANARY.viaJunctionPlain],
        ['j_in\\note.md', CANARY.inGrantNote],
        ['s_in', CANARY.inGrantNote],
        ['subdir/note.md', CANARY.inGrantNote]
    ];
    for (const [request, expected] of cases) {
        const slice = await made.readFileInGrant(request, 0, 4096);
        assert.ok(!isRefusal(slice), `${request} must open on the production primitives`);
        assert.equal(slice.bytes.toString('utf8'), expected, `${request} served the wrong file`);
    }

    for (const request of ['s_out', 'j_out\\secret.md', 'hop\\exists.md', 'unc_out']) {
        const result = await made.readFileInGrant(request, 0, 4096);
        assert.ok(isRefusal(result), `${request} must refuse on the production primitives`);
        assert.equal(result.reason, 'ESCAPES');
    }
});

test('A37-request-separators — a request reaches the same file in every separator spelling', async () => {
    arm('A37-request-separators');
    // The sibling surface of the grant defect. `path.join` folds separators, so these agree
    // today; nothing asserted it, which is exactly how the grant side went wrong.
    for (const request of [
        'subdir/note.md',
        'subdir\\note.md',
        './subdir/note.md',
        '.\\subdir\\note.md',
        'subdir//note.md',
        'secrets/../subdir/note.md',
        'secrets\\..\\subdir/note.md'
    ]) {
        assert.equal(await text(request), CANARY.inGrantNote, `${request} must reach the same file`);
    }
    // And the escape refuses in both spellings, so separator folding has not opened a hole.
    for (const request of ['../outside/secret.md', '..\\outside\\secret.md', '..//outside//secret.md']) {
        const r = await refusal(request);
        assert.equal(r.reason, 'ESCAPES', `${request} must refuse`);
    }
});

test('A38-both-contained — when BOTH readings are in-grant and DIFFER, the gate matches the OS', { ...tier2('A38-both-contained') }, async () => {    arm('A38-both-contained');
    // ⚠⚠ THE CELL NO OTHER FIXTURE COVERS. Every other link fixture puts one reading in-grant
    // and the other outside, so the walk's choice between them is never load-bearing. Here both
    // are in-grant and they name DIFFERENT FILES — which one the OS uses depends on the alias's
    // reparse tag, and Node cannot read it.
    const shapes = [
        ['bc\\Lsym\\L2', CANARY.bcSubstituted, 'a DIRECTORY SYMLINK alias uses the substituted reading'],
        ['bc\\Ljunc\\L2', CANARY.bcTraversal, 'a JUNCTION alias uses the traversal reading'],
        ['bc2\\Lsym\\L2', CANARY.bc2Only, 'the traversal reading does not exist at all'],
        ['bc3\\Lsym\\L2', CANARY.bc3InGrant, 'the traversal reading is itself a link pointing outside']
    ];
    for (const [request, expected, why] of shapes) {
        // Precondition asserted, not assumed: this is what the operating system serves.
        const served = fs.readFileSync(path.join(FX.grant, request), 'utf8');
        assert.equal(served, expected, `precondition (${why})`);
        // The last two are the ones that shipped broken — refused MISSING and ESCAPES
        // respectively, on in-grant content every other reader on the machine serves.
        assert.equal(await text(request), expected, `${request}: ${why}`);
    }

    // And the pairing that stops "open everything" passing: the same shape whose real answer
    // IS outside must still refuse.
    const r = await refusal('bc4\\Lsym\\L2');
    assert.equal(r.reason, 'ESCAPES');
});

/* ---------------- meta-arms ---------------- */

test('META-primitives — each injected primitive is called at its intended site', { ...tier2('META-primitives') }, async () => {    arm('META-primitives');
    const sink = [];
    const made = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives(sink) });
    assert.ok(!isRefusal(made));
    // Startup: one lstat and one realpathNative on the NAMED root, one lstat on the canonical
    // root. Nothing names the parent, and the canonicalization happens exactly once.
    assert.deepEqual(sink.map(c => c.name), ['lstat', 'realpathNative', 'lstat']);

    // A distinct expectation per primitive, at the site where it must be used. Swapping any one
    // for a direct `fs` call blinds the spy — so each is asserted, not just a subset.
    const expectations = [
        ['lstat', () => made.readFileInGrant('subdir/note.md', 0, 10)],
        ['open', () => made.readFileInGrant('subdir/note.md', 0, 10)],
        ['fstat', () => made.readFileInGrant('subdir/note.md', 0, 10)],
        ['read', () => made.readFileInGrant('subdir/note.md', 0, 10)],
        ['close', () => made.readFileInGrant('subdir/note.md', 0, 10)],
        ['readlink', () => made.readFileInGrant('s_in', 0, 10)],
        ['realpathNative', () => made.readFileInGrant('s_in', 0, 10)],
        ['readdir', () => made.listDirInGrant('listing')]
    ];
    for (const [primitive, run] of expectations) {
        sink.length = 0;
        const result = await run();
        assert.ok(!isRefusal(result), `${primitive} probe must succeed`);
        assert.ok(sink.some(c => c.name === primitive), `${primitive} must be reached through the injected table`);
    }

    // The request-time realpath arbitration is a separate site from startup canonicalization.
    sink.length = 0;
    await made.readFileInGrant('s_in', 0, 10);
    const arbitrations = sink.filter(c => c.name === 'realpathNative' && c.argument !== made.disclosedRoot());
    assert.equal(arbitrations.length, 1, 'a link-bearing request arbitrates exactly once');

    // A link-free path costs no arbitration — only the root identity re-check.
    sink.length = 0;
    await made.readFileInGrant('subdir/note.md', 0, 10);
    const stray = sink.filter(c => c.name === 'realpathNative' && c.argument !== made.disclosedRoot());
    assert.deepEqual(stray, [], 'a link-free path must not arbitrate');
});

test('META-this-unbound — an injected callback never receives the primitive table as `this`', async () => {
    arm('META-this-unbound');
    // ⚠ EXECUTED DEFECT, now a standing arm. `table.lstat(p)` binds `this` to the table, handing
    // a supplied callback the whole primitive record — `open` and `read` included — and the
    // fence is bypassed entirely. Freezing the table does not help: its members stay callable.
    const captured = [];
    const real = spyPrimitives([]);
    const primitives = {
        ...real,
        lstat: function (target) {
            captured.push(this);
            return real.lstat(target);
        },
        readdir: function (target) {
            captured.push(this);
            return real.readdir(target);
        }
    };
    const made = createFsGate({ rawGrant: FX.grant, primitives });
    assert.ok(!isRefusal(made));
    await made.readFileInGrant('subdir/note.md', 0, 10);
    await made.listDirInGrant('listing');

    assert.ok(captured.length > 0, 'the injected callbacks must actually have been called');
    for (const value of captured) {
        assert.equal(value, undefined, `an injected callback received \`this\` = ${JSON.stringify(Object.keys(value ?? {}))}`);
    }
});

test('META-no-outside-names — no arm, refusal OR pass, names a path outside the canonical root', { ...tier2('META-no-outside-names') }, async () => {    arm('META-no-outside-names');
    // Stage (a) refusals may touch NOTHING except the root identity re-check.
    const lexicalArms = [
        '../outside/secret.md',
        path.join(FX.outside, 'secret.md'),
        'C:notes',
        'D:\\y',
        'subdir\\note.md\u0000x',
        '..',
        '.'
    ];
    for (const request of lexicalArms) {
        const sink = [];
        const made = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives(sink) });
        assert.ok(!isRefusal(made));
        const canonical = made.disclosedRoot();
        sink.length = 0;
        const result = await made.readFileInGrant(request, 0, 100);
        assert.ok(isRefusal(result), `${request} must refuse`);
        const touches = sink.filter(c => !(c.name === 'realpathNative' && c.argument === canonical));
        assert.deepEqual(touches, [], `stage (a) touched the filesystem for ${request}`);
    }

    // Every remaining arm — refusals AND passes — runs on the shared guarding gate, whose
    // primitives THROW on an out-of-grant argument. This asserts that guard actually fired on
    // real traversals rather than sitting unarmed.
    const passes = [
        ['s_in', CANARY.inGrantNote],
        ['x\\alias\\escape', CANARY.twinTraversal],
        ['dsalias\\esc', CANARY.mirrorDecoy],
        ['alias\\plain.md', CANARY.viaJunctionPlain],
        ['j_in\\note.md', CANARY.inGrantNote],
        ['j_chain_in\\note.md', CANARY.inGrantNote],
        ['sc_in_a', CANARY.inGrantNote],
        ['rc_a', CANARY.inGrantNote],
        ['j_self\\j_self\\subdir\\note.md', CANARY.inGrantNote]
    ];
    for (const [request, expected] of passes) {
        assert.equal(await text(request), expected, `${request} must still open under the guard`);
    }
    const listed = await gate.listDirInGrant('listing');
    assert.ok(!isRefusal(listed));
    const rootListing = await gate.listGrantRoot();
    assert.ok(!isRefusal(rootListing));

    // Two independent readings, because one of them used to be unfalsifiable. VIOLATIONS is
    // the load-bearing one: it is written inside the throwing branch, so it survives the fence
    // catching the error and mapping it to a refusal.
    assert.deepEqual(VIOLATIONS, [], `the shared gate named paths outside the grant: ${JSON.stringify(VIOLATIONS.slice(0, 5))}`);
    const offenders = GATE_SINK.filter(c => outsideRoot(root, c.argument));
    assert.deepEqual(offenders, [], `the shared gate's sink recorded out-of-grant paths: ${JSON.stringify(offenders.slice(0, 5))}`);
});

test('META-guard-armed — the containment guard is armed and not vacuous', async () => {
    arm('META-guard-armed');
    assert.equal(ROOT_GUARD, root, 'the guard must be armed with the canonical root');
    // Non-vacuous in two directions: it saw real traffic, including reparse traversals...
    assert.ok(GATE_SINK.length > 50, `the guard saw only ${GATE_SINK.length} calls`);
    assert.ok(GATE_SINK.some(c => c.name === 'readlink'), 'the guard must have seen link traversals');
    assert.ok(GATE_SINK.some(c => c.name === 'read'), 'the guard must have seen successful reads');
    // ...and it genuinely throws when handed an outside path.
    // ...and it genuinely throws when handed an outside path, AND records the violation, so
    // the assertion in META-no-outside-names is falsifiable rather than vacuous.
    const before = VIOLATIONS.length;
    const probeSink = [];
    assert.throws(
        () => guardingPrimitives(probeSink).lstat(path.join(FX.outside, 'secret.md')),
        /FENCE VIOLATION/,
        'the guard must reject an out-of-grant argument'
    );
    assert.equal(VIOLATIONS.length, before + 1, 'a violation must be RECORDED, not only thrown');
    assert.equal(probeSink.length, 1, 'and it must reach the sink the assertion filters');
    VIOLATIONS.length = before;
});

test('SHAPE-no-mutator — the gate is frozen, null-prototype, and exposes no setter', async () => {
    arm('SHAPE-no-mutator');
    assert.equal(Object.isFrozen(gate), true);
    assert.equal(Object.getPrototypeOf(gate), null);
    assert.deepEqual(Object.keys(gate).sort(), ['disclosedRoot', 'listDirInGrant', 'listGrantRoot', 'readFileInGrant']);
    for (const key of Object.keys(gate)) {
        assert.equal(typeof gate[key], 'function', `${key} must be a method, not a value`);
    }
    assert.throws(() => {
        gate.disclosedRoot = () => 'C:\\outside';
    }, 'the gate must not accept a replacement method');

    const record = spyPrimitives([]);
    const made = createFsGate({ rawGrant: FX.grant, primitives: record });
    assert.ok(!isRefusal(made));
    record.lstat = () => {
        throw new Error('the gate retained the caller object');
    };
    const slice = await made.readFileInGrant('subdir/note.md', 0, 100);
    assert.ok(!isRefusal(slice));
});
