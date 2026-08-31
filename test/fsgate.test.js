import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
        readdir: t => { record('readdir', t); return fs.readdirSync(t, { withFileTypes: true }); },
        // ⚠ THE WRITE PRIMITIVES ARE INSTRUMENTED TOO, AND THAT IS NOT OPTIONAL.
        // `createFsGate` falls back to the production primitive for anything not supplied, so a
        // spy table missing these would leave every WRITE outside the containment guard while the
        // suite still looked fully instrumented — the guard would be structurally unable to
        // witness the one class of call that can destroy data.
        openExclusive: t => { record('openExclusive', t); return fs.openSync(t, 'wx'); }
        // ⚠⚠ `writeAll` IS DELIBERATELY NOT SUPPLIED, AND SUPPLYING IT WAS THE DEFECT.
        //
        // The spy's version was a single `fs.writeSync` — it REPLACED the production completion
        // loop, so every injected create exercised the spy's writer and not the shipped one. That
        // is the same instrumentation-stands-in-for-the-code shape that let M48 survive, one
        // primitive over, and two review lenses flagged it independently.
        //
        // Omitting it makes `createFsGate` fall through to the production primitive, so the arms
        // exercise the real loop. Nothing is lost from the containment guard: it inspects
        // `args[0]`, and for `writeAll` that is a FILE DESCRIPTOR, never a path — so this primitive
        // was never guarded and the spy was buying only a sink entry.
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

    // ⚠⚠ A LINK-FREE PATH NOW ARBITRATES TOO, AND THIS ASSERTION WAS INVERTED ON PURPOSE.
    //
    // It used to read `assert.deepEqual(stray, [], 'a link-free path must not arbitrate')` — the
    // old cost model, pinned as a contract. That model was the hole: arbitration ran only when
    // `sawReparse` was set, and `sawReparse` comes from `isSymbolicLink()`, so any reparse tag the
    // runtime cannot classify skipped it and the fence served the spelled path. Arbitration is now
    // unconditional, which is what makes that class detectable.
    //
    // The arm is kept rather than deleted because the COUNT still matters: exactly one arbitration
    // per resolution. A regression that arbitrated per COMPONENT would be a real cost defect and
    // this is the only thing watching for it.
    sink.length = 0;
    await made.readFileInGrant('subdir/note.md', 0, 10);
    const linkFree = sink.filter(c => c.name === 'realpathNative' && c.argument !== made.disclosedRoot());
    assert.equal(linkFree.length, 1, 'a link-free path arbitrates exactly once — no more, and no longer zero');
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
    // ⚠ THE GATE INVENTORY GREW ON PURPOSE, 2026-08-29, and this list is the record of it.
    // `resolveInGrant` and `resolveNewInGrant` are the shared containment seam the Scribe reaches
    // the fence through (scribe spec D8). Sibling of `E4-export-inventory`: that one pins the
    // MODULE's surface and is deliberately UNCHANGED by this work — the seam rides on the
    // constructed gate, so root and primitives stay bound and a second package cannot supply
    // its own boundary.
    assert.deepEqual(Object.keys(gate).sort(), [
        'createFileInGrant',
        'disclosedRoot',
        'hashInGrant',
        'listDirInGrant',
        'listGrantRoot',
        'readFileInGrant'
    ]);
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

/* ---------------- the gate-mediated seam — scribe spec D8 ---------------- */

/**
 * ⚠ THESE ARMS REPLACED FOUR THAT TESTED A DIFFERENT SHAPE, AND THE REASON IS THE POINT.
 *
 * The first seam returned RESOLVED PATHNAMES to the caller. Its review round returned five HIGHs,
 * two of them reproduced as live writes onto files outside the grant — an alternate-data-stream
 * leaf and a hardlink leaf. Every one was the same class: a path-based check cannot establish what
 * object a name will resolve to at open time, and a returned string leaves an unbounded window
 * between the check and the use.
 *
 * The gate-mediated shape was ruled on 2026-08-29. The caller now names a path and the GATE
 * performs the operation, so the guarantee ends at the syscall rather than at the `return`.
 */

/** The two name classes that are not filenames. Both refuse in stage (a), on BOTH paths. */
const NOT_FILENAMES = [
    ['note.md::$DATA', 'STREAM_SYNTAX'],
    ['note.md:hidden', 'STREAM_SYNTAX'],
    ['s_out:wyrd', 'STREAM_SYNTAX'],
    ['subdir/note.md:s', 'STREAM_SYNTAX'],
    ['NUL', 'RESERVED_NAME'],
    ['CON', 'RESERVED_NAME'],
    ['COM1', 'RESERVED_NAME'],
    ['nul.md', 'RESERVED_NAME'],
    ['NUL.', 'RESERVED_NAME'],
    ['subdir/AUX.txt', 'RESERVED_NAME'],
    ['LPT9/child.md', 'RESERVED_NAME'],
    // ⚠ THE ROUND-3 DELTAS, PINNED. Both round-4 lenses found these unpinned independently: `M46`
    // deletes the WHOLE device screen and dies to a bare `NUL`, so it would have stayed green if
    // only the stem trim or only the policy entries were removed. A mutant that a simpler vector
    // already kills proves nothing about the specific guard beside it.
    ['NUL .txt', 'RESERVED_NAME'],          // trailing space BEFORE the extension — the stem trim
    ['COM1  .log', 'RESERVED_NAME'],        // two spaces, same rule
    ['NUL. .txt', 'RESERVED_NAME'],         // dot/space interleaved around the first delimiter
    ['COM0', 'RESERVED_NAME'],              // portability policy, not a documented Win32 device
    ['LPT0', 'RESERVED_NAME'],
    ['COM¹.md', 'RESERVED_NAME'],           // superscript form
    ['sub:dir/note.md', 'STREAM_SYNTAX'],   // colon in a NON-FINAL component
    ['CONIN$', 'RESERVED_NAME']
];

test('A39-not-filenames — stream syntax and device names refuse in stage (a), on EVERY entry', async () => {
    arm('A39-not-filenames');

    // ⚠ Asserted across the WHOLE gate surface, not just the write path that surfaced them. The
    // guard lives in `lexicalStage` precisely so a later entry inherits it instead of remembering
    // it — this arm is what makes that claim checkable rather than aspirational.
    // ⚠⚠ PLATFORM-BRANCHED, AND ITS ABSENCE WAS A REAL DEFECT CAUGHT BY THE ESCALATION LENS.
    // This arm asserted the unconditional contract with no branch anywhere. Off win32 that is now
    // WRONG BEHAVIOUR to demand — and worse, three of the four entries below are `createFileInGrant`,
    // so on POSIX the arm would have CREATED `NUL`, `CON`, `COM1`, `nul.md`, `subdir/AUX.txt` and
    // the rest inside the fixture grant, and then failed on its own `existsSync(NUL) === false`
    // assertion at the end. ~20 red arms that are correct behaviour, indistinguishable from a real
    // regression, in a repo whose standing row is `POSIX is reasoned, never measured`.
    const win32 = process.platform === 'win32';

    for (const [request, reason] of NOT_FILENAMES) {
        // The stream screen is unconditional ON THE CREATE PATH on every host; the device screen and
        // the read-path stream screen are win32-only. See `NameScreens` in src/fsgate.ts.
        const screenedOnRead = win32;
        const screenedOnCreate = reason === 'STREAM_SYNTAX' ? true : win32;

        for (const result of [
            await gate.readFileInGrant(request, 0, 4096),
            await gate.listDirInGrant(request),
            await gate.hashInGrant(request)
        ]) {
            assert.ok(isRefusal(result), `${request} must refuse on the read path, got content`);
            if (screenedOnRead) {
                assert.equal(result.reason, reason, `${request} must refuse ${reason}`);
            } else {
                assert.notEqual(result.reason, 'STREAM_SYNTAX', `${request}: no stream screen off win32`);
                assert.notEqual(result.reason, 'RESERVED_NAME', `${request}: no device screen off win32`);
            }
        }

        // ⚠ THE CREATE IS ONLY DRIVEN WHERE A SCREEN IS EXPECTED TO CATCH IT. Off win32 a device
        // name is an ordinary legal filename, so `createFileInGrant('NUL', …)` would SUCCEED — and
        // an arm that drives it anyway leaves a real `NUL` in the fixture and then fails its own
        // tail assertion. Not driving it is the honest shape: this arm is about the screens, and
        // where no screen applies there is nothing here to assert.
        if (screenedOnCreate) {
            const created = await gate.createFileInGrant(request, Buffer.from('x'));
            assert.ok(isRefusal(created), `${request} must refuse on create, got a created file`);
            assert.equal(created.reason, reason, `${request} must refuse ${reason} on create`);
        }
    }

    // ⚠ "STAGE (a) TOUCHES NOTHING" IS ASSERTED AGAINST THE SINK, not merely stated. A review lens
    // pointed out that the arm claimed this and never checked it — and a lexical refusal that
    // quietly probed the filesystem first would be an existence oracle wearing a lexical refusal's
    // reason code. The sink records every primitive call below the fence, so the count is the check.
    // ⚠ THE CLAIM IS ABOUT THE REQUEST, NOT ABOUT ALL I/O, and the first version of this assertion
    // was wrong for exactly that reason: `rootStillCanonical` re-resolves the GRANT ROOT before
    // stage (a) runs, so the sink is never empty. That call names the root and tells a caller
    // nothing about the path it asked for. What must never happen is a primitive touching anything
    // derived from the REQUEST — that is what would turn a lexical refusal into an oracle.
    // ⚠ ALL FOUR ENTRIES, not just read and create. The first version ran two, so a regression that
    // probed the filesystem before the lexical refusal in `listDirInGrant` or `hashInGrant` alone
    // would have kept its refusal reason and passed — the arm's name says "every entry".
    // ⚠ ONLY THE ENTRIES A SCREEN ACTUALLY GUARDS ON THIS HOST. The oracle claim is about LEXICAL
    // refusals; a request no screen applies to is resolved for real and legitimately reaches
    // primitives, so driving it here would fail this assertion for the right reason and the wrong
    // arm.
    GATE_SINK.length = 0;
    for (const [request, reason] of NOT_FILENAMES) {
        if (win32) {
            await gate.readFileInGrant(request, 0, 4096);
            await gate.listDirInGrant(request);
            await gate.hashInGrant(request);
        }
        if (reason === 'STREAM_SYNTAX' || win32) {
            await gate.createFileInGrant(request, Buffer.from('x'));
        }
    }
    const touchedRequest = GATE_SINK.filter(
        c => typeof c.argument === 'string' && c.argument !== root
    );
    assert.deepEqual(touchedRequest, [],
        'a stage (a) refusal must reach no primitive naming anything but the grant root');

    // Off win32 `NUL` is an ordinary name no screen refuses, and nothing above creates it.
    if (win32) assert.equal(fs.existsSync(path.join(root, 'NUL')), false);
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote);
});

/**
 * ⚠⚠ THIS ARM REPLACED `A46-posix-names`, AND WHY IT WAS DELETED IS THE POINT.
 *
 * `A46` constructed a gate with the Win32 name screens explicitly DISABLED, to exercise the POSIX
 * branch on a Windows host. Both round-1 review lenses independently returned HIGH: the option that
 * made it possible was a containment opt-out, and `A46` was driving REAL filesystem operations
 * through a deliberately disabled protection — including fixture entries combining stream syntax
 * with an outbound link — while silently accepting any non-refusal as success. The arm could have
 * performed the very escape the screen exists to prevent and reported green.
 *
 * The option is gone, so the POSIX branch is no longer constructible here and there is nothing left
 * to point an arm at. **That is recorded as lost coverage rather than papered over**: the POSIX
 * branch of these two screens is unexercised on this host, which folds into the standing
 * `POSIX is reasoned, never measured` row in `issuelog.md`.
 *
 * What CAN still be pinned on any host is that the screens follow the host and are not switchable,
 * which is what this arm does.
 */
test('A47-name-rules-host — the name screens follow the host and take no override', async () => {
    arm('A47-name-rules-host');

    // ⚠ THE OVERRIDE IS ASSERTED ABSENT, NOT ASSUMED ABSENT. Passing the removed option must not
    // resurrect it — if someone re-adds the field, this arm fails rather than the fence quietly
    // becoming configurable again. The cast is deliberate: the property is not in the type, and
    // that is exactly the state being pinned.
    const overridden = createFsGate(
        /** @type {any} */ ({ rawGrant: FX.grant, windowsNameRules: false })
    );
    assert.ok(!isRefusal(overridden), 'the fixture grant should be accepted');

    const win32 = process.platform === 'win32';

    // ⚠ BOTH SCREENS, NOT ONE. The first version drove only `note.md:hidden`, so a change that made
    // the DEVICE screen unconditional — or deleted it — passed this arm untouched while its name
    // and inventory row both claimed to cover "the two Win32 name screens". Caught by the
    // escalation lens.
    for (const [request, reason] of [['note.md:hidden', 'STREAM_SYNTAX'], ['NUL', 'RESERVED_NAME']]) {
        const result = await overridden.readFileInGrant(request, 0, 4096);
        // ⚠ NO `assert.ok(isRefusal(...))` HERE, AND ITS ABSENCE IS THE POINT. The first version
        // asserted the request still refuses on every host — which off win32 passes only by fixture
        // accident (the file does not exist, so MISSING), and which PINS THE OPPOSITE OF THIS
        // CHANGE'S OWN JUSTIFICATION: the day a fixture makes a colon-bearing file real, the arm
        // would go red for demonstrating exactly the capability the change exists to restore.
        // Only the reason-code discrimination below carries any weight, so only it is asserted.
        if (isRefusal(result)) {
            if (win32) {
                assert.equal(result.reason, reason,
                    `on win32 ${request} must hit ${reason}, and no option may disable it`);
            } else {
                assert.notEqual(result.reason, reason,
                    `off win32 ${request} must not hit ${reason}, and no option may enable it`);
            }
        } else {
            assert.ok(!win32, `on win32 ${request} must not resolve to content`);
        }
    }

    // ⚠ THE CREATE PATH KEEPS THE STREAM SCREEN ON EVERY HOST — the one asymmetry in `NameScreens`,
    // and the finding that produced it. On the create path this screen is the ONLY guard: the leaf
    // is joined lexically and never walked, so nothing downstream can see a `<link>:<stream>` name.
    const created = await overridden.createFileInGrant('note.md:hidden', Buffer.from('x'));
    assert.ok(isRefusal(created), 'a stream-syntax create must refuse on every host');
    assert.equal(created.reason, 'STREAM_SYNTAX',
        'the create-path stream screen is unconditional and takes no override');

    // The containment fence is independent of any of this, on every host.
    for (const request of ['../outside/escapee.md', 'subdir/../../outside/escapee.md']) {
        const escape = await overridden.readFileInGrant(request, 0, 4096);
        assert.ok(isRefusal(escape), `${request} must refuse`);
        assert.equal(escape.reason, 'ESCAPES', `${request} must refuse ESCAPES`);
    }
});

test('A40-create — a new file is created and written; the escapes refuse and create nothing', async () => {
    arm('A40-create');

    const made = await gate.createFileInGrant('created-by-a40.md', Buffer.from('hello\n'));
    assert.ok(!isRefusal(made), 'an in-grant new file must be created');
    assert.equal(made.rel, 'created-by-a40.md');
    assert.equal(made.bytes, 6);
    assert.equal(fs.readFileSync(path.join(root, 'created-by-a40.md'), 'utf8'), 'hello\n');

    // ⚠ THE RETURN CARRIES NO ABSOLUTE PATH. That is the shape ruling, asserted rather than assumed.
    assert.deepEqual(Object.keys(made).sort(), ['bytes', 'ok', 'rel']);

    const nested = await gate.createFileInGrant('subdir/created-by-a40.md', Buffer.from('nested\n'));
    assert.ok(!isRefusal(nested));
    assert.equal(nested.rel, path.join('subdir', 'created-by-a40.md'));

    // A parent that escapes is caught by the fence, not by a second check.
    for (const request of ['../outside/escapee.md', 'subdir/../../outside/escapee.md', 'j_out/escapee.md']) {
        const r = await gate.createFileInGrant(request, Buffer.from('nope'));
        assert.ok(isRefusal(r), `${request} must refuse`);
    }
    assert.equal(fs.existsSync(path.join(FX.outside, 'escapee.md')), false, 'nothing may be created outside');

    // The in-grant junction twin must still work, or the arm above proves only "refuses junctions".
    // ⚠ A DISTINCT NAME, deliberately: `j_in` is a junction to `subdir`, so this canonicalises into
    // `subdir` and reusing the name above would refuse EXISTS — correctly, and the arm would then
    // be reading its own earlier write as a junction failure.
    const viaJunction = await gate.createFileInGrant('j_in/via-junction.md', Buffer.from('via junction\n'));
    assert.ok(!isRefusal(viaJunction), 'an in-grant junction parent must still create');
    assert.equal(viaJunction.rel, path.join('subdir', 'via-junction.md'), 'and it lands on the canonical parent');

    // ⚠ THE DANGLING JUNCTION LIVES HERE, IN TIER 1, ON PURPOSE. Junction creation needs no
    // privilege, so this escape is reachable on a machine without Developer Mode — and an arm that
    // only ran in tier 2 would leave the unprivileged half of a reproduced escape untested exactly
    // where the fence is most likely to be running unattended. Its symlink twin is in A41.
    const dangleTarget = path.join(FX.outside, 'nodir2');
    assert.equal(fs.existsSync(dangleTarget), false, 'the dangling junction target must start absent');
    const dangled = await gate.createFileInGrant('dangle_junc_out', Buffer.from('MUST NOT LAND\n'));
    assert.ok(isRefusal(dangled), 'a dangling junction leaf must refuse');
    assert.equal(dangled.reason, 'EXISTS');
    assert.equal(fs.existsSync(dangleTarget), false,
        '⚠ the dangling junction CREATED a directory outside the grant');

    assert.equal((await gate.createFileInGrant('no-such-dir/child.md', Buffer.from('x'))).reason, 'MISSING');
    assert.equal((await gate.createFileInGrant('subdir/note.md/child.md', Buffer.from('x'))).reason, 'NOT_A_DIRECTORY');
    assert.equal((await gate.createFileInGrant('created-by-a40.md', 'not a buffer')).reason, 'BAD_INPUT');
});

test('A41-exists-refuses — anything already at the name refuses EXISTS, unfollowed', { ...tier2('A41-exists-refuses') }, async () => {
    arm('A41-exists-refuses');

    // ⚠⚠ THE ARM THE PREVIOUS SHAPE FAILED. `h_out.md` is a HARDLINK to outside/secret.md and
    // `s_out` is a symlink to it; the old seam accepted both as ordinary leaves and a write through
    // either landed outside the grant — reproduced, not theorised. Neither is inspected now: `wx`
    // means the OS refuses every existing object without following it, so the classes this fence
    // cannot enumerate (reparse tags it cannot classify) are covered by the same line.
    const before = fs.readFileSync(path.join(FX.outside, 'secret.md'));

    for (const request of ['h_out.md', 's_out', 's_in', 'j_out', 'j_in', 'subdir/note.md', 'subdir']) {
        const r = await gate.createFileInGrant(request, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), `${request} already exists and must refuse`);
        assert.equal(r.reason, 'EXISTS', `${request} must refuse EXISTS, got ${r.reason}`);
    }

    const after = fs.readFileSync(path.join(FX.outside, 'secret.md'));
    assert.ok(before.equals(after), 'the outside file must be byte-identical afterwards');

    // ⚠⚠ THE DANGLING CASE — THE ONE THE WHOLE CORPUS AVOIDED, AND A REPRODUCED ESCAPE.
    //
    // `wx` refuses existing OBJECTS, not existing NAMES. Win32 `CREATE_NEW` takes STATUS_REPARSE
    // and retries at the substituted path, so a link whose target does NOT exist is FOLLOWED and
    // the file is created there. Measured against this gate before the fix: `dangle_out` returned
    // CREATED with the bytes landing in `outside/`, and the junction returned a clean-looking
    // NOT_A_FILE refusal having already created the outside directory.
    //
    // The assertion that matters is not the refusal — it is that the outside target STILL DOES NOT
    // EXIST afterwards. A refusal returned after the filesystem was already mutated is the shape
    // that made this invisible.
    for (const [request, target] of [
        ['dangle_out', path.join(FX.outside, 'nope.md')],
        ['dangle_junc_out', path.join(FX.outside, 'nodir2')]
    ]) {
        assert.equal(fs.existsSync(target), false, `${target} must not exist before the arm runs`);
        const r = await gate.createFileInGrant(request, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), `${request} must refuse`);
        assert.equal(r.reason, 'EXISTS', `${request} must refuse EXISTS, got ${r.reason}`);
        assert.equal(fs.existsSync(target), false,
            `⚠ ${request} CREATED SOMETHING OUTSIDE THE GRANT at ${target}`);
    }

    // ⚠⚠ AND AGAIN ON AN UNINJECTED GATE — WITHOUT THIS THE ARM ABOVE TESTS THE SPY, NOT THE FENCE.
    //
    // `spyPrimitives` supplies its own `openExclusive`, and it re-implements the open rather than
    // delegating to the production one — so every assertion above exercises the SPY's `wx`, and the
    // real `_openExclusive` is never reached. Mutation M48 (`wx` -> `w`) survived against the
    // injected gate for exactly that reason: the instrumentation had quietly replaced the thing
    // under test, and the arm looked like coverage it did not have.
    //
    // This half runs on the production primitives, which is the only place the shipped flag is
    // observable. Same pattern as `A36-defaults`, for the same reason.
    const bare = createFsGate({ rawGrant: FX.grant });
    assert.ok(!isRefusal(bare));
    const bareBefore = fs.readFileSync(path.join(FX.outside, 'secret.md'));
    for (const request of ['h_out.md', 's_out', 'subdir/note.md']) {
        const r = await bare.createFileInGrant(request, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), `${request} must refuse on the PRODUCTION primitives`);
        assert.equal(r.reason, 'EXISTS', `${request} must refuse EXISTS uninjected, got ${r.reason}`);
    }
    assert.ok(
        bareBefore.equals(fs.readFileSync(path.join(FX.outside, 'secret.md'))),
        'the outside file must survive the uninjected pass byte-identical'
    );

    // ⚠⚠ AND ONE UNINJECTED CREATE THAT SUCCEEDS, BYTE-COMPARED.
    //
    // Every assertion above refuses at OPEN, so none of them reaches the shipped `writeAll` — the
    // production writer had no arm at all, and a mutant returning a short count would have survived
    // exactly the way M48 did. This is the same blind spot one level down: fixing the open half and
    // leaving the write half is how a repair looks complete while covering one of two primitives.
    // ⚠ THE SIZE IS LOAD-BEARING AND 2048 BYTES WAS TOO SMALL. A short write is what this arm
    // exists to catch, and a single `writeSync` comfortably completes a small buffer — so the
    // payload must exceed a realistic single-call ceiling or the arm proves nothing. Mutation M50
    // survived against a 2048-byte payload for exactly this reason.
    const payload = Buffer.from('uninjected write, byte-compared\n'.repeat(400)); // ~12.8 KB
    const wrote = await bare.createFileInGrant('uninjected-a41.md', payload);
    assert.ok(!isRefusal(wrote), 'the uninjected gate must create');
    assert.equal(wrote.bytes, payload.length, 'the reported count must be the whole payload');
    assert.ok(
        payload.equals(fs.readFileSync(path.join(root, 'uninjected-a41.md'))),
        'the file on disk must be byte-identical to what was handed in — a short write is data loss'
    );
});

test('A45-root-identity — a re-spelled root is accepted; a replaced one refuses, and folding fails both', async () => {
    arm('A45-root-identity');

    // ⚠⚠ THE ARM BOTH ROUND-4 LENSES SAID WAS MISSING, AND THEY WERE RIGHT: `A35-root-moved` swaps
    // the root for a junction to `evil`, whose spelling differs by far more than case — so it goes
    // red under case-folding, under exact comparison, and under identity alike. Nothing
    // DISCRIMINATED the three, and a regression to `toLowerCase()` would have stayed green through
    // two rounds that were specifically looking for it.
    //
    // This arm separates them by injecting the primitives, which is the only way to stage a
    // case-only re-spelling without a case-sensitive volume to hand.
    const canonical = fs.realpathSync.native(FX.grant);
    const reSpelled = canonical.toUpperCase();

    // ⚠ THE RE-SPELLING MUST HAPPEN AFTER STARTUP, NOT AT IT. The first version of this arm made
    // `realpathNative` return the same altered spelling on every call, so the stored root and the
    // recheck's answer matched and the comparison branch never ran — the arm exercised nothing and
    // said so by failing. A counter stages the rename between construction and the request, which
    // is the actual scenario.
    const stagedRealpath = () => {
        let seen = 0;
        return t => {
            const real = fs.realpathSync.native(t);
            if (real.toLowerCase() === canonical.toLowerCase()) {
                seen += 1;
                return seen === 1 ? real : reSpelled;   // renamed after the gate was built
            }
            return real;
        };
    };

    // (a) SAME OBJECT, DIFFERENT SPELLING — must be ACCEPTED. Exact comparison alone refuses this,
    //     which was the round-3 regression; identity is what rescues it.
    const respelled = createFsGate({
        rawGrant: FX.grant,
        primitives: { ...spyPrimitives([]), realpathNative: stagedRealpath() }
    });
    assert.ok(!isRefusal(respelled), 'a gate over a re-spellable root must construct');
    const readBack = await respelled.readFileInGrant('subdir/note.md', 0, 4096);
    assert.ok(!isRefusal(readBack),
        `a case-only re-spelling of the SAME directory must not refuse: ${readBack.reason}`);

    // (b) DIFFERENT OBJECT, SPELLING DIFFERING ONLY BY CASE — must REFUSE. This is the half
    //     case-folding gets wrong: it compares the spellings equal and serves through the
    //     replacement. Only identity separates it from (a), which is what makes the pair a
    //     discriminator rather than two restatements of A35.
    const swapped = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            realpathNative: stagedRealpath(),
            lstat: t => {
                const st = fs.lstatSync(t);
                if (t === reSpelled) {
                    // The re-spelled name now names a DIFFERENT object.
                    return { dev: st.dev, ino: st.ino + 1n === st.ino ? 1 : Number(st.ino) + 1,
                        isDirectory: () => true, isSymbolicLink: () => false, size: st.size };
                }
                return st;
            }
        }
    });
    assert.ok(!isRefusal(swapped), 'the swapped-root gate must construct before the swap is seen');
    const r = await swapped.readFileInGrant('subdir/note.md', 0, 4096);
    assert.ok(isRefusal(r), 'a root whose OBJECT changed must refuse even when only the case differs');
    assert.equal(r.reason, 'ROOT_MOVED');
});

test('A43-probe-errors — only ENOENT reaches the open; every other probe failure refuses', async () => {
    arm('A43-probe-errors');

    // ⚠ THE RULE THIS PINS IS "ONLY `ENOENT` PROCEEDS", and until now nothing measured it. `M49`
    // deletes the success branch; nothing exercised the CATCH condition, so a regression letting
    // every probe error through would have been invisible. Both round-3 lenses found this
    // independently, which is the strongest signal a gap is real.
    const cases = [
        { label: 'EACCES', code: 'EACCES', reason: 'DENIED' },
        { label: 'EPERM', code: 'EPERM', reason: 'DENIED' },
        { label: 'EIO', code: 'EIO', reason: 'IO_ERROR' },
        { label: 'ENOTDIR', code: 'ENOTDIR', reason: 'NOT_A_DIRECTORY' },
        { label: 'ELOOP', code: 'ELOOP', reason: 'ELOOP' },
        { label: 'EISDIR', code: 'EISDIR', reason: 'NOT_A_FILE' },
        { label: 'ENAMETOOLONG', code: 'ENAMETOOLONG', reason: 'NAME_TOO_LONG' },
        { label: 'an error with no code', reason: 'IO_ERROR' },
        { label: 'an unrecognised-code error', code: 'EUNRECOGNISED', reason: 'IO_ERROR' }
    ];
    for (const { label, code, reason } of cases) {
        let openedAnyway = false;
        // ⚠ THE WITNESS, AND WITHOUT IT THREE OF THESE ROWS COULD PASS FOR THE WRONG REASON.
        // A review lens found that `EIO`, the no-code row and the unrecognised-code row all expect
        // `IO_ERROR` — which is also what a regression returning an EARLIER `IO_ERROR` would
        // produce, never reaching the injected probe at all. The row would go green while testing
        // nothing about the leaf probe. Counting the hook is what makes the arm's claim about the
        // probe rather than about the reason code.
        let leafProbeCalls = 0;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                // Fail ONLY the leaf probe. Every other lstat — the walk, the parent — behaves.
                lstat: t => {
                    if (path.basename(t) === 'probe-target.md') {
                        leafProbeCalls += 1;
                        const error = new Error(`injected ${label}`);
                        if (code !== undefined) error.code = code;
                        throw error;
                    }
                    return fs.lstatSync(t);
                },
                openExclusive: t => { openedAnyway = true; return fs.openSync(t, 'wx'); }
            }
        });
        assert.ok(!isRefusal(injected));

        const r = await injected.createFileInGrant('probe-target.md', Buffer.from('x'));
        assert.ok(isRefusal(r), `${label}: the leaf probe must refuse, not create`);
        assert.equal(r.reason, reason, `${label}: the probe must map to its actual refusal reason`);
        assert.notEqual(r.reason, 'EXISTS', `${label}: the probe must not be reported as EXISTS`);
        assert.equal(leafProbeCalls, 1,
            `⚠ ${label}: the refusal did NOT come from the leaf probe — this row proved nothing`);
        assert.equal(openedAnyway, false, `⚠ ${label}: the probe REACHED THE OPEN`);
        assert.equal(fs.existsSync(path.join(root, 'probe-target.md')), false,
            `${label}: the probe must create nothing`);
    }
});

test('A44-short-write — a short write refuses IO_ERROR rather than reporting a smaller success', async () => {
    arm('A44-short-write');

    // ⚠ THE COMPLETION LOOP AND THE CLASSIFICATION ARE SEPARATE GUARDS, and only the loop was
    // pinned. `M50` forces a single-call write and `A41`'s byte-compare catches it — but nothing
    // asserted that a write which genuinely cannot complete is reported as a FAILURE rather than
    // as `ok: true` with a reduced count. That reduced-count contract is the original defect, and
    // a caller has no way to notice it.
    const payload = Buffer.from('x'.repeat(1000));
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            // A writer that cannot finish, however many times it is asked.
            writeAll: () => 10
        }
    });
    assert.ok(!isRefusal(injected));

    const r = await injected.createFileInGrant('short-write.md', payload);
    assert.ok(isRefusal(r), 'a short write must refuse, not report a smaller success');
    assert.equal(r.reason, 'IO_ERROR');
    assert.match(r.detail, /10 of 1000 bytes/);

    // ⚠ SAME WITNESS AS A43's, AND FOR THE SAME REASON. `IO_ERROR` is what this row expects and
    // also what a regression refusing BEFORE `writeAll` would return, so without counting the hook
    // the row cannot tell "the short-write guard fired" from "something else failed first".
    let zeroWriteCalls = 0;
    const zeroWriter = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            writeAll: () => { zeroWriteCalls += 1; return 0; }
        }
    });
    assert.ok(!isRefusal(zeroWriter), 'writeAll returns 0: the gate must construct');

    const zero = await zeroWriter.createFileInGrant('zero-write.md', Buffer.from('x'));
    assert.ok(isRefusal(zero), 'writeAll returns 0: no-progress must refuse, not report success');
    assert.equal(zero.reason, 'IO_ERROR', 'writeAll returns 0: no-progress must be IO_ERROR');
    assert.match(zero.detail, /0 of 1 bytes/, 'writeAll returns 0: detail must report zero progress');
    assert.equal(zeroWriteCalls, 1,
        '⚠ writeAll returns 0: the refusal did NOT come from the write — this case proved nothing');

    const emptyGate = createFsGate({
        rawGrant: FX.grant,
        primitives: spyPrimitives([])
    });
    assert.ok(!isRefusal(emptyGate), 'empty buffer: the gate must construct');

    const empty = await emptyGate.createFileInGrant('empty-write.md', Buffer.alloc(0));
    assert.ok(!isRefusal(empty), 'empty buffer: zero bytes is a complete, successful write');
    assert.equal(empty.bytes, 0, 'empty buffer: success must report zero bytes written');
    assert.equal(fs.readFileSync(path.join(root, 'empty-write.md')).length, 0,
        'empty buffer: the created file must be empty');
});

/* ------------------------------------------------------------------ *
 * The write-failure outcome — S1, ruled 2026-08-31 (fork 3B + 3b).     *
 *                                                                      *
 * ⚠ THESE ARMS ASSERT RETENTION, NEVER ABSENCE. A failed write LEAVES  *
 * its target and REPORTS that it did; deleting the leftover was ruled  *
 * out because deleting by path reopens the TOCTOU and deleting by      *
 * handle has no pure-Node form. An arm here asserting the file is gone *
 * would be asserting the rejected design.                              *
 * ------------------------------------------------------------------ */

test('A47-write-throws-retains — a throwing write refuses AND reports what it left', async () => {
    arm('A47-write-throws-retains');

    // ⚠ THE WITNESS COUNTER IS NOT DECORATION. `IO_ERROR` is also what a regression refusing
    // EARLIER would return, so without counting the hook the arm cannot tell "the write threw"
    // from "something refused before the write". Same defect the s4rev review found on A43/A44.
    let writeCalls = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            writeAll: () => {
                writeCalls += 1;
                const error = new Error('injected EIO');
                error.code = 'EIO';
                throw error;
            }
        }
    });
    assert.ok(!isRefusal(injected));

    const r = await injected.createFileInGrant('write-throws.md', Buffer.from('never lands'));
    assert.ok(isRefusal(r), 'a throwing write must refuse');
    assert.equal(r.reason, 'IO_ERROR');
    assert.equal(writeCalls, 1, '⚠ the refusal did NOT come from the write — this arm proved nothing');
    assert.notEqual(r.retained, null, 'a post-creation failure must report the file it left');
    assert.equal(r.retained.rel, 'write-throws.md');
    assert.equal(r.retained.state, 'indeterminate');
    // ⚠ RETENTION, ASSERTED. The file staying is the ruled behaviour, not a leak.
    assert.equal(fs.existsSync(path.join(root, 'write-throws.md')), true,
        'the ruled behaviour RETAINS the target; an absent file means someone added an unlink');
});

test('A48-short-write-retains — a short write refuses AND reports the truncated file', async () => {
    arm('A48-short-write-retains');

    let writeCalls = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            writeAll: () => { writeCalls += 1; return 3; }
        }
    });
    assert.ok(!isRefusal(injected));

    const r = await injected.createFileInGrant('short-retains.md', Buffer.from('x'.repeat(50)));
    assert.ok(isRefusal(r), 'a short write must refuse');
    assert.equal(r.reason, 'IO_ERROR');
    assert.match(r.detail, /3 of 50 bytes/);
    assert.equal(writeCalls, 1, '⚠ the refusal did NOT come from the write — this arm proved nothing');
    assert.notEqual(r.retained, null, 'the truncated file must be reported, not silently left');
    assert.equal(r.retained.rel, 'short-retains.md');
    assert.equal(r.retained.state, 'indeterminate');
    assert.equal(fs.existsSync(path.join(root, 'short-retains.md')), true,
        'the truncated file stays; the refusal is how the caller learns it is there');
});

test('A49-close-fails-after-write — a failed close is a refusal, and closes exactly once', async () => {
    arm('A49-close-fails-after-write');

    // ⚠⚠ THE INJECTED CLOSE PERFORMS THE REAL CLOSE AND *THEN* THROWS. A close that only throws
    // would leak the descriptor and force the arm to choose between leaking and contradicting its
    // own count; doing the real work first means exactly one gate-level close call, no leak, and
    // no contradiction.
    let closeCalls = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            close: fd => {
                closeCalls += 1;
                fs.closeSync(fd);
                const error = new Error('injected close failure');
                error.code = 'EIO';
                throw error;
            }
        }
    });
    assert.ok(!isRefusal(injected));

    const payload = Buffer.from('complete content\n');
    const r = await injected.createFileInGrant('close-fails.md', payload);

    // Against `main` this returned `ok: true` — the success was constructed inside the `try` and
    // the close error was swallowed by a bare `catch {}` in the `finally`.
    assert.ok(isRefusal(r), 'a failed close must refuse; the bytes may never have reached the disk');
    assert.equal(r.reason, 'IO_ERROR');
    assert.match(r.detail, /failed to close/);
    assert.notEqual(r.retained, null, 'the file exists and its content is unflushed-or-complete');
    assert.equal(r.retained.rel, 'close-fails.md');
    assert.equal(r.retained.state, 'indeterminate');

    // ⚠⚠ EQUALITY, NOT `>= 1`. A "did it reach close" assertion goes green against the
    // double-close defect — flag set AFTER the call, so a throwing close leaves it false and the
    // `finally` closes an already-released descriptor. `=== 1` is the only form that sees it, and
    // it is the sole killer of M69.
    assert.equal(closeCalls, 1, '⚠ the descriptor was closed twice — the close flag is set too late');
    assert.equal(fs.existsSync(path.join(root, 'close-fails.md')), true, 'the target is retained');
});

test('A50-refusal-before-open-retains-nothing — a pre-open refusal states retained: null', async () => {
    arm('A50-refusal-before-open-retains-nothing');

    // ⚠ THE OTHER HALF OF THE CHECK. Without it the field could be populated unconditionally and
    // every retention arm above would still pass — the `null` rows are what make `retained`
    // informative rather than a constant.
    let opens = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            openExclusive: t => { opens += 1; return fs.openSync(t, 'wx'); }
        }
    });
    assert.ok(!isRefusal(injected));

    const cases = [
        { label: 'EXISTS (the leaf probe finds the name taken)', request: 'subdir/note.md', reason: 'EXISTS' },
        { label: 'a lexical escape', request: '../outside/secret.md', reason: 'ESCAPES' },
        { label: 'a non-Buffer payload', request: 'never-opened.md', bytes: 'not a buffer', reason: 'BAD_INPUT' }
    ];
    for (const { label, request, bytes, reason } of cases) {
        const r = await injected.createFileInGrant(request, bytes ?? Buffer.from('x'));
        assert.ok(isRefusal(r), `${label}: must refuse`);
        assert.equal(r.reason, reason, `${label}: reason`);
        assert.ok('retained' in r, `⚠ ${label}: the field is REQUIRED — a missing one is the M65 shape`);
        assert.equal(r.retained, null, `⚠ ${label}: nothing was opened, so nothing may be reported as left`);
    }
    assert.equal(opens, 0, '⚠ a pre-open refusal reached the open — these rows proved the wrong thing');
});

test('A51-nonexistent-errno-retains-indeterminate — a non-EEXIST open failure is indeterminate', async () => {
    arm('A51-nonexistent-errno-retains-indeterminate');

    // ⚠ THE PRIMITIVE IS INJECTABLE AND ITS CONTRACT PROMISES NOTHING ABOUT WHAT A THROWING
    // IMPLEMENTATION MATERIALISED. This one materialises the target and then throws — a legal
    // implementation of the declared contract, and the reason `null` here would be unsound.
    let opens = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            openExclusive: t => {
                opens += 1;
                fs.writeFileSync(t, 'partial', { flag: 'wx' });
                const error = new Error('injected EIO after materialising');
                error.code = 'EIO';
                throw error;
            }
        }
    });
    assert.ok(!isRefusal(injected));

    const r = await injected.createFileInGrant('errno-open.md', Buffer.from('x'));
    assert.ok(isRefusal(r), 'a throwing open must refuse');
    assert.equal(r.reason, 'IO_ERROR');
    assert.equal(opens, 1, '⚠ the refusal did NOT come from the open — this arm proved nothing');
    assert.notEqual(r.retained, null,
        '⚠ a non-EEXIST open failure may NOT claim nothing was created — the primitive never promised that');
    assert.equal(r.retained.rel, 'errno-open.md');
    assert.equal(r.retained.state, 'indeterminate');
    assert.equal(fs.existsSync(path.join(root, 'errno-open.md')), true,
        'this injection really did materialise the target — that is the whole point of the arm');
});

test('A53-post-probe-exists-retains-nothing — an EEXIST at the open retains nothing', async () => {
    arm('A53-post-probe-exists-retains-nothing');

    // ⚠⚠ THIS BRANCH IS NOT A50's. A50's ordinary existing-file case returns from `resolveNew`
    // BEFORE `openExclusive` is ever called, so it cannot reach the `wx` refusal — the branch the
    // flag exists for, where an object appears between the leaf probe and the open. The open
    // witness is what distinguishes the two arms; without it they are indistinguishable and a
    // mutant giving this branch `retained: indeterminate` would pass every other arm.
    let opens = 0;
    let leafProbes = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            // The probe says the name is free...
            lstat: t => {
                if (path.basename(t) === 'post-probe.md') {
                    leafProbes += 1;
                    const error = new Error('injected ENOENT — the name is free');
                    error.code = 'ENOENT';
                    throw error;
                }
                return fs.lstatSync(t);
            },
            // ...and by the time the open runs, something else owns it.
            openExclusive: () => {
                opens += 1;
                const error = new Error('injected EEXIST — the race lost');
                error.code = 'EEXIST';
                throw error;
            }
        }
    });
    assert.ok(!isRefusal(injected));

    const r = await injected.createFileInGrant('post-probe.md', Buffer.from('x'));
    assert.ok(isRefusal(r), 'the post-probe race must refuse');
    assert.equal(r.reason, 'EXISTS');
    assert.equal(leafProbes, 1, 'the leaf probe must have run and reported the name free');
    assert.equal(opens, 1, '⚠ THE OPEN WAS NEVER REACHED — this arm is then a duplicate of A50');
    assert.equal(r.retained, null,
        '⚠ EEXIST means something ELSE owns the name; this invocation created nothing to report');
});

test('A52-success-closes-once — a successful write closes its descriptor exactly once', async () => {
    arm('A52-success-closes-once');

    // ⚠⚠ THIS ARM PASSES AGAINST TODAY'S `main`, AND SAYING SO IS THE POINT. It is a regression
    // guard against a double-close the restructure could introduce, not evidence of new behaviour.
    // Counting it as coverage for the S1 change would inflate what the change is shown to do.
    let closeCalls = 0;
    const injected = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            close: fd => { closeCalls += 1; return fs.closeSync(fd); }
        }
    });
    assert.ok(!isRefusal(injected));

    const made = await injected.createFileInGrant('closes-once.md', Buffer.from('once\n'));
    assert.ok(!isRefusal(made), 'the ordinary success path must still create');
    assert.equal(made.bytes, 5);
    assert.equal(closeCalls, 1, 'a successful write closes exactly once — never zero, never twice');
    assert.equal(fs.readFileSync(path.join(root, 'closes-once.md'), 'utf8'), 'once\n');
    // The success shape is unchanged by S1: no `retained` field on a success.
    assert.deepEqual(Object.keys(made).sort(), ['bytes', 'ok', 'rel']);
});

test('A42-hash — a source hashes through the gate, and no result carries an absolute path', async () => {
    arm('A42-hash');
    const seen = VIOLATIONS.length;

    const hashed = await gate.hashInGrant('subdir/note.md');
    assert.ok(!isRefusal(hashed), 'an in-grant source must hash');
    assert.equal(hashed.algorithm, 'sha256');
    assert.equal(hashed.rel, path.join('subdir', 'note.md'));
    assert.equal(hashed.size, Buffer.byteLength(CANARY.inGrantNote));
    // Independently computed, so the arm asserts the DIGEST rather than merely its shape.
    assert.equal(
        hashed.digest,
        createHash('sha256').update(fs.readFileSync(path.join(root, 'subdir', 'note.md'))).digest('hex')
    );

    // ⚠⚠ HASH REFUSALS ARE ASSERTED TO BE REFUSALS, not merely inspected for their fields.
    // The field sweep below checks SHAPE; without these, a regression that hashed `j_out/x.md`
    // through the in-grant junction spelling would read an outside file, return a digest carrying
    // no absolute path, and pass the arm cleanly. A review lens found that gap.
    for (const request of ['j_out/x.md', 's_out', '../outside/secret.md', 'j_out']) {
        const r = await gate.hashInGrant(request);
        assert.ok(isRefusal(r), `hashInGrant(${request}) must refuse, it returned a digest`);
    }

    // ⚠ EVERY RESULT BRANCH IS INSPECTED, SUCCESSES INCLUDED. The previous A42 skipped successes
    // with an early `continue`, so the arm named "names no outside path in any field" never once
    // looked at a success record. A review lens found that; it is not repeated here.
    const probes = [
        'subdir/note.md', '../outside/secret.md', path.join(FX.outside, 'secret.md'),
        'no-such-note.md', 'C:notes', 'note.md::$DATA', 'NUL', 'j_out/x.md'
    ];
    for (const request of probes) {
        const results = [
            await gate.hashInGrant(request),
            await gate.createFileInGrant(request, Buffer.from('probe'))
        ];
        for (const result of results) {
            for (const [field, value] of Object.entries(result)) {
                if (typeof value !== 'string') continue;
                assert.equal(path.isAbsolute(value), false,
                    `${request}: \`${field}\` carried an absolute path: ${value}`);
                assert.equal(outsideRoot(root, value), false,
                    `${request}: \`${field}\` named an outside path: ${value}`);
                assert.ok(!value.includes(FX.outside),
                    `${request}: \`${field}\` embedded the outside root: ${value}`);
            }
        }
    }

    assert.equal(VIOLATIONS.length, seen, 'no primitive may be handed an outside path by the seam');
});
