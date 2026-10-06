import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';

// ⚠ THE SUBJECT IS THIS PACKAGE'S OWN BUILD OUTPUT, REACHED BY RELATIVE PATH — and that is the
// opposite of the rule that applies in a CONSUMER. `wyrd-mcp` asks for the fence by package name
// so it cannot acquire a deep-path coupling to a sibling's layout. Here the layout IS this
// package's, `wyrd-fence` resolving from inside `wyrd-fence` would depend on a workspace symlink
// that a published checkout does not have, and the import audit refuses a shipped file whose
// relative dependency lives in another package. `../dist/fsgate.js` is the same file `types` and
// `exports` declare, and `dist/` maps back to `src/fsgate.ts`, which ships.
import { createFsGate, isRefusal } from '../dist/fsgate.js';
import { buildFixture, CANARY, teardown } from './fixtures.mjs';
import { declare as arm, tier2 } from './manifest.mjs';

test('A83-metadata-rel-slashes — nested metadata uses the same forward-slash rel as the grant walk', async () => {
    arm('A83-metadata-rel-slashes');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-metadata-rel-'));
    const grant = path.join(base, 'grant');
    try {
        fs.mkdirSync(path.join(grant, 'folder'), { recursive: true });
        fs.writeFileSync(path.join(grant, 'folder', 'file.md'), 'nested');
        const gate = createFsGate({ rawGrant: grant, primitives: {
            placeholderAttributes: async () => ({ attributes: 0, reparseTag: 0 })
        } });
        assert.equal(isRefusal(gate), false);
        const metadata = await gate.fileMetadataInGrant(path.join('folder', 'file.md'));
        assert.equal(isRefusal(metadata), false);
        assert.equal(metadata.rel, 'folder/file.md');
        const walk = await gate.walkGrant();
        assert.equal(isRefusal(walk), false);
        assert.equal(walk.files.length, 1);
        assert.equal(metadata.rel, walk.files[0].rel);
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('SR15-walk-alias-cycle — a fresh grant walk handles aliases and refuses escapes', async () => {
    arm('SR15-walk-alias-cycle');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-walk-'));
    const grant = path.join(base, 'grant');
    const outside = path.join(base, 'outside');
    try {
        fs.mkdirSync(grant);
        fs.mkdirSync(outside);
        fs.mkdirSync(path.join(grant, 'inside'));
        fs.mkdirSync(path.join(grant, 'cloud'));
        fs.writeFileSync(path.join(grant, 'cloud', 'hidden.md'), 'dehydrated');
        fs.writeFileSync(path.join(grant, 'inside', 'pass.md'), 'inside');
        fs.writeFileSync(path.join(outside, 'deny.md'), 'outside');
        fs.symlinkSync(path.join(grant, 'inside'), path.join(grant, 'alias'), process.platform === 'win32' ? 'junction' : 'dir');
        fs.symlinkSync(grant, path.join(grant, 'cycle'), process.platform === 'win32' ? 'junction' : 'dir');
        fs.symlinkSync(outside, path.join(grant, 'escape'), process.platform === 'win32' ? 'junction' : 'dir');
        const opens = [];
        const listings = [];
        const gate = createFsGate({ rawGrant: grant, primitives: {
            open: (target, flags) => { opens.push(target); return fs.openSync(target, flags); },
            lstat: target => Object.assign(fs.lstatSync(target), { ino: 1 }),
            readdir: target => { listings.push(target); return fs.readdirSync(target, { withFileTypes: true }); },
            placeholderAttributes: async target => ({ attributes: path.basename(target) === 'cloud' ? 0x1000 : 0, reparseTag: 0 })
        } });
        assert.equal(isRefusal(gate), false);
        const walk = await gate.walkGrant();
        assert.equal(isRefusal(walk), false);
        assert.equal(walk.files.length, 1, 'the alias and cycle do not repeat the file');
        assert.match(walk.files[0].rel, /^(alias|inside)\/pass\.md$/);
        assert.ok(walk.inaccessible_count >= 1, 'outside alias is refused');
        assert.equal(JSON.stringify(walk).includes(base), false, 'no resolved pathname escapes');
        assert.equal(opens.length, 0, 'enumeration never opens content');
        assert.equal(listings.some(target => path.basename(target) === 'cloud'), false, 'dehydrated directory is not enumerated');
        const passing = await gate.readFileInGrant('inside/pass.md', 0, 20);
        assert.equal(passing.bytes.toString(), 'inside');
        const refused = await gate.readFileInGrant('escape/deny.md', 0, 20);
        assert.equal(isRefusal(refused), true);
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

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
 * primitives throw on any path argument outside the canonical root, so the hardlink limit in
 * README.md is asserted where paths actually OPEN, not only where they are refused.
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

/**
 * Is this recorded call one of `rootStillCanonical`'s own, on the granted root?
 *
 * ⚠⚠ TWO CALLS ARE RECORDED: real path and numeric `lstat` of the root. The latter became
 * unconditional under F8 (2026-09-03). The exact-ID read added later uses `lstatBigint`, which
 * this spy does not record; it still names only the canonical root.
 *
 * ⚠ THE ALLOWANCE IS STILL PINNED TO THE CANONICAL ROOT, WHICH IS THE WHOLE POINT. These arms
 * assert that the NAME SCREENS reach the filesystem zero times before a request is refused; they
 * were never about the root re-check, which runs first and touches only the grant itself. Widening
 * the allowance to the second call keeps that assertion exactly as strong: a touch of anything
 * other than the canonical root — above all the REQUESTED path — still fails the arm.
 */
function isRootRecheck(call, canonicalRoot) {
    return (call.name === 'realpathNative' || call.name === 'lstat')
        && call.argument === canonicalRoot;
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
        openExclusive: t => { record('openExclusive', t); return fs.openSync(t, 'wx'); },
        replaceStaged: (stage, target) => { record('replaceStaged', stage); record('replaceTarget', target); return fs.renameSync(stage, target); },
        // ⚠ THE APPEND OPEN IS MIRRORED FOR THE SAME REASON `openExclusive` IS: `createFsGate`
        // falls back to the production primitive for anything not supplied, so a spy table missing
        // it would leave every append outside the containment guard while the suite still looked
        // fully instrumented. It DELEGATES the mode rather than re-deciding it — re-implementing
        // the flag choice here is the M48 shape, where the instrumentation stood in for the code.
        openAppend: (t, mode) => {
            record('openAppend', t);
            return mode === 'exclusive-create'
                ? fs.openSync(t, 'ax')
                : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
        }
        // ⚠⚠ `appendOnce` IS DELIBERATELY NOT SUPPLIED, exactly as `writeAll` is not, and for the
        // same reason one level over: the shipped `_appendOnce` is the single `fs.writeSync` whose
        // ONE-CALL property is the contract, and a spy standing in for it would mean no arm ever
        // exercised the shipped one. Its first argument is a descriptor, never a path, so the
        // containment guard was never buying anything here.
        //
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
            const outsideArgument = args.find(arg => typeof arg === 'string' && ROOT_GUARD !== null && outsideRoot(ROOT_GUARD, arg));
            if (outsideArgument !== undefined) {
                // Record BEFORE throwing, and into an array the fence cannot swallow.
                VIOLATIONS.push({ primitive: name, argument: outsideArgument });
                sink.push({ name, argument: outsideArgument });
                const error = new Error(`FENCE VIOLATION: ${name} named ${outsideArgument}, outside ${ROOT_GUARD}`);
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

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const overwriteDir = () => fs.mkdtempSync(path.join(root, 'ow-'));
const overwriteGate = overrides => {
    const made = createFsGate({ rawGrant: FX.grant, primitives: { ...guardingPrimitives([]), ...overrides } });
    assert.ok(!isRefusal(made));
    return made;
};
const relative = absolute => path.relative(root, absolute);

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

test('A25-case — a case-only difference follows the HOST filesystem, measured rather than assumed', async () => {
    arm('A25-case');

    // ⚠⚠ TWO CLAIMS WERE CONFLATED HERE AND ONE OF THEM WAS SILENTLY PLATFORM-DEPENDENT. The arm
    // read `text('SUBDIR\\NOTE.MD')` and called the result "a case-only difference". That request
    // carries a BACKSLASH — a separator on Win32 and an ordinary filename character on POSIX — and
    // it assumed case folding, which is a property of the FILESYSTEM rather than of the fence. Off
    // Windows the request did not name the file it meant, so whatever the arm did there, it was
    // not what it said.
    //
    // ⚠ NOTHING IT ASSERTED ON WINDOWS IS WEAKENED. Both spellings are still required to reach the
    // file and the folded read is still required to SUCCEED; the POSIX branch is added beside them,
    // not in place of them.
    //
    // ⚠ THE FOLD IS MEASURED ON THE FIXTURE'S OWN VOLUME, never inferred from `process.platform`.
    // The fixture is built under the OS temp directory, which need not share a filesystem with this
    // checkout, and macOS ships case-INSENSITIVE by default while its POSIX siblings do not. So
    // `platform` cannot answer this and `fs.existsSync` over the real fixture can.
    const folds = fs.existsSync(path.join(FX.grant, 'SUBDIR', 'NOTE.MD'));

    // Backslash is a separator on Win32 only; `A37-request-separators` owns the separator claim.
    const spellings = process.platform === 'win32'
        ? ['SUBDIR\\NOTE.MD', 'SUBDIR/NOTE.MD']
        : ['SUBDIR/NOTE.MD'];

    // ⚠ SAID OUT LOUD, THE WAY `--portable` NAMES WHAT IT HELD BACK. An arm whose claim narrows on
    // some hosts has to report the narrowing where the run is read, or the green is worth less than
    // it looks.
    console.log(
        `    A25-case: this filesystem ${folds ? 'FOLDS case' : 'is case-SENSITIVE'}; `
        + `${spellings.length} spelling(s) exercised`
        + (process.platform === 'win32'
            ? '; 0 held back.'
            : '; the backslash spelling is HELD BACK — it is not a separator on this platform.')
    );

    for (const request of spellings) {
        if (folds) {
            assert.equal(await text(request), CANARY.inGrantNote, `${request} must reach the same file`);
        } else {
            // ⚠ THE OTHER BRANCH IS AN ASSERTION, NOT A SKIP. On a case-sensitive filesystem the
            // gate must report the name MISSING rather than finding a near match — a gate doing its
            // own case folding would be resolving to a file the caller did not name.
            const r = await refusal(request);
            assert.equal(r.reason, 'MISSING', `${request} must refuse MISSING on a case-sensitive filesystem`);
        }
    }

    // ⚠ THE PAIR, AND IT RUNS ON BOTH BRANCHES. Without it a gate that refused everything would
    // pass the case-sensitive branch and one that opened everything would pass the folding branch.
    assert.equal(await text('subdir/note.md'), CANARY.inGrantNote, 'the exactly-spelled request must open');
    assert.equal((await refusal('subdir/absent.md')).reason, 'MISSING', 'a genuinely absent in-grant name is MISSING');
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

/**
 * ⚠⚠ A35 STAGES THE ROOT RE-CHECK'S OBSERVATION; IT DOES NOT WAIT FOR AN OS CACHE.
 *
 * The rename and junction below are real, and `reveal` first proves through an uninjected
 * `fs.realpathSync.native` call that the OS resolves the granted root to the replacement. Only
 * after that precondition holds does `realpathNative(canonicalRoot)` stage the answer for the gate.
 * Every other primitive remains a production filesystem call.
 *
 * This does not settle on the gate's answer: the observation is revealed before either product
 * call, and the exact `ROOT_MOVED` assertions below remain the oracle.
 */
function stagedRootSwapObservation(canonicalRoot, replacementRoot) {
    const normalizedRoot = path.normalize(canonicalRoot);
    const normalizedReplacement = path.normalize(replacementRoot);
    let swapped = false;
    return {
        realpathNative(target) {
            if (swapped && path.normalize(target) === normalizedRoot) return replacementRoot;
            return fs.realpathSync.native(target);
        },
        reveal: () => {
            const observed = path.normalize(fs.realpathSync.native(canonicalRoot));
            assert.equal(observed, normalizedReplacement,
                `the real root swap must be observable before staging: observed ${observed}; ` +
                `expected ${normalizedReplacement}`);
            swapped = true;
        }
    };
}

test('A82-create-exclusive-open-race — a file appearing after the leaf probe stays untouched', async t => {
    arm('A82-create-exclusive-open-race');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-create-race-'));
    try {
        const target = path.join(fs.realpathSync.native(base), 'raced.md');
        const interposed = Buffer.from('interposed content must survive intact');
        let appearances = 0;
        const made = createFsGate({ rawGrant: base, primitives: {
            // Override only the probe: the shipped openExclusive must exercise its own flags.
            lstat: name => {
                try { return fs.lstatSync(name); }
                catch (error) {
                    if (name === target && error.code === 'ENOENT') {
                        fs.writeFileSync(target, interposed, { flag: 'wx' });
                        appearances++;
                    }
                    // Return the real missing-leaf observation after the competing file appears.
                    throw error;
                }
            }
        } });
        assert.ok(!isRefusal(made), 'gate construction');
        const result = await made.createFileInGrant('raced.md', Buffer.from('replacement'));
        assert.equal(appearances, 1, 'the leaf probe must observe ENOENT and interpose exactly once');
        assert.deepEqual({
            ok: result.ok, reason: result.reason, retained: result.retained,
            content: fs.readFileSync(target)
        }, { ok: false, reason: 'EXISTS', retained: null, content: interposed },
        'the production exclusive open must refuse without changing the competing file');
        t.diagnostic('real ENOENT leaf observation, one interposed file, production open refused EXISTS; content unchanged');
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('A81-root-numeric-snapshot — a changed numeric root observation refuses', async () => {
    arm('A81-root-numeric-snapshot');
    const canonical = fs.realpathSync.native(FX.grant);
    let armed = false;
    const made = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...spyPrimitives([]),
            lstat: target => {
                const stats = fs.lstatSync(target);
                if (armed && target === canonical) stats.ino += 2048;
                return stats;
            },
            lstatBigint: target => fs.lstatSync(target, { bigint: true })
        }
    });
    assert.ok(!isRefusal(made));
    armed = true;
    const result = await made.readFileInGrant('subdir/note.md', 0, 4096);
    assert.ok(isRefusal(result), 'a changed numeric snapshot must refuse');
    assert.equal(result.reason, 'ROOT_MOVED');
});

test('A80-root-observation-fail-closed — each unavailable root observation refuses', async () => {
    arm('A80-root-observation-fail-closed');
    const canonical = fs.realpathSync.native(FX.grant);
    for (const fault of ['realpath', 'numeric-read', 'exact-read', 'exact-zero']) {
        let armed = false;
        const primitives = {
            ...spyPrimitives([]),
            realpathNative: target => {
                if (armed && target === canonical && fault === 'realpath') throw new Error('root realpath unavailable');
                return fs.realpathSync.native(target);
            },
            lstat: target => {
                if (armed && target === canonical && fault === 'numeric-read') throw new Error('root lstat unavailable');
                const stats = fs.lstatSync(target);
                return stats;
            },
            lstatBigint: target => {
                if (armed && target === canonical && fault === 'exact-read') throw new Error('root exact identity unavailable');
                const stats = fs.lstatSync(target, { bigint: true });
                if (armed && target === canonical && fault === 'exact-zero') stats.ino = 0n;
                return stats;
            }
        };
        const made = createFsGate({ rawGrant: FX.grant, primitives });
        assert.ok(!isRefusal(made), `${fault}: gate construction`);
        armed = true;
        const result = await made.readFileInGrant('subdir/note.md', 0, 4096);
        assert.ok(isRefusal(result), `${fault}: unobserved root must refuse`);
        assert.equal(result.reason, 'ROOT_MOVED', `${fault}: refusal reason`);
    }
});

test('A35-root-moved — swapping the granted folder after startup is CAUGHT, not closed', async t => {
    arm('A35-root-moved');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-rootswap-'));
    try {
        const vault = path.join(base, 'vault');
        const evil = path.join(base, 'evil');
        fs.mkdirSync(vault);
        fs.mkdirSync(evil);
        fs.writeFileSync(path.join(vault, 'note.md'), 'REAL-VAULT');
        fs.writeFileSync(path.join(evil, 'note.md'), 'SWAPPED-CONTENT');
        const originalIdentity = fs.lstatSync(vault, { bigint: true });
        const originalNumeric = fs.lstatSync(vault);

        const rootObservation = stagedRootSwapObservation(
            fs.realpathSync.native(vault),
            fs.realpathSync.native(evil)
        );
        const made = createFsGate({
            rawGrant: vault,
            primitives: { ...spyPrimitives([]), realpathNative: rootObservation.realpathNative }
        });
        assert.ok(!isRefusal(made));
        const roundedIdentityGate = createFsGate({
            rawGrant: vault,
            primitives: {
                ...spyPrimitives([]),
                realpathNative: rootObservation.realpathNative,
                lstat: target => {
                    const stats = fs.lstatSync(target);
                    if (path.normalize(target) === path.normalize(evil)) {
                        stats.dev = originalNumeric.dev;
                        stats.ino = originalNumeric.ino;
                    }
                    return stats;
                }
            }
        });
        assert.ok(!isRefusal(roundedIdentityGate));
        assert.equal((await made.readFileInGrant('note.md', 0, 100)).bytes.toString('utf8'), 'REAL-VAULT');

        // Move the real folder aside and put a junction to elsewhere in its place.
        fs.renameSync(vault, path.join(base, 'vault-real'));
        fs.symlinkSync(evil, vault, 'junction');
        rootObservation.reveal();

        const after = await made.readFileInGrant('note.md', 0, 100);
        assert.ok(isRefusal(after), 'the swapped root must not serve content');
        if (after.reason !== 'ROOT_MOVED') {
            const replacement = fs.realpathSync.native(vault);
            const currentIdentity = fs.lstatSync(replacement, { bigint: true });
            t.diagnostic(`root swap: original=${originalIdentity.dev}:${originalIdentity.ino}, replacement=${currentIdentity.dev}:${currentIdentity.ino}, numeric original=${Number(originalIdentity.ino)}, numeric replacement=${Number(currentIdentity.ino)}, realpath=${replacement}, refusal=${after.reason}: ${after.detail}`);
        }
        assert.equal(after.reason, 'ROOT_MOVED');
        // ⚠ THE APPEND LEG — a SECOND write entry point, and it re-checks the root itself rather
        // than inheriting the check from `resolveNew`, which it does not call. Deleting the recheck
        // from the append path alone would leave every other arm here green.
        const appended = await made.appendLineInGrant('note.jsonl', Buffer.from('{"x":1}\n'));
        assert.ok(isRefusal(appended), 'the swapped root must not accept an append');
        assert.equal(appended.reason, 'ROOT_MOVED');
        assert.equal(appended.retained, null, 'a root refusal opens nothing');
        assert.equal(fs.existsSync(path.join(evil, 'note.jsonl')), false,
            '⚠ THE APPEND LANDED IN THE SWAPPED DIRECTORY');
        // A numeric file-ID collision must not hide the replacement directory.
        const rounded = await roundedIdentityGate.readFileInGrant('note.md', 0, 100);
        assert.ok(isRefusal(rounded));
        assert.equal(rounded.reason, 'ROOT_MOVED');
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

test('A37-request-separators — a request reaches the same file in every separator spelling the HOST recognises', async () => {
    arm('A37-request-separators');
    // The sibling surface of the grant defect. `path.join` folds separators, so these agree
    // today; nothing asserted it, which is exactly how the grant side went wrong.
    //
    // ⚠⚠ FOUR OF THESE SPELLINGS CARRY A BACKSLASH AND WERE ASSERTED UNCONDITIONALLY. A backslash
    // is a separator on WIN32 ONLY; on POSIX it is an ordinary filename character. So off Windows
    // `subdir\note.md` did not name the file this arm said it named, and the arm was
    // coverage-shaped rather than coverage — the identical defect `A25-case` carried in this file.
    //
    // ⚠ THE SEPARATOR IS MEASURED ON THE FIXTURE'S OWN VOLUME, never inferred from
    // `process.platform`. The fixture is built under the OS temp directory, which need not sit on
    // the volume this checkout does, and `platform` is a claim about the PROCESS while this is a
    // question about path resolution where the FILE IS. The probe is an absolute path assembled
    // with a literal backslash, put to the real filesystem — paired with the forward-slash
    // spelling, which is a separator on every host, so a missing fixture cannot read as "no".
    assert.ok(
        fs.existsSync(`${FX.grant}/subdir/note.md`),
        'precondition: `/` is a separator on every host and the fixture file is reachable by it'
    );
    const BACKSLASH_IS_SEPARATOR = fs.existsSync(`${FX.grant}\\subdir\\note.md`);

    // Separator-agnostic, and asserted on every host: this half carries the arm's name.
    for (const request of ['subdir/note.md', './subdir/note.md', 'subdir//note.md', 'secrets/../subdir/note.md']) {
        assert.equal(await text(request), CANARY.inGrantNote, `${request} must reach the same file`);
    }
    // And the escape refuses, so separator folding has not opened a hole.
    for (const request of ['../outside/secret.md', '..//outside//secret.md']) {
        assert.equal((await refusal(request)).reason, 'ESCAPES', `${request} must refuse`);
    }

    const backslashIn = ['subdir\\note.md', '.\\subdir\\note.md', 'secrets\\..\\subdir/note.md'];
    const backslashEscape = '..\\outside\\secret.md';

    if (BACKSLASH_IS_SEPARATOR) {
        // ⚠ NOTHING THIS ARM ASSERTED ON WINDOWS IS WEAKENED. The same three in-grant spellings
        // must still reach the file and the same escape spelling must still refuse ESCAPES; the
        // other branch is added BESIDE these, never in place of them.
        for (const request of backslashIn) {
            assert.equal(await text(request), CANARY.inGrantNote, `${request} must reach the same file`);
        }
        assert.equal((await refusal(backslashEscape)).reason, 'ESCAPES', `${backslashEscape} must refuse`);
        console.log('    A37-request-separators: `\\` IS a separator here; all 7 spellings exercised, 0 held back.');
    } else {
        // ⚠ THE OTHER BRANCH ASSERTS, IT DOES NOT SKIP — but what it is ENTITLED to assert is
        // bounded by a product question NOBODY HAS RULED: does the fence promise backslash folding
        // off win32? `path.sep` says no, and the gate is currently of two minds about it — stage
        // (a)'s depth guard splits on `/[\\/]/` on every host, while the `path.join` beside it
        // folds only what the host folds. Pinning either outcome here would quietly encode a
        // decision this arm does not get to make, so it pins the two things that are TRUE UNDER
        // EITHER RULING and prints which way this host actually came out:
        //
        //   1. SAFETY. A backslash request must never serve out-of-grant content, and never a
        //      different in-grant file than the one it names.
        //   2. COHERENCE. The three in-grant spellings must agree with each other, and the escape
        //      spelling must agree with them — a gate that folds the backslash for `subdir\note.md`
        //      but not for `..\outside\secret.md` is broken under BOTH readings, and that
        //      disagreement is exactly the hole a fold would open.
        const outcomes = [];
        for (const request of backslashIn) {
            const result = await gate.readFileInGrant(request, 0, 1 << 16);
            if (isRefusal(result)) {
                outcomes.push(`refused:${result.reason}`);
                continue;
            }
            const served = result.bytes.toString('utf8');
            assert.notEqual(served, CANARY.outsideSecret, `${request} served OUT-OF-GRANT content`);
            assert.equal(served, CANARY.inGrantNote, `${request} opened, but served a file it does not name`);
            outcomes.push('served');
        }
        assert.equal(new Set(outcomes).size, 1, `the backslash spellings disagree: ${outcomes.join(', ')}`);

        // The two readings are exhaustive, and each one forces the escape spelling's answer.
        const folds = outcomes[0] === 'served';
        if (!folds) {
            assert.equal(
                outcomes[0], 'refused:MISSING',
                'treating `\\` as an ordinary filename character makes these absent in-grant names, and nothing else'
            );
        }
        const escape = await gate.readFileInGrant(backslashEscape, 0, 1 << 16);
        assert.ok(isRefusal(escape), `${backslashEscape} must never open here`);
        assert.equal(
            escape.reason, folds ? 'ESCAPES' : 'MISSING',
            folds
                ? 'this gate folds `\\` into a separator, so the escape spelling must refuse ESCAPES'
                : 'this gate reads `\\` literally, so the escape spelling names an absent in-grant file'
        );

        // ⚠ SAID OUT LOUD, THE WAY `A25-case` AND `--portable` NAME WHAT THEY HELD BACK. A green
        // that quietly covered less is the failure this suite exists to prevent.
        console.log(
            '    A37-request-separators: `\\` is NOT a separator on this filesystem; this gate '
            + `${folds ? 'FOLDS it anyway' : 'reads it literally'}; 4 backslash spellings asserted for SAFETY and `
            + 'COHERENCE only — their fixed expectation is HELD BACK pending an unruled product question: '
            + 'does the fence promise backslash folding off win32? `path.sep` says no; nobody has ruled.'
        );
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

test('A67-probe-directory — a present directory returns kind only', async () => {
    arm('A67-probe-directory');
    const result = await gate.probeInGrant('subdir');
    assert.deepEqual(result, { ok: true, kind: 'directory' });
    assert.equal(Object.isFrozen(result), true);
    assert.ok(!('name' in result) && !('rel' in result) && !('resolvedPath' in result));

    const sink = [];
    const measuredGate = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives(sink) });
    assert.ok(!isRefusal(measuredGate));
    sink.length = 0;
    await measuredGate.probeInGrant('subdir');
    assert.deepEqual(
        sink.map(call => call.name),
        ['realpathNative', 'lstat', 'lstat', 'realpathNative', 'lstat'],
        'a direct successful probe is five constant-cost calls and never readdir'
    );

    /**
     * Cost criterion 17.
     *
     * What implementation would still pass this? One that introduced a new, uninstrumented
     * filesystem-enumeration primitive or called the platform API directly instead of the fence's
     * primitive table. `spyPrimitives` covers every path-resolution primitive this probe uses
     * today, but it is not an operating-system syscall tracer. This arm therefore proves
     * call-sequence independence at that existing seam, for this fixed one-segment request; it does
     * not claim constant wall time, a fixed count for deeper paths/link chains, or that a future
     * primitive is covered.
     */
    const costRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-entry-cost-'));
    try {
        for (const layer of ['Arc', 'Mage', 'Forum']) fs.mkdirSync(path.join(costRoot, layer));
        const costSink = [];
        const costGate = createFsGate({ rawGrant: costRoot, primitives: spyPrimitives(costSink) });
        assert.ok(!isRefusal(costGate));

        costSink.length = 0;
        for (const layer of ['Arc', 'Mage', 'Forum']) {
            assert.deepEqual(await costGate.probeInGrant(layer), { ok: true, kind: 'directory' });
        }
        assert.deepEqual(
            costSink.map(call => call.name),
            Array.from({ length: 3 }, () => [
                'realpathNative', 'lstat', 'lstat', 'realpathNative', 'lstat'
            ]).flat(),
            'three present startup layers are 15 calls at this one-segment depth'
        );

        costSink.length = 0;
        assert.deepEqual(await costGate.probeInGrant('Mage'), { ok: true, kind: 'directory' });
        const sparseCalls = costSink.map(call => ({ ...call }));
        assert.equal(sparseCalls.length, 5);

        for (let index = 0; index < 10_000; index += 1) {
            fs.writeFileSync(path.join(costRoot, `entry-${String(index).padStart(5, '0')}.md`), '');
        }
        assert.equal(fs.readdirSync(costRoot).length, 10_003,
            'precondition: exactly 10,000 files were added beside the three layers');

        costSink.length = 0;
        assert.deepEqual(await costGate.probeInGrant('Mage'), { ok: true, kind: 'directory' });
        const crowdedCalls = costSink.map(call => ({ ...call }));
        assert.deepEqual(crowdedCalls, sparseCalls,
            'adding 10,000 vault files must not change one fixed probe call sequence');
    } finally {
        fs.rmSync(costRoot, { recursive: true, force: true });
    }
});

test('A68-probe-file — a present file returns kind only', async () => {
    arm('A68-probe-file');
    const result = await gate.probeInGrant('notes');
    assert.deepEqual(result, { ok: true, kind: 'file' });
});

test('A69-probe-missing — an absent name uses MISSING', async () => {
    arm('A69-probe-missing');
    const result = await gate.probeInGrant('absent-layer');
    assert.ok(isRefusal(result));
    assert.equal(result.reason, 'MISSING');
    assert.equal(result.resolvedPath, '');
});

test('A70-probe-junction — an in-grant junctioned directory is present', async () => {
    arm('A70-probe-junction');
    const result = await gate.probeInGrant('j_in');
    assert.deepEqual(result, { ok: true, kind: 'directory' });
});

test('A71-probe-escape — an escaping request uses the shared refusal', async () => {
    arm('A71-probe-escape');
    const result = await gate.probeInGrant('../outside/secret.md');
    assert.ok(isRefusal(result));
    assert.equal(result.reason, 'ESCAPES');
    assert.equal(result.resolvedPath, '');
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

    // ⚠ THE TWO APPEND PRIMITIVES, EACH AT ITS OWN SITE. Swapping either for a direct `fs` call
    // blinds the containment guard for the whole append path, which is why they are asserted
    // individually rather than inferred from a successful append.
    //
    // ⚠ `appendOnce` IS NOT SUPPLIED BY THE SPY (see `spyPrimitives`), so it is asserted here
    // through a table that supplies it — the arm's subject is the SITE, and a primitive omitted
    // from the shared spy for a different reason still has to be reached where it belongs.
    {
        let openAppendCalls = 0;
        let appendOnceCalls = 0;
        const appendSpy = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: (t, mode) => {
                    openAppendCalls += 1;
                    return mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                },
                appendOnce: (fd, buffer) => {
                    appendOnceCalls += 1;
                    return fs.writeSync(fd, buffer, 0, buffer.length, null);
                }
            }
        });
        assert.ok(!isRefusal(appendSpy));
        const done = await appendSpy.appendLineInGrant('meta-primitives-append.jsonl', Buffer.from('{"x":1}\n'));
        assert.ok(!isRefusal(done), `the meta append must succeed: ${JSON.stringify(done)}`);
        assert.equal(openAppendCalls, 1, 'openAppend must be reached through the injected table, exactly once');
        assert.equal(appendOnceCalls, 1, 'appendOnce must be reached through the injected table, exactly once');
    }
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

    // ⚠ THE APPEND PRIMITIVES TOO. `table.openAppend(p, m)` binds `this` to the table and hands a
    // supplied callback the whole primitive record — `open` and `read` included — so the fence is
    // bypassed entirely. The append path is a NEW set of call sites and inherits nothing from the
    // ones above; `Reflect.apply` has to be used at each of them or this hole reopens for writes.
    const appendCaptured = [];
    const appendReal = spyPrimitives([]);
    const appendGate = createFsGate({
        rawGrant: FX.grant,
        primitives: {
            ...appendReal,
            openAppend: function (target, mode) {
                appendCaptured.push(this);
                return appendReal.openAppend(target, mode);
            },
            appendOnce: function (fd, buffer) {
                appendCaptured.push(this);
                return fs.writeSync(fd, buffer, 0, buffer.length, null);
            }
        }
    });
    assert.ok(!isRefusal(appendGate));
    const appendResult = await appendGate.appendLineInGrant('this-unbound-append.jsonl', Buffer.from('{"x":1}\n'));
    assert.ok(!isRefusal(appendResult), `the append must succeed: ${JSON.stringify(appendResult)}`);
    assert.equal(appendCaptured.length, 2, 'both append primitives must have been called');
    for (const value of appendCaptured) {
        assert.equal(value, undefined,
            `an injected APPEND callback received \`this\` = ${JSON.stringify(Object.keys(value ?? {}))}`);
    }

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
        const touches = sink.filter(c => !isRootRecheck(c, canonical));
        assert.deepEqual(touches, [], `stage (a) touched the filesystem for ${request}`);

        // ⚠ THE APPEND LEG, ON THE SAME REQUESTS AND THE SAME ALLOWANCE. Stage (a) is shared code,
        // but the append path reaches it through its OWN call — one whose screen set differs — so a
        // regression that moved I/O ahead of the lexical refusal on this path alone would be
        // invisible to the loop above.
        sink.length = 0;
        const appendResult = await made.appendLineInGrant(request, Buffer.from('{"x":1}\n'));
        assert.ok(isRefusal(appendResult), `${request} must refuse on the append path`);
        assert.equal(appendResult.retained, null, `${request}: stage (a) opened nothing, so it retains nothing`);
        const appendTouches = sink.filter(c => !isRootRecheck(c, canonical));
        assert.deepEqual(appendTouches, [], `the append path's stage (a) touched the filesystem for ${request}`);
    }

    // ⚠ AND NO APPEND RESULT — REFUSAL OR SUCCESS — NAMES A PATH OUTSIDE THE ROOT. The field sweep
    // A42 runs for hash and create, extended to the third write-shaped entry point rather than
    // trusting that a shared helper stayed shared.
    for (const request of [
        'lineage-meta.jsonl', '../outside/x.jsonl', path.join(FX.outside, 'x.jsonl'),
        'C:notes', 'note.jsonl::$DATA', 'NUL', 'j_out/x.jsonl', 'no-such-dir/x.jsonl'
    ]) {
        const result = await gate.appendLineInGrant(request, Buffer.from('{"x":1}\n'));
        for (const [field, value] of Object.entries(result)) {
            if (typeof value !== 'string') continue;
            assert.equal(path.isAbsolute(value), false,
                `append(${request}): \`${field}\` carried an absolute path: ${value}`);
            assert.equal(outsideRoot(root, value), false,
                `append(${request}): \`${field}\` named an outside path: ${value}`);
            assert.ok(!value.includes(FX.outside),
                `append(${request}): \`${field}\` embedded the outside root: ${value}`);
        }
        // `retained` is a nested object and carries a `rel` of its own — swept too, because a
        // resolved absolute leaking there leaks just as far.
        if (!isRefusal(result) || result.retained === null) continue;
        assert.equal(path.isAbsolute(result.retained.rel), false,
            `append(${request}): \`retained.rel\` carried an absolute path: ${result.retained.rel}`);
        assert.equal(outsideRoot(root, result.retained.rel), false,
            `append(${request}): \`retained.rel\` named an outside path: ${result.retained.rel}`);
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
    //
    // ⚠ IT GREW AGAIN ON 2026-09-02, BY ONE: `appendLineInGrant`, the Scribe's lineage-log write.
    // Growing this list is the RULING, not a consequence — the arm going red is how a new gate
    // method becomes a deliberate act. `E4-export-inventory` is deliberately UNCHANGED by that
    // work: the module still exports exactly `createFsGate` and `isRefusal`, so the new surface
    // rides on a constructed gate and no consumer gains a second way in.
    // The conditional overwrite is the next deliberately exposed gate method.
    assert.deepEqual(Object.keys(gate).sort(), [
        'appendLineInGrant',
        'createFileInGrant',
        'disclosedRoot',
        'fileMetadataInGrant',
        'grantPlaceholderSummary',
        'hashInGrant',
        'listDirInGrant',
        'listGrantRoot',
        'overwriteFileInGrant',
        'placeholderDetection',
        'probeInGrant',
        'readFileInGrant',
        'walkGrant'
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
        // the read-path stream screen are win32-only. See `NameScreens` in wyrd-fence's fsgate.ts.
        const screenedOnRead = win32;
        const screenedOnCreate = reason === 'STREAM_SYNTAX' ? true : win32;

        for (const result of [
            await gate.readFileInGrant(request, 0, 4096),
            await gate.listDirInGrant(request),
            await gate.probeInGrant(request),
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
    // ⚠ ALL FIVE PATH-NAMING ENTRIES, not just read and create. The first version ran two, so a regression that
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
            await gate.probeInGrant(request);
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

    // ⚠⚠ REVERSED 2026-09-08, AND THE PARAGRAPH THIS REPLACES ASSERTED THE OPPOSITE. It read *"the
    // in-grant junction twin must still work, or the arm above proves only 'refuses junctions'"*
    // and required `j_in/via-junction.md` to CREATE, landing on the canonical `subdir`. That is the
    // `Arc/` defect, measured through this exact shape: a junction named `Notes` pointing at `Arc`
    // is in-grant by every containment predicate, so the create succeeded and the file landed in
    // the user's immutable provenance layer. A write must go where the caller spelled it.
    //
    // ⚠ `retained: null` — the comparison fires before the leaf is joined and before anything opens.
    const viaJunction = await gate.createFileInGrant('j_in/via-junction.md', Buffer.from('via junction\n'));
    assert.ok(isRefusal(viaJunction), 'an in-grant junction parent must REFUSE, or `Arc/` is writable through one');
    assert.equal(viaJunction.reason, 'PARENT_ALIAS', `expected PARENT_ALIAS, got ${viaJunction.reason}`);
    assert.equal(viaJunction.retained, null, 'nothing was opened on this path');
    assert.equal(
        fs.existsSync(path.join(root, 'subdir', 'via-junction.md')), false,
        '⚠ the refusal came AFTER the file had already landed on the canonical parent'
    );

    // ⚠ THE OTHER HALF, OR THIS ARM PROVES ONLY "REFUSES EVERY LINK-BEARING PARENT". A parent that
    // is a real directory reached by a DIFFERENTLY-CASED spelling is not an alias — Windows folds
    // it to the same directory — and it must still create. This is the false positive the exact
    // comparison would have produced, asserted rather than reasoned about.
    if (fs.existsSync(path.join(root, 'SUBDIR'))) {
        const folded = await gate.createFileInGrant('SUBDIR/folded-by-a40.md', Buffer.from('folded\n'));
        assert.ok(!isRefusal(folded),
            `a case-only parent spelling is not an alias and must create: ${JSON.stringify(folded)}`);
        assert.equal(folded.rel, path.join('subdir', 'folded-by-a40.md'));
    } else {
        // Case-SENSITIVE volume: `SUBDIR` names nothing, so there is no folded spelling to exercise.
        console.log('    A40-create: this filesystem is case-SENSITIVE; the folded-parent leg is HELD BACK.');
    }

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

    // ⚠ THE APPEND LEG, ON BOTH HALVES. The discrimination this arm exists for — same object
    // re-spelled must be ACCEPTED, different object must REFUSE — has to hold on the append path
    // too, and that path performs the check itself rather than through `resolveNew`.
    const respelledAppend = createFsGate({
        rawGrant: FX.grant,
        primitives: { ...spyPrimitives([]), realpathNative: stagedRealpath() }
    });
    assert.ok(!isRefusal(respelledAppend));
    const acceptedAppend = await respelledAppend.appendLineInGrant('a45-respelled.jsonl', Buffer.from('{"x":1}\n'));
    assert.ok(!isRefusal(acceptedAppend),
        `a case-only re-spelling of the SAME directory must not refuse an append: ${acceptedAppend.reason}`);

    const swappedAppend = await swapped.appendLineInGrant('a45-swapped.jsonl', Buffer.from('{"x":1}\n'));
    assert.ok(isRefusal(swappedAppend), 'a root whose OBJECT changed must refuse an append');
    assert.equal(swappedAppend.reason, 'ROOT_MOVED');
    assert.equal(swappedAppend.retained, null);
});

/**
 * ⚠⚠ THIS ARM PINS A GAP THAT IS OPEN ON PURPOSE. IT IS NOT A REGRESSION GUARD — IT IS THE
 * EVIDENCE UNDER AN UNDECIDED FORK (F8: should the root-identity comparison become
 * unconditional?), AND CLOSING THE GAP MUST TURN IT RED.
 *
 * `rootStillCanonical` compares the granted directory's captured `dev`/`ino` ONLY INSIDE
 * `if (current !== root)`. So the comparison never runs when the canonical path STRING is
 * unchanged — and a directory removed and rebuilt under the identical name has an unchanged
 * string and a different object. `A35-root-moved` cannot reach this: it puts a JUNCTION at the
 * old name, which resolves elsewhere and so takes the changed-spelling branch. `A45-root-identity`
 * cannot reach it either: its "replaced" case is staged through a `realpathNative` returning a
 * DIFFERENT SPELLING, which is the same branch again. Both were confirmed by reading them, not
 * inherited.
 *
 * ⚠ THE THREE READERS WHO FOUND THIS ALL READ IT AND NONE RAN IT. This arm is the measurement,
 * on the real filesystem with the shipped primitives, and it says what actually came back.
 *
 * ⚠⚠ IF THIS ARM IS RED, DO NOT "FIX" THE ARM. Either the platform stopped behaving as measured
 * (leg 2 says which observation moved) or F8 was ruled and the fence was tightened — in which
 * case this arm is the ruling's review event and should be rewritten to assert the refusal,
 * deliberately, with the ruling cited.
 */
test('A55-same-path-replacement — a DIFFERENT directory at the IDENTICAL canonical path is REFUSED: F8 closed', async () => {
    arm('A55-same-path-replacement');

    /* ⚠⚠ THIS ARM WAS INVERTED ON 2026-09-03, AND THE INVERSION IS THE RULING (F8, option C).
     *
     * It used to assert the GAP: that a directory destroyed and recreated under the same name was
     * served by every surface. That was a pin — a test whose passing meant a known hole was still
     * open, written so that closing the hole would turn it red and force a review. Option C was
     * ruled, the identity check in `rootStillCanonical` became unconditional, and this arm asserts the
     * REFUSAL. The git history of this file is where the pinned form lives; do not restore it.
     *
     * What the fixture proves is unchanged and is what makes the arm meaningful: the canonical path
     * STRING is identical after the swap (so a spelling comparison alone would still be fooled),
     * and the object identity genuinely differs (so there is something for the check to catch).
     * Both are asserted below before the refusals, exactly as they were under the pinned form. */

    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-samepath-'));
    try {
        const vault = path.join(base, 'vault');
        fs.mkdirSync(vault);
        fs.writeFileSync(path.join(vault, 'note.md'), 'REAL-VAULT');

        const made = createFsGate({ rawGrant: vault });
        assert.ok(!isRefusal(made));
        const canonicalRoot = made.disclosedRoot();
        const identityBefore = fs.lstatSync(canonicalRoot, { bigint: true });
        assert.equal((await made.readFileInGrant('note.md', 0, 100)).bytes.toString('utf8'), 'REAL-VAULT');

        /* (1) THE SWAP — a real one, not a staged spelling. The granted directory is DESTROYED and
         *     a different directory is created under the same name. */
        fs.rmSync(vault, { recursive: true });
        // ⚠ ASSERTED, NOT ASSUMED. A Windows handle held open on the directory would make the
        // removal fail, and a fixture that never got built must fail loudly rather than let the
        // arm below pass against the original directory.
        assert.equal(fs.existsSync(vault), false, 'the granted directory must actually be gone');
        fs.mkdirSync(vault);
        fs.writeFileSync(path.join(vault, 'note.md'), 'REPLACEMENT-CONTENT');
        fs.writeFileSync(path.join(vault, 'planted.md'), 'PLANTED-IN-THE-REPLACEMENT');

        /* (2) THE FENCE HAD EVERYTHING IT NEEDED AND ASKED NOTHING. Both observations, made the way
         *     `rootStillCanonical` makes them: the spelling is unchanged, which is what suppresses
         *     the branch, and the identity DID change, which is what the suppressed branch would
         *     have caught. If either of these ever fails, the platform moved and the arm below is
         *     measuring something other than what it claims. */
        assert.equal(path.normalize(fs.realpathSync.native(canonicalRoot)), path.normalize(canonicalRoot),
            'the canonical path string must be unchanged — that is the condition that skips the identity check');
        const identityAfter = fs.lstatSync(canonicalRoot, { bigint: true });
        assert.ok(identityBefore.dev !== identityAfter.dev || identityBefore.ino !== identityAfter.ino,
            'the replacement must be a genuinely different object, or this arm proves nothing');
        assert.ok(identityBefore.ino !== 0n && identityAfter.ino !== 0n,
            'both identities must be supplied by the filesystem, or the comparison could not have run anyway');

        /* (3) WHAT THE FENCE DOES ABOUT IT NOW: refuses ROOT_MOVED, on every surface. EVERY surface
         *     is asserted rather than one, because the gap was never read-only — the create and
         *     append legs wrote INTO the replacement, and a fix that closed only the read side
         *     would leave the worse half open while looking closed. */
        const after = await made.readFileInGrant('note.md', 0, 100);
        assert.ok(isRefusal(after), 'the read surface must refuse a replaced root');
        assert.equal(after.reason, 'ROOT_MOVED');

        const planted = await made.readFileInGrant('planted.md', 0, 100);
        assert.ok(isRefusal(planted), 'a file existing ONLY in the replacement must not be readable');
        assert.equal(planted.reason, 'ROOT_MOVED');

        const listing = await made.listGrantRoot();
        assert.ok(isRefusal(listing), 'the listing surface must refuse a replaced root');
        assert.equal(listing.reason, 'ROOT_MOVED');

        const probed = await made.probeInGrant('note.md');
        assert.ok(isRefusal(probed), 'the probe surface must refuse a replaced root');
        assert.equal(probed.reason, 'ROOT_MOVED');

        const hashed = await made.hashInGrant('note.md');
        assert.ok(isRefusal(hashed), 'provenance must not be taken over a replacement');
        assert.equal(hashed.reason, 'ROOT_MOVED');

        const created = await made.createFileInGrant('written.md', Buffer.from('WROTE-INTO-THE-REPLACEMENT'));
        assert.ok(isRefusal(created), 'the create surface must refuse a replaced root');
        assert.equal(created.reason, 'ROOT_MOVED');
        assert.equal(fs.existsSync(path.join(vault, 'written.md')), false,
            'and it must not have written the file before refusing');

        const appended = await made.appendLineInGrant('lineage.jsonl', Buffer.from('{"x":1}\n'));
        assert.ok(isRefusal(appended), 'the append surface must refuse a replaced root');
        assert.equal(appended.reason, 'ROOT_MOVED');
        assert.equal(appended.retained, null, 'and it must have opened nothing');
        assert.equal(fs.existsSync(path.join(vault, 'lineage.jsonl')), false);

        /**
         * (4) WHAT CLOSING IT WOULD COST, MEASURED RATHER THAN REASONED ABOUT.
         *
         * ⚠⚠ THIS LEG PINS A COST, NOT A DESIRABLE BEHAVIOUR, AND IT IS THE HALF THAT MAKES THE
         * FORK A DECISION INSTEAD OF AN OVERSIGHT. The identity branch FAILS CLOSED when either
         * side cannot supply `dev`/`ino` — network shares and some filesystems report `ino === 0`.
         * ⚠⚠ THIS LEG WENT RED WHEN F8 WAS CLOSED, EXACTLY AS IT WAS BUILT TO, AND THE COST IS NOW
         * PAID RATHER THAN AVOIDED. Under the old conditional form the branch never ran on an
         * unchanged spelling, so a root whose filesystem reports `ino === 0` was served normally.
         * Unconditional + fail-closed means such a root now refuses EVERY request from the first
         * one — a total loss of service on a filesystem that is not misbehaving, not a wrinkle.
         *
         * ⚠ THE RULING ACCEPTED THAT, AND IT IS NARROWER THAN IT SOUNDS. Measured 2026-09-03 across
         * seven local NTFS locations — the temp directory, a drive root, several repository and
         * document trees, a user profile and a cloud-synced folder — and ALL supplied a non-zero
         * dev/ino. The identity-less case is remote and exotic filesystems, none of which is a
         * target host today. The alternative — serving a
         * root whose identity cannot be proven — is the failure this library exists to prevent, so
         * fail-closed is the only defensible side.
         *
         * This leg now PINS the refusal, so if anyone ever softens the fail-closed rule to buy
         * network-share support back, they do it deliberately and this arm makes them say so.
         */
        const anonymous = path.join(base, 'anon');
        fs.mkdirSync(anonymous);
        fs.writeFileSync(path.join(anonymous, 'note.md'), 'IDENTITY-LESS-FILESYSTEM');
        const anonymousCanonical = fs.realpathSync.native(anonymous);
        const anonymousGate = createFsGate({
            rawGrant: anonymous,
            primitives: {
                lstat: target => {
                    const stats = fs.lstatSync(target);
                    if (path.normalize(target) !== path.normalize(anonymousCanonical)) return stats;
                    // A filesystem that supplies no inode for the granted directory.
                    return { ...stats, ino: 0, isDirectory: () => true, isSymbolicLink: () => false };
                }
            }
        });
        assert.ok(!isRefusal(anonymousGate),
            'a root whose filesystem supplies no inode must still CONSTRUCT — the refusal is at use, not at grant');
        const anonymousRead = await anonymousGate.readFileInGrant('note.md', 0, 100);
        assert.ok(isRefusal(anonymousRead),
            'THE ACCEPTED COST OF CLOSING F8: an identity-less root refuses every request, fail-closed');
        assert.equal(anonymousRead.reason, 'ROOT_MOVED');
    } finally {
        teardown(base);
    }
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

test('A54-writeall-loop — the SHIPPED completion loop, driven at `fs.writeSync`', async () => {
    arm('A54-writeall-loop');

    // ⚠⚠ WHY THIS ARM IS NOT A DUPLICATE OF `A44-short-write`. A44 injects `writeAll`, so it pins
    // the CALLER's classification of a returned count and never executes one line of the shipped
    // completion loop. `_writeAll` is module-private and reaches `fs.writeSync` directly — it is
    // below the injection seam entirely — so its `n <= 0` break, its resumption after a partial
    // write, and its behaviour when the syscall throws were all unreached. MEASURED, not assumed:
    // on 2026-09-01 changing `if (n <= 0) break` to `if (n < 0) break` in the built output left the
    // whole 70-arm suite GREEN. That is the definition of an unexercised branch.
    //
    // ⚠ THE SEAM IS `fs.writeSync` ITSELF, AND IT IS THE ONLY ONE THERE IS. Adding a primitive to
    // reach this loop would mean adding an option to a security-adjacent factory — the move this
    // module has already refused once, in the `windowsNameRules` block. Patching the runtime
    // function for ONE descriptor is confined to this arm, restored in `finally`, and asserted
    // restored; it changes nothing that ships.
    const realWriteSync = fs.writeSync;
    /** Only ever the descriptor this arm opened. Every other caller of `fs.writeSync` is untouched. */
    let ours = -1;

    // ⚠ NO `writeAll` IS SUPPLIED, WHICH IS THE WHOLE POINT — `createFsGate` then falls through to
    // the production primitive, and the arm exercises the shipped loop rather than a stand-in.
    const primitivesRecordingFd = () => ({
        ...spyPrimitives([]),
        openExclusive: t => { ours = fs.openSync(t, 'wx'); return ours; }
    });

    try {
        /* (1) NO PROGRESS — the `n <= 0` break. Without it the loop never terminates. */
        let noProgressCalls = 0;
        fs.writeSync = (fd, ...rest) => {
            if (fd !== ours) return realWriteSync(fd, ...rest);
            noProgressCalls += 1;
            return 0;
        };
        const stuck = createFsGate({ rawGrant: FX.grant, primitives: primitivesRecordingFd() });
        assert.ok(!isRefusal(stuck));
        const stuckResult = await stuck.createFileInGrant('loop-no-progress.md', Buffer.from('x'.repeat(64)));
        assert.ok(isRefusal(stuckResult), 'a loop that cannot progress must refuse, not hang or succeed');
        assert.equal(stuckResult.reason, 'IO_ERROR');
        assert.match(stuckResult.detail, /0 of 64 bytes/);
        assert.notEqual(stuckResult.retained, null, 'the target was opened, so retention is indeterminate');
        // ⚠ THE WITNESS. `IO_ERROR` is also what a regression refusing BEFORE the loop returns, and
        // a count of EXACTLY ONE is what separates "the break fired" from "it looped and gave up".
        assert.equal(noProgressCalls, 1,
            '⚠ the shipped loop must ask ONCE and break — anything else means this case proved nothing');

        /* (2) PARTIAL WRITES — the loop must RESUME until the buffer is exhausted. */
        let partialCalls = 0;
        fs.writeSync = (fd, buffer, offset, length, position) => {
            if (fd !== ours) return realWriteSync(fd, buffer, offset, length, position);
            partialCalls += 1;
            // One byte at a time, so completion can only come from iterating.
            return realWriteSync(fd, buffer, offset, 1, position);
        };
        const dribble = createFsGate({ rawGrant: FX.grant, primitives: primitivesRecordingFd() });
        assert.ok(!isRefusal(dribble));
        const payload = Buffer.from('the loop resumes until the buffer is exhausted');
        const done = await dribble.createFileInGrant('loop-partial.md', payload);
        assert.ok(!isRefusal(done), `a resumable partial write must complete: ${JSON.stringify(done)}`);
        assert.equal(done.bytes, payload.length, 'the reported count is the whole buffer');
        assert.ok(fs.readFileSync(path.join(root, 'loop-partial.md')).equals(payload),
            'the file on disk must be byte-identical to what was handed in');
        assert.equal(partialCalls, payload.length,
            '⚠ one call per byte — fewer means the loop was not the thing that completed the write');

        /* (3) THE SYSCALL THROWS — the loop must not swallow it; the gate maps and reports. */
        let throwCalls = 0;
        fs.writeSync = (fd, ...rest) => {
            if (fd !== ours) return realWriteSync(fd, ...rest);
            throwCalls += 1;
            const error = new Error('injected EIO from the syscall');
            error.code = 'EIO';
            throw error;
        };
        const thrower = createFsGate({ rawGrant: FX.grant, primitives: primitivesRecordingFd() });
        assert.ok(!isRefusal(thrower));
        const threw = await thrower.createFileInGrant('loop-throws.md', Buffer.from('x'));
        assert.ok(isRefusal(threw), 'a throwing syscall must surface as a refusal');
        assert.equal(threw.reason, 'IO_ERROR');
        // ⚠ THE ERRNO IN THE DETAIL IS WHAT SEPARATES PROPAGATION FROM SWALLOWING, and without it
        // this case could not tell them apart. A loop that caught the throw and broke would report
        // `wrote 0 of 1 bytes` — also `IO_ERROR`, also `retained`, also one syscall — so reason,
        // retention and the witness count are all satisfied by the mutant this case exists to kill.
        assert.match(threw.detail, /EIO/, 'the throw must reach the errno mapper, not be folded into a short write');
        assert.notEqual(threw.retained, null, 'the target was opened, so retention is indeterminate');
        assert.equal(throwCalls, 1, '⚠ the refusal did NOT come from the syscall — this case proved nothing');
    } finally {
        fs.writeSync = realWriteSync;
    }
    // ⚠ ASSERTED, NOT TRUSTED TO THE `finally`. A patch left in place would corrupt every arm that
    // runs after this one, in ways that would read as unrelated failures.
    assert.equal(fs.writeSync, realWriteSync, 'the runtime write must be restored');
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

/* ------------------------------------------------------------------ *
 * THE APPEND PATH — `appendLineInGrant`, added 2026-09-02.             *
 *                                                                      *
 * ⚠⚠ NONE OF THESE ARE COVERED BY THE CREATE ARMS, AND THE REASON IS   *
 * MECHANICAL RATHER THAN CAUTIOUS. `appendLineInGrant` does NOT call   *
 * `resolveNew`: that function refuses EXISTS the moment its leaf probe *
 * finds anything, which is right for a create and fatal for an append  *
 * — the second append to a lineage file would refuse. So the parent    *
 * resolution, the name screens and the containment check are performed *
 * AGAIN on the append path, by the same calls in the same order, and a *
 * guard deleted from one is invisible to every arm on the other.       *
 * ------------------------------------------------------------------ */

const LINE_A = Buffer.from('{"seq":1}\n');
const LINE_B = Buffer.from('{"seq":2}\n');

test('A56-append-core — the first append creates, the second appends, and no parent is made', async () => {
    arm('A56-append-core');

    const first = await gate.appendLineInGrant('lineage-a56.jsonl', LINE_A);
    assert.ok(!isRefusal(first), `the first append must create: ${JSON.stringify(first)}`);
    assert.equal(first.rel, 'lineage-a56.jsonl');
    assert.equal(first.bytes, LINE_A.length);
    // ⚠ THE RETURN CARRIES NO ABSOLUTE PATH, AND NO EXTRA FIELD. Same shape ruling as A40's.
    assert.deepEqual(Object.keys(first).sort(), ['bytes', 'ok', 'rel']);

    const second = await gate.appendLineInGrant('lineage-a56.jsonl', LINE_B);
    assert.ok(!isRefusal(second), 'the second append must APPEND, not refuse EXISTS');
    assert.equal(second.bytes, LINE_B.length);

    // ⚠ THE FILE IS READ BACK WHOLE. Reporting the right count while truncating the earlier record
    // is exactly the defect a count assertion alone cannot see.
    assert.equal(
        fs.readFileSync(path.join(root, 'lineage-a56.jsonl'), 'utf8'),
        `${LINE_A}${LINE_B}`,
        'both records must be present, in order, byte-for-byte'
    );

    // ⚠⚠ THE FENCE MAKES NO DIRECTORY. The Scribe refuses when `.wyrd/` is missing, and that is
    // only true if the fence declines to create it — asserted, because a `mkdir` added later would
    // silently take that decision away from the caller.
    const nestedMissing = await gate.appendLineInGrant('.wyrd/lineage.jsonl', LINE_A);
    assert.ok(isRefusal(nestedMissing), 'a missing parent must refuse, not be created');
    assert.equal(nestedMissing.reason, 'MISSING');
    assert.equal(fs.existsSync(path.join(root, '.wyrd')), false,
        '⚠ the fence CREATED the parent directory — the Scribe can no longer refuse a missing .wyrd/');

    // The nested case works once the parent is really there, which is what makes the row above a
    // statement about the DIRECTORY and not about nested paths.
    fs.mkdirSync(path.join(root, '.wyrd'));
    const nested = await gate.appendLineInGrant('.wyrd/lineage.jsonl', LINE_A);
    assert.ok(!isRefusal(nested), `an existing parent must accept the append: ${JSON.stringify(nested)}`);
    assert.equal(nested.rel, path.join('.wyrd', 'lineage.jsonl'));

    // Line framing, refused without the fence ever parsing the record.
    const framings = [
        ['not a buffer', 'a non-Buffer line'],
        [Buffer.alloc(0), 'an empty line'],
        [Buffer.from('no newline'), 'a line with no terminator'],
        [Buffer.from('two\nlines\n'), 'two records in one call'],
        [Buffer.from('\nleading'), 'a newline that is not last']
    ];
    for (const [value, label] of framings) {
        const r = await gate.appendLineInGrant('lineage-a56.jsonl', value);
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.reason, 'BAD_INPUT', `${label} must refuse BAD_INPUT, got ${r.reason}`);
        assert.equal(r.retained, null, `${label} refuses before anything opens`);
    }
    // ⚠ AND THE FILE IS UNCHANGED BY ALL OF THEM. A framing refusal that had already appended
    // would be the worst of both.
    assert.equal(
        fs.readFileSync(path.join(root, 'lineage-a56.jsonl'), 'utf8'),
        `${LINE_A}${LINE_B}`,
        'a framing refusal must not have written anything'
    );
});

test('A57-append-parent-containment — parents are fenced, and an aliased parent refuses', async () => {
    arm('A57-append-parent-containment');

    // ⚠⚠ REVERSED 2026-09-08. This leg used to require `j_in/lineage-a57.jsonl` to APPEND, landing
    // on the canonical `subdir`. That is the SECOND `Arc/` route and it needs no page write at all:
    // `LINEAGE_PATH` is the fixed `.wyrd/lineage.jsonl`, so a `.wyrd` junction to `Arc` is a
    // complete attack — measured, an ordinary stamp wrote `lineage.jsonl` INTO `Arc/`.
    //
    // ⚠ TIER 1, DELIBERATELY, AND THE NAME IS NOT THE TIER. `j_in` is a JUNCTION, which needs no
    // privilege — the same reasoning `A28-symlinked-root` and `A40-create`'s junction leg stand on.
    //
    // ⚠ THE APPEND PATH DOES NOT CALL `resolveNew`, so this is a SECOND copy of the comparison and
    // not the same one measured twice. Deleting either leaves the other green.
    const viaJunction = await gate.appendLineInGrant('j_in/lineage-a57.jsonl', LINE_A);
    assert.ok(isRefusal(viaJunction), 'an in-grant junction parent must REFUSE on the append path too');
    assert.equal(viaJunction.reason, 'PARENT_ALIAS', `expected PARENT_ALIAS, got ${viaJunction.reason}`);
    assert.equal(viaJunction.retained, null, 'nothing was opened on this path');
    assert.equal(
        fs.existsSync(path.join(root, 'subdir', 'lineage-a57.jsonl')), false,
        '⚠ the refusal came AFTER the line had already landed on the canonical parent'
    );

    // ⚠ THE OTHER HALF, or the arm proves only "refuses everything with a link in it": an ORDINARY
    // real-directory parent must still append, and it must land on that parent.
    const plainParent = await gate.appendLineInGrant('subdir/lineage-a57-plain.jsonl', LINE_A);
    assert.ok(!isRefusal(plainParent), `a real directory parent must append: ${JSON.stringify(plainParent)}`);
    assert.equal(plainParent.rel, path.join('subdir', 'lineage-a57-plain.jsonl'));
    // And AGAIN, because an append that only ever creates would satisfy the line above while the
    // existing-file branch — the one `resolveNew` cannot serve — was never reached.
    const plainAgain = await gate.appendLineInGrant('subdir/lineage-a57-plain.jsonl', LINE_B);
    assert.ok(!isRefusal(plainAgain), `the second append must reach the existing-file branch: ${JSON.stringify(plainAgain)}`);
    assert.equal(
        fs.readFileSync(path.join(root, 'subdir', 'lineage-a57-plain.jsonl'), 'utf8'),
        `${LINE_A}${LINE_B}`
    );

    // An escaping parent is caught by the fence itself, not by a second check bolted on here.
    const escaping = [
        ['../outside/lineage.jsonl', 'a `..` parent'],
        ['subdir/../../outside/lineage.jsonl', 'a parent that climbs out mid-path'],
        ['j_out/lineage.jsonl', 'a junction parent pointing outside'],
        ['ds_out/lineage.jsonl', 'a directory-symlink parent pointing outside']
    ];
    for (const [request, label] of escaping) {
        const r = await gate.appendLineInGrant(request, LINE_A);
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.retained, null, `${label} refuses before anything opens`);
    }
    assert.equal(fs.existsSync(path.join(FX.outside, 'lineage.jsonl')), false,
        '⚠ an escaping parent LANDED A FILE OUTSIDE THE GRANT');

    // A parent that does not exist, and one that is a file rather than a directory.
    const missing = await gate.appendLineInGrant('no-such-dir/lineage.jsonl', LINE_A);
    assert.ok(isRefusal(missing));
    assert.equal(missing.reason, 'MISSING');
    const notADirectory = await gate.appendLineInGrant('subdir/note.md/lineage.jsonl', LINE_A);
    assert.ok(isRefusal(notADirectory));
    assert.equal(notADirectory.reason, 'NOT_A_DIRECTORY');
});

test('A66-parent-alias-refused — a write goes where it was SPELLED, and the check beats EXISTS', async () => {
    arm('A66-parent-alias-refused');

    /**
     * ⚠⚠ THE PROPERTY IS NOT CONTAINMENT, AND THAT IS WHY NO EXISTING ARM CAUGHT THIS. `alias_dir`
     * is an in-grant junction to `protected_dir`: it resolves INSIDE the grant, so `ESCAPES` is
     * false, the walk is happy and the realpath arbitration is happy. Every containment predicate
     * this fence owns returns "yes" and the write lands somewhere the caller never named. Measured
     * against the shipped gate on 2026-09-04 with a real vault layout: `Notes -> Arc`, then
     * `writePage({path:'Notes/planted.md'})` returned `ok: true` with the file at
     * `vault/Arc/planted.md`.
     *
     * ⚠ TIER 1. A junction needs no Windows privilege, so this escape is reachable on a machine
     * without Developer Mode and the arm must run there.
     */
    const protectedDir = path.join(root, 'protected_dir');
    const before = fs.readdirSync(protectedDir).sort();

    // ---- part 1: the create path -------------------------------------------
    const created = await gate.createFileInGrant('alias_dir/planted.md', Buffer.from('MUST NOT LAND\n'));
    assert.ok(isRefusal(created), 'a create through an aliased parent must refuse');
    assert.equal(created.reason, 'PARENT_ALIAS', `expected PARENT_ALIAS, got ${created.reason}: ${created.detail}`);
    assert.equal(created.retained, null, 'nothing was opened, so nothing is retained');

    // ---- part 2: the append path, which does NOT share part 1's code --------
    const appended = await gate.appendLineInGrant('alias_dir/lineage.jsonl', LINE_A);
    assert.ok(isRefusal(appended), 'an append through an aliased parent must refuse');
    assert.equal(appended.reason, 'PARENT_ALIAS', `expected PARENT_ALIAS, got ${appended.reason}: ${appended.detail}`);
    assert.equal(appended.retained, null, 'nothing was opened, so nothing is retained');

    // ⚠⚠ THE ASSERTION THAT MATTERS IS NOT THE REFUSAL — it is that the protected directory is
    // UNCHANGED. A refusal returned after the bytes had already landed satisfies every line above.
    assert.deepEqual(fs.readdirSync(protectedDir).sort(), before,
        '⚠ A WRITE LANDED IN THE PROTECTED DIRECTORY AND THE REFUSAL CAME AFTERWARDS');

    /**
     * ⚠⚠ THE ORDERING CLAIM, AND IT IS THE WHOLE MECHANISM THE SCRIBE'S CONFIG LOAD RESTS ON.
     * `protected_dir/occupied.md` already EXISTS, so `alias_dir/occupied.md` names a taken name
     * through an aliased parent. If the comparison sat after the leaf probe the answer would be
     * `EXISTS`, and an already-present file would HIDE the alias — which is exactly how an existing
     * `Arc/scribe.json` would hide a `.wyrd -> Arc` junction from a read-first config load.
     */
    const occupied = await gate.createFileInGrant('alias_dir/occupied.md', Buffer.from('MUST NOT LAND\n'));
    assert.ok(isRefusal(occupied));
    assert.equal(occupied.reason, 'PARENT_ALIAS',
        `an existing leaf must not hide the alias: expected PARENT_ALIAS, got ${occupied.reason}`);
    assert.equal(
        fs.readFileSync(path.join(protectedDir, 'occupied.md'), 'utf8'), CANARY.protectedOccupied,
        'and the existing file is byte-identical afterwards'
    );

    /**
     * ⚠⚠ THE DETAIL MUST NAME THE CALLER'S SPELLING AND NOT WHERE THE ALIAS POINTS. The comparison's
     * own comment calls this a legibility rule; this is what makes it a rule rather than a note.
     * Reporting `parent.rel` — the canonical `protected_dir` — would tell a caller who probed with a
     * junction exactly what it resolves to, which is a fact about the vault's shape they did not
     * have before probing. Both names are in-grant, so nothing escapes either way; what changes is
     * whether a refusal answers a question it was not asked.
     *
     * ⚠⚠ COMPARED CASE-FOLDED SINCE 2026-09-08, AND THE CASE-SENSITIVE VERSION WAS A HOLE RATHER
     * THAN A STYLE CHOICE. This host's filesystem folds case, so a resolved spelling can legitimately
     * come back `Protected_Dir` or `PROTECTED_DIR` for the same directory — and a plain
     * `includes('protected_dir')` passes over every one of those. A check that catches only the
     * lowercase spelling of a leak is not a check. Both sides are folded, so neither the detail's
     * casing nor the target's decides the answer.
     */
    const namesTarget = (detail, target) => detail.toLowerCase().includes(target.toLowerCase());
    for (const [refused, label] of [[created, 'create'], [appended, 'append'], [occupied, 'occupied-leaf']]) {
        assert.ok(!namesTarget(refused.detail, 'protected_dir'),
            `the ${label} refusal names the alias TARGET: ${JSON.stringify(refused.detail)}`);
        assert.ok(namesTarget(refused.detail, 'alias_dir'),
            `and the ${label} refusal must name the caller's own spelling: ${JSON.stringify(refused.detail)}`);
    }

    /**
     * ⚠⚠ A DEEPER ANCESTOR, NOT ONLY THE IMMEDIATE PARENT. `alias_dir/sub/x.md` puts the alias one
     * level ABOVE the write's own parent, so a check that compared only the final component would
     * pass it and land the file in `protected_dir/sub/`. The property is about the whole resolved
     * parent path, and this is the leg that says so.
     */
    const subBefore = fs.readdirSync(path.join(protectedDir, 'sub')).sort();
    const deep = await gate.createFileInGrant('alias_dir/sub/x.md', Buffer.from('MUST NOT LAND\n'));
    assert.ok(isRefusal(deep), 'a create through a DEEPER aliased ancestor must refuse');
    assert.equal(deep.reason, 'PARENT_ALIAS',
        `expected PARENT_ALIAS through a deeper ancestor, got ${deep.reason}: ${deep.detail}`);
    assert.equal(deep.retained, null, 'nothing was opened, so nothing is retained');
    assert.ok(!namesTarget(deep.detail, 'protected_dir'),
        `the deeper refusal must not name the alias TARGET either: ${JSON.stringify(deep.detail)}`);
    assert.ok(namesTarget(deep.detail, 'alias_dir'),
        `and the deeper refusal must name the caller's own spelling: ${JSON.stringify(deep.detail)}`);
    assert.deepEqual(fs.readdirSync(path.join(protectedDir, 'sub')).sort(), subBefore,
        '⚠ A DEEPER-ANCESTOR ALIAS LANDED A WRITE IN THE PROTECTED DIRECTORY');

    const deepAppend = await gate.appendLineInGrant('alias_dir/sub/lineage.jsonl', LINE_A);
    assert.ok(isRefusal(deepAppend), 'and on the append path too');
    assert.equal(deepAppend.reason, 'PARENT_ALIAS',
        `expected PARENT_ALIAS on the deeper append, got ${deepAppend.reason}: ${deepAppend.detail}`);
    // ⚠ THE LEG HAD NO DETAIL CHECK AT ALL UNTIL 2026-09-08, WHICH IS THE CLASS RATHER THAN AN
    // OVERSIGHT: the property was asserted on the legs someone remembered rather than on every
    // refusing leg, so the deeper APPEND could have named the target and nothing would have said so.
    assert.ok(!namesTarget(deepAppend.detail, 'protected_dir'),
        `the deeper append refusal must not name the alias TARGET: ${JSON.stringify(deepAppend.detail)}`);
    assert.ok(namesTarget(deepAppend.detail, 'alias_dir'),
        `and it must name the caller's own spelling: ${JSON.stringify(deepAppend.detail)}`);
    assert.deepEqual(fs.readdirSync(path.join(protectedDir, 'sub')).sort(), subBefore,
        '⚠ THE DEEPER APPEND LANDED IN THE PROTECTED DIRECTORY');

    /**
     * ⚠⚠ THE DIRECTORY-SYMLINK VARIANT, HELD BACK WITH A PRINTED LINE RATHER THAN SKIPPING THE ARM.
     * `A14-M`/`A23-dsym` measured (2026-08-28) that the OS resolves a directory SYMLINK by the
     * SUBSTITUTED spelling where it resolves a JUNCTION by the traversal one, and that Node cannot
     * distinguish the two kinds — so a guard shown holding for junctions is not thereby shown
     * holding for symlinks. The junction legs above need no privilege and are tier 1; this one does
     * need it, so it is gated on the fixture's presence exactly as the case-fold legs below are,
     * instead of putting the whole arm behind `tier2()` and losing the tier-1 coverage.
     */
    if (fs.existsSync(path.join(root, 'alias_dsym'))) {
        const dsym = await gate.createFileInGrant('alias_dsym/planted.md', Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(dsym), 'a create through a directory SYMLINK alias must refuse');
        assert.equal(dsym.reason, 'PARENT_ALIAS',
            `expected PARENT_ALIAS through a directory symlink, got ${dsym.reason}: ${dsym.detail}`);
        assert.equal(dsym.retained, null, 'nothing was opened, so nothing is retained');
        assert.ok(!namesTarget(dsym.detail, 'protected_dir'),
            `the symlink refusal must not name the alias TARGET: ${JSON.stringify(dsym.detail)}`);
        assert.ok(namesTarget(dsym.detail, 'alias_dsym'),
            `and it must name the caller's own spelling: ${JSON.stringify(dsym.detail)}`);

        const dsymAppend = await gate.appendLineInGrant('alias_dsym/lineage.jsonl', LINE_A);
        assert.ok(isRefusal(dsymAppend), 'and on the append path too');
        assert.equal(dsymAppend.reason, 'PARENT_ALIAS',
            `expected PARENT_ALIAS on the symlink append, got ${dsymAppend.reason}: ${dsymAppend.detail}`);
        // ⚠ THE SYMLINK APPEND LEG HAD NO DETAIL CHECK EITHER UNTIL 2026-09-08 — same class as the
        // deeper append above, and it matters more here: the symlink legs are the ones that need
        // privilege, so they run least often and are least likely to be noticed drifting.
        assert.ok(!namesTarget(dsymAppend.detail, 'protected_dir'),
            `the symlink append refusal must not name the alias TARGET: ${JSON.stringify(dsymAppend.detail)}`);
        assert.ok(namesTarget(dsymAppend.detail, 'alias_dsym'),
            `and it must name the caller's own spelling: ${JSON.stringify(dsymAppend.detail)}`);

        assert.deepEqual(fs.readdirSync(protectedDir).sort(), before,
            '⚠ A WRITE THROUGH THE DIRECTORY-SYMLINK ALIAS LANDED IN THE PROTECTED DIRECTORY');
        console.log('    A66-parent-alias-refused: the directory-SYMLINK alias legs ran.');
    } else {
        console.log(
            '    A66-parent-alias-refused: the directory-SYMLINK alias legs are HELD BACK — this run '
            + 'has no symlink privilege, so the fixture was not built. The JUNCTION legs above ran.'
        );
    }

    // ---- the false positive the exact comparison would have produced --------
    // ⚠ A DIFFERENTLY-CASED SPELLING OF A REAL DIRECTORY IS NOT AN ALIAS. On a case-folding volume
    // `PROTECTED_DIR` and `protected_dir` are one directory, `realpathNative` returns the canonical
    // spelling, and an exact comparison would refuse an ordinary user's path. Measured on the
    // fixture's own volume rather than inferred from `process.platform`, the way `A25-case` does.
    if (fs.existsSync(path.join(root, 'PROTECTED_DIR'))) {
        const folded = await gate.createFileInGrant('PROTECTED_DIR/folded-by-a66.md', Buffer.from('folded\n'));
        assert.ok(!isRefusal(folded),
            `a case-only spelling is not an alias and must create: ${JSON.stringify(folded)}`);
        assert.equal(folded.rel, path.join('protected_dir', 'folded-by-a66.md'));
        const foldedAppend = await gate.appendLineInGrant('PROTECTED_DIR/lineage-a66.jsonl', LINE_A);
        assert.ok(!isRefusal(foldedAppend),
            `and on the append path too: ${JSON.stringify(foldedAppend)}`);
        console.log('    A66-parent-alias-refused: this filesystem FOLDS case; the case-fold legs ran.');
    } else {
        // ⚠ SAID OUT LOUD. On a case-SENSITIVE volume the folded spelling names nothing, so the
        // false-positive leg has nothing to exercise — and the ACCEPTED COST is live there instead:
        // a genuine `mage -> Mage` alias folds equal and is allowed. Stated where the run is read.
        console.log(
            '    A66-parent-alias-refused: this filesystem is case-SENSITIVE; the case-fold legs are '
            + 'HELD BACK, and a genuine case-only alias would be ALLOWED here by design.'
        );
    }
});

test('A58-append-leaf-no-follow — a link, junction or directory leaf refuses before any write', { ...tier2('A58-append-leaf-no-follow') }, async () => {    arm('A58-append-leaf-no-follow');

    // ⚠⚠ THIS IS THE ARM THE CREATE PATH GETS FOR FREE AND THE APPEND PATH DOES NOT.
    // `createFileInGrant` opens `wx`, so the operating system refuses every existing object without
    // the fence inspecting anything. An append MUST open something that already exists, so `wx` is
    // unavailable and the no-follow property has to be established by the probe — which means it
    // can be deleted, and only this arm would notice.
    const outsideBefore = fs.readFileSync(path.join(FX.outside, 'secret.md'));

    const leaves = [
        ['s_out', 'a symlink to an outside file'],
        ['s_in', 'a symlink to an in-grant file'],
        ['j_out', 'a junction to outside'],
        ['j_in', 'a junction to an in-grant directory'],
        ['subdir', 'a directory'],
        ['dangle_out', 'a DANGLING symlink whose target does not exist'],
        ['dangle_junc_out', 'a DANGLING junction whose target does not exist']
    ];
    for (const [request, label] of leaves) {
        const r = await gate.appendLineInGrant(request, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.retained, null, `${label} must refuse BEFORE anything is opened`);
    }

    // ⚠⚠ THE HARD LINK, WHICH THIS ARM ASSERTED AS A SUCCESS UNTIL 2026-09-02 AND NOW ASSERTS AS A
    // REFUSAL. `h_out.md` is an in-grant name for a file whose other name is outside the grant;
    // `isSymbolicLink()` is false, `readlink` throws EINVAL, and every canonicalization API
    // correctly reports an in-grant path — so nothing in the leaf probe's KIND inspection or in the
    // dev/ino identity binding can see it, and the append used to land on the outside file. The
    // read path still lives with that alias; an append cannot, because a write through it is a
    // write outside the grant. The link count is the one reading that separates them.
    //
    // ⚠ BOTH DIRECTIONS ARE ASSERTED — that it refuses, AND that neither file moved. A refusal
    // returned after the bytes had already landed would satisfy the first assertion alone.
    const inGrantHardlink = path.join(FX.grant, 'h_out.md');
    const inGrantBefore = fs.readFileSync(inGrantHardlink);
    const hardlinked = await gate.appendLineInGrant('h_out.md', Buffer.from('{"hardlink":true}\n'));
    assert.ok(isRefusal(hardlinked),
        'a leaf with more than one name must refuse: it may alias a file outside the grant, and no ' +
        'path-based check can prove it does not');
    assert.equal(hardlinked.reason, 'NOT_A_FILE',
        `expected NOT_A_FILE, got ${hardlinked.reason}: ${hardlinked.detail}`);
    assert.equal(hardlinked.retained, null, 'the pre-open reading refuses BEFORE anything is opened');
    assert.ok(
        outsideBefore.equals(fs.readFileSync(path.join(FX.outside, 'secret.md'))),
        '⚠ THE APPEND REACHED THE OUTSIDE FILE THROUGH THE HARD LINK'
    );
    assert.ok(
        inGrantBefore.equals(fs.readFileSync(inGrantHardlink)),
        'and nothing was written to the in-grant name either — one object, so this is the same bytes'
    );

    // Every OTHER leaf left the outside file untouched — the loop above asserts refusal, and this
    // asserts that no refusal came after the filesystem had already been mutated.
    assert.ok(
        outsideBefore.equals(fs.readFileSync(path.join(FX.outside, 'secret.md'))),
        '⚠ AN APPEND REACHED THROUGH TO THE OUTSIDE FILE'
    );
    assert.equal(fs.existsSync(path.join(FX.outside, 'nope.md')), false,
        '⚠ the dangling symlink was FOLLOWED and created its target outside the grant');
    assert.equal(fs.existsSync(path.join(FX.outside, 'nodir2')), false,
        '⚠ the dangling junction was FOLLOWED and created its target outside the grant');

    // The other half, or the arm proves only "refuses everything": an ORDINARY existing file must
    // append, and it must be the SAME file afterwards.
    const plain = path.join(root, 'ordinary-a58.jsonl');
    fs.writeFileSync(plain, LINE_A);
    const appended = await gate.appendLineInGrant('ordinary-a58.jsonl', LINE_B);
    assert.ok(!isRefusal(appended), `an ordinary existing file must append: ${JSON.stringify(appended)}`);
    assert.equal(fs.readFileSync(plain, 'utf8'), `${LINE_A}${LINE_B}`);

    /* ⚠⚠ THE POST-OPEN REAL PATH, WHICH NOTHING ABOVE REACHES — AND `M83` MEASURED THAT.
     *
     * Every leaf above refuses at the PROBE, so the containment check that runs AFTER the open was
     * unexercised: deleting it left the whole suite green (measured 2026-09-02, the row came back
     * SURVIVED). The check exists for the class the probe cannot classify — a reparse tag this
     * runtime reports as an ordinary file, which `realpathNative` resolves and the fence then finds
     * outside the grant. No such tag can be created here, so it is staged at the one seam the fence
     * offers: the primitive itself, answering as the operating system would for that tag.
     *
     * ⚠ THE INJECTION IS SCOPED TO THE POST-OPEN CALL. `realpathNative` is also the root re-check's
     * call and the walk's arbitration; answering "outside" for those would refuse ROOT_MOVED or
     * ESCAPES much earlier and the arm would pass having never reached the line it names. */
    {
        const escapeTarget = path.join(FX.outside, 'a58-realpath-decoy.md');
        fs.writeFileSync(escapeTarget, 'OUTSIDE-DECOY\n');
        const leafName = 'a58-realpath.jsonl';
        const leafPath = path.join(root, leafName);
        fs.writeFileSync(leafPath, 'IN-GRANT\n');
        let postOpenAnswers = 0;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                realpathNative: t => {
                    if (path.basename(t) === leafName) {
                        postOpenAnswers += 1;
                        // What the OS would report for a reparse tag it followed out of the grant.
                        return escapeTarget;
                    }
                    return fs.realpathSync.native(t);
                }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant(leafName, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), 'a leaf whose real path leaves the grant must refuse AFTER the open');
        assert.equal(r.reason, 'ESCAPES', `expected ESCAPES, got ${r.reason}: ${r.detail}`);
        assert.equal(postOpenAnswers, 1,
            '⚠ the post-open realpath was never consulted — this leg proved nothing');
        assert.notEqual(r.retained, null, 'the descriptor was opened, so retention is indeterminate');
        assert.equal(fs.readFileSync(escapeTarget, 'utf8'), 'OUTSIDE-DECOY\n',
            '⚠ THE APPEND LANDED OUTSIDE THE GRANT');
        assert.equal(fs.readFileSync(leafPath, 'utf8'), 'IN-GRANT\n',
            'and it did not write to the in-grant leaf either — the refusal is before the write');
        fs.rmSync(escapeTarget, { force: true });
    }

    // ⚠⚠ AND AGAIN ON AN UNINJECTED GATE. `spyPrimitives` supplies `openAppend`, so every row above
    // exercises the SPY's flags rather than the shipped `_openAppend`. That is the M48 shape
    // exactly, one primitive over — the instrumentation quietly replacing the thing under test.
    const bare = createFsGate({ rawGrant: FX.grant });
    assert.ok(!isRefusal(bare));
    for (const [request, label] of leaves) {
        const r = await bare.appendLineInGrant(request, Buffer.from('MUST NOT LAND\n'));
        assert.ok(isRefusal(r), `${label} must refuse on the PRODUCTION primitives`);
    }
    assert.ok(
        outsideBefore.equals(fs.readFileSync(path.join(FX.outside, 'secret.md'))),
        '⚠ THE UNINJECTED APPEND REACHED THROUGH TO THE OUTSIDE FILE'
    );
    assert.equal(fs.existsSync(path.join(FX.outside, 'nope.md')), false,
        '⚠ the uninjected gate FOLLOWED the dangling symlink');
});

test('A59-append-probe-errors — only a leaf ENOENT selects create; every other probe error refuses', async () => {
    arm('A59-append-probe-errors');

    // Same shape and same witness discipline as `A43-probe-errors`, on the other write path — and
    // it is a separate arm because the probe is a separate probe: A43's lives in `resolveNew`,
    // which the append path does not call.
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
        // ⚠ THE WITNESS. `IO_ERROR` is also what a regression refusing EARLIER returns, so counting
        // the probe is what makes the row a claim about the probe rather than about the code.
        let leafProbeCalls = 0;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                lstat: t => {
                    if (path.basename(t) === 'probe-a59.jsonl') {
                        leafProbeCalls += 1;
                        const error = new Error(`injected ${label}`);
                        if (code !== undefined) error.code = code;
                        throw error;
                    }
                    return fs.lstatSync(t);
                },
                openAppend: (t, mode) => {
                    openedAnyway = true;
                    return mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                }
            }
        });
        assert.ok(!isRefusal(injected));

        const r = await injected.appendLineInGrant('probe-a59.jsonl', LINE_A);
        assert.ok(isRefusal(r), `${label}: the leaf probe must refuse, not append`);
        assert.equal(r.reason, reason, `${label}: the probe must map to its actual refusal reason`);
        assert.equal(leafProbeCalls, 1,
            `⚠ ${label}: the refusal did NOT come from the leaf probe — this row proved nothing`);
        assert.equal(openedAnyway, false, `⚠ ${label}: the probe REACHED THE OPEN`);
        assert.equal(r.retained, null, `${label}: nothing was opened, so nothing is retained`);
        assert.equal(fs.existsSync(path.join(root, 'probe-a59.jsonl')), false,
            `${label}: the probe must create nothing`);
    }

    // And the positive control: a genuine ENOENT DOES select create, or every row above passes for
    // the trivial reason that the append path refuses everything.
    const clean = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives([]) });
    assert.ok(!isRefusal(clean));
    const created = await clean.appendLineInGrant('probe-a59-clean.jsonl', LINE_A);
    assert.ok(!isRefusal(created), 'an absent leaf must select the create branch and succeed');
});

test('A60-append-target-changed — a leaf that is not the object observed refuses TARGET_CHANGED', async () => {
    arm('A60-append-target-changed');

    /* ⚠⚠ THE FIRST TWO CASES DO NOT INJECT `openAppend`, AND THE FIRST VERSION OF THEM DID —
     * MEASURED 2026-09-02, WHERE IT COST BOTH ROWS THEIR SUBJECT. `M77-append-create-not-exclusive`
     * (`ax` -> `a`) and `M78-append-existing-creates` (`O_CREAT` onto the existing branch) both
     * patch the SHIPPED `_openAppend`, and both came back SURVIVED because the injected table had
     * replaced it: the cases exercised the spy's flags and the real ones were never reached. That is
     * `M48` exactly, one primitive over — the instrumentation quietly standing in for the thing
     * under test. The race is therefore staged through the LEAF PROBE, which is the last call the
     * fence makes before the open, and the open itself is the production one. */

    /* (1) ABSENT AT THE PROBE, PRESENT AT THE OPEN. The `ax` open fails EEXIST and the answer is
     *     TARGET_CHANGED, never a silent append onto whatever arrived. */
    {
        const target = path.join(root, 'race-appeared.jsonl');
        // ⚠ THE FILE REALLY IS THERE THE WHOLE TIME. Only the PROBE is lied to, so the create
        // branch is selected and the production open meets an existing object — which is the state
        // a genuine race produces, and the one `ax` exists to refuse.
        fs.writeFileSync(target, 'PLANTED\n');
        let probed = false;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: undefined,   // ⚠ production `_openAppend`, deliberately — see above
                lstat: t => {
                    if (path.basename(t) === 'race-appeared.jsonl') {
                        probed = true;
                        const error = new Error('injected ENOENT — the name looks free');
                        error.code = 'ENOENT';
                        throw error;
                    }
                    return fs.lstatSync(t);
                }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('race-appeared.jsonl', LINE_A);
        assert.ok(isRefusal(r), 'a leaf that appeared since the probe must refuse');
        assert.equal(r.reason, 'TARGET_CHANGED');
        assert.equal(probed, true, '⚠ the leaf probe was never reached — this case proved nothing');
        assert.equal(r.retained, null, 'the exclusive open failed, so nothing was created by this call');
        assert.equal(fs.readFileSync(target, 'utf8'), 'PLANTED\n',
            '⚠ the append landed on an object it never observed');
    }

    /* (2) PRESENT AT THE PROBE, GONE AT THE OPEN. The existing branch carries NO `O_CREAT`, so the
     *     open fails ENOENT rather than silently recreating an empty lineage file.
     *
     * ⚠⚠ THE SEAM IS `fs.lstatSync` ITSELF, PATCHED FOR ONE PATH, AND THERE IS NO OTHER ONE.
     * The removal has to land AFTER the exact-identity read and BEFORE the open, and the fence
     * makes no injectable call in that window: the identity read goes to `fs.lstatSync(…, {bigint:
     * true})` directly (see `exactIdentityOf` for why it must), and the next thing that happens is
     * the open. Injecting `Primitives.lstat` puts the removal one call too early and the identity
     * read then refuses for its own reason, never reaching the open — which is what `M78` needs
     * reached. Same pattern and same discipline as `A54-writeall-loop`'s `fs.writeSync` patch:
     * scoped to one path, restored in `finally`, asserted restored. */
    {
        const target = path.join(root, 'race-vanished.jsonl');
        fs.writeFileSync(target, LINE_A);
        const realLstatSync = fs.lstatSync;
        let identityReads = 0;
        try {
            fs.lstatSync = (p, options) => {
                const stats = realLstatSync(p, options);
                // Only the BIGINT read of our one target — that is the exact-identity call, and the
                // last observation the fence makes before it opens.
                if (options?.bigint === true && path.basename(String(p)) === 'race-vanished.jsonl') {
                    identityReads += 1;
                    fs.rmSync(target, { force: true });
                }
                return stats;
            };
            const injected = createFsGate({
                rawGrant: FX.grant,
                primitives: {
                    ...spyPrimitives([]),
                    openAppend: undefined,   // ⚠ production `_openAppend`, deliberately
                    lstat: t => realLstatSync(t)
                }
            });
            assert.ok(!isRefusal(injected));
            const r = await injected.appendLineInGrant('race-vanished.jsonl', LINE_B);
            assert.ok(isRefusal(r), 'a leaf that vanished since the probe must refuse');
            assert.equal(r.reason, 'TARGET_CHANGED');
            assert.equal(identityReads, 1, '⚠ the exact-identity read never happened — this case proved nothing');
            assert.equal(fs.existsSync(target), false,
                '⚠ THE FILE WAS RECREATED — an O_CREAT crept onto the existing branch and the lineage lost its history');
        } finally {
            fs.lstatSync = realLstatSync;
        }
        // ⚠ ASSERTED, NOT TRUSTED TO THE `finally`. A patch left in place would corrupt every arm
        // that runs after this one, in ways that read as unrelated failures.
        assert.equal(fs.lstatSync, realLstatSync, 'the runtime lstat must be restored');
    }

    /* (3) A DIFFERENT OBJECT UNDER THE SAME NAME, SWAPPED BETWEEN THE PROBE AND THE OPEN. This is
     *     the identity comparison itself, and it is the row the number-form `ino` would MISS: a
     *     file deleted and recreated in one directory takes the very next inode, and at NTFS
     *     magnitudes float64 rounds adjacent ids together. Measured 2026-09-02. */
    {
        const target = path.join(root, 'race-swapped.jsonl');
        fs.writeFileSync(target, 'ORIGINAL\n');
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: (t, mode) => {
                    if (path.basename(t) === 'race-swapped.jsonl') {
                        // A genuinely different object at the identical name, before the open.
                        fs.rmSync(t, { force: true });
                        fs.writeFileSync(t, 'REPLACEMENT\n');
                    }
                    return mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('race-swapped.jsonl', LINE_B);
        assert.ok(isRefusal(r), 'a replaced object under an unchanged name must refuse');
        assert.equal(r.reason, 'TARGET_CHANGED');
        assert.notEqual(r.retained, null, 'the descriptor was opened, so retention is indeterminate');
        assert.equal(fs.readFileSync(target, 'utf8'), 'REPLACEMENT\n',
            '⚠ the append wrote into the object it had NOT observed');
    }

    /* (4) THE NAME RE-POINTED AFTER THE OPEN — the descriptor and the name now denote different
     *     objects. This is the one only an `fstat` can see, and a path-based check before the open
     *     structurally cannot.
     *
     * ⚠⚠ STAGED ON THE REAL FILESYSTEM, NOT BY INJECTING `lstat`, AND THE FIRST VERSION OF THIS
     * CASE DID INJECT AND PROVED NOTHING. The identity comparison reads `fs.lstatSync(…, {bigint:
     * true})` directly rather than through `Primitives.lstat` — it has to, because that primitive
     * is typed `=> fs.Stats`, the number form, and NTFS ids round there (see `exactIdentityOf`).
     * So an injected `lstat` returning a decoy's number-form stats is invisible to the very check
     * this case is about, and the arm went green having staged nothing. Replacing the file for
     * real is the only way to move the identity, which is the cost that design decision carries
     * and this is where it is paid. */
    {
        const target = path.join(root, 'race-repointed.jsonl');
        fs.writeFileSync(target, 'ORIGINAL\n');
        let opened = false;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: (t, mode) => {
                    const fd = mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                    if (path.basename(t) === 'race-repointed.jsonl') opened = true;
                    return fd;
                },
                // ⚠ THE RE-POINT HAPPENS AT THE FIRST POST-OPEN READING, WHICH IS `fstat`. Doing it
                // in `openAppend` would be case (3) again — the swap would precede the open. Here
                // the descriptor is already held, and the NAME is moved out from under it: on
                // Windows a file with an open handle can be renamed, so the original survives under
                // a different name and a genuinely different object takes its place.
                fstat: fd => {
                    if (opened) {
                        opened = false;
                        fs.renameSync(target, path.join(root, 'race-repointed-moved.jsonl'));
                        fs.writeFileSync(target, 'REPLACEMENT\n');
                    }
                    return fs.fstatSync(fd);
                }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('race-repointed.jsonl', LINE_B);
        assert.ok(isRefusal(r), 'a name re-pointed after the open must refuse');
        assert.equal(r.reason, 'TARGET_CHANGED');
        assert.notEqual(r.retained, null, 'the descriptor was opened, so retention is indeterminate');
        // ⚠ THE ORIGINAL OBJECT IS THE ONE TO INSPECT — it is what the descriptor still holds, so a
        // write that got through would land THERE and not at the name.
        assert.equal(fs.readFileSync(path.join(root, 'race-repointed-moved.jsonl'), 'utf8'), 'ORIGINAL\n',
            '⚠ the append wrote after the descriptor and the name had diverged');
        assert.equal(fs.readFileSync(target, 'utf8'), 'REPLACEMENT\n',
            'and it did not write to the replacement either');
    }

    /* (5) AN IDENTITY THE FILESYSTEM WILL NOT SUPPLY. `ino === 0` is what a network share reports,
     *     and it CANNOT prove the object unchanged — so the append path fails closed, exactly as
     *     `rootStillCanonical` does for the grant root. */
    {
        const target = path.join(root, 'race-anonymous.jsonl');
        fs.writeFileSync(target, 'ORIGINAL\n');
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: (t, mode) => {
                    // The identity read happens on the real file; strip it by removing the name and
                    // leaving a directory in its place, which supplies no usable file identity.
                    if (path.basename(t) === 'race-anonymous.jsonl') {
                        fs.rmSync(t, { force: true });
                        fs.mkdirSync(t);
                    }
                    return mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('race-anonymous.jsonl', LINE_B);
        assert.ok(isRefusal(r), 'a leaf that became a directory between probe and open must refuse');
        assert.ok(r.reason === 'TARGET_CHANGED' || r.reason === 'NOT_A_FILE' || r.reason === 'DENIED' ||
            r.reason === 'IO_ERROR' || r.reason === 'MISSING',
            `the refusal must name the disagreement, got ${r.reason}`);
        assert.equal(fs.statSync(target).isDirectory(), true,
            '⚠ the append path wrote through to a directory');
        fs.rmdirSync(target);
    }
});

test('A61-append-name-screens — the CREATE screens run on an append, before any I/O', async () => {
    arm('A61-append-name-screens');

    // ⚠ `createScreens`, NOT `readScreens` — the stream screen is unconditional on EVERY host for a
    // write, because the leaf is joined lexically and never reaches the walk. That is the escape
    // reproduced on 2026-08-29 on the create path, and the append path joins its leaf the same way.
    const screened = [
        ['note.jsonl::$DATA', 'STREAM_SYNTAX', 'an explicit primary-stream spelling'],
        ['s_out:wyrd', 'STREAM_SYNTAX', 'the REPRODUCED shape — a stream on a symlink leaf'],
        ['subdir/x:s.jsonl', 'STREAM_SYNTAX', 'a colon in the leaf of a nested path'],
        // ⚠ A TWO-CHARACTER STEM, DELIBERATELY. `a:b/…` matches `DRIVE_RELATIVE` (`^[A-Za-z]:`)
        // and refuses BAD_INPUT before the component loop ever runs, so it would test the wrong
        // screen while looking like it tested this one. Measured while writing this arm.
        ['dir:s/lineage.jsonl', 'STREAM_SYNTAX', 'a colon in an INTERMEDIATE component']
    ];
    // Reserved device names are the WIN32-only screen; asserted only where the fence applies it.
    if (process.platform === 'win32') {
        screened.push(
            ['NUL', 'RESERVED_NAME', 'a bare reserved device name'],
            ['nul.jsonl', 'RESERVED_NAME', 'a reserved name with an extension'],
            ['subdir/COM1.jsonl', 'RESERVED_NAME', 'a reserved name at depth']
        );
    }

    for (const [request, reason, label] of screened) {
        const sink = [];
        const made = createFsGate({ rawGrant: FX.grant, primitives: spyPrimitives(sink) });
        assert.ok(!isRefusal(made));
        const canonical = made.disclosedRoot();
        sink.length = 0;
        const r = await made.appendLineInGrant(request, LINE_A);
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.reason, reason, `${label}: expected ${reason}, got ${r.reason}`);
        assert.equal(r.retained, null, `${label} refuses before anything opens`);
        // ⚠ AND IT TOUCHED NOTHING. The root re-check's own two calls are the sole permitted ones —
        // the same allowance `META-no-outside-names` makes for stage (a). See `isRootRecheck`.
        const touches = sink.filter(c => !isRootRecheck(c, canonical));
        assert.deepEqual(touches, [], `${label}: the name screens reached the filesystem`);
    }

    // The other lexical refusals reach the append path too, and they also touch nothing.
    for (const [request, reason] of [
        ['../outside/lineage.jsonl', 'ESCAPES'],
        [path.join(FX.outside, 'lineage.jsonl'), 'BAD_INPUT'],
        ['C:notes', 'BAD_INPUT'],
        ['.', 'IS_ROOT']
    ]) {
        const r = await gate.appendLineInGrant(request, LINE_A);
        assert.ok(isRefusal(r), `${request} must refuse`);
        assert.equal(r.reason, reason, `${request}: expected ${reason}, got ${r.reason}`);
        assert.equal(r.retained, null);
    }
});

test('A62-append-one-write — on the PRODUCTION primitives: O_APPEND, one call, no retry, no splice', async () => {
    arm('A62-append-one-write');

    /* (1) `O_APPEND` IS IN EFFECT, MEASURED RATHER THAN INFERRED FROM THE FLAG NAME. A descriptor
     *     without it writes at position 0 and OVERWRITES; with it every write re-selects the end of
     *     file. Two appends onto a pre-populated file separate the two outright. */
    const bare = createFsGate({ rawGrant: FX.grant });
    assert.ok(!isRefusal(bare));
    const target = path.join(root, 'append-a62.jsonl');
    fs.writeFileSync(target, 'PREEXISTING-HEADER-LINE\n');
    const one = await bare.appendLineInGrant('append-a62.jsonl', LINE_A);
    assert.ok(!isRefusal(one), `the production append must succeed: ${JSON.stringify(one)}`);
    const two = await bare.appendLineInGrant('append-a62.jsonl', LINE_B);
    assert.ok(!isRefusal(two));
    assert.equal(
        fs.readFileSync(target, 'utf8'),
        `PREEXISTING-HEADER-LINE\n${LINE_A}${LINE_B}`,
        '⚠ O_APPEND IS NOT IN EFFECT — the appends overwrote from the start of the file'
    );

    /* (2) EXACTLY ONE `fs.writeSync`, WITH THE WHOLE LINE. The seam is the runtime function itself,
     *     patched for ONE descriptor and asserted restored — `A54-writeall-loop`'s pattern, for its
     *     reason: reaching `_appendOnce` any other way means a new option on this factory. */
    const realWriteSync = fs.writeSync;
    try {
        let calls = 0;
        let sawWholeLine = false;
        let ours = -1;
        // ⚠ The descriptor is captured through `openAppend`, which DELEGATES to the production
        // flags rather than choosing its own — otherwise this leg would measure the spy's open.
        const capture = {
            openAppend: (t, mode) => {
                ours = mode === 'exclusive-create'
                    ? fs.openSync(t, 'ax')
                    : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                return ours;
            }
        };
        fs.writeSync = (fd, buffer, offset, length, position) => {
            if (fd !== ours) return realWriteSync(fd, buffer, offset, length, position);
            calls += 1;
            if (offset === 0 && length === LINE_A.length && position === null) sawWholeLine = true;
            return realWriteSync(fd, buffer, offset, length, position);
        };
        const counted = createFsGate({ rawGrant: FX.grant, primitives: capture });
        assert.ok(!isRefusal(counted));
        const r = await counted.appendLineInGrant('append-a62-counted.jsonl', LINE_A);
        assert.ok(!isRefusal(r), `the counted append must succeed: ${JSON.stringify(r)}`);
        assert.equal(calls, 1, '⚠ the shipped append issued more than one write — a retry under O_APPEND splices records');
        assert.ok(sawWholeLine, '⚠ the shipped append did not hand the WHOLE line to one call at a null position');

        /* (3) A SHORT COUNT IS NOT RETRIED. The completion-loop shape would ask again; this must
         *     ask once and refuse, or a concurrent appender's record lands between the fragments. */
        calls = 0;
        ours = -1;
        fs.writeSync = (fd, buffer, offset, length, position) => {
            if (fd !== ours) return realWriteSync(fd, buffer, offset, length, position);
            calls += 1;
            return realWriteSync(fd, buffer, offset, 3, position);
        };
        const shorted = createFsGate({ rawGrant: FX.grant, primitives: capture });
        assert.ok(!isRefusal(shorted));
        const short = await shorted.appendLineInGrant('append-a62-short.jsonl', LINE_A);
        assert.ok(isRefusal(short), 'a short append must refuse, not report a smaller success');
        assert.equal(short.reason, 'IO_ERROR');
        assert.match(short.detail, new RegExp(`3 of ${LINE_A.length} bytes`));
        assert.equal(calls, 1, '⚠ THE SHORT APPEND WAS RETRIED — that is how this fence splices its own records');
        assert.notEqual(short.retained, null, 'a partial append leaves a fragment and must say so');
    } finally {
        fs.writeSync = realWriteSync;
    }
    assert.equal(fs.writeSync, realWriteSync, 'the runtime write must be restored');

    /* (4) CONCURRENT APPENDERS PRODUCE N INTACT LINES, WITH NO SPLICE. Interleaved over the REAL
     *     gate with the production primitives — the property is about the descriptor's flags, and
     *     interleaving the promises is what puts more than one open descriptor in flight at once.
     *
     * ⚠ EACH LINE IS UNIQUE AND FIXED-WIDTH, so a spliced result is detectable rather than merely
     * suspicious: a fragment fails the shape check and a lost record fails the count. */
    const CONCURRENT = 24;
    const concurrentTarget = path.join(root, 'append-a62-concurrent.jsonl');
    const gates = Array.from({ length: CONCURRENT }, () => {
        const made = createFsGate({ rawGrant: FX.grant });
        assert.ok(!isRefusal(made));
        return made;
    });
    const results = await Promise.all(gates.map((g, index) =>
        g.appendLineInGrant(
            'append-a62-concurrent.jsonl',
            Buffer.from(`{"appender":${String(index).padStart(3, '0')},"payload":"${'z'.repeat(200)}"}\n`)
        )
    ));
    const refused = results.filter(r => isRefusal(r));
    assert.deepEqual(refused.map(r => `${r.reason}: ${r.detail}`), [],
        'every concurrent appender must succeed — a refusal here is a real contention defect, not noise');

    const lines = fs.readFileSync(concurrentTarget, 'utf8').split('\n');
    assert.equal(lines.pop(), '', 'the file must end with exactly one trailing newline');
    assert.equal(lines.length, CONCURRENT, `⚠ ${lines.length} lines survived of ${CONCURRENT} — records were lost or spliced`);
    const seenAppenders = new Set();
    for (const line of lines) {
        const match = /^\{"appender":(\d{3}),"payload":"z{200}"\}$/.exec(line);
        assert.ok(match !== null, `⚠ A SPLICED OR PARTIAL RECORD: ${JSON.stringify(line.slice(0, 80))}`);
        seenAppenders.add(match[1]);
    }
    assert.equal(seenAppenders.size, CONCURRENT, '⚠ two appenders wrote the same record — one overwrote the other');
});

test('A63-append-retention — pre-open refusals retain nothing; post-open failures are indeterminate', async () => {
    arm('A63-append-retention');

    // ⚠ THE `retained` FIELD IS REQUIRED ON EVERY APPEND REFUSAL, exactly as it is on every create
    // refusal — the compiler enumerates the sites, not a reviewer. These two loops assert the
    // VALUE, which the type cannot.

    /* PRE-OPEN — nothing was opened, so nothing was retained. */
    for (const [request, line, label] of [
        ['lineage-a63.jsonl', 'not a buffer', 'a non-Buffer line'],
        ['lineage-a63.jsonl', Buffer.from('no terminator'), 'an unterminated line'],
        ['../outside/x.jsonl', LINE_A, 'an escaping request'],
        ['no-such-dir/x.jsonl', LINE_A, 'a missing parent'],
        ['subdir', LINE_A, 'a directory leaf'],
        ['note.jsonl::$DATA', LINE_A, 'a stream-syntax leaf']
    ]) {
        const r = await gate.appendLineInGrant(request, line);
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.retained, null, `⚠ ${label} claimed retention having opened nothing`);
    }

    /* POST-OPEN — the conservative answer, because `openAppend` and `appendOnce` are injectable and
     * their contracts promise nothing about what a failing call materialised. */
    const postOpen = [
        {
            label: 'a throwing append',
            primitives: { appendOnce: () => { const e = new Error('injected EIO'); e.code = 'EIO'; throw e; } },
            reason: 'IO_ERROR'
        },
        {
            label: 'a short append',
            primitives: { appendOnce: () => 2 },
            reason: 'IO_ERROR'
        },
        {
            label: 'a non-EEXIST open failure',
            primitives: { openAppend: () => { const e = new Error('injected EACCES'); e.code = 'EACCES'; throw e; } },
            reason: 'DENIED'
        }
    ];
    for (const { label, primitives, reason } of postOpen) {
        const name = `retain-a63-${label.replace(/[^a-z]+/gi, '-')}.jsonl`;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: { ...spyPrimitives([]), ...primitives }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant(name, LINE_A);
        assert.ok(isRefusal(r), `${label} must refuse`);
        assert.equal(r.reason, reason, `${label}: expected ${reason}, got ${r.reason}`);
        assert.notEqual(r.retained, null, `⚠ ${label} claimed nothing was retained — the primitive promises no such thing`);
        assert.equal(r.retained.rel, name);
        assert.equal(r.retained.state, 'indeterminate');
    }

    // A short append is the one that genuinely leaves a fragment, and the arm says so rather than
    // asserting the file is gone — the S1 ruling: a failed write RETAINS and REPORTS.
    const fragment = createFsGate({
        rawGrant: FX.grant,
        primitives: { ...spyPrimitives([]), appendOnce: (fd, buffer) => fs.writeSync(fd, buffer, 0, 2, null) }
    });
    assert.ok(!isRefusal(fragment));
    const partial = await fragment.appendLineInGrant('retain-a63-fragment.jsonl', LINE_A);
    assert.ok(isRefusal(partial));
    assert.equal(partial.reason, 'IO_ERROR');
    assert.equal(fs.readFileSync(path.join(root, 'retain-a63-fragment.jsonl'), 'utf8'), LINE_A.subarray(0, 2).toString(),
        'the fragment stays; the refusal is how the caller learns it is there');
});

test('A64-append-close — success and failure each close exactly once, and a close failure cannot succeed', async () => {
    arm('A64-append-close');

    /* SUCCESS closes exactly once. Never zero (a leaked descriptor), never twice (acting on one the
     * runtime may already have reused). */
    {
        let closeCalls = 0;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: { ...spyPrimitives([]), close: fd => { closeCalls += 1; return fs.closeSync(fd); } }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('close-a64-ok.jsonl', LINE_A);
        assert.ok(!isRefusal(r), `the ordinary success path must append: ${JSON.stringify(r)}`);
        assert.equal(closeCalls, 1, 'a successful append closes exactly once');
    }

    /* A FAILING APPEND still closes exactly once, through the `finally`. */
    {
        let closeCalls = 0;
        const injected = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                close: fd => { closeCalls += 1; return fs.closeSync(fd); },
                appendOnce: () => { const e = new Error('injected EIO'); e.code = 'EIO'; throw e; }
            }
        });
        assert.ok(!isRefusal(injected));
        const r = await injected.appendLineInGrant('close-a64-throws.jsonl', LINE_A);
        assert.ok(isRefusal(r));
        assert.equal(closeCalls, 1, 'a failing append closes exactly once — never twice');
    }

    /* A CLOSE FAILURE IS A REFUSAL, NOT A FOOTNOTE. The bytes may never have reached the disk, so a
     * success committed before the close is a claim the fence cannot back.
     *
     * ⚠⚠ THE INJECTED CLOSE PERFORMS THE REAL CLOSE AND *THEN* THROWS — `A49`'s pattern, for its
     * reason: a close that only throws leaks the descriptor and forces the arm to choose between
     * leaking and contradicting its own count. */
    {
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
        const r = await injected.appendLineInGrant('close-a64-fails.jsonl', LINE_A);
        assert.ok(isRefusal(r), 'a failed close must refuse — the bytes may never have reached the disk');
        assert.equal(r.reason, 'IO_ERROR');
        assert.match(r.detail, /failed to close/);
        assert.notEqual(r.retained, null, 'the line was written and may or may not be flushed');
        assert.equal(r.retained.rel, 'close-a64-fails.jsonl');
        assert.equal(r.retained.state, 'indeterminate');
        // ⚠ EQUALITY, NOT `>= 1`. A "did it reach close" assertion goes green against the
        // double-close defect — the flag set AFTER the call leaves it false when close throws and
        // the `finally` closes an already-released descriptor.
        assert.equal(closeCalls, 1, '⚠ the descriptor was closed twice — the close flag is set too late');
        assert.equal(fs.existsSync(path.join(root, 'close-a64-fails.jsonl')), true, 'the target is retained');
    }
});

test('A65-append-hardlink-refused — a leaf with a second name refuses at both readings, and a link created in the window is caught', async () => {
    arm('A65-append-hardlink-refused');

    // ⚠⚠ THIS ARM NEEDS NO SYMLINK PRIVILEGE AND IS DELIBERATELY TIER 1. `fs.linkSync` creates a
    // hard link on Windows without Developer Mode, so the one escape class the append path screens
    // that the create path does not is measured on the machine an unattended fence actually runs on.

    // ---- THE PRE-OPEN READING. Two names before the call, so the probe's own `lstat` sees it.
    {
        const primary = path.join(root, 'a65-pre.jsonl');
        const alias = path.join(FX.outside, 'a65-pre-alias.jsonl');
        fs.writeFileSync(primary, LINE_A);
        fs.linkSync(primary, alias);
        // The measurement this arm rests on, asserted rather than assumed: this filesystem reports
        // a link count, and it reports 2 for a linked pair. On one that does not, the screen cannot
        // fire and the README's residual is what applies — so the arm says so out loud.
        assert.equal(fs.lstatSync(primary, { bigint: true }).nlink, 2n,
            'this filesystem must report a link count for the screen to be measurable here');

        const before = fs.readFileSync(alias);
        const r = await gate.appendLineInGrant('a65-pre.jsonl', LINE_B);
        assert.ok(isRefusal(r), 'a leaf with two names must refuse before it is opened');
        assert.equal(r.reason, 'NOT_A_FILE', `expected NOT_A_FILE, got ${r.reason}: ${r.detail}`);
        assert.equal(r.retained, null, 'nothing was opened, so nothing can have been retained');
        assert.ok(before.equals(fs.readFileSync(alias)), '⚠ THE APPEND REACHED THE OUTSIDE NAME');
        assert.equal(fs.readFileSync(primary, 'utf8'), LINE_A.toString(),
            'and the in-grant name is unchanged — one object, so this is the same assertion twice');

        fs.rmSync(alias, { force: true });
        // With the alias gone the count is back to one and the SAME leaf appends, which is what
        // makes the refusal above a claim about the link count rather than about the file.
        assert.equal(fs.lstatSync(primary, { bigint: true }).nlink, 1n);
        const after = await gate.appendLineInGrant('a65-pre.jsonl', LINE_B);
        assert.ok(!isRefusal(after), `once single-named the leaf must append: ${JSON.stringify(after)}`);
        assert.equal(fs.readFileSync(primary, 'utf8'), `${LINE_A}${LINE_B}`);
    }

    // ---- THE POST-OPEN READING, DRIVEN AS A REAL RACE.
    //
    // ⚠⚠ IT CANNOT BE A SPY. `exactIdentityOf` and `exactIdentityOfDescriptor` read the filesystem
    // DIRECTLY rather than through the injectable table — see their declaration for why the number
    // form is unusable — so no injected `lstat`/`fstat` can stage an `nlink`. The seam that IS
    // available is `openAppend`: linking inside it puts the second name in existence AFTER the
    // pre-open probe read 1 and BEFORE the descriptor the post-open `fstat` reads. That is the
    // window the second check exists for, reproduced rather than simulated.
    {
        const primary = path.join(root, 'a65-post.jsonl');
        const alias = path.join(FX.outside, 'a65-post-alias.jsonl');
        fs.writeFileSync(primary, LINE_A);

        let linkedDuringOpen = 0;
        let preOpenCount = null;
        const raced = createFsGate({
            rawGrant: FX.grant,
            primitives: {
                ...spyPrimitives([]),
                openAppend: (t, mode) => {
                    if (path.basename(t) === 'a65-post.jsonl' && linkedDuringOpen === 0) {
                        preOpenCount = fs.lstatSync(t, { bigint: true }).nlink;
                        fs.linkSync(t, alias);
                        linkedDuringOpen += 1;
                    }
                    return mode === 'exclusive-create'
                        ? fs.openSync(t, 'ax')
                        : fs.openSync(t, fs.constants.O_WRONLY | fs.constants.O_APPEND);
                }
            }
        });
        assert.ok(!isRefusal(raced));

        const r = await raced.appendLineInGrant('a65-post.jsonl', LINE_B);
        // The witness. Without it a refusal raised EARLIER — at the pre-open reading, say — would
        // pass every assertion below while proving nothing about the post-open check.
        assert.equal(linkedDuringOpen, 1, '⚠ the race never fired — this leg proved nothing');
        assert.equal(preOpenCount, 1n,
            '⚠ the leaf already had two names at the open — the pre-open check would have caught it');

        assert.ok(isRefusal(r), 'a link created between the probe and the open must be caught');
        assert.equal(r.reason, 'NOT_A_FILE', `expected NOT_A_FILE, got ${r.reason}: ${r.detail}`);
        assert.notEqual(r.retained, null, 'the descriptor was opened, so retention is indeterminate');
        assert.equal(fs.readFileSync(primary, 'utf8'), LINE_A.toString(),
            '⚠ THE LINE WAS APPENDED — the post-open reading did not refuse before appendOnce');
        assert.equal(fs.readFileSync(alias, 'utf8'), LINE_A.toString(),
            '⚠ and it reached the outside name, which is the same object');

        fs.rmSync(alias, { force: true });
    }
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

test('A72-overwrite-if-match — exact bytes, validation and first refusal create no stage', async () => {
    arm('A72-overwrite-if-match');
    const dir = overwriteDir();
    const target = path.join(dir, 'page.md');
    const request = relative(target);
    fs.writeFileSync(target, Buffer.from([0, 255, 10]));
    const old = digest(fs.readFileSync(target));
    const names = () => fs.readdirSync(dir).sort();
    const original = names();
    for (const [sha, data, reason] of [
        ['A'.repeat(64), Buffer.from('x'), 'BAD_INPUT'],
        [old, 'not a buffer', 'BAD_INPUT'],
        ['0'.repeat(64), Buffer.from('x'), 'DIGEST_MISMATCH']
    ]) {
        const result = await gate.overwriteFileInGrant(request, sha, data);
        assert.equal(result.reason, reason);
        assert.deepEqual(result.effect, { target: 'not_replaced', stage: { state: 'none' } });
        assert.deepEqual(names(), original);
    }
    const missing = await gate.overwriteFileInGrant(relative(path.join(dir, 'missing.md')), old, Buffer.alloc(0));
    assert.equal(missing.reason, 'MISSING');
    assert.deepEqual(missing.effect.stage, { state: 'none' });
    assert.deepEqual(names(), original);
    const empty = await gate.overwriteFileInGrant(request, old, Buffer.alloc(0));
    assert.deepEqual(empty, { ok: true, rel: request, bytes: 0, previousSha256: old,
        sha256: digest(Buffer.alloc(0)), effect: { target: 'replaced', stage: { state: 'none' } } });
    assert.equal(fs.readFileSync(target).length, 0);
    const newBytes = Buffer.from([7, 0, 255]);
    const next = await gate.overwriteFileInGrant(request, digest(Buffer.alloc(0)), newBytes);
    assert.equal(next.ok, true);
    assert.equal(next.bytes, 3);
    assert.deepEqual(fs.readFileSync(target), newBytes);
    assert.deepEqual(names(), original);
    const create = await gate.createFileInGrant(request, Buffer.from('no'));
    assert.equal(create.reason, 'EXISTS');
    assert.deepEqual(fs.readFileSync(target), newBytes);
    const production = createFsGate({ rawGrant: FX.grant });
    assert.equal(isRefusal(production), false);
    const defaultReplace = await production.overwriteFileInGrant(request, digest(newBytes), Buffer.from('production'));
    assert.equal(defaultReplace.ok, true, 'production writeAll, fsync and rename run without an injected substitute');
    assert.equal(fs.readFileSync(target, 'utf8'), 'production');
});

test('A73-overwrite-leaf-no-follow — identity, links, aliases and final digest', async () => {
    arm('A73-overwrite-leaf-no-follow');
    const dir = overwriteDir();
    const target = path.join(dir, 'page.md');
    const request = relative(target);
    const oldBytes = Buffer.from('old');
    fs.writeFileSync(target, oldBytes);
    const expected = digest(oldBytes);
    assert.equal((await gate.overwriteFileInGrant(relative(dir), expected, Buffer.from('new'))).reason, 'NOT_A_FILE');
    const hard = path.join(dir, 'hard.md');
    fs.linkSync(target, hard);
    let hardOpened = 0;
    const hardGate = overwriteGate({ open: (name, flags) => { hardOpened++; return fs.openSync(name, flags); } });
    assert.equal((await hardGate.overwriteFileInGrant(request, expected, Buffer.from('new'))).reason, 'NOT_A_FILE');
    assert.equal(hardOpened, 0, 'a multiply named target must be rejected before open');
    fs.unlinkSync(hard);
    assert.equal((await gate.overwriteFileInGrant('../outside/secret.md', expected, Buffer.from('new'))).reason, 'ESCAPES');
    const alias = path.join(root, `ow-alias-${path.basename(dir)}`);
    fs.symlinkSync(dir, alias, 'junction');
    assert.equal((await gate.overwriteFileInGrant(relative(path.join(alias, 'page.md')), expected, Buffer.from('new'))).reason, 'PARENT_ALIAS');
    fs.unlinkSync(alias);
    let swapped = false;
    const openSwap = overwriteGate({ open: (name, flags) => {
        if (name === target && !swapped) {
            swapped = true;
            fs.renameSync(target, path.join(dir, 'old.md'));
            fs.writeFileSync(target, oldBytes);
        }
        return fs.openSync(name, flags);
    } });
    assert.equal((await openSwap.overwriteFileInGrant(request, expected, Buffer.from('new'))).reason, 'TARGET_CHANGED');
    assert.equal(swapped, true);
    let postOpenSwap = false;
    const temporarilyMoved = path.join(dir, 'temporarily-open.md');
    const afterOpen = overwriteGate({ open: (name, flags) => {
        const fd = fs.openSync(name, flags);
        if (name === target && !postOpenSwap) {
            postOpenSwap = true;
            fs.renameSync(target, temporarilyMoved);
            fs.writeFileSync(target, oldBytes);
        }
        return fd;
    }, read: (fd, buffer, offset, length, position) => {
        if (postOpenSwap && fs.existsSync(temporarilyMoved)) {
            fs.unlinkSync(target);
            fs.renameSync(temporarilyMoved, target);
        }
        return fs.readSync(fd, buffer, offset, length, position);
    } });
    assert.equal((await afterOpen.overwriteFileInGrant(request, expected, Buffer.from('new'))).reason, 'TARGET_CHANGED');
    assert.equal(postOpenSwap, true);
    if (fs.existsSync(temporarilyMoved)) { fs.unlinkSync(target); fs.renameSync(temporarilyMoved, target); }
    let edited = false;
    const editAfterFirstHash = overwriteGate({ stageFlush: fd => {
        fs.fsyncSync(fd);
        fs.writeFileSync(target, Buffer.from('edit'));
        edited = true;
    } });
    const final = await editAfterFirstHash.overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(edited, true);
    assert.equal(final.reason, 'DIGEST_MISMATCH');
    assert.equal(final.effect.target, 'not_replaced');
    assert.equal(final.effect.stage.state, 'retained');
    assert.equal(fs.existsSync(path.join(root, final.effect.stage.relHint)), true);
    assert.equal(fs.readFileSync(target, 'utf8'), 'edit');
    fs.writeFileSync(target, oldBytes);
    const movedParent = path.join(root, `ow-moved-${path.basename(dir)}`);
    let moveStageFd;
    const parentChange = await overwriteGate({ openExclusive: name => {
        moveStageFd = fs.openSync(name, 'wx');
        return moveStageFd;
    }, close: fd => {
        fs.closeSync(fd);
        if (fd === moveStageFd) fs.renameSync(dir, movedParent);
    } }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(parentChange.ok, false);
    assert.equal(parentChange.effect.target, 'not_replaced');
    assert.equal(parentChange.effect.stage.state, 'retained');
    fs.renameSync(movedParent, dir);
});

test('A73b-overwrite-symlink — file, dangling and directory parent links refuse', async () => {
    arm('A73b-overwrite-symlink');
    const dir = overwriteDir();
    const target = path.join(dir, 'page.md');
    fs.writeFileSync(target, 'old');
    const valid = digest(Buffer.from('old'));
    const link = path.join(dir, 'link.md');
    const dangling = path.join(dir, 'dangling.md');
    const parent = path.join(root, `ow-sym-${path.basename(dir)}`);
    fs.symlinkSync(target, link, 'file');
    fs.symlinkSync(path.join(dir, 'gone.md'), dangling, 'file');
    fs.symlinkSync(dir, parent, 'dir');
    for (const name of [link, dangling]) {
        const r = await gate.overwriteFileInGrant(relative(name), valid, Buffer.from('new'));
        assert.equal(r.ok, false);
        assert.deepEqual(r.effect.stage, { state: 'none' });
    }
    const aliased = await gate.overwriteFileInGrant(relative(path.join(parent, 'page.md')), valid, Buffer.from('new'));
    assert.equal(aliased.reason, 'PARENT_ALIAS');
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    const outside = path.join(FX.outside, `ow-symlink-${path.basename(dir)}.md`);
    fs.writeFileSync(outside, 'outside');
    let held;
    const lateLink = await overwriteGate({ replaceStaged: (stage, name) => {
        held = `${stage}-held`;
        fs.renameSync(stage, held);
        fs.symlinkSync(outside, stage, 'file');
        fs.renameSync(stage, name);
    } }).overwriteFileInGrant(relative(target), valid, Buffer.from('new'));
    assert.equal(lateLink.reason, 'TARGET_CHANGED');
    assert.equal(lateLink.effect.target, 'indeterminate');
    assert.equal(lateLink.effect.stage.state, 'indeterminate');
    assert.deepEqual(fs.readdirSync(dir).sort(), ['page.md', 'link.md', 'dangling.md', path.basename(held)].sort());
    assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
    assert.equal(fs.readFileSync(target, 'utf8'), 'outside');
    assert.equal(fs.readFileSync(held, 'utf8'), 'new');
    assert.equal(fs.readFileSync(outside, 'utf8'), 'outside');
    fs.unlinkSync(target); fs.unlinkSync(held); fs.unlinkSync(outside);
    fs.unlinkSync(link); fs.unlinkSync(dangling); fs.unlinkSync(parent);
});

test('A74-overwrite-effect-reporting — retained and indeterminate stages, replace outcomes, measured residual race', async () => {
    arm('A74-overwrite-effect-reporting');
    const dir = overwriteDir();
    const target = path.join(dir, 'page.md');
    const request = relative(target);
    fs.writeFileSync(target, 'old');
    const expected = digest(Buffer.from('old'));
    const run = (overrides, content = Buffer.from('new')) => overwriteGate(overrides).overwriteFileInGrant(request, expected, content);
    const names = () => fs.readdirSync(dir).sort();
    const collision = path.join(dir, '.wyrd-stage-collision');
    fs.writeFileSync(collision, 'canary');
    let collisionCalls = 0;
    const collided = await run({ openExclusive: name => {
        if (collisionCalls++ === 0) { const error = new Error('collision'); error.code = 'EEXIST'; throw error; }
        return fs.openSync(name, 'wx');
    } });
    assert.equal(collided.ok, true);
    assert.equal(collisionCalls, 2);
    assert.deepEqual(names(), ['page.md', '.wyrd-stage-collision'].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.equal(fs.readFileSync(collision, 'utf8'), 'canary');
    fs.writeFileSync(target, 'old');
    let exhaustedCalls = 0;
    const exhausted = await run({ openExclusive: () => {
        exhaustedCalls++;
        const error = new Error('collision'); error.code = 'EEXIST'; throw error;
    } });
    assert.equal(exhausted.reason, 'IO_ERROR');
    assert.equal(exhaustedCalls, 8);
    assert.deepEqual(exhausted.effect.stage, { state: 'none' });
    assert.deepEqual(names(), ['page.md', '.wyrd-stage-collision'].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    let closeStageFd;
    let closeThrown = false;
    for (const [name, override] of [
        ['short', { writeAll: (fd, data) => fs.writeSync(fd, data.subarray(0, 1)) }],
        ['zero', { writeAll: () => 0 }],
        ['throw', { writeAll: () => { throw new Error('write'); } }],
        ['flush', { stageFlush: () => { throw new Error('flush'); } }],
        ['close', { openExclusive: name => { closeStageFd = fs.openSync(name, 'wx'); return closeStageFd; },
            close: fd => { fs.closeSync(fd); if (fd === closeStageFd && !closeThrown) { closeThrown = true; throw new Error('close'); } } }]
    ]) {
        const beforeNames = names();
        const r = await run(override);
        assert.equal(r.ok, false, name);
        assert.equal(r.effect.target, 'not_replaced', name);
        assert.equal(r.effect.stage.state, 'retained', name);
        const stage = path.join(root, r.effect.stage.relHint);
        assert.deepEqual(names(), [...beforeNames, path.basename(stage)].sort(), `${name}: directory contents`);
        assert.equal(fs.lstatSync(stage).isFile(), true, `${name}: stage kind`);
        assert.equal(fs.readFileSync(stage, 'utf8'), name === 'short' ? 'n' : name === 'zero' || name === 'throw' ? '' : 'new', `${name}: stage bytes`);
        assert.equal(fs.readFileSync(target, 'utf8'), 'old', name);
    }
    let inPlaceStage;
    const beforeInPlace = names();
    const changedStage = await run({ openExclusive: name => { inPlaceStage = name; return fs.openSync(name, 'wx'); },
        stageFlush: fd => { fs.fsyncSync(fd); fs.writeFileSync(inPlaceStage, 'bad'); } });
    assert.equal(changedStage.reason, 'TARGET_CHANGED');
    assert.equal(changedStage.effect.target, 'not_replaced');
    assert.equal(changedStage.effect.stage.state, 'indeterminate');
    assert.deepEqual(names(), [...beforeInPlace, path.basename(inPlaceStage)].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(inPlaceStage, 'utf8'), 'bad');
    const outside = path.join(FX.outside, `ow-hard-${path.basename(dir)}.md`);
    fs.writeFileSync(outside, 'outside');
    let heldStage;
    const beforeLate = names();
    const lateHard = await run({ replaceStaged: (stage, name) => {
        heldStage = `${stage}-held`;
        fs.renameSync(stage, heldStage);
        fs.linkSync(outside, stage);
        fs.renameSync(stage, name);
    } });
    assert.equal(lateHard.reason, 'TARGET_CHANGED');
    assert.equal(lateHard.effect.target, 'indeterminate');
    assert.equal(lateHard.effect.stage.state, 'indeterminate');
    assert.deepEqual(names(), [...beforeLate, path.basename(heldStage)].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'outside');
    assert.equal(fs.readFileSync(heldStage, 'utf8'), 'new');
    assert.equal(fs.readFileSync(outside, 'utf8'), 'outside');
    fs.unlinkSync(target); fs.writeFileSync(target, 'old'); fs.unlinkSync(heldStage); fs.unlinkSync(outside);
    const sameBytes = path.join(dir, 'same-bytes.md');
    fs.writeFileSync(sameBytes, 'new');
    const beforeSame = names();
    const sameObjectSwap = await run({ replaceStaged: (stage, name) => {
        heldStage = `${stage}-held`;
        fs.renameSync(stage, heldStage);
        fs.renameSync(sameBytes, stage);
        fs.renameSync(stage, name);
    } });
    assert.equal(sameObjectSwap.reason, 'TARGET_CHANGED');
    assert.equal(sameObjectSwap.effect.target, 'indeterminate');
    assert.deepEqual(names(), [...beforeSame.filter(name => name !== 'same-bytes.md'), path.basename(heldStage)].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.equal(fs.readFileSync(heldStage, 'utf8'), 'new');
    fs.unlinkSync(target); fs.writeFileSync(target, 'old'); fs.unlinkSync(heldStage);
    const preLinkOutside = path.join(FX.outside, `ow-prelink-${path.basename(dir)}.md`);
    fs.writeFileSync(preLinkOutside, 'outside');
    let preLinkFd;
    let preLinkName;
    let preLinkSwapped = false;
    const beforePreLink = names();
    const preLink = await run({ openExclusive: name => { preLinkName = name; preLinkFd = fs.openSync(name, 'wx'); return preLinkFd; },
        close: fd => {
            fs.closeSync(fd);
            if (fd === preLinkFd && !preLinkSwapped) {
                preLinkSwapped = true;
                fs.renameSync(preLinkName, `${preLinkName}-held`);
                fs.linkSync(preLinkOutside, preLinkName);
            }
        } });
    assert.equal(preLink.reason, 'TARGET_CHANGED');
    assert.equal(preLink.effect.stage.state, 'indeterminate');
    assert.deepEqual(names(), [...beforePreLink, path.basename(preLinkName), `${path.basename(preLinkName)}-held`].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(preLinkName, 'utf8'), 'outside');
    assert.equal(fs.readFileSync(`${preLinkName}-held`, 'utf8'), 'new');
    assert.equal(fs.readFileSync(preLinkOutside, 'utf8'), 'outside');
    fs.unlinkSync(preLinkName); fs.unlinkSync(`${preLinkName}-held`); fs.unlinkSync(preLinkOutside);
    const beforeCorrupt = names();
    const postCorrupt = await run({ replaceStaged: (stage, name) => {
        fs.renameSync(stage, name);
        fs.writeFileSync(name, 'bad');
    } });
    assert.equal(postCorrupt.reason, 'TARGET_CHANGED');
    assert.equal(postCorrupt.effect.target, 'indeterminate');
    assert.equal(postCorrupt.effect.stage.state, 'indeterminate');
    assert.deepEqual(names(), beforeCorrupt);
    assert.equal(fs.readFileSync(target, 'utf8'), 'bad');
    fs.writeFileSync(target, 'old');
    const beforeReplaceNames = names();
    const before = await run({ replaceStaged: () => { throw new Error('before rename'); } });
    assert.equal(before.effect.target, 'indeterminate');
    assert.equal(before.effect.stage.state, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    const beforeStage = path.join(root, before.effect.stage.relHint);
    assert.deepEqual(names(), [...beforeReplaceNames, path.basename(beforeStage)].sort());
    assert.equal(fs.readFileSync(beforeStage, 'utf8'), 'new');
    const beforeAfterNames = names();
    const after = await run({ replaceStaged: (stage, name) => { fs.renameSync(stage, name); throw new Error('after rename'); } });
    assert.equal(after.effect.target, 'indeterminate');
    assert.equal(after.effect.stage.state, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.deepEqual(names(), beforeAfterNames);
    assert.equal(fs.existsSync(path.join(root, after.effect.stage.relHint)), false);
    fs.writeFileSync(target, 'old');
    let stageSwapped = false;
    let swapStageFd;
    let swapStageName;
    const beforeStageSwapNames = names();
    const replacedStage = await run({ openExclusive: name => {
        swapStageName = name;
        swapStageFd = fs.openSync(name, 'wx');
        return swapStageFd;
    }, close: fd => {
        fs.closeSync(fd);
        if (fd === swapStageFd && !stageSwapped) {
            fs.renameSync(swapStageName, `${swapStageName}-held`);
            fs.writeFileSync(swapStageName, 'bad');
            stageSwapped = true;
        }
    } });
    assert.equal(stageSwapped, true);
    assert.equal(replacedStage.reason, 'TARGET_CHANGED');
    assert.equal(replacedStage.effect.stage.state, 'indeterminate');
    assert.deepEqual(names(), [...beforeStageSwapNames, path.basename(swapStageName), `${path.basename(swapStageName)}-held`].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(swapStageName, 'utf8'), 'bad');
    assert.equal(fs.readFileSync(`${swapStageName}-held`, 'utf8'), 'new');
    let stageRealpathCalls = 0;
    let published = false;
    const beforeRootMoveNames = names();
    const finalRootMove = await run({ realpathNative: name => {
        if (name.includes('.wyrd-stage-')) stageRealpathCalls++;
        if (name === root && stageRealpathCalls >= 2 && !published) return FX.outside;
        return fs.realpathSync.native(name);
    }, replaceStaged: (stage, name) => { published = true; fs.renameSync(stage, name); } });
    assert.equal(finalRootMove.reason, 'ROOT_MOVED');
    assert.equal(finalRootMove.effect.target, 'not_replaced');
    assert.equal(published, false);
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.deepEqual(names(), [...beforeRootMoveNames, path.basename(finalRootMove.effect.stage.relHint)].sort());
    assert.equal(fs.readFileSync(path.join(root, finalRootMove.effect.stage.relHint), 'utf8'), 'new');
    const beforePostRootNames = names();
    const postRootMove = await run({ realpathNative: name => {
        if (name === root && published) return FX.outside;
        return fs.realpathSync.native(name);
    }, replaceStaged: (stage, name) => { published = true; fs.renameSync(stage, name); } });
    assert.equal(postRootMove.reason, 'ROOT_MOVED');
    assert.equal(postRootMove.effect.target, 'indeterminate');
    assert.equal(postRootMove.effect.stage.state, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.deepEqual(names(), beforePostRootNames);
    fs.writeFileSync(target, 'old');
    published = false;
    const beforeMeasuredNames = names();
    const measured = await run({ replaceStaged: (stage, name) => {
        fs.writeFileSync(name, 'external');
        fs.renameSync(stage, name);
    } });
    // This measures the last-check-to-rename residual race; it is not a passing safety proof.
    assert.equal(measured.ok, true);
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.deepEqual(names(), beforeMeasuredNames);
});

test('A75-overwrite-post-parent — descriptor reads and sampled parent checks', async t => {
    arm('A75-overwrite-post-parent');
    if (process.platform !== 'win32') { t.diagnostic('Windows junction race only'); return; }
    const parent = overwriteDir();
    const moved = `${parent}-moved`;
    const other = overwriteDir();
    const target = path.join(parent, 'page.md');
    const otherTarget = path.join(other, 'page.md');
    fs.writeFileSync(target, 'old');
    fs.writeFileSync(otherTarget, 'other');
    let redirected = false;
    let postAliasReads = 0;
    const result = await overwriteGate({ read: (fd, buffer, offset, length, position) => {
        if (redirected) postAliasReads++;
        return fs.readSync(fd, buffer, offset, length, position);
    }, replaceStaged: (stage, name) => {
        fs.renameSync(parent, moved);
        fs.symlinkSync(other, parent, 'junction');
        fs.renameSync(path.join(moved, path.basename(stage)), path.join(other, path.basename(stage)));
        fs.renameSync(stage, name);
        redirected = true;
    } }).overwriteFileInGrant(relative(target), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(result.reason, 'DENIED');
    assert.equal(result.effect.target, 'indeterminate');
    assert.equal(postAliasReads, 0, 'the aliased parent must refuse before post-publication read');
    assert.equal(fs.readFileSync(otherTarget, 'utf8'), 'other');
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    const outsideParent = overwriteDir();
    const outsideMoved = `${outsideParent}-moved`;
    const outsideDir = fs.mkdtempSync(path.join(FX.outside, 'ow-'));
    const outsideTarget = path.join(outsideDir, 'page.md');
    const outsideRequest = path.join(outsideParent, 'page.md');
    fs.writeFileSync(outsideRequest, 'old');
    fs.writeFileSync(outsideTarget, 'outside');
    const escaped = await overwriteGate({ replaceStaged: (stage, name) => {
        fs.renameSync(outsideParent, outsideMoved);
        fs.symlinkSync(outsideDir, outsideParent, 'junction');
        fs.renameSync(path.join(outsideMoved, path.basename(stage)), path.join(outsideDir, path.basename(stage)));
        fs.renameSync(stage, name);
    } }).overwriteFileInGrant(relative(outsideRequest), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(escaped.reason, 'DENIED');
    assert.equal(escaped.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(outsideTarget, 'utf8'), 'outside');
    assert.equal(fs.readFileSync(outsideRequest, 'utf8'), 'old');
    const fresh = overwriteDir();
    const freshMoved = `${fresh}-moved`;
    const freshTarget = path.join(fresh, 'page.md');
    fs.writeFileSync(freshTarget, 'old');
    const recreated = await overwriteGate({ replaceStaged: (stage, name) => {
        fs.renameSync(fresh, freshMoved);
        fs.mkdirSync(fresh);
        fs.renameSync(path.join(freshMoved, path.basename(stage)), stage);
        fs.renameSync(stage, name);
    } }).overwriteFileInGrant(relative(freshTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(recreated.reason, 'DENIED');
    assert.equal(recreated.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(freshTarget, 'utf8'), 'old');
    const canonicalDir = overwriteDir();
    const canonicalTarget = path.join(canonicalDir, 'page.md');
    fs.writeFileSync(canonicalTarget, 'old');
    let canonicalPublished = false;
    const misresolved = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); canonicalPublished = true; },
        realpathNative: name => name === canonicalTarget && canonicalPublished ? otherTarget : fs.realpathSync.native(name)
    }).overwriteFileInGrant(relative(canonicalTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(misresolved.reason, 'PARENT_ALIAS');
    assert.equal(misresolved.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(canonicalDir), ['page.md']);
    assert.equal(fs.readFileSync(canonicalTarget, 'utf8'), 'new');
    const preCanonicalTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(preCanonicalTarget, 'old');
    const preMisresolved = await overwriteGate({
        realpathNative: name => name === preCanonicalTarget ? otherTarget : fs.realpathSync.native(name)
    }).overwriteFileInGrant(relative(preCanonicalTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(preMisresolved.reason, 'PARENT_ALIAS');
    assert.deepEqual(preMisresolved.effect, { target: 'not_replaced', stage: { state: 'none' } });
    assert.equal(fs.readFileSync(preCanonicalTarget, 'utf8'), 'old');
    const stageCanonicalTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(stageCanonicalTarget, 'old');
    const stageMisresolved = await overwriteGate({
        realpathNative: name => name.includes('.wyrd-stage-') ? otherTarget : fs.realpathSync.native(name)
    }).overwriteFileInGrant(relative(stageCanonicalTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(stageMisresolved.reason, 'TARGET_CHANGED');
    assert.equal(stageMisresolved.effect.target, 'not_replaced');
    assert.equal(stageMisresolved.effect.stage.state, 'indeterminate');
    assert.equal(fs.readFileSync(stageCanonicalTarget, 'utf8'), 'old');
    const finalSampleTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(finalSampleTarget, 'old');
    let finalPublished = false;
    let finalNameSwapped = false;
    const finalSample = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); finalPublished = true; },
        realpathNative: name => {
            const canonical = fs.realpathSync.native(name);
            if (name === finalSampleTarget && finalPublished) finalNameSwapped = true;
            return canonical;
        },
        lstat: name => fs.lstatSync(name === finalSampleTarget && finalNameSwapped ? otherTarget : name),
        lstatBigint: name => fs.lstatSync(name === finalSampleTarget && finalNameSwapped ? otherTarget : name, { bigint: true })
    }).overwriteFileInGrant(relative(finalSampleTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(finalSample.reason, 'TARGET_CHANGED');
    assert.equal(finalSample.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(path.dirname(finalSampleTarget)), ['page.md']);
    assert.equal(fs.readFileSync(finalSampleTarget, 'utf8'), 'new');
    const firstNameTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(firstNameTarget, 'old');
    let firstNamePublished = false;
    let firstNameProbe = true;
    const firstNameSample = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); firstNamePublished = true; },
        lstatBigint: name => {
            if (name === firstNameTarget && firstNamePublished && firstNameProbe) {
                firstNameProbe = false;
                return fs.lstatSync(otherTarget, { bigint: true });
            }
            return fs.lstatSync(name, { bigint: true });
        }
    }).overwriteFileInGrant(relative(firstNameTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(firstNameSample.reason, 'TARGET_CHANGED');
    assert.equal(firstNameSample.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(path.dirname(firstNameTarget)).sort(), ['page.md']);
    assert.equal(fs.readFileSync(firstNameTarget, 'utf8'), 'new');
    const transientParentTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(transientParentTarget, 'old');
    let transientPublished = false;
    let transientProbe = true;
    const transientParent = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); transientPublished = true; },
        read: (fd, buffer, offset, length, position) => {
            if (transientPublished) transientProbe = false;
            return fs.readSync(fd, buffer, offset, length, position);
        },
        lstatBigint: name => {
            if (name === path.dirname(transientParentTarget) && transientPublished && transientProbe) {
                transientProbe = false;
                return fs.lstatSync(other, { bigint: true });
            }
            return fs.lstatSync(name, { bigint: true });
        }
    }).overwriteFileInGrant(relative(transientParentTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(transientParent.reason, 'TARGET_CHANGED');
    assert.equal(transientParent.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(path.dirname(transientParentTarget)).sort(), ['page.md']);
    assert.equal(fs.readFileSync(transientParentTarget, 'utf8'), 'new');
    const parentSampleTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(parentSampleTarget, 'old');
    let parentPublished = false;
    const parentSample = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); parentPublished = true; },
        lstatBigint: name => fs.lstatSync(name === path.dirname(parentSampleTarget) && parentPublished ? other : name, { bigint: true })
    }).overwriteFileInGrant(relative(parentSampleTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(parentSample.reason, 'TARGET_CHANGED');
    assert.equal(parentSample.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(path.dirname(parentSampleTarget)).sort(), ['page.md']);
    assert.equal(fs.readFileSync(parentSampleTarget, 'utf8'), 'new');
    const lateParentTarget = path.join(overwriteDir(), 'page.md');
    fs.writeFileSync(lateParentTarget, 'old');
    let lateParentPublished = false;
    let lateParentFlip = false;
    const lateParentSample = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); lateParentPublished = true; },
        read: (fd, buffer, offset, length, position) => {
            if (lateParentPublished) lateParentFlip = true;
            return fs.readSync(fd, buffer, offset, length, position);
        },
        lstatBigint: name => fs.lstatSync(name === path.dirname(lateParentTarget) && lateParentFlip ? other : name, { bigint: true })
    }).overwriteFileInGrant(relative(lateParentTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(lateParentSample.reason, 'TARGET_CHANGED');
    assert.equal(lateParentSample.effect.target, 'indeterminate');
    assert.deepEqual(fs.readdirSync(path.dirname(lateParentTarget)).sort(), ['page.md']);
    assert.equal(fs.readFileSync(lateParentTarget, 'utf8'), 'new');
    const lateDir = overwriteDir();
    const lateMoved = `${lateDir}-moved`;
    const lateTarget = path.join(lateDir, 'page.md');
    fs.writeFileSync(lateTarget, 'old');
    let latePublished = false;
    let lateSwapped = false;
    let verificationFd;
    const late = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); latePublished = true; },
        open: (name, flags) => {
            const fd = fs.openSync(name, flags);
            if (latePublished && name === lateTarget) verificationFd = fd;
            return fd;
        },
        close: fd => {
            fs.closeSync(fd);
            if (fd === verificationFd && !lateSwapped) {
                lateSwapped = true;
                fs.renameSync(lateDir, lateMoved);
                fs.mkdirSync(lateDir);
                fs.renameSync(path.join(lateMoved, 'page.md'), lateTarget);
            }
        }
    }).overwriteFileInGrant(relative(lateTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(late.ok, true);
    assert.equal(lateSwapped, false, 'post-rename must not open a new descriptor');
    assert.equal(fs.readFileSync(lateTarget, 'utf8'), 'new');
    const escapedParent = overwriteDir();
    const escapedMoved = `${escapedParent}-moved`;
    const escapedOutside = fs.mkdtempSync(path.join(FX.outside, 'ow-'));
    const escapedTarget = path.join(escapedParent, 'page.md');
    fs.writeFileSync(escapedTarget, 'old');
    let escapedPublished = false;
    let swapDenied = false;
    let outsideOpens = 0;
    let outsideReads = 0;
    const escapedAfterParent = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); escapedPublished = true; },
        lstat: name => {
            if (name === escapedTarget && escapedPublished) {
                escapedPublished = false;
                try {
                    fs.renameSync(escapedParent, escapedMoved);
                    fs.symlinkSync(escapedOutside, escapedParent, 'junction');
                    fs.renameSync(path.join(escapedMoved, 'page.md'), path.join(escapedOutside, 'page.md'));
                } catch (error) {
                    if (!['EACCES', 'EPERM'].includes(error.code)) throw error;
                    swapDenied = true;
                }
            }
            return fs.lstatSync(name);
        },
        realpathNative: name => name === escapedTarget && !escapedPublished
            && fs.existsSync(path.join(escapedOutside, 'page.md')) ? escapedTarget : fs.realpathSync.native(name),
        open: (name, flags) => {
            if (name === escapedTarget && fs.realpathSync.native(escapedParent) === escapedOutside) outsideOpens++;
            return fs.openSync(name, flags);
        },
        read: (fd, buffer, offset, length, position) => {
            if (fs.existsSync(path.join(escapedOutside, 'page.md'))) outsideReads++;
            return fs.readSync(fd, buffer, offset, length, position);
        }
    }).overwriteFileInGrant(relative(escapedTarget), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(outsideOpens, 0, 'post-rename must not open through a swapped parent');
    assert.equal(outsideReads, 0, 'post-rename must not read an outside object');
    if (swapDenied) {
        t.diagnostic('Windows denied moving a parent while the stage descriptor was held');
        assert.equal(escapedAfterParent.ok, true);
        assert.equal(fs.readFileSync(escapedTarget, 'utf8'), 'new');
        assert.equal(fs.existsSync(path.join(escapedOutside, 'page.md')), false);
    } else {
        assert.equal(escapedAfterParent.reason, 'TARGET_CHANGED');
        assert.equal(escapedAfterParent.effect.target, 'indeterminate');
        assert.equal(fs.readFileSync(path.join(escapedOutside, 'page.md'), 'utf8'), 'new');
    }
});

test('A77-overwrite-between-samples — physical parent swap and restoration', async t => {
    arm('A77-overwrite-between-samples');
    if (process.platform === 'win32') { t.diagnostic('held descriptor prevents physical parent move on Windows'); return; }
    const parent = overwriteDir();
    const moved = `${parent}-moved`;
    const empty = `${parent}-empty`;
    const target = path.join(parent, 'page.md');
    fs.writeFileSync(target, 'old');
    let published = false;
    let firstSample = false;
    let swapped = false;
    const result = await overwriteGate({
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; },
        lstat: name => {
            if (name === target && published) firstSample = true;
            return fs.lstatSync(name);
        },
        lstatBigint: name => {
            if (name === target && firstSample && !swapped) {
                fs.renameSync(parent, moved);
                fs.mkdirSync(parent);
                fs.renameSync(parent, empty);
                fs.renameSync(moved, parent);
                swapped = true;
            }
            return fs.lstatSync(name, { bigint: true });
        }
    }).overwriteFileInGrant(relative(target), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(swapped, true);
    assert.equal(result.ok, true);
    assert.deepEqual(result.effect, { target: 'replaced', stage: { state: 'none' } });
    assert.deepEqual(fs.readdirSync(parent), ['page.md']);
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    assert.deepEqual(fs.readdirSync(empty), []);
});

test('A78-overwrite-stage-preopen — swapped stage is rejected before outside object opens', async t => {
    arm('A78-overwrite-stage-preopen');
    const parent = overwriteDir();
    const target = path.join(parent, 'page.md');
    const outside = path.join(FX.outside, 'stage-outside.md');
    fs.writeFileSync(target, 'old');
    fs.writeFileSync(outside, 'outside');
    let stageReadFd;
    let stagePath;
    let outsideOpens = 0;
    const result = await overwriteGate({
        open: (name, flags) => {
            const fd = fs.openSync(name, flags);
            if (name.includes('.wyrd-stage-')) {
                if (stageReadFd === undefined) stageReadFd = fd;
                // Exact bigint identity: numeric NTFS ids round (ULP 4), so a stage file created just
                // after `outside` can collide with it (see exactIdentityOf in src/fsgate.ts).
                const opened = fs.fstatSync(fd, { bigint: true });
                const outsideId = fs.statSync(outside, { bigint: true });
                if (opened.dev === outsideId.dev && opened.ino === outsideId.ino) {
                    outsideOpens++;
                    t.diagnostic(`outside open: stage=${opened.dev}:${opened.ino} outside=${outsideId.dev}:${outsideId.ino} name=${name}`);
                }
            }
            return fd;
        },
        close: fd => {
            fs.closeSync(fd);
            if (fd === stageReadFd && stagePath === undefined) {
                stagePath = path.join(parent, fs.readdirSync(parent).find(name => name.startsWith('.wyrd-stage-')));
                fs.renameSync(stagePath, `${stagePath}-held`);
                fs.linkSync(outside, stagePath);
            }
        }
    }).overwriteFileInGrant(relative(target), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(result.reason, 'TARGET_CHANGED');
    assert.equal(result.effect.target, 'not_replaced');
    assert.equal(result.effect.stage.state, 'indeterminate');
    assert.equal(outsideOpens, 0);
    assert.deepEqual(fs.readdirSync(parent).sort(), [path.basename(stagePath), `${path.basename(stagePath)}-held`, 'page.md'].sort());
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(outside, 'utf8'), 'outside');
});

test('A79-overwrite-alias-reason — spelling-only real path mismatch uses alias refusal', async t => {
    arm('A79-overwrite-alias-reason');
    if (process.platform === 'win32') { t.diagnostic('non-Windows path equality only'); return; }
    const parent = overwriteDir();
    const target = path.join(parent, 'file.md');
    fs.writeFileSync(target, 'old');
    const result = await overwriteGate({
        realpathNative: name => name === target ? path.join(parent, 'File.md') : fs.realpathSync.native(name)
    }).overwriteFileInGrant(relative(target), digest(Buffer.from('old')), Buffer.from('new'));
    assert.equal(result.reason, 'PARENT_ALIAS');
    assert.deepEqual(result.effect, { target: 'not_replaced', stage: { state: 'none' } });
    assert.deepEqual(fs.readdirSync(parent), ['file.md']);
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
});

test('A76-overwrite-verification-read — unreadable verification reports IO_ERROR with observed effects', async () => {
    arm('A76-overwrite-verification-read');
    const parent = overwriteDir();
    const target = path.join(parent, 'page.md');
    const request = relative(target);
    const expected = digest(Buffer.from('old'));
    fs.writeFileSync(target, 'old');
    const denied = () => { const error = new Error('verification read denied'); error.code = 'EACCES'; throw error; };
    const pre = await overwriteGate({ open: (name, flags) => name.includes('.wyrd-stage-') ? denied() : fs.openSync(name, flags) })
        .overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(pre.reason, 'DENIED');
    assert.equal(pre.effect.target, 'not_replaced');
    assert.equal(pre.effect.stage.state, 'retained');
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(path.join(root, pre.effect.stage.relHint), 'utf8'), 'new');
    let stageReadFd;
    const preRead = await overwriteGate({
        open: (name, flags) => {
            const fd = fs.openSync(name, flags);
            if (name.includes('.wyrd-stage-')) stageReadFd = fd;
            return fd;
        },
        read: (fd, buffer, offset, length, position) => fd === stageReadFd ? denied() : fs.readSync(fd, buffer, offset, length, position)
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(preRead.reason, 'DENIED');
    assert.equal(preRead.effect.target, 'not_replaced');
    assert.equal(preRead.effect.stage.state, 'retained');
    assert.equal(fs.readFileSync(target, 'utf8'), 'old');
    assert.equal(fs.readFileSync(path.join(root, preRead.effect.stage.relHint), 'utf8'), 'new');
    for (const code of ['ENOENT', 'EACCES']) {
        let stageOpens = 0;
        const beforeNames = fs.readdirSync(parent).sort();
        const preOpen = await overwriteGate({
            open: (name, flags) => {
                if (name.includes('.wyrd-stage-') && ++stageOpens === 2) {
                    const error = new Error('stage became unavailable'); error.code = code; throw error;
                }
                return fs.openSync(name, flags);
            }
        }).overwriteFileInGrant(request, expected, Buffer.from('new'));
        assert.equal(preOpen.reason, code === 'ENOENT' ? 'MISSING' : 'DENIED');
        assert.match(preOpen.detail, /\.wyrd-stage-/);
        assert.equal(preOpen.effect.target, 'not_replaced');
        assert.equal(preOpen.effect.stage.state, 'indeterminate');
        assert.deepEqual(fs.readdirSync(parent).sort(), [...beforeNames, path.basename(preOpen.effect.stage.relHint)].sort());
        assert.equal(fs.readFileSync(target, 'utf8'), 'old');
        assert.equal(fs.readFileSync(path.join(root, preOpen.effect.stage.relHint), 'utf8'), 'new');
    }
    let published = false;
    const post = await overwriteGate({
        open: (name, flags) => name === target && published ? denied() : fs.openSync(name, flags),
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(post.ok, true, 'post-rename must not open the installed name');
    assert.deepEqual(post.effect, { target: 'replaced', stage: { state: 'none' } });
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    const postRead = await overwriteGate({
        read: (fd, buffer, offset, length, position) => published ? denied() : fs.readSync(fd, buffer, offset, length, position),
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(postRead.reason, 'DENIED');
    assert.equal(postRead.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    const unreadableName = await overwriteGate({
        lstat: name => name === target && published ? denied() : fs.lstatSync(name),
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(unreadableName.reason, 'DENIED');
    assert.equal(unreadableName.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    let firstInstalledProbe = true;
    const firstNameDenied = await overwriteGate({
        lstat: name => {
            if (name === target && published && firstInstalledProbe) {
                firstInstalledProbe = false;
                return denied();
            }
            return fs.lstatSync(name);
        },
        read: (fd, buffer, offset, length, position) => {
            if (published) firstInstalledProbe = false;
            return fs.readSync(fd, buffer, offset, length, position);
        },
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(firstNameDenied.reason, 'DENIED');
    assert.equal(firstNameDenied.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    const parentDenied = await overwriteGate({
        lstat: name => {
            if (name === parent && published) return denied();
            return fs.lstatSync(name);
        },
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(parentDenied.reason, 'DENIED');
    assert.equal(parentDenied.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    let descriptorRead = false;
    const lateParentDenied = await overwriteGate({
        lstat: name => name === parent && descriptorRead ? denied() : fs.lstatSync(name),
        read: (fd, buffer, offset, length, position) => {
            if (published) descriptorRead = true;
            return fs.readSync(fd, buffer, offset, length, position);
        },
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(lateParentDenied.reason, 'DENIED');
    assert.equal(lateParentDenied.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    const identityDenied = await overwriteGate({
        lstatBigint: name => {
            if (name === target && published) return denied();
            return fs.lstatSync(name, { bigint: true });
        },
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(identityDenied.reason, 'DENIED');
    assert.equal(identityDenied.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
    fs.writeFileSync(target, 'old');
    published = false;
    const descriptorDenied = await overwriteGate({
        fstatBigint: fd => published ? denied() : fs.fstatSync(fd, { bigint: true }),
        replaceStaged: (stage, name) => { fs.renameSync(stage, name); published = true; }
    }).overwriteFileInGrant(request, expected, Buffer.from('new'));
    assert.equal(descriptorDenied.reason, 'DENIED');
    assert.equal(descriptorDenied.effect.target, 'indeterminate');
    assert.equal(fs.readFileSync(target, 'utf8'), 'new');
});

test('SR2-no-open-without-opt-in — metadata, census and read guard a synthetic placeholder', async t => {
    arm('SR2-no-open-without-opt-in');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-sr2-'));
    try {
        for (let i = 0; i < 20; i++) fs.writeFileSync(path.join(base, `file${i}.md`), 'local bytes');
        const opens = [];
        const custom = createFsGate({ rawGrant: base, primitives: {
            open: (target, flags) => { opens.push(target); return fs.openSync(target, flags); },
            placeholderAttributes: async target => ({
                attributes: path.basename(target) === 'file7.md' ? 0x1000 : 0,
                reparseTag: 0
            })
        } });
        assert.equal(isRefusal(custom), false);
        const summary = await custom.grantPlaceholderSummary();
        assert.equal(summary.placeholder_detection, 'available');
        assert.equal(summary.placeholder_count, 1);
        assert.equal(summary.file_count, 20);
        assert.equal(summary.placeholder_fraction, 0.05);
        const metadata = await custom.fileMetadataInGrant('file7.md');
        assert.equal(metadata.rel, 'file7.md');
        assert.equal(metadata.size, Buffer.byteLength('local bytes'));
        assert.equal(metadata.dehydrated, true);
        assert.equal(typeof metadata.mtimeMs, 'number');
        assert.equal(JSON.stringify(metadata).includes(base), false);
        const blocked = await custom.readFileInGrant('file7.md', 0, 20);
        assert.equal(blocked.reason, 'PLACEHOLDER');
        assert.match(blocked.detail, /would download/);
        assert.equal(opens.length, 0, 'the placeholder content must remain unopened');
        const blockedHash = await custom.hashInGrant('file7.md');
        assert.equal(blockedHash.reason, 'PLACEHOLDER');
        assert.equal(opens.length, 0, 'the Scribe hash path must also remain unopened');
        const ordinary = await custom.readFileInGrant('file6.md', 0, 20);
        assert.equal(ordinary.ok, true);
        assert.equal(ordinary.bytes.toString(), 'local bytes');
        const hydrated = await custom.readFileInGrant('file7.md', 0, 20, true);
        assert.equal(hydrated.ok, true);
        assert.equal(hydrated.dehydrated, true);
        assert.equal(opens.filter(target => path.basename(target) === 'file7.md').length, 1);

        const tagOpens = [];
        const tagGate = createFsGate({ rawGrant: base, primitives: {
            open: (target, flags) => { tagOpens.push(target); return fs.openSync(target, flags); },
            placeholderAttributes: async target => ({ attributes:
                path.basename(target) === 'file9.md' ? 0x40000 :
                path.basename(target) === 'file10.md' ? 0x400000 : 0,
                reparseTag: path.basename(target) === 'file8.md' ? 0x9000101a : 0 })
        } });
        for (const name of ['file8.md', 'file9.md', 'file10.md']) {
            const result = await tagGate.readFileInGrant(name, 0, 20);
            assert.equal(result.reason, 'PLACEHOLDER', `${name} must refuse from its tag or recall bit`);
        }
        assert.equal(tagOpens.length, 0);

        const empty = path.join(base, 'empty');
        fs.mkdirSync(empty);
        const unavailableGate = createFsGate({ rawGrant: empty, primitives: {
            placeholderAttributes: async () => null
        } });
        const unavailable = await unavailableGate.grantPlaceholderSummary();
        assert.equal(unavailable.placeholder_detection, 'unavailable');
        assert.equal(unavailable.placeholder_count, null);
        assert.equal(unavailable.placeholder_fraction, null);
        if (process.platform === 'win32') {
            fs.writeFileSync(path.join(empty, 'plain.md'), 'local');
            const unavailableOpens = [];
            const failedDetector = createFsGate({ rawGrant: empty, primitives: {
                open: (target, flags) => { unavailableOpens.push(target); return fs.openSync(target, flags); },
                placeholderAttributes: async () => null
            } });
            const blocked = await failedDetector.readFileInGrant('plain.md', 0, 20);
            assert.equal(blocked.reason, 'IO_ERROR');
            assert.equal(unavailableOpens.length, 0);
            const blockedHash = await failedDetector.hashInGrant('plain.md');
            assert.equal(blockedHash.reason, 'IO_ERROR');
            assert.equal(unavailableOpens.length, 0);
            const optedIn = await failedDetector.readFileInGrant('plain.md', 0, 20, true);
            assert.equal(optedIn.bytes.toString(), 'local');
            assert.equal(optedIn.placeholder_detection, 'unavailable');
        } else {
            t.diagnostic('Windows fail-closed open check is exercised only on Windows');
        }
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('SR5-native-placeholder-layout — shipped Windows helper reports independent sizes and offline bit', async t => {
    arm('SR5-native-placeholder-layout');
    if (process.platform !== 'win32') {
        t.diagnostic('native FindFirstFileW measurement requires Windows');
        return;
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-native-metadata-'));
    const names = ['tiny ü note.md', 'medium.md', 'large.md'];
    try {
        fs.writeFileSync(path.join(base, names[0]), 'abc');
        fs.writeFileSync(path.join(base, names[1]), Buffer.alloc(70000, 0x61));
        const large = path.join(base, names[2]);
        const fd = fs.openSync(large, 'w');
        try { fs.ftruncateSync(fd, 0x100000000 + 37); } finally { fs.closeSync(fd); }
        const built = fs.readFileSync(new URL('../dist/fsgate.js', import.meta.url), 'utf8');
        const match = /const WINDOWS_PLACEHOLDER_SCRIPT = String.raw\s*`([\s\S]*?)`;/m.exec(built);
        assert.ok(match, 'the shipped helper script must be present in the built fence');
        const script = match[1];
        assert.match(built, /'-Command', WINDOWS_PLACEHOLDER_SCRIPT/);
        assert.doesNotMatch(built, /-EncodedCommand/);
        execFileSync('attrib.exe', ['+O', path.join(base, names[0])]);
        const input = names.map(name => Buffer.from(path.join(base, name), 'utf16le').toString('base64')).join('\n') + '\n';
        const child = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
            input, encoding: 'utf8', timeout: 15000, windowsHide: true
        });
        assert.equal(child.status, 0, child.stderr);
        const lines = child.stdout.trim().split(/\r?\n/);
        assert.equal(lines.length, names.length, child.stdout);
        for (let i = 0; i < names.length; i++) {
            const parts = lines[i].trim().split(' ').map(Number);
            assert.equal(parts.length, 4, lines[i]);
            assert.ok(parts.every(Number.isSafeInteger), lines[i]);
            assert.equal(parts[2] * 0x100000000 + parts[3], fs.statSync(path.join(base, names[i])).size,
                `native size for ${names[i]}`);
            if (i === 0) assert.notEqual(parts[0] & 0x1000, 0, 'attrib +O must appear as Offline');
        }
        const gate = createFsGate({ rawGrant: base });
        assert.equal(isRefusal(gate), false);
        const metadata = await gate.fileMetadataInGrant(names[0]);
        assert.equal(metadata.dehydrated, true, 'the runtime detector must parse the real helper reply');
    } finally {
        try { execFileSync('attrib.exe', ['-O', path.join(base, names[0])]); } catch {}
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('SR29-clm-helper-load — a constrained child names its failed helper and leaves content closed', async t => {
    arm('SR29-clm-helper-load');
    if (process.platform !== 'win32') {
        t.diagnostic('PowerShell Constrained Language Mode requires Windows');
        return;
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-clm-'));
    try {
        fs.writeFileSync(path.join(base, 'note.md'), 'local bytes');
        const built = fs.readFileSync(new URL('../dist/fsgate.js', import.meta.url), 'utf8');
        const match = /const WINDOWS_PLACEHOLDER_SCRIPT = String.raw\s*`([\s\S]*?)`;/m.exec(built);
        assert.ok(match);
        const prefix = "$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'\n";
        const input = Buffer.from(path.join(base, 'note.md'), 'utf16le').toString('base64');
        const start = Date.now();
        const child = spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', prefix + match[1]], {
            input: input + '\nB' + input + '\n', encoding: 'utf8', timeout: 7000, windowsHide: true
        });
        t.diagnostic(`constrained Add-Type: exit ${child.status}, ${Date.now() - start} ms; stdout ${JSON.stringify(child.stdout)}`);
        assert.equal(child.status, 1, child.stderr);
        assert.equal(child.stderr, '');
        assert.equal(child.stdout.trim(), 'HELPER_LOAD_FAILED');
        const patched = built.replace(/(const WINDOWS_PLACEHOLDER_SCRIPT = String.raw\s*`)/,
            (_, head) => head + '\n' + prefix);
        assert.notEqual(patched, built);
        const counted = patched.replace("const child = spawn('powershell.exe',",
            "placeholderSpawnCount++;\n        const child = spawn('powershell.exe',");
        assert.notEqual(counted, patched);
        const isolated = await import('data:text/javascript;base64,' +
            Buffer.from('export let placeholderSpawnCount = 0;\n' + counted).toString('base64'));
        const gate = isolated.createFsGate({ rawGrant: base });
        assert.equal(isRefusal(gate), false);
        const first = Date.now();
        const read = await gate.readFileInGrant('note.md', 0, 20);
        t.diagnostic(`first refused read: ${Date.now() - first} ms`);
        assert.equal(isolated.placeholderSpawnCount, 1, 'the first probe starts one helper');
        const fresh = isolated.createFsGate({ rawGrant: base });
        assert.equal(isRefusal(fresh), false);
        assert.equal(fresh.placeholderDetection(), 'unavailable', 'a fresh gate inherits the module latch before probing');
        const hash = await gate.hashInGrant('note.md');
        const write = await gate.appendLineInGrant('note.md', Buffer.from('line\n'));
        const cause = 'placeholder detection unavailable because PowerShell could not load the helper ' +
            '(Add-Type failed; Constrained Language Mode or an application-control policy are common causes)';
        for (const refusal of [read, hash, write]) {
            assert.equal(refusal.reason, 'IO_ERROR');
            assert.equal(refusal.detail, cause, 'one accurate cause with no extra path or error text');
        }
        assert.equal(fs.readFileSync(path.join(base, 'note.md'), 'utf8'), 'local bytes');
        const created = await fresh.createFileInGrant('new.md', Buffer.from('new bytes'));
        assert.equal(created.ok, true, 'creating a new file does not consult the failed helper');
        assert.equal(fs.readFileSync(path.join(base, 'new.md'), 'utf8'), 'new bytes');
        const walk = await fresh.walkGrant();
        assert.equal(walk.placeholder_detection, 'unavailable');
        assert.equal(walk.files.length, 0);
        assert.equal(isolated.placeholderSpawnCount, 1, 'the batch after the latch does not restart the helper');
        assert.equal(gate.placeholderDetection(), 'unavailable');
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('SR6-post-open-placeholder — a flipped detector prevents every content read', async () => {
    arm('SR6-post-open-placeholder');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-postopen-'));
    try {
        fs.writeFileSync(path.join(base, 'note.md'), 'content');
        for (const operation of ['read', 'hash']) {
            let calls = 0;
            let reads = 0;
            const gate = createFsGate({ rawGrant: base, primitives: {
                placeholderAttributes: async () => ({ attributes: ++calls >= 2 ? 0x1000 : 0, reparseTag: 0 }),
                read: (...args) => { reads++; return fs.readSync(...args); }
            } });
            assert.equal(isRefusal(gate), false);
            const result = operation === 'read'
                ? await gate.readFileInGrant('note.md', 0, 16)
                : await gate.hashInGrant('note.md');
            assert.equal(result.reason, 'PLACEHOLDER', operation);
            assert.equal(reads, 0, operation);
            assert.equal(calls, 2, operation);
        }
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('SR7-write-placeholder-guards — overwrite, stage and append refuse before content', async () => {
    arm('SR7-write-placeholder-guards');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-write-placeholder-'));
    const target = path.join(base, 'note.md');
    try {
        fs.writeFileSync(target, 'old');
        const digest = createHash('sha256').update('old').digest('hex');
        for (const variant of ['overwrite', 'stage', 'append']) {
            const contentOpens = [];
            let reads = 0;
            const gate = createFsGate({ rawGrant: base, primitives: {
                placeholderAttributes: async name => ({
                    attributes: variant === 'stage' ? (name.includes('.wyrd-stage-') ? 0x1000 : 0) : 0x1000,
                    reparseTag: 0
                }),
                open: (name, flags) => { contentOpens.push(name); return fs.openSync(name, flags); },
                openAppend: (name, mode) => { contentOpens.push(name); return fs.openSync(name, mode === 'existing' ? 'a' : 'ax'); },
                read: (...args) => { reads++; return fs.readSync(...args); }
            } });
            assert.equal(isRefusal(gate), false);
            const result = variant === 'append'
                ? await gate.appendLineInGrant('note.md', Buffer.from('new\n'))
                : await gate.overwriteFileInGrant('note.md', digest, Buffer.from('new'));
            assert.equal(result.reason, 'PLACEHOLDER', variant);
            if (variant === 'stage') {
                assert.equal(contentOpens.filter(name => name.includes('.wyrd-stage-')).length, 0);
            } else {
                assert.equal(contentOpens.length, 0, variant);
                assert.equal(reads, 0, variant);
            }
            assert.equal(fs.readFileSync(target, 'utf8'), 'old');
        }
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('SR8-detector-startup-bound — a blocked helper fails closed before open', async t => {
    arm('SR8-detector-startup-bound');
    if (process.platform !== 'win32') {
        t.diagnostic('PowerShell startup bound requires Windows');
        return;
    }
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-slow-helper-'));
    try {
        fs.writeFileSync(path.join(base, 'note.md'), 'local');
        const fake = path.join(base, 'powershell.exe');
        const source = 'public class DelayedPowerShell { public static void Main(string[] args) { System.Threading.Thread.Sleep(30000); } }';
        const compile = spawnSync('powershell.exe',
            ['-NoProfile', '-NonInteractive', '-Command',
                `Add-Type -TypeDefinition '${source}' -OutputAssembly '${fake.replaceAll("'", "''")}' -OutputType ConsoleApplication`],
            { encoding: 'utf8', timeout: 15000, windowsHide: true });
        assert.equal(compile.status, 0, compile.stderr);
        const program = `
            import { createFsGate } from ${JSON.stringify(new URL('../dist/fsgate.js', import.meta.url).href)};
            let opened = 0;
            const gate = createFsGate({ rawGrant: ${JSON.stringify(base)}, primitives: {
                open: () => { opened++; throw new Error('content opened before detector answered'); }
            } });
            const started = Date.now();
            const result = await gate.readFileInGrant('note.md', 0, 16);
            console.log(JSON.stringify({ reason: result.reason, elapsed: Date.now() - started, opened }));
        `;
        const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], {
            encoding: 'utf8', timeout: 9000, windowsHide: true,
            env: { ...process.env, PATH: base + path.delimiter + process.env.PATH }
        });
        assert.equal(child.status, 0, child.stderr);
        const answer = JSON.parse(child.stdout.trim());
        assert.equal(answer.reason, 'IO_ERROR');
        assert.equal(answer.opened, 0);
        assert.ok(answer.elapsed >= 4500 && answer.elapsed < 8000, `startup elapsed ${answer.elapsed} ms`);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('SR22-walk-batch-fail-closed — native batch excludes a failed probe', async t => {
    arm('SR22-walk-batch-fail-closed');
    if (process.platform !== 'win32') { t.diagnostic('native batch is Windows-only'); return; }
    const grant = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-batch-arm-'));
    try {
        for (let i = 0; i < 40; i++)
            fs.writeFileSync(path.join(grant, `${String(i).padStart(2, '0')}.md`), 'note');
        const lost = path.join(grant, '00.md');
        let seen = 0;
        const gate = createFsGate({ rawGrant: grant, primitives: {
            lstat: target => {
                const stat = fs.lstatSync(target);
                if (target === lost && ++seen === 2) fs.unlinkSync(lost);
                return stat;
            }
        } });
        assert.ok(!isRefusal(gate));
        const walk = await gate.walkGrant();
        assert.ok(!isRefusal(walk));
        assert.equal(seen, 2, 'the file vanished after its walk stat');
        assert.equal(walk.files.length, 39);
        assert.equal(walk.files.some(file => file.rel === '00.md'), false);
        assert.equal(walk.inaccessible_count, 1);
        assert.equal(walk.placeholder_count, null, 'one failed probe makes the count unmeasured');
        assert.ok(walk.files.every(file => file.dehydrated === false));
    } finally { fs.rmSync(grant, { recursive: true, force: true }); }
});

test('SR9-write-post-open-placeholder — detector flips before verification or append', async () => {
    arm('SR9-write-post-open-placeholder');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-write-postopen-'));
    const target = path.join(base, 'note.md');
    try {
        fs.writeFileSync(target, 'old');
        const digest = createHash('sha256').update('old').digest('hex');
        for (const variant of ['overwrite', 'stage', 'append']) {
            const calls = new Map();
            const opened = new Map();
            let blockedReads = 0;
            let appends = 0;
            const gate = createFsGate({ rawGrant: base, primitives: {
                placeholderAttributes: async name => {
                    const key = name.includes('.wyrd-stage-') ? 'stage' : 'target';
                    const count = (calls.get(key) ?? 0) + 1;
                    calls.set(key, count);
                    const flip = variant === 'stage' ? key === 'stage' : key === 'target';
                    return { attributes: flip && count >= 2 ? 0x1000 : 0, reparseTag: 0 };
                },
                open: (name, flags) => {
                    const fd = fs.openSync(name, flags);
                    opened.set(fd, name);
                    return fd;
                },
                read: (fd, ...args) => {
                    const name = opened.get(fd);
                    if (variant === 'stage' ? name?.includes('.wyrd-stage-') : name === target) blockedReads++;
                    return fs.readSync(fd, ...args);
                },
                appendOnce: (fd, bytes) => { appends++; return fs.writeSync(fd, bytes); }
            } });
            assert.equal(isRefusal(gate), false);
            const result = variant === 'append'
                ? await gate.appendLineInGrant('note.md', Buffer.from('new\n'))
                : await gate.overwriteFileInGrant('note.md', digest, Buffer.from('new'));
            assert.equal(result.reason, 'PLACEHOLDER', variant);
            assert.equal(blockedReads, 0, variant);
            assert.equal(appends, 0, variant);
            assert.equal(fs.readFileSync(target, 'utf8'), 'old');
        }
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});
