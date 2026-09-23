import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createFsGate, isRefusal } from 'wyrd-fence';
import { main, NO_GRANT_MESSAGE, readGrantArg } from '../dist/main.js';
import { declare as arm } from './manifest.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = path.join(repoRoot, 'dist', 'index.js');
const CHILD_TIMEOUT_MS = 20_000;

function harness(overrides = {}) {
    const lines = [];
    const codes = [];
    return {
        lines,
        codes,
        deps: {
            argv: [],
            env: {},
            makeFsGate: createFsGate,
            stderr: line => lines.push(line),
            setExitCode: code => codes.push(code),
            connect: async () => {},
            ...overrides
        }
    };
}

test('S1-no-grant — no grant refuses with the STATIC message, exits non-zero, and probes nothing', async () => {
    arm('S1-no-grant');
    const calls = [];
    const h = harness({
        makeFsGate: options => {
            calls.push(options);
            return createFsGate(options);
        }
    });
    const result = await main(h.deps);
    assert.equal(result.started, false);
    assert.equal(result.reason, 'NO_GRANT');
    assert.deepEqual(h.codes, [2]);
    assert.equal(h.lines[0], NO_GRANT_MESSAGE);
    assert.deepEqual(calls, [], 'the gate factory must not run when no grant exists');
    // The message is fixed text. Nothing in it can have come from the filesystem.
    assert.match(NO_GRANT_MESSAGE, /--grant/);
    assert.match(NO_GRANT_MESSAGE, /WYRD_GRANT/);
    assert.match(NO_GRANT_MESSAGE, /Arc\//);
    assert.match(NO_GRANT_MESSAGE, /Mage\//);
    assert.match(NO_GRANT_MESSAGE, /Forum\//);
});

test('S14-no-grant-claims — the no-grant refusal states the refusals and the limits it is about to be trusted on', () => {
    arm('S14-no-grant-claims');
    // ⚠⚠ THIS IS THE LAST THING A USER SEES BEFORE GRANTING, AND IT HAD NO ARM UNTIL 2026-09-01.
    // `S1-no-grant` pins the two grant flags and the three layer names — everything a static
    // message needs to be static — and nothing about what the message CLAIMS. Reverting this text
    // to its pre-correction wording ("EVERY file inside it is readable" / "It does not serve
    // anything above it") passed the whole battery, on the one surface a user reads while deciding
    // whether to hand over a folder.
    //
    // ⚠ PINS CLAIMS, NOT PHRASING, so a reword survives and a dropped or strengthened claim does
    // not. Every match below is a fact the code keeps, and each was wrong once in the reassuring
    // direction.

    // Read-only, SCOPED to the tool surface — unqualified it is false of the process, which
    // attempts an observation log when WYRD_OBSERVE is set.
    assert.match(NO_GRANT_MESSAGE, /only tool it registers is `read`/i);
    assert.match(NO_GRANT_MESSAGE, /none writes, moves\s+or deletes/i);

    // Reachable: the folder is the whole of the restriction, hidden entries included.
    assert.match(NO_GRANT_MESSAGE, /ANY PATH INSIDE IT CAN BE REQUESTED/);
    assert.match(NO_GRANT_MESSAGE, /no extension filter/i);

    // Readable is narrower, in exactly the two ways `read` refuses.
    assert.match(NO_GRANT_MESSAGE, /a directory is\s+refused/i);
    assert.match(NO_GRANT_MESSAGE, /bytes that are not valid UTF-8/i);
    assert.match(NO_GRANT_MESSAGE, /READABLE, not what is\s+REACHABLE/);

    // The limit that reaches OUTSIDE the grant. "A hard link is followed" alone discloses nothing.
    assert.match(
        NO_GRANT_MESSAGE,
        /hard link that already exists inside the folder makes the file it points at\s+readable[\s,]+wherever on the disk that file lives/i
    );

    // The process write, and the fact that its destination is unchecked.
    assert.match(NO_GRANT_MESSAGE, /WYRD_OBSERVE/);
    assert.match(NO_GRANT_MESSAGE, /which is not checked/i);

    // The refuted wordings. Both were false in the reassuring direction, which is the worst one.
    // ⚠ `\s+` BETWEEN EVERY WORD — this string is hand-wrapped, and a negative pinned to one
    // wrapping stops matching when the break moves, passing for the wrong reason.
    assert.ok(
        !/EVERY\s+file\s+inside\s+it\s+is\s+readable/i.test(NO_GRANT_MESSAGE),
        'the refuted "every file is readable" claim must never come back'
    );
    assert.ok(
        !/does\s+not\s+serve\s+anything\s+above\s+it/i.test(NO_GRANT_MESSAGE),
        'the refuted containment claim must never come back — an in-grant hard link reaches outside'
    );
});

test('S2-missing — a grant naming a non-existent absolute directory refuses AND prints the resolved path', async () => {
    arm('S2-missing');
    const missing = path.join(os.tmpdir(), 'wyrd-does-not-exist-8f21', 'vault');
    const h = harness({ env: { WYRD_GRANT: missing } });
    const result = await main(h.deps);
    assert.equal(result.started, false);
    assert.equal(result.reason, 'GRANT_MISSING');
    assert.deepEqual(h.codes, [2]);
    assert.ok(
        h.lines.some(line => line.includes(path.normalize(missing))),
        `the refusal must print the resolved path; got ${JSON.stringify(h.lines)}`
    );
});

test('S3-file-grant — a grant that is a file refuses', async () => {
    arm('S3-file-grant');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-file-grant-'));
    try {
        const file = path.join(base, 'note.md');
        fs.writeFileSync(file, 'x');
        const h = harness({ env: { WYRD_GRANT: file } });
        const result = await main(h.deps);
        assert.equal(result.started, false);
        assert.equal(result.reason, 'GRANT_NOT_A_DIRECTORY');
        assert.deepEqual(h.codes, [2]);
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

// ⚠ `S4-config-shapes`, `S8-link-grants` AND `S12-separator-spellings` LEFT ON 2026-09-01, and the
// two arms above are what they left behind on purpose. All three were pure `createFsGate` calls
// against a grant STRING — fence source contract that happened to sit in a file named `startup` —
// and they now live in `wyrd-fence/test/grant.test.js` under their original ids. `S2-missing` and
// `S3-file-grant` still drive `main()` through the same refusals and assert what THIS package
// prints, which is the half the fence cannot cover.

test('S5-precedence — the command line overrides the environment', async () => {
    arm('S5-precedence');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-precedence-'));
    try {
        const wins = path.join(base, 'wins');
        const loses = path.join(base, 'loses');
        fs.mkdirSync(wins);
        fs.mkdirSync(loses);
        const seen = [];
        const h = harness({
            argv: ['--grant', wins],
            env: { WYRD_GRANT: loses },
            makeFsGate: options => {
                seen.push(options.rawGrant);
                return createFsGate(options);
            }
        });
        const result = await main(h.deps);
        assert.equal(result.started, true);
        assert.deepEqual(seen, [wins]);
        assert.ok(h.lines.some(line => line.includes(fs.realpathSync.native(wins))));
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('S6-arg-forms — `--grant=value` is accepted as well as `--grant value`', () => {
    arm('S6-arg-forms');
    assert.equal(readGrantArg(['--grant', 'C:\\v']), 'C:\\v');
    assert.equal(readGrantArg(['--grant=C:\\v']), 'C:\\v');
    assert.equal(readGrantArg([]), null);
    assert.equal(readGrantArg(['--other', 'x']), null);
});

test('S7-valid — a valid grant starts and discloses the canonical root', async () => {
    arm('S7-valid');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-ok-grant-'));
    try {
        const h = harness({ env: { WYRD_GRANT: base } });
        const result = await main(h.deps);
        assert.equal(result.started, true);
        assert.ok(h.lines.some(line => line.includes(fs.realpathSync.native(base))));
        assert.deepEqual(h.codes, []);
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('S16-layer-probes — startup never reads the root listing', async () => {
    arm('S16-layer-probes');
    const probed = [];
    let rootListings = 0;
    const fakeGate = {
        disclosedRoot: () => 'C:\\granted',
        listGrantRoot: async () => {
            rootListings += 1;
            throw new Error('the root listing must not be read');
        },
        probeInGrant: async name => {
            probed.push(name);
            if (name === 'Arc') return { ok: true, kind: 'directory' };
            if (name === 'Mage') return { ok: true, kind: 'file' };
            return { ok: false, reason: 'MISSING', detail: 'missing', resolvedPath: '' };
        }
    };
    const h = harness({
        env: { WYRD_GRANT: 'C:\\granted' },
        makeFsGate: () => fakeGate
    });
    const result = await main(h.deps);
    assert.equal(result.started, true);
    assert.equal(rootListings, 0);
    assert.deepEqual(probed, ['Arc', 'Mage', 'Forum']);
    assert.ok(h.lines.some(line => /Arc\/ — immutable source/.test(line)));
    assert.ok(h.lines.every(line => !/Mage\/ — agent-curated/.test(line)));
});

test('S13-grant-source-parity — --grant, --grant= and WYRD_GRANT agree exactly, forward slashes included', async () => {
    arm('S13-grant-source-parity');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-parity-'));
    try {
        const vault = path.join(base, 'vault');
        fs.mkdirSync(vault);
        const forward = vault.replace(/\\/g, '/');
        const canonical = fs.realpathSync.native(vault);

        const sources = [
            ['--grant value', { argv: ['--grant', forward], env: {} }],
            ['--grant=value', { argv: [`--grant=${forward}`], env: {} }],
            ['WYRD_GRANT', { argv: [], env: { WYRD_GRANT: forward } }]
        ];
        for (const [label, deps] of sources) {
            const h = harness(deps);
            const result = await main(h.deps);
            assert.equal(result.started, true, `${label} must start`);
            assert.deepEqual(h.codes, [], `${label} must not set an exit code`);
            assert.ok(
                h.lines.some(line => line.includes(canonical)),
                `${label} must disclose the canonical root; got ${JSON.stringify(h.lines)}`
            );
        }
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/* ---------------- the observer ---------------- */

test('S9-import-touch — an import-time filesystem touch IS detected', () => {
    arm('S9-import-touch');
    const bootstrap = path.join(repoRoot, 'test', 'import-touch-bootstrap.mjs');
    const log = path.join(os.tmpdir(), `wyrd-observe-probe-${process.pid}.jsonl`);
    let out;
    try {
        out = execFileSync(process.execPath, [bootstrap], {
            encoding: 'utf8',
            timeout: CHILD_TIMEOUT_MS,
            env: { ...process.env, WYRD_OBSERVE: log }
        });
    } finally {
        fs.rmSync(log, { force: true });
    }
    const parsed = JSON.parse(out);
    assert.equal(parsed.armed, true, 'the observer must arm');
    assert.equal(parsed.calls[0].primitive, 'instrumentation-ready');
    // Deleting the deliberate touch, or installing the observer after the import, turns this red.
    const touched = parsed.calls.some(
        call => typeof call.argument === 'string' && call.argument.includes('import-touch-module')
    );
    assert.equal(touched, true, `the import-time read must be visible; saw ${out.slice(0, 800)}`);
});

test('S10-bootstrap-order — the bootstrap arms the instrument before importing anything', () => {
    arm('S10-bootstrap-order');
    const source = fs.readFileSync(entrypoint, 'utf8');
    const staticImports = [...source.matchAll(/^\s*import\s[^\n]*from\s+'([^']+)'/gm)].map(m => m[1]);
    assert.deepEqual(staticImports, ['./observe.js'], 'observe.js must be the only static import');

    /**
     * ⚠⚠ THE CALL, NOT MERELY A CALL. `indexOf('installObserver(')` was the original check and it
     * is too weak in both directions, measured 2026-09-14 by mutation `M27` ("instrument AFTER
     * importing the app modules") coming back SURVIVED with NO ARM RED.
     *
     * `M27` deletes the arming statement and re-inserts it below the dynamic imports. The old
     * assertion still passed, because the file's doc comment mentions the arming call near the top
     * — so `indexOf` found the COMMENT, compared it against the first dynamic import, and reported
     * success while the real call sat underneath.
     * ⚠ `S9-import-touch` cannot cover this: it drives its own bootstrap fixture, not `dist/index.js`,
     * so no behavioural arm watches this file's ordering. **This string check is the only guard,
     * which is exactly why it has to be precise.**
     *
     * Asserted instead: the first EXECUTABLE arming statement precedes the first dynamic import,
     * with comments stripped so prose cannot satisfy it.
     *
     * ⚠ The two needles are BUILT from fragments rather than written whole. The release gate's
     * `imports` phase scans this file's bytes for an unresolvable dynamic-import specifier, and a
     * literal one inside a comment or a string is indistinguishable to it from a real dependency —
     * it refused this file once for exactly that.
     */
    const ARM_NEEDLE = 'installObserver' + '();';
    const IMPORT_NEEDLE = 'await ' + 'import(';
    const withoutComments = source
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^[ \t]*\/\/.*$/gm, '');
    const armedAt = withoutComments.indexOf(ARM_NEEDLE);
    const firstImportAt = withoutComments.indexOf(IMPORT_NEEDLE);
    assert.notEqual(armedAt, -1, 'the observer must be ARMED, not merely mentioned in a comment');
    assert.notEqual(firstImportAt, -1, 'the app modules must arrive by dynamic import');
    assert.ok(armedAt < firstImportAt,
        `arm, then import — the arming call at ${armedAt} must precede the first dynamic import at ${firstImportAt}`);
});

test('S11-child-no-grant — with no grant, the child process exits non-zero and names no candidate vault', () => {
    arm('S11-child-no-grant');
    const log = path.join(os.tmpdir(), `wyrd-observe-nogrant-${process.pid}.jsonl`);
    fs.rmSync(log, { force: true });
    let status = 0;
    let stderr = '';
    try {
        execFileSync(process.execPath, [entrypoint], {
            encoding: 'utf8',
            timeout: CHILD_TIMEOUT_MS,
            env: { ...process.env, WYRD_OBSERVE: log, WYRD_GRANT: '' },
            stdio: ['ignore', 'pipe', 'pipe']
        });
    } catch (error) {
        status = error.status;
        stderr = error.stderr ?? '';
    }
    assert.equal(status, 2, 'refusing to start must exit non-zero');
    assert.match(stderr, /no folder has been granted/);

    const records = fs
        .readFileSync(log, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map(line => JSON.parse(line));
    fs.rmSync(log, { force: true });
    assert.equal(records[0].primitive, 'instrumentation-ready');
    // AC-1's real content: nothing about a vault is probed before a grant exists. The server's
    // own module graph is not a vault, so the assertion is scoped to what a grant would name.
    const vaultish = records.filter(
        record => typeof record.argument === 'string' && /vault|notes|Mage|Forum|\bArc\b/i.test(record.argument)
    );
    assert.deepEqual(vaultish, [], `nothing vault-shaped may be probed: ${JSON.stringify(vaultish)}`);
});

test('S15-client-config-entrypoint — the example client config points at the real built entrypoint, and its grant is still a placeholder', () => {
    arm('S15-client-config-entrypoint');
    // ⚠⚠ `test/clients/wyrd.mcp.json` IS COPY-PASTE CONFIGURATION AND IT HARD-CODES A RELATIVE PATH.
    // `../../dist/index.js` is correct only while the file sits exactly where it sits, and nothing
    // asserted that until 2026-09-02: moving the file one directory, or renaming the build output,
    // leaves a config that still parses and reads plausibly and starts nothing. The failure then
    // lands on whoever pasted it rather than on this suite, which is the wrong end of the pipe.
    const configPath = path.join(repoRoot, 'test', 'clients', 'wyrd.mcp.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    const server = config.mcpServers?.wyrd;
    assert.ok(server, 'the config must declare an `mcpServers.wyrd` entry');
    assert.equal(server.command, 'node', 'the server is started by node, not by a shell or a wrapper');
    assert.ok(Array.isArray(server.args) && server.args.length > 0, 'the entry must carry args');

    // ⚠ RESOLVED PATHS, NOT STRINGS. Comparing the literal `../../dist/index.js` would pass a config
    // whose relative path is spelled correctly and anchored somewhere else, which is precisely the
    // defect: the path means nothing except relative to the CONFIG FILE'S OWN DIRECTORY, so that is
    // what it is resolved against here.
    const resolved = path.resolve(path.dirname(configPath), server.args[0]);
    assert.equal(resolved, entrypoint, `the config's entrypoint must resolve to ${entrypoint}`);
    // The battery builds before it tests, so an absent file here is a real break rather than an
    // ordering accident.
    assert.ok(fs.existsSync(resolved), `the config's entrypoint must exist: ${resolved}`);

    // ⚠ THE GRANT MUST STILL BE THE PLACEHOLDER. A committed real path discloses the author's disk
    // layout in a file that exists to be copied, and it is exactly the edit somebody makes once
    // while testing by hand and never undoes.
    const grantIndex = server.args.indexOf('--grant');
    assert.notEqual(grantIndex, -1, 'the example must show how the grant is passed');
    assert.equal(
        server.args[grantIndex + 1],
        'REPLACE-WITH-AN-ABSOLUTE-PATH-TO-A-DISPOSABLE-FOLDER',
        'the example grant must remain a placeholder — a real path here leaks a disk layout'
    );
});
