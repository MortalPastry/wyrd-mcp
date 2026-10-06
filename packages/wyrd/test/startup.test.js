import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createFsGate, isRefusal } from 'wyrd-fence';
import { main, NO_GRANT_MESSAGE, readGrantArg } from '../dist/main.js';
import { createServer, disclosure } from '../dist/server.js';
import { SCAN_BYTES, createSearchEngine, LexicalScanBackend } from '../dist/search.js';
import { pathToFileURL } from 'node:url';
import { httpDisclosure } from '../dist/main.js';
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
    assert.match(NO_GRANT_MESSAGE, /registers `read` and `search`/i);
    assert.match(NO_GRANT_MESSAGE, /neither writes, moves\s+or deletes/i);

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
        /hard link that already exists inside the folder makes the file it points at\s+readable and searchable[\s,]+wherever on the disk that file lives/i
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

// All backend fixtures are disposable files; startup still uses the real grant fence.
async function backendFixture(run) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-backend-'));
    const grant = path.join(base, 'grant');
    fs.mkdirSync(grant);
    const modulePath = path.join(base, 'backend #1.mjs');
    fs.writeFileSync(modulePath, `export function createSearchBackend(host) {
        return { backend: host.lexical, disclosure: ['Fixture backend delegates to built-in search.'] };
    }`);
    try { await run({ base, grant, modulePath }); }
    finally { fs.rmSync(base, { recursive: true, force: true }); }
}
const emptyBackend = { async search() { return { candidates: [], hasMore: false, typed_files: 0, searched_files: 0 }; } };
const moduleResult = () => ({ backend: emptyBackend, disclosure: ['Fixture module.'] });
function backendHarness(grant, modulePath, overrides = {}) {
    let starts = 0;
    const h = harness({ argv: ['--grant', grant, '--search-backend', modulePath],
        makeConfiguredServer: context => createServer({ fsgate: context.gate, ...context }),
        connect: async () => { starts++; },
        importSearchBackend: async () => ({ createSearchBackend: moduleResult }), ...overrides });
    h.starts = () => starts;
    return h;
}
async function backendRefusal(grant, modulePath, overrides, message) {
    const h = backendHarness(grant, modulePath, overrides);
    const result = await main(h.deps);
    assert.equal(result.started, false);
    assert.equal(result.reason, 'SEARCH_BACKEND');
    assert.equal(result.http, null);
    assert.equal(result.closeSearchBackend, null);
    assert.deepEqual(h.codes, [2]);
    assert.equal(h.starts(), 0);
    assert.equal(h.lines.length, 1);
    assert.match(h.lines[0], /^wyrd: refusing to start — /);
    assert.equal(/[\r\n]/.test(h.lines[0]), false);
    if (message) assert.match(h.lines[0], message);
}

test('SR49-backend-default — absent and empty selections keep the existing disclosure', async () => {
    arm('SR49-backend-default');
    await backendFixture(async ({ grant }) => {
        for (const args of [[], ['--search-backend='], ['--search-backend', '']]) {
            const h = harness({ argv: ['--grant', grant, ...args], env: { WYRD_SEARCH_BACKEND: args.length ? 'relative' : '' },
                importSearchBackend: async () => { assert.fail('empty selection imported'); } });
            const result = await main(h.deps);
            assert.equal(result.started, true);
            assert.equal(result.closeSearchBackend, null);
            assert.deepEqual(h.lines, [disclosure(fs.realpathSync.native(grant), 'stdio')]);
            assert.match(h.lines[0], /Search builds a lazy in-memory cache/);
            assert.doesNotMatch(h.lines[0], /Module:/);
        }
    });
});

test('SR50-backend-selection — command line wins and file URLs preserve special characters', async () => {
    arm('SR50-backend-selection');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const argv of [['--search-backend', modulePath], [`--search-backend=${modulePath}`], []]) {
            let imported = 0;
            const h = backendHarness(grant, modulePath, { argv: ['--grant', grant, ...argv],
                env: { WYRD_SEARCH_BACKEND: argv.length ? 'relative' : modulePath },
                importSearchBackend: async url => { imported++; assert.equal(url, pathToFileURL(modulePath).href); return { createSearchBackend: moduleResult }; } });
            assert.equal((await main(h.deps)).started, true);
            assert.equal(imported, 1);
        }
    });
});

test('SR51-backend-host — only the frozen six-key host reaches the factory after grant checks', async () => {
    arm('SR51-backend-host');
    await backendFixture(async ({ grant, modulePath }) => {
        fs.mkdirSync(path.join(grant, 'aRc'));
        let calls = 0;
        const h = backendHarness(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: host => {
            calls++;
            assert.deepEqual(Object.keys(host).sort(), ['contractVersion', 'grantId', 'layers', 'lexical', 'listingFailed', 'maxSliceBytes']);
            assert.equal(Object.isFrozen(host), true);
            assert.equal(Object.isFrozen(host.layers), true);
            assert.equal(host.contractVersion, 1);
            assert.deepEqual(host.layers, ['aRc']);
            assert.equal(host.listingFailed, false);
            assert.equal(host.lexical instanceof LexicalScanBackend, false);
            return moduleResult();
        } }) });
        assert.equal((await main(h.deps)).started, true);
        assert.equal(calls, 1);
        const refused = backendHarness(grant, modulePath, { argv: ['--search-backend', modulePath],
            importSearchBackend: async () => assert.fail('import before grant') });
        assert.equal((await main(refused.deps)).reason, 'NO_GRANT');
        const failed = backendHarness(grant, modulePath, { makeFsGate: options => {
            const gate = createFsGate(options);
            return { ...gate, probeInGrant: async () => ({ ok: false, reason: 'IO_ERROR', detail: 'fixture' }) };
        }, importSearchBackend: async () => ({ createSearchBackend: host => {
            assert.equal(host.listingFailed, true); assert.deepEqual(host.layers, []); return moduleResult();
        } }) });
        assert.equal((await main(failed.deps)).started, true);
        assert.match(failed.lines[0], /Vault structure detection did not finish/);
        assert.match(failed.lines[0], /detection was incomplete/);
        assert.doesNotMatch(failed.lines[0], /nothing was read/);
        const listFailed = backendHarness(grant, modulePath, { makeFsGate: options => {
            const gate = createFsGate(options);
            return { ...gate, listGrantRoot: async () => ({ ok: false, reason: 'IO_ERROR', detail: 'fixture listing' }) };
        }, importSearchBackend: async () => ({ createSearchBackend: host => {
            assert.equal(host.listingFailed, true); assert.deepEqual(host.layers, []); return moduleResult();
        } }) });
        assert.equal((await main(listFailed.deps)).started, true);
    });
});

test('SR52-backend-shared-search — one backend answers two servers with its ranked order and outside candidates drop', async () => {
    arm('SR52-backend-shared-search');
    await backendFixture(async ({ grant, modulePath, base }) => {
        fs.writeFileSync(path.join(grant, 'a.md'), 'needle alpha');
        fs.writeFileSync(path.join(grant, 'z.md'), 'needle zeta');
        fs.writeFileSync(path.join(base, 'outside.md'), 'outside secret');
        let factoryCalls = 0;
        let searchCalls = 0;
        let backend;
        const h = backendHarness(grant, modulePath, {
            importSearchBackend: async () => ({ createSearchBackend: async host => {
                factoryCalls++;
                backend = { async search(snapshot, query, reads) {
                    assert.equal(this, backend);
                    searchCalls++;
                    assert.equal(await reads.read('../outside.md', 0, 10), null);
                    const answer = await host.lexical.search(snapshot, query, reads);
                    return { ...answer, candidates: [...answer.candidates].reverse().concat({
                        path: '../outside.md', byte_offset: 0, excerpt_start: 0, version: { kind: 'stat', value: '0:14' } }) };
                } };
                return { backend, disclosure: ['Ranked fixture.'] };
            } }),
            makeConfiguredServer: undefined,
            serveStdio: async factory => {
                for (let i = 0; i < 2; i++) {
                    const server = factory();
                    const handler = server._getRequestHandler('tools/call');
                    const answer = await handler({ method: 'tools/call', params: { name: 'search', arguments: { query: 'needle' } } }, { mcpReq: { requestState: () => undefined } });
                    assert.deepEqual(answer.structuredContent.hits.map(hit => hit.path), ['z.md', 'a.md']);
                    assert.equal(answer.structuredContent.revalidation_dropped_count, 1);
                    assert.doesNotMatch(JSON.stringify(answer), /outside secret/);
                }
            }, connect: undefined
        });
        assert.equal((await main(h.deps)).started, true);
        assert.equal(factoryCalls, 1);
        assert.equal(searchCalls, 2);
    });
});

test('SR53-backend-path — relative, missing and directory paths refuse', async () => {
    arm('SR53-backend-path');
    await backendFixture(async ({ grant, modulePath, base }) => {
        for (const target of ['bare-module', 'C:relative.mjs', path.relative(process.cwd(), modulePath), path.join(base, 'missing.mjs'), grant])
            await backendRefusal(grant, target, {});
    });
});
test('SR54-backend-import — import rejection refuses with its message and no stack', async () => {
    arm('SR54-backend-import');
    await backendFixture(async ({ grant, modulePath }) => {
        await backendRefusal(grant, modulePath, { importSearchBackend: async () => { throw new Error('fixture import\nfailed'); } }, /fixture import failed$/);
        fs.writeFileSync(modulePath, 'export const broken = ;');
        await backendRefusal(grant, modulePath, { importSearchBackend: undefined });
    });
});

test('SR55-backend-export — missing and non-function exports refuse', async () => {
    arm('SR55-backend-export');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const imported of [null, {}, { createSearchBackend: 1 }])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => imported }, /export createSearchBackend/);
    });
});
test('SR56-backend-factory — factory throws and rejections refuse', async () => {
    arm('SR56-backend-factory');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const factory of [() => { throw new Error('factory boom'); }, async () => { throw new Error('factory boom'); }])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: factory }) }, /factory boom$/);
    });
});
test('SR57-backend-return — non-object returns refuse', async () => {
    arm('SR57-backend-return');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const value of [null, undefined, 1, 'bad'])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => value }) }, /return an object/);
    });
});
test('SR58-backend-search-guard — missing and non-function search refuse', async () => {
    arm('SR58-backend-search-guard');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const backend of [undefined, null, {}, { search: true }])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), backend }) }) }, /search function/);
    });
});
test('SR59-backend-lines-guard — disclosure requires an array of one to forty lines', async () => {
    arm('SR59-backend-lines-guard');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const disclosure of [undefined, 'line', [], Array(41).fill('line')])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), disclosure }) }) }, /1 to 40 lines/);
    });
});
test('SR60-backend-line-guard — lines reject empty, overlong, non-string and every control', async () => {
    arm('SR60-backend-line-guard');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const line of ['', '  ', 'x'.repeat(201), null, 3, ...Array.from({ length: 32 }, (_, i) => `before${String.fromCharCode(i)}after`), 'before\x7fafter', 'before\x85after', 'before\u2028after', 'before\u2029after'])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), disclosure: [line] }) }) }, /without controls/);
        const iterator = String.prototype[Symbol.iterator];
        let oversizedIterations = 0;
        String.prototype[Symbol.iterator] = function () {
            if (this.length > 400) oversizedIterations++;
            return iterator.call(this);
        };
        try {
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), disclosure: ['x'.repeat(1000)] }) }) });
            assert.equal(oversizedIterations, 0, 'oversized disclosure rejects before codepoint iteration');
        } finally { String.prototype[Symbol.iterator] = iterator; }
        const sparse = new Array(1);
        await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), disclosure: sparse }) }) });
    });
});
test('SR61-backend-close-guard — an optional close must be callable', async () => {
    arm('SR61-backend-close-guard');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const close of [null, false, 1])
            await backendRefusal(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), close }) }) }, /close must be a function/);
    });
});
test('SR62-backend-disclosure — stderr and model instructions scope built-in claims and attribute module text', async () => {
    arm('SR62-backend-disclosure');
    await backendFixture(async ({ grant, modulePath }) => {
        const lines = ['Fixture statement.', '😀'.repeat(200), ...Array(38).fill('Fixture detail.')];
        let server;
        const h = backendHarness(grant, modulePath, { makeConfiguredServer: undefined, importSearchBackend: async () => ({ createSearchBackend: () => ({ backend: emptyBackend, disclosure: lines }) }),
            connect: async configured => { server = configured; } });
        assert.equal((await main(h.deps)).started, true);
        lines[0] = 'Changed after startup';
        const model = server._options.instructions;
        for (const text of [h.lines[0], model]) {
            assert.ok(text.includes(modulePath));
            assert.match(text, /not confined to the granted folder/);
            assert.match(text, /this process's permissions/);
            assert.match(text, /cannot prevent it opening other files or the network/);
            assert.match(text, /  Module: Fixture statement\./);
            assert.match(text, /built-in search backend builds[\s\S]*holds no raw/);
            assert.doesNotMatch(text, /· Search builds|The PROCESS\s+can write|this server opens no network|this server is listening/);
        }
        const tools = await server._getRequestHandler('tools/list')({ method: 'tools/list' }, { mcpReq: { requestState: () => undefined } });
        assert.equal(tools.tools.find(tool => tool.name === 'search').annotations.readOnlyHint, false);
        for (const tlsEnabled of [false, true]) for (const exposure of ['loopback', 'network']) {
            const handle = { endpoint: { scheme: tlsEnabled ? 'https' : 'http', tlsEnabled, exposure, interfaceAddress: '127.0.0.1', certificate: { fingerprint256: 'fixture', validTo: '2099-01-01' } }, port: 1234, allowedOrigins: [] };
            const text = httpDisclosure(handle, grant, { path: modulePath, lines: ['HTTP fixture.'] });
            assert.ok(text.includes(modulePath));
            assert.match(text, /not confined to the granted folder/);
            assert.match(text, /  Module: HTTP fixture\./);
            assert.doesNotMatch(text, /both are read-only/);
        }
    });
});
test('SR63-backend-real-import-close — production import works and close drains once', async () => {
    arm('SR63-backend-real-import-close');
    await backendFixture(async ({ grant, modulePath, base }) => {
        const closed = path.join(base, 'closed.txt');
        fs.writeFileSync(modulePath, `import fs from 'node:fs';
            export function createSearchBackend(host) {
                return { backend: host.lexical, disclosure: ['Real fixture module.'],
                    close: async () => { fs.appendFileSync(${JSON.stringify(closed)}, 'closed'); } };
            }`);
        const h = backendHarness(grant, modulePath, { importSearchBackend: undefined });
        const result = await main(h.deps);
        assert.equal(result.started, true);
        assert.equal(typeof result.closeSearchBackend, 'function');
        await Promise.all([result.closeSearchBackend(), result.closeSearchBackend()]);
        assert.equal(fs.readFileSync(closed, 'utf8'), 'closed');
    });
});

test('SR64-backend-http-shutdown — signals close the module once and report failure with exit code one', { timeout: 25_000 }, async () => {
    arm('SR64-backend-http-shutdown');
    await backendFixture(async ({ grant, modulePath, base }) => {
        for (const [fail, priorCode, expected] of [[false, 0, 0], [true, 0, 1], [true, 2, 2]]) {
            const closed = path.join(base, `close-${fail}-${priorCode}.txt`);
            fs.writeFileSync(modulePath, `import fs from 'node:fs';
                export function createSearchBackend(host) { return { backend: host.lexical,
                    disclosure: ['Shutdown fixture.'], close: async () => {
                        fs.appendFileSync(${JSON.stringify(closed)}, 'closed');
                        ${fail ? "throw new Error('fixture close failure');" : ''}
                    } }; }`);
            const preload = 'data:text/javascript,' + encodeURIComponent([
                `process.argv = [process.execPath, process.env.WYRD_TEST_INDEX, '--grant', process.env.WYRD_TEST_GRANT, '--search-backend', process.env.WYRD_TEST_MODULE, '--http', '0'];`,
                `process.on('message', () => { process.exitCode = ${priorCode}; process.emit('SIGINT'); process.emit('SIGTERM'); process.disconnect(); });`
            ].join('\n'));
            const child = spawn(process.execPath, ['--import', preload, entrypoint], {
                env: { ...process.env, WYRD_TEST_INDEX: entrypoint, WYRD_TEST_GRANT: grant, WYRD_TEST_MODULE: modulePath,
                    WYRD_READ_TOKEN: Buffer.alloc(32, 1).toString('base64url'), WYRD_OBSERVE: '' }, stdio: ['ignore', 'ignore', 'pipe', 'ipc']
            });
            let stderr = '';
            let sent = false;
            child.stderr.setEncoding('utf8');
            child.stderr.on('data', chunk => {
                stderr += chunk;
                if (!sent && stderr.includes('wyrd Reader is listening')) { sent = true; child.send('shutdown'); }
            });
            const exited = new Promise((resolve, reject) => { child.once('exit', (code, signal) => resolve({ code, signal })); child.once('error', reject); });
            let timer;
            try {
                const result = await Promise.race([exited, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`shutdown timed out: ${stderr}`)), 6000); })]);
                assert.equal(sent, true, stderr);
                assert.deepEqual(result, { code: expected, signal: null }, stderr);
                assert.equal(fs.readFileSync(closed, 'utf8'), 'closed');
                if (fail) assert.match(stderr, /wyrd: search backend shutdown failed — fixture close failure/);
                else assert.doesNotMatch(stderr, /shutdown failed/);
            } finally {
                clearTimeout(timer);
                if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
                await exited;
            }
        }
    });
});


test('SR65-backend-private-inputs — backend edits cannot change revalidation', async () => {
    arm('SR65-backend-private-inputs');
    await backendFixture(async ({ grant }) => {
        fs.writeFileSync(path.join(grant, 'a.md'), 'needle original');
        const gate = createFsGate({ rawGrant: grant });
        let walks = 0, readsCount = 0;
        const tracked = { ...gate, walkGrant: async () => { walks++; return gate.walkGrant(); },
            readFileInGrant: async (...args) => { readsCount++; return gate.readFileInGrant(...args); } };
        const lexical = new LexicalScanBackend();
        const normal = await createSearchEngine(tracked, lexical)('needle');
        assert.equal(normal.hits.length, 1);
        assert.equal(walks, 1); assert.equal(readsCount, 2);
        let heldSnapshot, heldReads;
        const backend = { async search(snapshot, query, reads) {
            heldSnapshot = snapshot; heldReads = reads;
            const file = snapshot.files[0];
            // Reflect models a module that ignores a failed write rather than throwing.
            Reflect.set(file, 'size', 999);
            Reflect.set(file, 'mtimeMs', 0);
            Reflect.set(reads, 'metadata', async () => ({ ...file, size: 999, mtimeMs: 0 }));
            Reflect.set(reads, 'read', async () => ({ bytes: Buffer.from('fabricated'), size: 999 }));
            Reflect.set(snapshot.files, '0', { ...file, rel: 'other.md' });
            const metadata = await reads.metadata('a.md');
            Reflect.set(metadata, 'size', 999);
            return { candidates: [{ path: 'a.md', byte_offset: 0, excerpt_start: 0,
                version: { kind: 'stat', value: '0:999' } }], hasMore: false, typed_files: 0, searched_files: 1 };
        } };
        const answer = await createSearchEngine(tracked, backend)('needle');
        assert.deepEqual(answer.hits, []);
        assert.equal(answer.revalidation_dropped_count, 1);
        assert.equal(Object.isFrozen(heldSnapshot), true);
        assert.equal(Object.isFrozen(heldSnapshot.files), true);
        assert.equal(Object.isFrozen(heldSnapshot.files[0]), true);
        assert.equal(Object.isFrozen(heldReads), true);
    });
});

async function executableCloseFixture({ grant, modulePath, base }, { mode = 'stdio', hung = false, fail = false, signal = null, refuse = false } = {}) {
    const closed = path.join(base, 'close-record.txt');
    fs.writeFileSync(modulePath, `import fs from 'node:fs';
        export function createSearchBackend(host) { ${hung ? 'setInterval(() => {}, 1000);' : ''} return { backend: host.lexical,
            disclosure: ['Close fixture.'], close: async () => {
                fs.appendFileSync(${JSON.stringify(closed)}, 'begin');
                ${hung ? 'await new Promise(() => {});' : 'await new Promise(resolve => setTimeout(resolve, 100));'}
                fs.appendFileSync(${JSON.stringify(closed)}, 'end');
                ${fail ? "throw new Error('bad\\nclose');" : ''}
            } }; }`);
    const preload = 'data:text/javascript,' + encodeURIComponent([
        // Inject the timer seam in the real process; keep all other timers unchanged.
        `const nativeTimer = globalThis.setTimeout; globalThis.setTimeout = (fn, ms, ...args) => nativeTimer(fn, ms === 10000 ? 250 : ms, ...args);`,
        `process.on('message', () => { process.emit(${JSON.stringify(signal || 'SIGINT')}); process.emit('SIGTERM'); process.disconnect(); });`
    ].join('\n'));
    const args = ['--import', preload, entrypoint, '--grant', grant, '--search-backend', modulePath,
        ...(mode === 'http' ? ['--http', '0'] : []), ...(refuse ? ['--tls-cert', 'missing'] : [])];
    const child = spawn(process.execPath, args, { env: { ...process.env, WYRD_OBSERVE: '',
        WYRD_READ_TOKEN: Buffer.alloc(32, 1).toString('base64url') }, stdio: ['pipe', 'ignore', 'pipe', 'ipc'] });
    let stderr = '', sent = false;
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', chunk => {
        stderr += chunk;
        if (!sent && (stderr.includes('wyrd is serving exactly one folder:') || stderr.includes('wyrd Reader is listening'))) {
            sent = true;
            if (signal || mode === 'http') child.send('shutdown');
            else { child.stdin.end(); child.disconnect(); }
        }
    });
    if (refuse) { child.stdin.end(); child.disconnect(); }
    const exited = new Promise((resolve, reject) => {
        child.once('exit', (code, signal) => resolve({ code, signal })); child.once('error', reject);
    });
    let timer;
    const start = Date.now();
    try {
        const result = await Promise.race([exited, new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error(`child close timed out: ${stderr}`)), 2500);
        })]);
        assert.equal(result.signal, null, stderr);
        assert.equal(result.code, refuse ? 2 : hung || fail ? 1 : 0, stderr);
        assert.equal(fs.readFileSync(closed, 'utf8'), hung ? 'begin' : 'beginend');
        if (hung || fail) {
            assert.equal(stderr.split('\n').filter(line => line.includes('search backend shutdown failed')).length, 1);
            assert.match(stderr, hung ? /deadline exceeded/ : /bad close/);
        } else assert.doesNotMatch(stderr, /shutdown failed/);
        assert.ok(Date.now() - start < 2500);
    } finally {
        clearTimeout(timer);
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await exited;
    }
}

test('SR66-backend-stdio-close — EOF, signals and startup refusal await close once', async () => {
    arm('SR66-backend-stdio-close');
    for (const options of [{}, { signal: 'SIGINT' }, { signal: 'SIGTERM' }, { fail: true }, { refuse: true }])
        await backendFixture(fixture => executableCloseFixture(fixture, options));
});

test('SR67-backend-close-deadline — pending close cannot report success or hold either transport', async () => {
    arm('SR67-backend-close-deadline');
    for (const mode of ['stdio', 'http'])
        await backendFixture(fixture => executableCloseFixture(fixture, { mode, hung: true }));
});

test('SR68-backend-disclosure-copy — indexed values are copied once before validation', async () => {
    arm('SR68-backend-disclosure-copy');
    await backendFixture(async ({ grant, modulePath }) => {
        for (const overrideIterator of [false, true]) {
            let gets = 0, iterations = 0;
            const lines = ['unused'];
            Object.defineProperty(lines, '0', { get() { return ++gets === 1 ? 'First safe line.' : 'second\nunsafe'; } });
            if (overrideIterator) lines[Symbol.iterator] = function* () { iterations++; yield 'iterator\nunsafe'; };
            const h = backendHarness(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ ...moduleResult(), disclosure: lines }) }) });
            assert.equal((await main(h.deps)).started, true);
            assert.equal(gets, 1); assert.equal(iterations, 0);
            assert.match(h.lines[0], /Module: First safe line\./);
            assert.doesNotMatch(h.lines[0], /second|iterator/);
        }
    });
});

test('SR69-backend-lexical-facade — only a frozen delegating function is exposed', async () => {
    arm('SR69-backend-lexical-facade');
    await backendFixture(async ({ grant, modulePath }) => {
        fs.writeFileSync(path.join(grant, 'a.md'), 'needle');
        const h = backendHarness(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: host => {
            assert.deepEqual(Object.keys(host.lexical), ['search']);
            assert.equal(Object.isFrozen(host.lexical), true);
            assert.equal(Object.getPrototypeOf(host.lexical), Object.prototype);
            assert.equal(Reflect.set(host.lexical, 'search', emptyBackend.search), false);
            return { backend: host.lexical, disclosure: ['Facade fixture.'] };
        } }), makeConfiguredServer: undefined, connect: async server => {
            const result = await server._getRequestHandler('tools/call')({ method: 'tools/call', params: { name: 'search', arguments: { query: 'needle' } } }, { mcpReq: { requestState: () => undefined } });
            assert.equal(result.structuredContent.hits.length, 1);
        } });
        assert.equal((await main(h.deps)).started, true);
    });
});

test('SR70-backend-host-fields — process UUID and scan bound are stable and usable', async () => {
    arm('SR70-backend-host-fields');
    const ids = [];
    for (let i = 0; i < 2; i++) await backendFixture(async ({ grant, modulePath }) => {
        fs.writeFileSync(path.join(grant, 'a.md'), 'needle');
        const h = backendHarness(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: host => {
            assert.match(host.grantId, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
            ids.push(host.grantId); assert.equal(host.maxSliceBytes, SCAN_BYTES);
            assert.equal(host.maxSliceBytes, 65536);
            return { backend: { async search(snapshot, query, reads) {
                assert.notEqual(await reads.read('a.md', 0, host.maxSliceBytes), null);
                assert.equal(await reads.read('a.md', 0, host.maxSliceBytes + 1), null);
                return host.lexical.search(snapshot, query, reads);
            } }, disclosure: ['Host fields fixture.'] };
        } }), makeConfiguredServer: undefined, connect: async server => {
            const result = await server._getRequestHandler('tools/call')({ method: 'tools/call', params: { name: 'search', arguments: { query: 'needle' } } }, { mcpReq: { requestState: () => undefined } });
            assert.equal(result.structuredContent.hits.length, 1);
        } });
        assert.equal((await main(h.deps)).started, true);
    });
    assert.equal(ids[0], ids[1]);
});


test('SR71-backend-retained-results — later backend edits cannot change accepted search state', async () => {
    arm('SR71-backend-retained-results');
    await backendFixture(async ({ grant, modulePath }) => {
        fs.writeFileSync(path.join(grant, 'a.md'), 'needle');
        const gate = createFsGate({ rawGrant: grant });
        const file = await gate.fileMetadataInGrant('a.md');
        const candidate = { path: 'a.md', byte_offset: 0, excerpt_start: 0,
            version: { kind: 'stat', value: `${file.mtimeMs}:${file.size}` } };
        const answer = { candidates: [candidate], hasMore: false, typed_files: 0, searched_files: 1 };
        const engine = createSearchEngine({ ...gate, probeInGrant: async name => {
            candidate.path = 'missing.md'; candidate.version.value = '0:0';
            answer.candidates.length = 0; answer.searched_files = 0;
            return gate.probeInGrant(name);
        } }, { search: async () => answer });
        assert.equal((await engine('needle')).hits.length, 1);
        const backend = { search: async () => ({ candidates: [], hasMore: false, typed_files: 0, searched_files: 7 }) };
        const h = backendHarness(grant, modulePath, { importSearchBackend: async () => ({ createSearchBackend: () => ({ backend, disclosure: ['Retained fixture.'] }) }), makeConfiguredServer: undefined,
            connect: async server => {
                backend.search = async () => ({ candidates: [], hasMore: false, typed_files: 0, searched_files: 0 });
                const result = await server._getRequestHandler('tools/call')({ method: 'tools/call', params: { name: 'search', arguments: { query: 'needle' } } }, { mcpReq: { requestState: () => undefined } });
                assert.equal(result.structuredContent.searchable_files, 7);
            } });
        assert.equal((await main(h.deps)).started, true);
    });
});
