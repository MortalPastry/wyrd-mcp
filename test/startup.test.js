import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createFsGate, isRefusal } from '../dist/fsgate.js';
import { main, NO_GRANT_MESSAGE, readGrantArg } from '../dist/main.js';
import { declare as arm, tier2 } from './manifest.mjs';

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

test('startup — no grant refuses with the STATIC message, exits non-zero, and probes nothing', async () => {
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

test('startup — a grant naming a non-existent absolute directory refuses AND prints the resolved path', async () => {
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

test('startup — a grant that is a file refuses', async () => {
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

test('startup — relative, drive-relative, namespaced and malformed grants each refuse with their own reason', () => {
    arm('S4-config-shapes');
    const cases = [
        ['.', 'CONFIG_RELATIVE'],
        ['vault', 'CONFIG_RELATIVE'],
        ['C:notes', 'CONFIG_DRIVE_RELATIVE'],
        ['\\\\?\\C:\\vault', 'CONFIG_NAMESPACED'],
        // ⚠ `path.normalize` absorbs `..` THROUGH the device prefix, giving `\\?\foo` — a
        // path naming a DIFFERENT volume than the one written. That is the malformed case, and
        // the mangling check runs ahead of the namespace check so the user is told the true
        // defect. Plan §2 asks for this exact string measured against the malformed refusal.
        ['\\\\?\\C:\\..\\foo', 'CONFIG_MALFORMED'],
        ['\\\\.\\C:\\vault', 'CONFIG_NAMESPACED'],
        ['\\\\server', 'CONFIG_MALFORMED'],
        ['', 'CONFIG_EMPTY'],
        ['C:\\vault\u0000x', 'CONFIG_NULL_BYTE']
    ];
    for (const [raw, expected] of cases) {
        const made = createFsGate({ rawGrant: raw });
        assert.ok(isRefusal(made), `${JSON.stringify(raw)} must refuse`);
        assert.equal(made.reason, expected, `${JSON.stringify(raw)} refused as ${made.reason}`);
    }
});

test('startup — the command line overrides the environment', async () => {
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

test('startup — `--grant=value` is accepted as well as `--grant value`', () => {
    arm('S6-arg-forms');
    assert.equal(readGrantArg(['--grant', 'C:\\v']), 'C:\\v');
    assert.equal(readGrantArg(['--grant=C:\\v']), 'C:\\v');
    assert.equal(readGrantArg([]), null);
    assert.equal(readGrantArg(['--other', 'x']), null);
});

test('startup — a valid grant starts and discloses the canonical root', async () => {
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

test('startup — a grant link that dangles, or that resolves to a FILE, each refuses', { ...tier2('S8-link-grants') }, () => {    arm('S8-link-grants');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-linkgrant-'));
    const links = [];
    try {
        // A junction whose target never existed: `lstat` on the link SUCCEEDS (measured), so the
        // refusal has to come from the canonicalization, not from the first stat.
        const dangling = path.join(base, 'dangling');
        fs.symlinkSync(path.join(base, 'no-such-target'), dangling, 'junction');
        links.push(dangling);
        const a = createFsGate({ rawGrant: dangling });
        assert.ok(isRefusal(a), 'a dangling grant link must refuse');
        assert.equal(a.reason, 'GRANT_MISSING');
        assert.ok(a.resolvedPath.length > 0, 'the refusal must carry the path the user named');

        // A symlink to a FILE passes `isSymbolicLink()` at step 6a and must still refuse: the
        // not-a-directory check has to be applied to the CANONICAL root, not only the named one.
        const file = path.join(base, 'note.md');
        fs.writeFileSync(file, 'x');
        const toFile = path.join(base, 'grant-to-file');
        fs.symlinkSync(file, toFile, 'file');
        links.push(toFile);
        const b = createFsGate({ rawGrant: toFile });
        assert.ok(isRefusal(b), 'a grant link resolving to a file must refuse');
        assert.equal(b.reason, 'GRANT_NOT_A_DIRECTORY');
    } finally {
        for (const link of links.reverse()) {
            try {
                fs.unlinkSync(link);
            } catch {
                try {
                    fs.rmdirSync(link);
                } catch { /* the rm below reports what survived */ }
            }
        }
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('startup — EVERY separator spelling of one folder is accepted and lands on one root', () => {
    arm('S12-separator-spellings');
    // ⚠ THE PASS HALF IS THE POINT, and its absence shipped a defect. MCP client configs are
    // JSON, where a native Windows path needs every separator doubled — so `C:/Users/joe/notes`
    // is how people actually write it. Refusing that is fail-closed behaviour on a legitimate
    // input, wearing a config error's clothes.
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-seps-'));
    try {
        const vault = path.join(base, 'vault');
        fs.mkdirSync(vault);
        fs.writeFileSync(path.join(vault, 'note.md'), 'SEPARATORS');
        const canonical = fs.realpathSync.native(vault);

        const spellings = {
            'all backslash': vault,
            'all forward slash': vault.replace(/\\/g, '/'),
            'trailing backslash': `${vault}\\`,
            'trailing forward slash': `${vault.replace(/\\/g, '/')}/`,
            'mixed, forward tail': `${path.dirname(vault)}/${path.basename(vault)}`,
            'mixed, forward head': vault.replace(/\\/g, '/').replace(/\/([^/]+)$/, '\\$1'),
            'case folded': vault.toLowerCase()
        };
        for (const [label, raw] of Object.entries(spellings)) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(!isRefusal(made), `${label} (${raw}) must be accepted, got ${made.reason}: ${made.detail}`);
            assert.equal(made.disclosedRoot(), canonical, `${label} must land on the canonical root`);
        }

        // ⚠ A UNC SHARE ROOT IS A LEGITIMATE GRANT AND MUST PASS THE LEXICAL STAGE. This is
        // the shape the UNC validator exists to accept, and it was refused CONFIG_MALFORMED
        // because `path.parse('\\\\nas\\vault').root` carries no trailing separator while its
        // normalized form's root does. No arm used a UNC grant at all, so nothing caught it.
        //
        // No share exists on this machine, so the assertion is that the verdict is a FILESYSTEM
        // one (GRANT_MISSING, reached only after every lexical check passed) and never a
        // CONFIG_ one. That is the distinction the defect erased.
        for (const raw of ['\\\\nas\\vault', '//nas/vault', '\\\\nas\\vault\\', '\\\\nas\\vault\\sub']) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(isRefusal(made), `${raw} has no share behind it, so it cannot be accepted`);
            assert.equal(made.reason, 'GRANT_MISSING', `${raw} was refused lexically as ${made.reason}`);
        }

        // The refusal half: the ONLY inputs on this platform where normalizing genuinely changes
        // the volume. Measured — `path.normalize('\\?\C:\..\foo')` is `\\?\foo`, the `..`
        // absorbed THROUGH the device prefix.
        for (const raw of ['\\\\?\\C:\\..\\foo', '\\\\.\\C:\\..\\foo', '\\\\?\\..\\foo']) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(isRefusal(made), `${raw} must refuse`);
            assert.equal(made.reason, 'CONFIG_MALFORMED', `${raw} refused as ${made.reason}`);
            // The message must describe what is actually wrong. The shipped defect said
            // "normalizes to a different volume root" about paths whose volume had not changed.
            assert.match(made.detail, /changes the volume it names/);
        }
        // Ordering is load-bearing: a namespaced path whose volume does NOT change is refused
        // by the namespace rule, not by the mangling rule.
        const namespaced = createFsGate({ rawGrant: '\\\\?\\C:\\vault' });
        assert.ok(isRefusal(namespaced));
        assert.equal(namespaced.reason, 'CONFIG_NAMESPACED');
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('startup — --grant, --grant= and WYRD_GRANT agree exactly, forward slashes included', async () => {
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

test('observer — an import-time filesystem touch IS detected', () => {
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

test('observer — the bootstrap arms the instrument before importing anything', () => {
    arm('S10-bootstrap-order');
    const source = fs.readFileSync(entrypoint, 'utf8');
    const staticImports = [...source.matchAll(/^\s*import\s[^\n]*from\s+'([^']+)'/gm)].map(m => m[1]);
    assert.deepEqual(staticImports, ['./observe.js'], 'observe.js must be the only static import');
    assert.ok(source.indexOf('installObserver(') < source.indexOf('await import('), 'arm, then import');
});

test('startup — with no grant, the child process exits non-zero and names no candidate vault', () => {
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
