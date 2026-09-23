import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { declare as arm } from './manifest.mjs';
import {
    captureOrCompare,
    refuseRecapture,
    RawStdioSession,
    tempPathTokens,
    treeSnapshot,
    V1_PROTOCOL_VERSION,
    V2_INVALID_TOOL_NAME_ERROR
} from './raw-stdio.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = path.join(packageRoot, 'dist', 'index.js');
const goldenPath = path.join(packageRoot, 'test', 'v1-reader.golden.json');

function makeDirectory(parent, name) {
    const target = path.join(parent, name);
    fs.mkdirSync(target, { recursive: true });
    return target;
}

function session(options) {
    return new RawStdioSession({
        entrypoint,
        entrypointLabel: 'dist/index.js',
        ...options
    });
}

test('E17-v1-raw-baseline — SDK-free JSON-RPC pins Reader wire, lifecycle and tool behavior', { timeout: 120_000 }, async () => {
    arm('E17-v1-raw-baseline');
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-v1-reader-'));
    const pathTokens = tempPathTokens(temporary);
    const processes = [];
    const open = options => {
        const child = session(options);
        processes.push(child);
        return child;
    };

    try {
        const noGrantProcess = open({
            env: { WYRD_GRANT: undefined, WYRD_OBSERVE: undefined },
            pathTokens
        });
        const noGrant = await noGrantProcess.waitForExit();

        const argumentGrant = makeDirectory(temporary, 'argument-grant');
        const environmentGrant = makeDirectory(temporary, 'environment-grant');
        fs.writeFileSync(path.join(argumentGrant, 'selected.txt'), 'selected by --grant\n');
        fs.writeFileSync(path.join(environmentGrant, 'selected.txt'), 'selected by WYRD_GRANT\n');
        const precedenceProcess = open({
            args: ['--grant', argumentGrant],
            env: { WYRD_GRANT: environmentGrant, WYRD_OBSERVE: undefined },
            pathTokens
        });
        await precedenceProcess.initialise();
        await precedenceProcess.callTool('read', { path: 'selected.txt' });
        const grantPrecedence = await precedenceProcess.finish();

        const grant = makeDirectory(temporary, 'reader-grant');
        const outside = path.join(temporary, 'outside.txt');
        fs.mkdirSync(path.join(grant, 'folder'));
        fs.writeFileSync(path.join(grant, 'normal.md'), 'ordinary text\n');
        fs.writeFileSync(path.join(grant, 'paged.md'), 'A😀Z');
        fs.writeFileSync(path.join(grant, 'non-text.bin'), Buffer.from([0x66, 0x80]));
        fs.writeFileSync(outside, 'outside\n');

        const preInitializeProcess = open({
            env: { WYRD_GRANT: grant, WYRD_OBSERVE: undefined },
            pathTokens
        });
        await preInitializeProcess.listTools({}, {
            byteStrictLabel: 'pre-initialize tools/list response'
        });
        const preInitialize = await preInitializeProcess.finish();

        const lifecycleProcess = open({
            env: { WYRD_GRANT: grant, WYRD_OBSERVE: undefined },
            pathTokens
        });
        const nonEmptyCapabilities = { roots: { listChanged: true } };
        await lifecycleProcess.initialise({ capabilities: nonEmptyCapabilities });
        // ⚠ NO byteStrictLabel HERE, and the omission is the point. An `initialize` response
        // embeds the grant's absolute path in its instructions, so its bytes carry a per-run temp
        // directory. Byte-strict retention deliberately bypasses `normalise`, so a byte check here
        // can never compare equal on a second run. Measured: capture passed and compare failed on
        // exactly this line. The duplicate-initialize CASE is still characterized — through the
        // normalized event, which is what the path normalizer exists for.
        await lifecycleProcess.initializeRequest(nonEmptyCapabilities);
        await lifecycleProcess.listTools({ cursor: 'v1-characterization-cursor' });
        const invalidToolName = await lifecycleProcess.request('tools/call', { name: 7 }, {
            byteStrictLabel: 'tools/call name-number response'
        });
        // The golden remains v1 -32603 evidence. The live v2 envelope is checked here and the
        // comparator substitutes only this response before its whole-corpus deepStrictEqual.
        assert.deepStrictEqual(
            invalidToolName.error,
            V2_INVALID_TOOL_NAME_ERROR,
            'v2 must return the one reviewed -32602 protocol-validation envelope'
        );
        const initializedLifecycle = await lifecycleProcess.finish();

        const before = treeSnapshot(temporary);

        const exchangeProcess = open({
            env: { WYRD_GRANT: grant, WYRD_OBSERVE: undefined },
            pathTokens
        });
        await exchangeProcess.initialise();
        await exchangeProcess.listTools();
        await exchangeProcess.callTool('read', { path: 'normal.md' });
        await exchangeProcess.callTool('read', { path: 'paged.md', offset: 0, limit: 5 });
        await exchangeProcess.callTool('read', { path: 'paged.md', offset: 5, limit: 5 });
        await exchangeProcess.callTool('read', { path: 'non-text.bin' });
        await exchangeProcess.callTool('read', { path: 'missing.md' });
        await exchangeProcess.callTool('read', { path: 'folder' });
        await exchangeProcess.callTool('read', { path: '../outside.txt' });
        await exchangeProcess.callTool('read', { path: 7 });
        await exchangeProcess.callTool('read', { path: 'paged.md', offset: 1, limit: 1 });
        await exchangeProcess.callTool('read', { path: 'paged.md', offset: 2, limit: 5 });
        await exchangeProcess.callTool('not-a-tool', {});
        const exchange = await exchangeProcess.finish();
        const after = treeSnapshot(temporary);

        captureOrCompare(goldenPath, {
            captured: true,
            protocolVersion: V1_PROTOCOL_VERSION,
            cases: {
                noGrant,
                grantPrecedence,
                expandedCharacterization: {
                    preInitialize,
                    initializedLifecycle
                },
                exchange: {
                    ...exchange,
                    filesystemBefore: before,
                    filesystemAfter: after
                }
            }
        });
    } finally {
        await Promise.allSettled(processes.map(child => child.dispose()));
        fs.rmSync(temporary, { recursive: true, force: true });
    }
});

/**
 * Criterion: the capture path REFUSES to overwrite an existing golden, and the real corpus file
 * survives an attempt byte for byte.
 *
 * ⚠ WHY THIS ARM EXISTS, AND IT IS NOT THE REASON A READER WILL ASSUME. `E17` above was credited
 * in `NEXT.md` and in the 2026-09-14 run log with catching a recapture that destroyed the
 * preserved v1 golden. It could not have: before 2026-09-15 `captureOrCompare` wrote the file and
 * returned BEFORE any comparison, so in capture mode no assertion in `E17` ever ran. The guard
 * everyone believed in was absent, and the belief was load-bearing — it is why `WYRD_CAPTURE_V1_GOLDENS=1`
 * was described as "a trap" rather than "a thing that cannot happen".
 *
 * What would still pass this? An implementation that refuses on `existsSync` but is reached
 * through some other write path — a direct `fs.writeFileSync` elsewhere, or a tool that rewrites
 * the golden outside this module. This arm proves THIS entry point refuses and that these bytes
 * survive it; it does not prove no other code can ever write that file. It deliberately runs
 * against the REAL golden rather than a fixture, because a fixture would prove the predicate and
 * leave the actual evidence file untested.
 */
test('E18-recapture-refused — the capture path refuses to overwrite an existing golden', () => {
    arm('E18-recapture-refused');

    const before = fs.readFileSync(goldenPath);
    assert.ok(before.length > 0, 'the v1 golden must exist for this arm to mean anything');

    // The reviewed v1 envelope this corpus exists to preserve. If a recapture ever lands, this is
    // the byte sequence that disappears — so the arm names it rather than checking length alone.
    assert.ok(
        before.includes('"code": -32603'),
        'the preserved v1 -32603 invalid-tool-name envelope must be present before the attempt'
    );

    // `captureOrCompare` reads the capture flag at import time, so this drives the refusal it
    // calls rather than the flag. The write in `captureOrCompare` is unreachable past this guard.
    assert.throws(
        () => refuseRecapture(goldenPath),
        error => {
            assert.match(error.message, /would overwrite it/i);
            assert.match(error.message, /destroys that evidence/i);
            return true;
        },
        'a recapture against an existing golden must throw'
    );

    // The refusal must also NOT fire where a legitimate first capture would run, or the guard
    // would make the corpus impossible to record in the first place.
    const absent = path.join(os.tmpdir(), `wyrd-absent-golden-${process.pid}.json`);
    fs.rmSync(absent, { force: true });
    assert.doesNotThrow(
        () => refuseRecapture(absent),
        'a first capture, where no golden exists yet, must still be allowed'
    );

    const after = fs.readFileSync(goldenPath);
    assert.deepStrictEqual(
        after,
        before,
        'the golden must be byte-identical after a refused recapture attempt'
    );
});
