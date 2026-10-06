import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { createFsGate } from 'wyrd-fence';
import { main } from '../dist/main.js';
import { createWriteAuthInfo, loadWriteToken, SCRIBE_HTTP_REFUSALS } from '../dist/http-policy.js';
import { createWriteCompletionTracker } from '../dist/write-completion.js';
import { declare as arm } from './manifest.mjs';

const temporaryBases = new Set();
process.once('exit', () => {
    for (const base of temporaryBases) fs.rmSync(base, { recursive: true, force: true });
});

function temporaryDirectory(prefix) {
    const base = fs.mkdtempSync(prefix);
    temporaryBases.add(base);
    return base;
}


const tokenText = Buffer.alloc(32, 7).toString('base64url');
const token = Buffer.from(tokenText, 'base64url');

function fixture() {
    const root = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-scribe-http-prep-'));
    const grant = path.join(root, 'grant');
    fs.mkdirSync(path.join(grant, 'Arc'), { recursive: true });
    fs.mkdirSync(path.join(grant, '.wyrd'), { recursive: true });
    fs.writeFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'baseline\n');
    return { root, grant };
}

function snapshot(grant) {
    const rows = [];
    const walk = (dir, prefix = '') => {
        for (const name of fs.readdirSync(dir).sort()) {
            const full = path.join(dir, name);
            const relative = `${prefix}${name}`;
            const stat = fs.lstatSync(full);
            rows.push([relative, stat.isDirectory() ? 'dir' :
                crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex')]);
            if (stat.isDirectory()) walk(full, `${relative}/`);
        }
    };
    walk(grant);
    return rows;
}

test('SH1-stdio-factory-invariance', async () => {
    arm('SH1-stdio-factory-invariance');
    const { root, grant } = fixture();
    try {
        let built = 0;
        const before = snapshot(grant);
        const result = await main({
            argv: ['--grant', grant], env: {},
            makeFsGate: ({ rawGrant }) => createFsGate({ rawGrant }),
            serveStdio: async makeServer => {
                const first = makeServer();
                const second = makeServer();
                assert.notEqual(first, second);
                built += 2;
            },
            stderr: () => assert.fail('stdio must not refuse'),
            setExitCode: () => assert.fail('stdio must not exit')
        });
        assert.deepEqual(result, { started: true, reason: null });
        assert.equal(built, 2);
        assert.deepEqual(snapshot(grant), before);
        // SV15 separately compares the complete raw stdio transcript to the unchanged golden.
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH2-prelisten-policy-refusals', () => {
    arm('SH2-prelisten-policy-refusals');
    const { root, grant } = fixture();
    try {
        const before = snapshot(grant);
        const file = path.join(root, 'token');
        fs.writeFileSync(file, `${tokenText}\n`);
        const refused = [
            loadWriteToken([], {}),
            loadWriteToken(['--write-token=secret'], {}),
            loadWriteToken(['--write-token-file=secret'], {}),
            loadWriteToken(['--write-token-file', file, '--write-token-file', file], {}),
            loadWriteToken(['--write-token-file'], {}),
            loadWriteToken(['--write-token-file', 'relative'], {}),
            loadWriteToken(['--write-token-file', path.join(root, 'missing')], {}),
            loadWriteToken(['--write-token-file', grant], {}),
            loadWriteToken(['--write-token-file', file], { WYRD_WRITE_TOKEN: tokenText }),
            loadWriteToken([], { WYRD_WRITE_TOKEN: 'invalid' })
        ];
        for (const result of refused) {
            assert.equal(result.ok, false);
            assert.match(result.detail, /Scribe|--write-token-file|WYRD_WRITE_TOKEN/);
            assert.deepEqual(snapshot(grant), before);
        }
        assert.equal(loadWriteToken([], { WYRD_WRITE_TOKEN: tokenText }).ok, true);
        assert.equal(loadWriteToken(['--write-token-file', file], {}).ok, true);
        assert.throws(() => createWriteAuthInfo(Buffer.alloc(1), 'A'), /Scribe HTTP token/);
        assert.throws(() => createWriteAuthInfo(token, 'C'), /Scribe HTTP tier/);
        assert.deepEqual(snapshot(grant), before);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH3-refusal-zero-effects', async () => {
    arm('SH3-refusal-zero-effects');
    const { root, grant } = fixture();
    try {
        const before = snapshot(grant);
        let writes = 0;
        const tracker = createWriteCompletionTracker();
        const attempt = async decision => {
            if (decision.kind !== 'authenticated') return;
            await tracker.run(async () => {
                writes += 1;
                fs.writeFileSync(path.join(grant, 'page.md'), 'written');
                fs.appendFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'written\n');
            });
        };
        for (const [name, refusal] of Object.entries(SCRIBE_HTTP_REFUSALS)) {
            assert.match(refusal.body, /Scribe/);
            assert.ok(name in SCRIBE_HTTP_REFUSALS);
            await attempt({ kind: name === 'unavailable' ? 'unavailable' : 'unauthenticated' });
            assert.deepEqual(snapshot(grant), before, `${name} changed disk or ledger`);
        }
        const verify = createWriteAuthInfo(token, 'A');
        for (const authorization of [null, '', 'Bearer wrong', `Basic ${tokenText}`]) {
            const decision = verify({ authorization, signal: new AbortController().signal });
            assert.equal(decision.kind, 'unauthenticated');
            await attempt(decision);
            assert.deepEqual(snapshot(grant), before);
        }
        assert.equal(writes, 0);
        const admitted = verify({ authorization: `Bearer ${tokenText}`, signal: new AbortController().signal });
        assert.deepEqual(admitted.authInfo.scopes, ['write']);
        assert.deepEqual(createWriteAuthInfo(token, 'B')({ authorization: `Bearer ${tokenText}`, signal: new AbortController().signal }).authInfo.scopes, ['write', 'overwrite']);
        await attempt(admitted);
        assert.equal(writes, 1);
        assert.notDeepEqual(snapshot(grant), before);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH4-disconnect-drain', async () => {
    arm('SH4-disconnect-drain');
    const { root, grant } = fixture();
    try {
        let release;
        const hold = new Promise(resolve => { release = resolve; });
        const controller = new AbortController();
        const tracker = createWriteCompletionTracker();
        const write = tracker.run(async () => {
            await hold;
            fs.writeFileSync(path.join(grant, 'page.md'), 'completed');
            fs.appendFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'completed\n');
            return 'done';
        }, controller.signal);
        controller.abort(new Error('client disconnected'));
        const close = tracker.close();
        let closed = false;
        void close.then(() => { closed = true; });
        await new Promise(resolve => setImmediate(resolve));
        const closedBeforeWrite = closed;
        release();
        assert.equal(closedBeforeWrite, false);
        assert.throws(() => tracker.run(async () => 'late'), /closing/);
        assert.equal(await write, 'done');
        await close;
        assert.equal(closed, true);
        assert.equal(fs.readFileSync(path.join(grant, 'page.md'), 'utf8'), 'completed');
        assert.equal(fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8'), 'baseline\ncompleted\n');
        assert.equal(tracker.close(), close);
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
