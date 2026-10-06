import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { createFsGate } from 'wyrd-fence';
import { overwritePage } from '../dist/mutate.js';
import { writePage } from '../dist/stamp.js';
import { gateAppender } from '../dist/ledger.js';
import { declare as arm } from './manifest.mjs';

const built = [];
process.on('exit', () => { for (const base of built) fs.rmSync(base, { recursive: true, force: true }); });
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function world(frontmatter = false) {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-overwrite-'));
    built.push(base);
    const grant = path.join(base, 'vault');
    fs.mkdirSync(path.join(grant, 'Mage'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'Arc'));
    fs.mkdirSync(path.join(grant, '.wyrd'));
    fs.writeFileSync(path.join(grant, '.wyrd', 'scribe.json'), JSON.stringify({
        schema: 'wyrd.scribe/v1', vault_id: '11111111-2222-4333-8444-555555555555',
        write_frontmatter: frontmatter
    }));
    fs.writeFileSync(path.join(grant, 'Mage', 'page.md'), 'old');
    fs.writeFileSync(path.join(grant, 'Mage', 'source.md'), 'source text');
    const gate = createFsGate({ rawGrant: grant });
    assert.notEqual(gate.ok, false);
    const options = { gate, appender: gateAppender(gate), version: '0.0.0-test',
        now: () => new Date('2026-09-28T00:00:00.000Z'),
        newUuid: () => '11111111-2222-4333-8444-555555555555',
        newEventId: () => 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee' };
    const request = { path: 'Mage/page.md', content: 'new', expectedSha256: digest('old'),
        derivedFrom: [{ source: 'Mage/source.md', spans: [{ quote: 'source' }] }] };
    return { grant, gate, options, request };
}

const file = (w, rel) => path.join(w.grant, ...rel.split('/'));
const ledger = w => fs.existsSync(file(w, '.wyrd/lineage.jsonl'))
    ? fs.readFileSync(file(w, '.wyrd/lineage.jsonl')) : Buffer.alloc(0);
const snapshot = w => ({ page: fs.readFileSync(file(w, 'Mage/page.md')),
    mage: fs.readdirSync(file(w, 'Mage')).sort(),
    wyrd: fs.readdirSync(file(w, '.wyrd')).sort(), line: ledger(w) });

test('ST44-overwrite-success-lineage', async () => {
    arm('ST44-overwrite-success-lineage');
    const w = world();
    const result = await overwritePage(w.request, w.options);
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(result.overwritten.effect, { target: 'replaced', stage: { state: 'none' } });
    assert.equal(fs.readFileSync(file(w, 'Mage/page.md'), 'utf8'), 'new');
    const lines = ledger(w).toString('utf8').trimEnd().split('\n');
    assert.equal(lines.length, 1);
    const record = JSON.parse(lines[0]);
    assert.equal(record.event, 'page_overwritten');
    assert.equal(record.writer.tool, 'overwrite_page');
    assert.equal(record.previous.content.digest, digest('old'));
    assert.equal(record.previous.content.bytes, 3);
    assert.equal(record.page.content.digest, digest('new'));
    assert.equal(record.page.identity.path, 'Mage/page.md');
    assert.deepEqual(record, result.record);
});

test('ST45-overwrite-source-fence-and-precondition', async () => {
    arm('ST45-overwrite-source-fence-and-precondition');
    const w = world();
    const escaped = await overwritePage({ ...w.request,
        derivedFrom: [{ source: '../outside/secret.md', spans: [{ quote: 'x' }] }] }, w.options);
    assert.equal(escaped.reason, 'ESCAPES');
    const mismatch = await overwritePage({ ...w.request, expectedSha256: digest('wrong') }, w.options);
    assert.equal(mismatch.reason, 'DIGEST_MISMATCH');
    assert.deepEqual(mismatch.effect, { target: 'not_replaced', stage: { state: 'none' } });
});

test('ST46-overwrite-arc-immutable', async () => {
    arm('ST46-overwrite-arc-immutable');
    const w = world();
    const forbidden = { ...w.options, gate: { hashInGrant() { assert.fail('source or config IO'); } } };
    for (const path of ['Arc/x.md', 'arc\\x.md', 'Mage/../Arc/x.md']) {
        const result = await overwritePage({ ...w.request, path }, forbidden);
        assert.equal(result.reason, 'ARC_IMMUTABLE');
    }
    assert.deepEqual(ledger(w), Buffer.alloc(0));
});

test('ST47-overwrite-ledger-failure', async () => {
    arm('ST47-overwrite-ledger-failure');
    const w = world();
    const cause = { ok: false, reason: 'DENIED', detail: 'append denied', resolvedPath: '' };
    const result = await overwritePage(w.request, { ...w.options,
        appender: { appendLine: async () => cause } });
    assert.equal(result.reason, 'OVERWRITE_LEDGER_FAILED');
    assert.deepEqual(result.cause, cause);
    assert.equal(result.overwritten.effect.target, 'replaced');
    assert.equal(fs.readFileSync(file(w, 'Mage/page.md'), 'utf8'), 'new');
    assert.equal(ledger(w).length, 0);
});

test('ST48-overwrite-frontmatter', async () => {
    arm('ST48-overwrite-frontmatter');
    const w = world(true);
    const oldProjection = { schema: 'wyrd.lineage/v1', event: 'page_written', event_id: 'old',
        recorded_at: '2026-09-01', writer: { server: 'wyrd-scribe', version: 'old', tool: 'write_page' },
        vault: { kind: 'uuid', id: 'old' }, sources: [] };
    const supplied = `---\r\ntitle: Note\r\nwyrd_lineage: ${JSON.stringify(oldProjection)}\r\n---\r\nBody\r\n`;
    const result = await overwritePage({ ...w.request, content: supplied }, w.options);
    assert.equal(result.ok, true, JSON.stringify(result));
    const output = fs.readFileSync(file(w, 'Mage/page.md'), 'utf8');
    assert.equal(output.match(/wyrd_lineage:/g).length, 1);
    assert.ok(output.includes('title: Note\r\n'));
    assert.ok(output.endsWith('---\r\nBody\r\n'));
    assert.ok(output.includes('"event":"page_overwritten"'));
    const installed = fs.readFileSync(file(w, 'Mage/page.md'));
    const lines = ledger(w).toString('utf8').trimEnd().split('\n');
    assert.equal(lines.length, 1);
    const record = JSON.parse(lines[0]);
    assert.equal(record.event, 'page_overwritten');
    assert.equal(record.page.content.digest, digest(installed));
    assert.equal(record.page.content.bytes, installed.length);
    const bad = world(true);
    for (const content of [
        '---\nwyrd_lineage: nope\n---\n',
        '---\nwyrd_lineage\n---\n',
        '---\nwyrd_lineage: {"schema":"wyrd.lineage/v1"}\n---\n',
        `---\nwyrd_lineage: ${JSON.stringify(oldProjection)}\nwyrd_lineage: ${JSON.stringify(oldProjection)}\n---\n`
    ]) {
        const refused = await overwritePage({ ...bad.request, content }, bad.options);
        assert.equal(refused.ok, false);
        assert.match(refused.reason, /^FRONTMATTER_/);
        assert.equal(fs.readFileSync(file(bad, 'Mage/page.md'), 'utf8'), 'old');
    }
    const off = world(false);
    const unchanged = '---\r\ntitle: Note\r\n---\r\nBody\r\n';
    const offResult = await overwritePage({ ...off.request, content: unchanged }, off.options);
    assert.equal(offResult.ok, true);
    assert.equal(fs.readFileSync(file(off, 'Mage/page.md'), 'utf8'), unchanged);
});

test('ST49-overwrite-internal-subtree', async () => {
    arm('ST49-overwrite-internal-subtree');
    const w = world();
    for (const path of ['.wyrd/scribe.json', '.WYRD\\lineage.jsonl', 'Mage/../.wyrd/x']) {
        const result = await overwritePage({ ...w.request, path }, {
            ...w.options, gate: { hashInGrant() { assert.fail('source or config IO'); } }
        });
        assert.equal(result.reason, 'OVERWRITE_INTERNAL_PATH');
    }
});

test('ST50-overwrite-refusal-disk-invariance', async () => {
    arm('ST50-overwrite-refusal-disk-invariance');
    const w = world(true);
    const before = snapshot(w);
    const cases = [
        { ...w.request, expectedSha256: digest('wrong') },
        { ...w.request, path: 'Mage/missing.md' },
        { ...w.request, path: 'Arc/no.md' },
        { ...w.request, path: '.wyrd/scribe.json' },
        { ...w.request, derivedFrom: [{ source: '../outside/x', spans: [{ quote: 'x' }] }] },
        { ...w.request, content: '---\nwyrd_lineage: broken\n---\n' }
    ];
    for (const request of cases) {
        const result = await overwritePage(request, w.options);
        assert.equal(result.ok, false);
        assert.deepEqual(snapshot(w), before, JSON.stringify(result));
    }
    const uninitialised = world();
    fs.rmSync(file(uninitialised, '.wyrd/scribe.json'));
    const beforeUninitialised = snapshot(uninitialised);
    for (const request of [
        { ...uninitialised.request, expectedSha256: digest('wrong') },
        { ...uninitialised.request, path: 'Mage/missing.md' }
    ]) {
        const result = await overwritePage(request, uninitialised.options);
        assert.equal(result.ok, false);
        assert.deepEqual(snapshot(uninitialised), beforeUninitialised,
            'precondition refusal must not mint config or change a directory');
    }
});

test('ST51-overwrite-resolved-protected-namespaces', async t => {
    arm('ST51-overwrite-resolved-protected-namespaces');
    if (process.platform !== 'win32') {
        t.diagnostic('Win32 trailing-dot, trailing-space and junction spellings require Windows');
        return;
    }
    const w = world();
    fs.rmSync(file(w, '.wyrd/scribe.json'));
    fs.writeFileSync(file(w, 'Arc/existing.md'), 'old');
    fs.writeFileSync(file(w, '.wyrd/existing.md'), 'old');
    fs.symlinkSync(file(w, 'Arc'), file(w, 'AliasArc'), 'junction');
    fs.symlinkSync(file(w, '.wyrd'), file(w, 'AliasWyrd'), 'junction');
    const before = fs.readdirSync(file(w, '.wyrd')).sort();
    const screenedGate = {
        disclosedRoot: () => w.gate.disclosedRoot(),
        probeInGrant: request => {
            assert.equal(request.includes('existing.md'), false,
                'protected target metadata must not be probed before the namespace screen');
            return w.gate.probeInGrant(request);
        },
        hashInGrant: () => assert.fail('protected target bytes were hashed before refusal'),
        readFileInGrant: () => assert.fail('source or config bytes were read before refusal'),
        createFileInGrant: () => assert.fail('config was created before refusal'),
        overwriteFileInGrant: () => assert.fail('protected target reached the overwrite fence')
    };
    for (const [target, reason] of [
        ['AliasArc/existing.md', 'ARC_IMMUTABLE'],
        ['AliasWyrd/existing.md', 'OVERWRITE_INTERNAL_PATH'],
        ['Arc./existing.md', 'ARC_IMMUTABLE'],
        ['Arc /existing.md', 'ARC_IMMUTABLE'],
        ['aRc\\existing.md', 'ARC_IMMUTABLE'],
        ['Mage/../Arc./existing.md', 'ARC_IMMUTABLE'],
        ['.wyrd./existing.md', 'OVERWRITE_INTERNAL_PATH'],
        ['.wyrd /existing.md', 'OVERWRITE_INTERNAL_PATH'],
    ]) {
        const result = await overwritePage({ ...w.request, path: target },
            { ...w.options, gate: screenedGate });
        assert.deepEqual(fs.readdirSync(file(w, '.wyrd')).sort(), before,
            target + ' must not mint config or ledger');
        assert.equal(result.reason, reason, target + ': ' + JSON.stringify(result));
    }
});

test('ST52-write-page-arc-alias-characterization', async t => {
    arm('ST52-write-page-arc-alias-characterization');
    if (process.platform !== 'win32') {
        t.diagnostic('junction alias reproduction requires Windows');
        return;
    }
    const w = world();
    fs.rmSync(file(w, '.wyrd/scribe.json'));
    fs.symlinkSync(file(w, 'Arc'), file(w, 'AliasArc'), 'junction');
    const result = await writePage({ path: 'AliasArc/new.md', content: 'new', derivedFrom: [] }, w.options);
    assert.equal(result.reason, 'PARENT_ALIAS', JSON.stringify(result));
    assert.equal(fs.existsSync(file(w, '.wyrd/scribe.json')), true,
        'tier A currently mints config before its fence detects the alias');
    assert.equal(fs.existsSync(file(w, 'Arc/new.md')), false);
});
