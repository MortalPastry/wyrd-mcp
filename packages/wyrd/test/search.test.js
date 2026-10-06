import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { RawMcpClient } from './raw-stdio.mjs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { createFsGate, isRefusal } from 'wyrd-fence';
import { createSearchEngine, LexicalScanBackend } from '../dist/search.js';
import { createServer } from '../dist/server.js';
import { declare as arm } from './manifest.mjs';
import { DEFAULT_OVERSIZED_BYTES, generateSearchVault, SCAN_WINDOW_BYTES } from '../scripts/search-fixture.mjs';

const temporaryBases = new Set();
process.once('exit', () => {
    for (const base of temporaryBases) fs.rmSync(base, { recursive: true, force: true });
});

function temporaryDirectory(prefix) {
    const base = fs.mkdtempSync(prefix);
    temporaryBases.add(base);
    return base;
}



function fixture(run, options = {}) {
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-search-'));
    const grant = path.join(base, 'grant');
    fs.mkdirSync(grant);
    const reads = [];
    const opens = [];
    const gate = createFsGate({ rawGrant: grant, primitives: {
        open: (target, flags) => { opens.push(target); return fs.openSync(target, flags); },
        read: (fd, buffer, offset, length, position) => {
            reads.push({ length, position });
            return fs.readSync(fd, buffer, offset, length, position);
        },
        placeholderAttributes: async target => options.unavailable ? null : ({
            attributes: options.placeholder === path.basename(target) ? 0x1000 : 0,
            reparseTag: 0
        }),
        lstat: target => {
            if (options.onStat) options.onStat(target, grant);
            return fs.lstatSync(target);
        },
        ...options.primitives
    } });
    assert.equal(isRefusal(gate), false);
    return Promise.resolve().then(() => run({ base, grant, gate, reads, opens }))
        .finally(() => fs.rmSync(base, { recursive: true, force: true }));
}

test('SR10-fresh-add-delete — each query enumerates the grant again', async () => {
    arm('SR10-fresh-add-delete');
    await fixture(async ({ grant, gate }) => {
        const search = createSearchEngine(gate);
        const first = await search('needle');
        assert.equal(first.state, 'zero_files_in_scope');
        fs.writeFileSync(path.join(grant, 'new.md'), 'needle here');
        assert.deepEqual((await search('needle')).hits.map(hit => hit.path), ['new.md']);
        fs.unlinkSync(path.join(grant, 'new.md'));
        assert.equal((await search('needle')).state, 'zero_files_in_scope');
    });
});

test('SR11-zero-maintenance-reads — warm scan uses metadata and one excerpt window', async () => {
    arm('SR11-zero-maintenance-reads');
    await fixture(async ({ grant, gate, reads }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'prefix needle suffix');
        const backend = new LexicalScanBackend();
        const search = createSearchEngine(gate, backend);
        await search('needle');
        reads.length = 0;
        const result = await search('needle');
        assert.equal(result.hits.length, 1);
        assert.equal(reads.length, 1, 'the unchanged cache must perform no scan reads');
        assert.ok(reads[0].length <= 1024, 'one bounded excerpt window');
        assert.equal(JSON.stringify([...backend.cache.values()]).includes('prefix needle suffix'), false);
        assert.deepEqual(Object.keys([...backend.cache.values()][0]).sort(), ['key', 'terms', 'typed']);
        assert.ok([...backend.cache.values()][0].terms.has('needle'));
    });
});

test('SR12-narrow-grant — frontmatter detects Mage without probing the parent', async () => {
    arm('SR12-narrow-grant');
    const touched = [];
    await fixture(async ({ grant, gate, base }) => {
        fs.writeFileSync(path.join(grant, 'alien.md'), '---\ntype: unfamiliar\n---\nneedle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.mage_detection, 'frontmatter');
        assert.equal(result.hits[0].layer, 'unclassified');
        assert.equal(result.hits[0].canonicity, 'unknown');
        assert.equal(touched.some(target => target === base), false, 'no parent stat');
    }, { onStat: target => touched.push(target) });
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'ordinary.md'), 'needle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.mage_detection, 'none');
        assert.equal(result.hits[0].layer, 'none');
    });
    await fixture(async ({ grant, gate }) => {
        for (const directory of ['Arc', 'Mage', 'Forum', 'Forum/Antechamber'])
            fs.mkdirSync(path.join(grant, directory), { recursive: true });
        for (const file of ['Arc/source.md', 'Mage/page.md', 'Forum/post.md',
            'Forum/Antechamber/draft.md', 'README.md'])
            fs.writeFileSync(path.join(grant, file), 'needle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.mage_detection, 'arc_sibling');
        const labels = Object.fromEntries(result.hits.map(hit => [hit.path, [hit.layer, hit.canonicity]]));
        assert.deepEqual(labels['Arc/source.md'], ['Arc', 'immutable source'], JSON.stringify(result));
        assert.deepEqual(labels['Mage/page.md'], ['Mage', 'agent-curated']);
        assert.deepEqual(labels['Forum/post.md'], ['Forum', 'non-canonical']);
        assert.deepEqual(labels['Forum/Antechamber/draft.md'], ['Forum', 'pre-canon draft']);
        assert.deepEqual(labels['README.md'], ['unclassified', 'unknown']);
    });
});

test('SR13-large-file-utf8 — bounded scan, byte anchor, excerpt and explicit eleventh hit', async () => {
    arm('SR13-large-file-utf8');
    await fixture(async ({ grant, gate, reads }) => {
        const text = 'é'.repeat(70_000) + ' needle 😀 tail';
        fs.writeFileSync(path.join(grant, 'large.md'), text);
        for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(grant, `note${i}.md`), 'needle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.hits.length, 10);
        assert.equal(result.truncated, true);
        const large = result.hits.find(hit => hit.path === 'large.md');
        assert.equal(large.byte_offset, Buffer.byteLength('é'.repeat(70_000) + ' '));
        assert.match(large.excerpt, /needle/);
        assert.equal([...large.excerpt].length <= 200, true);
        assert.equal(reads.every(read => read.length <= 64 * 1024), true);
        const exactTen = await fixture(async ({ grant: tenGrant, gate: tenGate }) => {
            for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(tenGrant, `${i}.md`), 'needle');
            return createSearchEngine(tenGate)('needle');
        });
        assert.equal(exactTen.hits.length, 10);
        assert.equal(exactTen.truncated, false);
    });
});

test('SR14-zero-files-vs-no-match — empty states and placeholder exclusion stay distinct', async t => {
    arm('SR14-zero-files-vs-no-match');
    await fixture(async ({ grant, gate, opens }) => {
        const search = createSearchEngine(gate);
        assert.equal((await search('needle')).state, 'zero_files_in_scope');
        fs.writeFileSync(path.join(grant, 'other.txt'), 'needle');
        assert.equal((await search('needle')).state, 'zero_searchable_files');
        fs.writeFileSync(path.join(grant, 'note.md'), 'haystack');
        assert.equal((await search('needle')).state, 'no_matches');
        fs.writeFileSync(path.join(grant, 'bad.md'), Buffer.from([0xff]));
        assert.equal((await search('needle')).searchable_files, 1, 'invalid UTF-8 was not searched');
        fs.writeFileSync(path.join(grant, 'extended.markdown'), 'needle');
        assert.deepEqual((await search('needle')).hits.map(hit => hit.path), ['extended.markdown']);
        assert.equal(opens.every(name => path.basename(name) !== 'other.txt'), true);
    });
    await fixture(async ({ grant, gate, opens }) => {
        fs.writeFileSync(path.join(grant, 'cloud.md'), 'needle');
        fs.writeFileSync(path.join(grant, 'local.md'), 'needle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.placeholder_count, 1);
        assert.equal(result.placeholder_fraction, 0.5);
        assert.equal(result.excluded_from_search, 1);
        assert.deepEqual(result.hits.map(hit => hit.path), ['local.md']);
        assert.equal(opens.some(name => path.basename(name) === 'cloud.md'), false);
    }, { placeholder: 'cloud.md' });
    await fixture(async ({ grant, gate, opens }) => {
        fs.writeFileSync(path.join(grant, 'unknown.md'), 'needle');
        const result = await createSearchEngine(gate)('needle');
        assert.equal(result.placeholder_detection, 'unavailable');
        assert.equal(result.placeholder_count, null);
        assert.equal(result.placeholder_fraction, null);
        assert.equal(result.excluded_from_search, null);
        if (process.platform === 'win32') {
            assert.equal(opens.length, 0, 'Windows refuses an unmeasured directory before content');
            assert.equal(result.state, 'scope_unavailable');
            t.diagnostic('Windows detector unavailable: search correctly held back');
        } else {
            assert.deepEqual(result.hits.map(hit => hit.path), ['unknown.md']);
            t.diagnostic('non-Windows detector unavailable: search proceeded with null counts');
        }
    }, { unavailable: true });
});

test('SR16-revalidate-excerpt — vanished and changed candidates produce no stale excerpt', async () => {
    arm('SR16-revalidate-excerpt');
    for (const change of ['delete', 'replace']) {
        await fixture(async ({ grant, gate, opens }) => {
            const name = path.join(grant, 'note.md');
            fs.writeFileSync(name, 'needle');
            const backend = { async search(snapshot) {
                const file = snapshot.files[0];
                if (change === 'delete') fs.unlinkSync(name);
                else fs.writeFileSync(name, 'a different size of text');
                return { candidates: [{ path: file.rel, byte_offset: 0, excerpt_start: 0,
                    version: { kind: 'stat', value: `${file.mtimeMs}:${file.size}` } }], hasMore: false, typed_files: 0, searched_files: 1 };
            } };
            const result = await createSearchEngine(gate, backend)('needle');
            assert.deepEqual(result.hits, []);
            assert.equal(opens.length, 0, `${change}: no stale content open`);
        });
    }
});

test('SR17-port-read-scope — backend reads stay within the searchable snapshot', async () => {
    arm('SR17-port-read-scope');
    await fixture(async ({ grant, gate, opens }) => {
        fs.writeFileSync(path.join(grant, 'page.md'), 'needle');
        fs.writeFileSync(path.join(grant, 'other.txt'), 'private');
        fs.writeFileSync(path.join(grant, 'cloud.md'), 'placeholder');
        const backend = { async search(snapshot, _query, reads) {
            assert.deepEqual(snapshot.files.map(file => file.rel), ['page.md']);
            assert.equal(await reads.read('other.txt', 0, 100), null);
            assert.equal(await reads.read('cloud.md', 0, 100), null);
            assert.equal(await reads.read('../outside.md', 0, 100), null);
            assert.equal(await reads.read('page.md', 0, 100_000), null);
            assert.equal((await reads.read('page.md', 0, 100)).bytes.toString(), 'needle');
            return { candidates: [], hasMore: false, typed_files: 0, searched_files: 1 };
        } };
        const result = await createSearchEngine(gate, backend)('needle');
        assert.equal(result.state, 'no_matches');
        assert.deepEqual(opens.map(name => path.basename(name)), ['page.md']);
    }, { placeholder: 'cloud.md' });
});

test('SR18-long-match-excerpt — long tokens fit before leading context is spent', async () => {
    arm('SR18-long-match-excerpt');
    await fixture(async ({ grant, gate, reads }) => {
        const longWord = 'n'.repeat(150);
        fs.writeFileSync(path.join(grant, 'long.md'), '😀'.repeat(100) + ' ' + longWord);
        const result = await createSearchEngine(gate)(longWord);
        assert.equal(result.hits.length, 1);
        assert.equal(result.hits[0].byte_offset, Buffer.byteLength('😀'.repeat(100) + ' '));
        assert.ok(result.hits[0].excerpt.includes(longWord), 'the entire long match must appear');
        assert.equal([...result.hits[0].excerpt].length, 200);
        assert.equal(reads.filter(read => read.length === 1024).length, 1, 'one excerpt read');
    });
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'short.md'), '😀'.repeat(80) + ' needle');
        const hit = (await createSearchEngine(gate)('needle')).hits[0];
        assert.equal(hit.byte_offset, Buffer.byteLength('😀'.repeat(80) + ' '));
        assert.ok(hit.excerpt.startsWith('😀'.repeat(80)), 'short match keeps leading context');
        assert.ok(hit.excerpt.includes('needle'));
    });
});

test('SR19-revalidated-truncation — only a valid eleventh candidate is withheld', async () => {
    arm('SR19-revalidated-truncation');
    for (const invalidated of [[], [10], [9, 10]]) {
        await fixture(async ({ grant, gate, reads }) => {
            for (let i = 0; i < 11; i++)
                fs.writeFileSync(path.join(grant, `${String(i).padStart(2, '0')}.md`), 'needle');
            const lexical = new LexicalScanBackend();
            await createSearchEngine(gate, lexical)('needle');
            reads.length = 0;
            const backend = { async search(snapshot, query, port) {
                const response = await lexical.search(snapshot, query, port);
                assert.equal(response.candidates.length, 11);
                for (const i of invalidated)
                    fs.unlinkSync(path.join(grant, `${String(i).padStart(2, '0')}.md`));
                return { ...response, hasMore: false };
            } };
            const result = await createSearchEngine(gate, backend)('needle');
            assert.equal(result.hits.length, 11 - invalidated.length > 10 ? 10 : 11 - invalidated.length);
            assert.equal(result.truncated, invalidated.length === 0);
            assert.equal(result.revalidation_dropped_count, invalidated.length);
            assert.equal(reads.length, result.hits.length, 'no excerpt read for withheld or invalid candidates');
        });
    }
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'one.md'), 'needle');
        const backend = { async search(snapshot) {
            const file = snapshot.files[0];
            return { candidates: [{ path: file.rel, byte_offset: 0, excerpt_start: 0,
                version: { kind: 'stat', value: `${file.mtimeMs}:${file.size}` } }], hasMore: true, typed_files: 0, searched_files: 1 };
        } };
        assert.equal((await createSearchEngine(gate, backend)('needle')).truncated, true);
    });
    await fixture(async ({ grant, gate }) => {
        for (let i = 0; i < 11; i++) fs.writeFileSync(path.join(grant, `${i}.md`), 'needle');
        const walk = await gate.walkGrant();
        const reads = {
            read: async (file, offset, bytes) => gate.readFileInGrant(file, offset, bytes),
            metadata: async file => gate.fileMetadataInGrant(file)
        };
        const response = await new LexicalScanBackend().search({ files: walk.files }, 'needle', reads);
        assert.equal(response.candidates.length, 11);
        assert.equal(response.hasMore, false, 'lexical backend reports no withheld candidates');
    });
});

function readCall(gate) {
    const handler = createServer({ fsgate: gate, transport: 'stdio' })._getRequestHandler('tools/call');
    return args => handler({ method: 'tools/call', params: { name: 'read', arguments: args } },
        { mcpReq: { requestState: () => undefined } });
}

test('SR31-read-observed-size — the header and truncation describe the file read', async t => {
    arm('SR31-read-observed-size');
    for (const [label, before, after, offset, limit, returned, truncated, lateSize] of [
        ['grow', 'old', 'replacement content', 0, 100, 'replacement content', false],
        ['shrink', 'stale larger content', 'new', 0, 100, 'new', false],
        ['page', 'old', 'new larger content', 1, 4, 'ew l', true],
        ['utf8', 'old', 'é😀tail', 0, 5, 'é', true],
        // The file shrinks after its bytes were returned: the size cannot fall below them.
        ['shrink-after-read', 'stale larger content', 'new', 8, 2, 'rg', false, 10]
    ]) {
        const late = lateSize !== undefined;
        let name;
        let reads = 0;
        await fixture(async ({ grant, gate }) => {
            name = path.join(grant, 'note.md');
            fs.writeFileSync(name, before);
            const result = await readCall(gate)({ path: 'note.md', offset, limit });
            t.diagnostic(label + ': ' + JSON.stringify(result));
            assert.equal(reads, 1, label + ': one interposed read');
            assert.equal(result.isError, undefined, label);
            assert.equal(result.content[1].text, returned, label);
            const next = offset + Buffer.byteLength(returned);
            assert.ok(result.content[0].text.includes(`bytes ${offset}..${next} of ${late ? lateSize : Buffer.byteLength(after)}`), label);
            assert.ok(result.content[0].text.includes(`truncated: ${truncated}`), label);
            assert.equal(result.content[0].text.includes(`next_offset: ${next}`), truncated, label);
        }, { primitives: {
            read(fd, buffer, offset, length, position) {
                reads++;
                if (!late) fs.writeFileSync(name, after);
                const count = fs.readSync(fd, buffer, offset, length, position);
                if (late) fs.writeFileSync(name, after);
                return count;
            }
        } });
    }
});

test('SR32-read-download-observation — opening cannot erase the download warning', async t => {
    arm('SR32-read-download-observation');
    for (const [label, before, after, downloaded] of [
        ['hydrated-on-open', true, false, true],
        ['placeholder-after-open', false, true, true],
        ['detection-lost-after-open', true, null, true],
        ['ordinary', false, false, false]
    ]) {
        let cloud = before;
        let opens = 0;
        await fixture(async ({ grant, gate }) => {
            fs.writeFileSync(path.join(grant, 'note.md'), 'downloaded text');
            const call = readCall(gate);
            if (before === true) {
                const blocked = await call({ path: 'note.md' });
                assert.equal(blocked.isError, true, label);
                assert.match(blocked.content[0].text, /reason: PLACEHOLDER/, label);
                assert.equal(opens, 0, label + ': default refusal must not open');
            }
            const result = await call({ path: 'note.md', hydrate: true });
            t.diagnostic(label + ': ' + JSON.stringify(result));
            assert.equal(opens, 1, label);
            assert.equal(result.isError, undefined, label);
            assert.equal(result.content[1].text, 'downloaded text', label);
            assert.equal(result.structuredContent.dehydrated, downloaded ? true : undefined, label);
            assert.equal(/This read downloaded a cloud placeholder\./.test(result.structuredContent.warning ?? ''), downloaded, label);
            assert.equal(result.structuredContent.placeholder_count, after === null ? null : Number(before), label);
            assert.equal(result.structuredContent.file_count, after === null ? null : 1, label);
            assert.equal(result.structuredContent.placeholder_fraction, after === null ? null : Number(before), label);
            assert.equal(result.structuredContent.placeholder_detection, after === null ? 'unavailable' : 'available', label);
        }, { primitives: {
            open(target, flags) {
                opens++;
                cloud = after;
                return fs.openSync(target, flags);
            },
            placeholderAttributes: async target => path.basename(target) !== 'note.md'
                ? { attributes: 0, reparseTag: 0 }
                : cloud === null ? null : ({ attributes: cloud ? 0x1000 : 0, reparseTag: 0 })
        } });
    }
});

test('SR30-revalidation-dropped-count — changed or unreadable candidates cannot claim no matches', async t => {
    arm('SR30-revalidation-dropped-count');
    for (const change of ['replace', 'delete', 'snapshot-key', 'before-refusal', 'before-placeholder',
        'read-refusal', 'slice-size', 'after-replace', 'after-refusal', 'after-placeholder', 'invalid-utf8', 'mixed']) {
        await fixture(async ({ grant, gate }) => {
            const name = path.join(grant, 'note.md');
            fs.writeFileSync(name, 'needle');
            if (change === 'mixed') fs.writeFileSync(path.join(grant, 'survivor.md'), 'needle');
            let revalidating = false;
            let metadataCalls = 0;
            const refusal = { ok: false, reason: 'IO_ERROR', detail: 'injected unreadability' };
            const fenced = {
                walkGrant: () => gate.walkGrant(),
                probeInGrant: target => gate.probeInGrant(target),
                async fileMetadataInGrant(target) {
                    if (!revalidating || target !== 'note.md') return gate.fileMetadataInGrant(target);
                    const stage = ++metadataCalls === 1 ? 'before' : 'after';
                    if (change === stage + '-refusal') return refusal;
                    const metadata = await gate.fileMetadataInGrant(target);
                    if (change === stage + '-placeholder') return { ...metadata, dehydrated: true };
                    return metadata;
                },
                async readFileInGrant(target, offset, bytes) {
                    if (!revalidating || target !== 'note.md') return gate.readFileInGrant(target, offset, bytes);
                    if (change === 'read-refusal') return refusal;
                    const slice = await gate.readFileInGrant(target, offset, bytes);
                    if (change === 'after-replace') fs.writeFileSync(name, 'a different size of text');
                    if (change === 'slice-size') return { ...slice, size: slice.size + 1 };
                    if (change === 'invalid-utf8') return { ...slice, bytes: Buffer.from([0xff]) };
                    return slice;
                }
            };
            const lexical = new LexicalScanBackend();
            const backend = { async search(snapshot, query, port) {
                const response = await lexical.search(snapshot, query, port);
                assert.equal(response.candidates.length, change === 'mixed' ? 2 : 1, 'the backend found real matches');
                revalidating = true;
                if (change === 'delete') fs.unlinkSync(name);
                if (change === 'replace' || change === 'mixed') fs.writeFileSync(name, 'a different size of text');
                if (change === 'snapshot-key') return { ...response,
                    candidates: response.candidates.map(candidate => ({ ...candidate, version: { kind: 'stat', value: 'stale' } })) };
                return response;
            } };
            const result = await createSearchEngine(fenced, backend)('needle');
            if (change === 'replace') t.diagnostic(JSON.stringify(result));
            assert.deepEqual(result.hits.map(hit => hit.path), change === 'mixed' ? ['survivor.md'] : [], change);
            assert.equal(result.files_in_scope, change === 'mixed' ? 2 : 1, change);
            assert.equal(result.searchable_files, change === 'mixed' ? 2 : 1, change);
            assert.equal(result.inaccessible_count, 0, change + ': walk count stays unchanged');
            assert.equal(result.placeholder_count, 0, change + ': walk count stays unchanged');
            assert.equal(result.truncated, false, change);
            assert.equal(result.state, change === 'mixed' ? 'matches' : 'search_coverage_unavailable', change);
            assert.equal(result.revalidation_dropped_count, 1, change);
        });
    }
    await fixture(async ({ grant, gate }) => {
        const search = createSearchEngine(gate);
        let result = await search('needle');
        assert.equal(result.state, 'zero_files_in_scope');
        assert.equal(result.revalidation_dropped_count, 0);
        fs.writeFileSync(path.join(grant, 'other.txt'), 'needle');
        result = await search('needle');
        assert.equal(result.state, 'zero_searchable_files');
        assert.equal(result.revalidation_dropped_count, 0);
        fs.writeFileSync(path.join(grant, 'note.md'), 'haystack');
        result = await search('needle');
        assert.equal(result.state, 'no_matches');
        assert.equal(result.revalidation_dropped_count, 0);
        result = await search('haystack');
        assert.equal(result.state, 'matches');
        assert.equal(result.revalidation_dropped_count, 0);
    });
});

test('SR20-cost-structure — deterministic oversized vault and bounded warm reads', async () => {
    arm('SR20-cost-structure');
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-cost-arm-'));
    const first = path.join(base, 'first');
    const second = path.join(base, 'second');
    const oversizedBytes = 1024 * 1024 + 17;
    assert.ok(DEFAULT_OVERSIZED_BYTES > 50_000_000, 'full fixture exceeds the RSS budget');
    const files = root => {
        const walk = dir => fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
            const full = path.join(dir, entry.name);
            return entry.isDirectory() ? walk(full) : [path.relative(root, full).split(path.sep).join('/')];
        });
        return walk(root).sort();
    };
    try {
        const a = generateSearchVault(first, { count: 24, oversizedBytes });
        const b = generateSearchVault(second, { count: 24, oversizedBytes });
        assert.deepEqual(a, b);
        const names = files(first);
        assert.deepEqual(names, files(second));
        assert.equal(names.length, 24);
        assert.equal(fs.statSync(path.join(first, ...a.oversizedRelative.split('/'))).size, oversizedBytes);
        assert.ok(oversizedBytes > SCAN_WINDOW_BYTES * 8);
        assert.ok(names.some(name => name.startsWith('Arc/')) && names.some(name => name.startsWith('Mage/')) &&
            names.some(name => name.startsWith('Forum/')) && names.some(name => name.split('/').length > 2));
        for (const name of names) {
            const digest = root => createHash('sha256').update(fs.readFileSync(path.join(root, ...name.split('/')))).digest('hex');
            assert.equal(digest(first), digest(second), `${name}: same seed must write same bytes`);
        }
        const ordinary = names.filter(name => name !== a.oversizedRelative)
            .map(name => fs.readFileSync(path.join(first, ...name.split('/')), 'utf8'));
        assert.ok(ordinary.some(text => /---\ntype: note/.test(text)));
        assert.ok(ordinary.some(text => /café|naïve|東京/.test(text)));

        const reads = [];
        const fds = new Map();
        const gate = createFsGate({ rawGrant: first, primitives: {
            open: (target, flags) => { const fd = fs.openSync(target, flags); fds.set(fd, target); return fd; },
            read: (fd, buffer, offset, length, position) => {
                reads.push({ file: fds.get(fd), length, position });
                return fs.readSync(fd, buffer, offset, length, position);
            },
            placeholderAttributes: async () => ({ attributes: 0, reparseTag: 0 })
        } });
        assert.equal(isRefusal(gate), false);
        const backend = new LexicalScanBackend();
        const search = createSearchEngine(gate, backend);
        await search('needle');
        assert.ok(reads.filter(read => read.file.endsWith('oversized.md')).length > 8,
            'the cold scan reads the oversized file in windows');
        assert.ok(reads.every(read => read.length <= SCAN_WINDOW_BYTES));
        for (const cached of backend.cache.values()) {
            assert.deepEqual(Object.keys(cached).sort(), ['key', 'terms', 'typed']);
            assert.ok(cached.terms instanceof Map);
            for (const [term, anchor] of cached.terms) {
                assert.match(term, /^[\p{L}\p{N}_]+$/u, 'cache keys are terms, not source passages');
                assert.deepEqual(Object.keys(anchor).sort(), ['byte_offset', 'excerpt_start']);
                assert.ok(Number.isSafeInteger(anchor.byte_offset));
                assert.ok(Number.isSafeInteger(anchor.excerpt_start));
            }
        }
        reads.length = 0;
        const warm = await search('needle');
        assert.ok(warm.hits.length > 0);
        assert.equal(reads.length, warm.hits.length, 'one on-demand excerpt read for each returned hit');
        assert.ok(reads.length <= 10);
        assert.ok(reads.every(read => read.length <= 1024), 'no warm index maintenance or unbounded excerpt read');
        const perFile = new Map();
        for (const read of reads) perFile.set(read.file, (perFile.get(read.file) ?? 0) + 1);
        assert.ok([...perFile.values()].every(count => count <= 1), 'at most one bounded read per hit');

        const measuredVault = path.join(base, 'measured');
        const measurement = spawnSync(process.execPath,
            ['scripts/measure-search.mjs', '--vault', measuredVault, '--count', '24',
                '--oversized-bytes', String(oversizedBytes)],
            { cwd: fileURLToPath(new URL('../', import.meta.url)), encoding: 'utf8' });
        assert.equal(measurement.status, 0, JSON.stringify({ stderr: measurement.stderr,
            signal: measurement.signal, error: measurement.error?.message }));
        assert.match(measurement.stdout, /Cold first query: .*re-ruled < 5000 ms/);
        assert.match(measurement.stdout, /Warm median: .*re-ruled < 500 ms/);
        assert.match(measurement.stdout, /Observed server peak RSS: .*re-ruled < 100 MB/);
        assert.equal(fs.existsSync(measuredVault), false, 'measurement removes its generated vault');
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
});

test('SR21-mixed-anchor-parity — ASCII and Unicode scans keep legacy byte anchors', async () => {
    arm('SR21-mixed-anchor-parity');
    await fixture(async ({ grant, gate }) => {
        const content = 'a '.repeat(32768) + 'x '.repeat(120) +
            'café needle 東京 atlas\n' + 'y '.repeat(110) + 'naïve needle';
        fs.writeFileSync(path.join(grant, 'mixed.md'), content);
        const expected = new Map();
        const recent = [];
        let offset = 0, token = '', start = 0, leading = [], codepoints = 0, overflow = false;
        const finish = () => {
            if (token && !overflow) {
                const context = Math.min(leading.length, Math.max(0, 200 - codepoints));
                const key = token.normalize('NFKC').toLowerCase();
                if (!expected.has(key)) expected.set(key, {
                    byte_offset: start, excerpt_start: leading[leading.length - context] ?? start
                });
            }
            token = ''; codepoints = 0; overflow = false;
        };
        for (const point of content) {
            if (/[\p{L}\p{N}_]/u.test(point)) {
                if (!token && !overflow) { start = offset; leading = recent.slice(); }
                codepoints++;
                if (token.length < 256) token += point; else overflow = true;
            } else finish();
            recent.push(offset);
            if (recent.length > 100) recent.shift();
            offset += Buffer.byteLength(point);
        }
        finish();
        const walk = await gate.walkGrant();
        const reads = {
            read: (file, at, bytes) => gate.readFileInGrant(file, at, bytes),
            metadata: file => gate.fileMetadataInGrant(file)
        };
        const backend = new LexicalScanBackend();
        for (const term of ['a', 'x', 'café', 'needle', '東京', 'atlas', 'naïve']) {
            const result = await backend.search({ files: walk.files }, term, reads);
            assert.equal(result.candidates.length, 1, term);
            const { byte_offset, excerpt_start } = result.candidates[0];
            assert.deepEqual({ byte_offset, excerpt_start }, expected.get(term), term);
        }
    });
});

const readerEntry = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist/index.js');
async function wire(grant, run) {
    const client = new RawMcpClient({ entrypoint: readerEntry, entrypointLabel: 'dist/index.js',
        env: { ...process.env, WYRD_GRANT: grant }, clientInfo: { name: 'search-wire-test', version: '1' } });
    try { await client.connect(); return await run(client); } finally { await client.close(); }
}

test('SR23-search-wire-shape — search returns contextual measured hits over stdio', async () => {
    arm('SR23-search-wire-shape');
    await fixture(async ({ grant }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'prefix context needle trailing context');
        await wire(grant, async client => {
            assert.deepEqual((await client.listTools()).tools.map(tool => tool.name), ['read', 'search']);
            const response = await client.callTool({ name: 'search', arguments: { query: 'needle' } });
            assert.equal(response.isError, undefined);
            const result = response.structuredContent;
            assert.equal(result.state, 'matches');
            assert.equal(result.truncated, false);
            assert.equal(result.hits.length, 1);
            assert.deepEqual(result.hits[0], { path: 'note.md', size: 38, layer: 'none',
                canonicity: 'unknown', excerpt: 'prefix context needle trailing context', byte_offset: 15 });
            assert.equal(result.revalidation_dropped_count, 0);
            assert.equal(result.searchable_files, 1);
            assert.equal(result.files_in_scope, 1);
            assert.ok(Array.isArray(result.warnings));
            for (const query of ['', 42, 'x'.repeat(257)]) {
                const bad = await client.callTool({ name: 'search', arguments: { query } });
                assert.equal(bad.isError, true);
                assert.match(bad.content[0].text, /^wyrd refused this search\.\nreason: BAD_INPUT\n/);
            }
        });
    });
});

test('SR24-cap-and-truncation — wire distinguishes ten hits from eleven', async () => {
    arm('SR24-cap-and-truncation');
    await fixture(async ({ grant }) => {
        for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(grant, `page-${i}.md`), 'needle');
        await wire(grant, async client => {
            const search = async () => (await client.callTool({ name: 'search', arguments: { query: 'needle' } })).structuredContent;
            let result = await search();
            assert.equal(result.hits.length, 10);
            assert.equal(result.truncated, false);
            fs.writeFileSync(path.join(grant, 'page-10.md'), 'needle');
            result = await search();
            assert.equal(result.hits.length, 10);
            assert.equal(result.truncated, true);
        });
    });
});

test('SR25-no-outside-result — a junction alias and sibling cannot escape the grant', async () => {
    arm('SR25-no-outside-result');
    await fixture(async ({ grant, base }) => {
        fs.writeFileSync(path.join(grant, 'inside.md'), 'needle');
        const outside = path.join(base, 'outside');
        fs.mkdirSync(outside); fs.writeFileSync(path.join(outside, 'secret.md'), 'needle');
        const alias = path.join(grant, 'alias');
        fs.symlinkSync(outside, alias, 'junction');
        try {
            await wire(grant, async client => {
                const result = (await client.callTool({ name: 'search', arguments: { query: 'needle' } })).structuredContent;
                assert.deepEqual(result.hits.map(hit => hit.path), ['inside.md']);
                const pass = await client.callTool({ name: 'read', arguments: { path: 'inside.md' } });
                assert.equal(pass.isError, undefined);
                const refused = await client.callTool({ name: 'read', arguments: { path: '../outside/secret.md' } });
                assert.equal(refused.isError, true);
            });
        } finally { fs.unlinkSync(alias); }
    });
});

test('SR26-disclosure — wire names both tools and the term-only cache', async () => {
    arm('SR26-disclosure');
    await fixture(async ({ grant }) => wire(grant, async client => {
        const instructions = client.getInstructions();
        assert.match(instructions, /tools are `read` and `search`; both are read-only/);
        assert.match(instructions, /lazy in-memory cache of normalized terms and anchors/);
        assert.match(instructions, /holds no raw/);
        assert.match(instructions, /writes no search data to disk/);
        const tool = (await client.listTools()).tools.find(item => item.name === 'search');
        assert.equal(tool.annotations.readOnlyHint, true);
        assert.match(tool.description, /Markdown files in the granted folder/);
    }));
});

test('SR28-hardlink-search-limit — outside Markdown is searchable through an in-grant hard link, the documented limit', async t => {
    arm('SR28-hardlink-search-limit');
    await fixture(async ({ grant, base }) => {
        const content = 'outside hard-link sentinel needle with context';
        const outside = path.join(base, 'outside.md');
        fs.writeFileSync(outside, content);
        const linked = path.join(grant, 'linked.md');
        try { fs.linkSync(outside, linked); }
        catch (error) {
            t.diagnostic('hard link unavailable: ' + (error.code ?? error.message));
            if (['win32', 'darwin', 'linux'].includes(process.platform)) throw error;
            return;
        }
        assert.equal(fs.lstatSync(linked).isSymbolicLink(), false);
        await wire(grant, async client => {
            const response = await client.callTool({ name: 'search', arguments: { query: 'needle' } });
            assert.equal(response.isError, undefined);
            const result = response.structuredContent;
            assert.equal(result.state, 'matches');
            assert.equal(result.hits.length, 1);
            assert.equal(result.hits[0].path, 'linked.md');
            assert.equal(result.hits[0].size, fs.statSync(outside).size);
            assert.match(result.hits[0].excerpt, /outside hard-link sentinel needle with context/);
            const read = await client.callTool({ name: 'read', arguments: { path: 'linked.md' } });
            assert.equal(read.isError, undefined);
            assert.equal(read.content[1].text, content);
        });
    });
});

const handBackend = make => ({ async search(snapshot, query, reads) {
    return { candidates: await make(snapshot, reads, query), hasMore: false,
        typed_files: 0, searched_files: snapshot.files.length };
} });
const shaVersion = text => ({ kind: 'sha256', value: createHash('sha256').update(text).digest('hex') });
const passage = (file, version, extra = {}) => ({ path: file.rel, byte_offset: 0,
    excerpt_start: 0, version, ...extra });
const expectDropped = result => {
    assert.deepEqual(result.hits, []);
    assert.equal(result.revalidation_dropped_count, 1);
    assert.equal(result.state, 'search_coverage_unavailable');
};

test('SR33-sha256-hit — byte hashes accept passages without changing hit fields', async () => {
    arm('SR33-sha256-hit');
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), '');
        expectDropped(await createSearchEngine(gate, handBackend(({ files }) =>
            [passage(files[0], shaVersion(''))]))('needle'));
    });
    for (const text of ['needle', 'é needle 😀']) await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), text);
        const backend = handBackend(({ files }) => [passage(files[0], shaVersion(text),
            text ? { source_range_end: Buffer.byteLength(text) } : {})]);
        const result = await createSearchEngine(gate, backend)('needle');
        assert.equal(result.hits.length, 1);
        assert.equal(result.revalidation_dropped_count, 0);
        assert.equal(result.hits[0].excerpt, text);
        assert.deepEqual(Object.keys(result.hits[0]).sort(),
            ['byte_offset', 'canonicity', 'excerpt', 'layer', 'path', 'size']);
    });
});

test('SR34-sha256-mismatch — each candidate compares its own hash', async () => {
    arm('SR34-sha256-mismatch');
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        const backend = handBackend(({ files }) => [passage(files[0], shaVersion('wrong'))]);
        expectDropped(await createSearchEngine(gate, backend)('needle'));
        const mixed = handBackend(({ files }) => [passage(files[0], shaVersion('needle')),
            passage(files[0], shaVersion('wrong'))]);
        const result = await createSearchEngine(gate, mixed)('needle');
        assert.equal(result.hits.length, 1);
        assert.equal(result.revalidation_dropped_count, 1);
    });
});

test('SR35-sha256-backend-change — revalidation observes changes after the answer', async () => {
    arm('SR35-sha256-backend-change');
    for (const change of ['delete', 'bytes', 'metadata', 'transient-metadata']) await fixture(async ({ grant, gate }) => {
        const name = path.join(grant, 'note.md');
        fs.writeFileSync(name, 'needle');
        fs.utimesSync(name, new Date(1700000000000), new Date(1700000000000));
        const backend = handBackend(({ files }) => {
            if (change === 'delete') fs.unlinkSync(name);
            if (change === 'bytes') fs.writeFileSync(name, 'new content');
            if (change === 'metadata' || change === 'transient-metadata') fs.utimesSync(name, new Date(), new Date(files[0].mtimeMs + 5000));
            return [passage(files[0], shaVersion('needle'))];
        });
        let restored = false;
        const fenced = { ...gate, async fileMetadataInGrant(rel) {
            const observed = await gate.fileMetadataInGrant(rel);
            if (change === 'transient-metadata' && !restored) {
                restored = true;
                fs.utimesSync(name, new Date(), new Date(observed.mtimeMs - 5000));
            }
            return observed;
        } };
        expectDropped(await createSearchEngine(fenced, backend)('needle'));
    });
});

test('SR36-sha256-one-pass — bounded hashing is shared only within a query', async () => {
    arm('SR36-sha256-one-pass');
    await fixture(async ({ grant, gate }) => {
        const text = 'é'.repeat(32767) + '😀 needle ' + 'x'.repeat(65540);
        fs.writeFileSync(path.join(grant, 'note.md'), text);
        let hashReads = 0;
        const fenced = { ...gate, async readFileInGrant(name, offset, bytes) {
            assert.ok(bytes <= SCAN_WINDOW_BYTES);
            if (bytes === SCAN_WINDOW_BYTES) hashReads++;
            return gate.readFileInGrant(name, offset, bytes);
        } };
        const backend = handBackend(({ files }) => [passage(files[0], shaVersion(text)),
            passage(files[0], shaVersion(text), { byte_offset: 65539, excerpt_start: 65538,
                source_range_end: 65545 })]);
        const search = createSearchEngine(fenced, backend);
        for (let query = 1; query <= 2; query++) {
            const result = await search('needle');
            assert.equal(result.hits.length, 2);
            assert.equal(result.revalidation_dropped_count, 0);
            assert.equal(hashReads, 3 * query, 'one three-window hash per query');
        }
    });
});

test('SR37-malformed-version — invalid declarations are dropped and counted', async t => {
    arm('SR37-malformed-version');
    const versions = [undefined, null, { kind: 'other', value: shaVersion('needle').value },
        { kind: 'stat', value: 123 }, { kind: 'sha256', value: 123 },
        { kind: 'sha256', value: 'a'.repeat(63) }, { kind: 'sha256', value: 'a'.repeat(65) },
        { kind: 'sha256', value: 'a'.repeat(64) + '\n' },
        { kind: 'sha256', value: 'A'.repeat(64) }, { kind: 'sha256', value: 'g'.repeat(64) }];
    for (const version of versions) await fixture(async ({ grant, gate, opens }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        t.diagnostic(JSON.stringify(version) ?? 'missing version');
        const backend = handBackend(({ files }) => [passage(files[0], version)]);
        expectDropped(await createSearchEngine(gate, backend)('needle'));
        assert.equal(opens.length, 0, 'malformed versions must not open content');
    });
});

test('SR38-source-range — every invalid exclusive range is dropped and counted', async t => {
    arm('SR38-source-range');
    const ranges = [
        { source_range_end: 1.5 }, { source_range_end: Number.MAX_SAFE_INTEGER + 1 },
        { source_range_end: NaN }, { source_range_end: Infinity }, { source_range_end: '6' },
        { source_range_end: null }, { source_range_end: 0 }, { source_range_end: -1 },
        { byte_offset: 2, source_range_end: 2 }, { byte_offset: 3, source_range_end: 2 },
        { source_range_end: 7 }, { excerpt_start: 1, source_range_end: 6 }
    ];
    for (const extra of ranges) await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        t.diagnostic(JSON.stringify(extra));
        const backend = handBackend(({ files }) => [passage(files[0], shaVersion('needle'), extra)]);
        expectDropped(await createSearchEngine(gate, backend)('needle'));
    });
});

test('SR39-sha256-window-refusal — failed, resized and stalled hash windows fail closed', async () => {
    arm('SR39-sha256-window-refusal');
    for (const fault of ['refused', 'size', 'stalled']) await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        const fenced = { ...gate, async readFileInGrant(name, offset, bytes) {
            const slice = await gate.readFileInGrant(name, offset, bytes);
            if (bytes !== SCAN_WINDOW_BYTES) return slice;
            if (fault === 'refused') return { ok: false, reason: 'NOT_FOUND' };
            if (fault === 'size') return { ...slice, size: slice.size + 1 };
            return { ...slice, nextOffset: offset };
        } };
        const backend = handBackend(({ files }) => [passage(files[0], shaVersion('')),
            passage(files[0], shaVersion('needle'))]);
        const result = await createSearchEngine(fenced, backend)('needle');
        assert.deepEqual(result.hits, []);
        assert.equal(result.revalidation_dropped_count, 2);
    });
});

test('SR40-sha256-read-change — metadata revalidates captured excerpts including reuse', async () => {
    arm('SR40-sha256-read-change');
    for (const phase of [3, 5]) await fixture(async ({ grant, gate }) => {
        const name = path.join(grant, 'note.md');
        fs.writeFileSync(name, 'needle');
        let observations = 0;
        const fenced = { ...gate, async fileMetadataInGrant(rel) {
            if (++observations === phase) {
                const stat = fs.statSync(name);
                fs.utimesSync(name, stat.atime, new Date(stat.mtimeMs + 5000));
            }
            return gate.fileMetadataInGrant(rel);
        } };
        const backend = handBackend(({ files }) => Array.from({ length: phase === 5 ? 2 : 1 },
            () => passage(files[0], shaVersion('needle'))));
        const result = await createSearchEngine(fenced, backend)('needle');
        assert.equal(result.hits.length, phase === 5 ? 1 : 0);
        assert.equal(result.revalidation_dropped_count, 1);
    });
});

test('SR41-sha256-snapshot-scope — hashing cannot open files outside the searchable snapshot', async () => {
    arm('SR41-sha256-snapshot-scope');
    for (const rel of ['other.txt', '../outside.md', 'absent.md']) await fixture(async ({ grant, gate, opens }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        fs.writeFileSync(path.join(grant, 'other.txt'), 'needle');
        const backend = handBackend(() => [{ path: rel, byte_offset: 0, excerpt_start: 0, version: shaVersion('needle') }]);
        expectDropped(await createSearchEngine(gate, backend)('needle'));
        assert.equal(opens.length, 0);
    });
});

test('SR42-stat-version — declared stat candidates retain lexical behavior', async () => {
    arm('SR42-stat-version');
    await fixture(async ({ grant, gate }) => {
        fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
        const backend = handBackend(({ files }) => [passage(files[0],
            { kind: 'stat', value: `${files[0].mtimeMs}:${files[0].size}` })]);
        const result = await createSearchEngine(gate, backend)('needle');
        const lexical = await createSearchEngine(gate)('needle');
        assert.deepEqual(result, lexical);
        const walk = await gate.walkGrant();
        const response = await new LexicalScanBackend().search({ files: walk.files }, 'needle', {
            read: (...args) => gate.readFileInGrant(...args), metadata: rel => gate.fileMetadataInGrant(rel)
        });
        assert.deepEqual(response.candidates[0], passage(walk.files[0],
            { kind: 'stat', value: `${walk.files[0].mtimeMs}:${walk.files[0].size}` }));
    });
});

test('SR43-sha256-withheld-change — a changing eleventh hash cannot declare truncation', async () => {
    arm('SR43-sha256-withheld-change');
    await fixture(async ({ grant, gate }) => {
        for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(grant, `${i}.md`), 'needle');
        const name = path.join(grant, 'z.md');
        fs.writeFileSync(name, 'needle');
        fs.utimesSync(name, new Date(1700000000000), new Date(1700000000000));
        let restoreMtime = null;
        const fenced = { ...gate, async fileMetadataInGrant(rel) {
            const observed = await gate.fileMetadataInGrant(rel);
            if (restoreMtime !== null && rel === 'z.md') {
                fs.utimesSync(name, new Date(), new Date(restoreMtime));
                restoreMtime = null;
            }
            return observed;
        }, async readFileInGrant(rel, offset, bytes) {
            const slice = await gate.readFileInGrant(rel, offset, bytes);
            if (rel === 'z.md' && bytes === SCAN_WINDOW_BYTES) {
                const stat = fs.statSync(name);
                restoreMtime = stat.mtimeMs;
                fs.utimesSync(name, stat.atime, new Date(stat.mtimeMs + 5000));
            }
            return slice;
        } };
        const backend = handBackend(({ files }) => files.map(file => passage(file,
            file.rel === 'z.md' ? shaVersion('needle') : { kind: 'stat', value: `${file.mtimeMs}:${file.size}` })));
        const result = await createSearchEngine(fenced, backend)('needle');
        assert.equal(result.hits.length, 10);
        assert.equal(result.truncated, false);
        assert.equal(result.revalidation_dropped_count, 1);
    });
});

test('SR44-sha256-same-stat-swap — excerpts come from the hashed bytes', async () => {
    arm('SR44-sha256-same-stat-swap');
    await fixture(async ({ grant, gate }) => {
        const name = path.join(grant, 'note.md');
        const text = 'a'.repeat(65530) + 'needle old tail';
        const replacement = 'b'.repeat(65530) + 'needle new tail';
        fs.writeFileSync(name, text);
        fs.utimesSync(name, new Date(1700000000000), new Date(1700000000000));
        let swapped = false;
        const fenced = { ...gate, async readFileInGrant(rel, offset, bytes) {
            const slice = await gate.readFileInGrant(rel, offset, bytes);
            if (!swapped && bytes === SCAN_WINDOW_BYTES && slice.nextOffset === Buffer.byteLength(text)) {
                const stat = fs.statSync(name);
                fs.writeFileSync(name, replacement);
                fs.utimesSync(name, stat.atime, stat.mtime);
                assert.equal(fs.statSync(name).mtimeMs, stat.mtimeMs);
                assert.equal(fs.statSync(name).size, stat.size);
                swapped = true;
            }
            return slice;
        } };
        const result = await createSearchEngine(fenced, handBackend(({ files }) =>
            [passage(files[0], shaVersion(text), { byte_offset: 65530, excerpt_start: 65528 })]))('needle');
        assert.equal(swapped, true);
        assert.equal(result.hits.length, 1);
        assert.equal(result.hits[0].excerpt, text.slice(65528));
    });
});

test('SR45-candidate-anchors — every candidate validates both numeric anchors', async t => {
    arm('SR45-candidate-anchors');
    const invalid = [
        { byte_offset: -1 }, { byte_offset: 6 }, { byte_offset: 7 },
        { byte_offset: 0.5 }, { byte_offset: Number.MAX_SAFE_INTEGER + 1 },
        { byte_offset: NaN }, { byte_offset: Infinity }, { byte_offset: '0' }, { byte_offset: null },
        { excerpt_start: -1 }, { excerpt_start: 0.5 }, { excerpt_start: NaN },
        { excerpt_start: Infinity }, { excerpt_start: Number.MAX_SAFE_INTEGER + 1 },
        { excerpt_start: '0' }, { excerpt_start: null }, { excerpt_start: 1 }
    ];
    for (const kind of ['stat', 'sha256']) for (const ranged of [false, true])
        for (const extra of invalid) await fixture(async ({ grant, gate, opens }) => {
            fs.writeFileSync(path.join(grant, 'note.md'), 'needle');
            t.diagnostic(JSON.stringify({ kind, ranged, extra }));
            const backend = handBackend(({ files }) => [passage(files[0], kind === 'sha256' ?
                shaVersion('needle') : { kind, value: files[0].mtimeMs + ':' + files[0].size },
                { ...(ranged ? { source_range_end: 6 } : {}), ...extra })]);
            expectDropped(await createSearchEngine(gate, backend)('needle'));
            assert.equal(opens.length, 0);
        });
});

test('SR46-sha256-withheld-excerpt — an uncuttable eleventh excerpt is a counted drop', async () => {
    arm('SR46-sha256-withheld-excerpt');
    for (const text of [Buffer.from([0xff, 0x61]), Buffer.from('\u00e9 tail')])
        await fixture(async ({ grant, gate }) => {
            for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(grant, i + '.md'), 'needle');
            fs.writeFileSync(path.join(grant, 'z.md'), text);
            const backend = handBackend(({ files }) => files.map(file => passage(file,
                file.rel === 'z.md' ? shaVersion(text) :
                    { kind: 'stat', value: file.mtimeMs + ':' + file.size },
                file.rel === 'z.md' && text[0] !== 0xff ? { excerpt_start: 1, byte_offset: 1 } : {})));
            const result = await createSearchEngine(gate, backend)('needle');
            assert.equal(result.hits.length, 10);
            assert.equal(result.truncated, false);
            assert.equal(result.revalidation_dropped_count, 1);
        });
    await fixture(async ({ grant, gate }) => {
        for (let i = 0; i < 10; i++) fs.writeFileSync(path.join(grant, i + '.md'), 'needle');
        const text = 'x'.repeat(32);
        fs.writeFileSync(path.join(grant, 'z.md'), text);
        const backend = handBackend(({ files }) => {
            const file = files.find(file => file.rel === 'z.md');
            return [
                ...files.filter(file => file.rel !== 'z.md').map(file => passage(file,
                    { kind: 'stat', value: file.mtimeMs + ':' + file.size })),
                ...Array.from({ length: 16 }, (_, i) => passage(file, shaVersion('wrong'),
                    { excerpt_start: i, byte_offset: i })),
                passage(file, shaVersion(text), { excerpt_start: 16, byte_offset: 16 })
            ];
        });
        const result = await createSearchEngine(gate, backend)('needle');
        assert.equal(result.hits.length, 10);
        assert.equal(result.truncated, false);
        assert.equal(result.revalidation_dropped_count, 17);
    });
});

test('SR47-sha256-window-cap — uncaptured windows drop while duplicate windows share capture', async () => {
    arm('SR47-sha256-window-cap');
    await fixture(async ({ grant, gate, reads }) => {
        const text = 'x'.repeat(32);
        fs.writeFileSync(path.join(grant, 'note.md'), text);
        const backend = handBackend(({ files }) => [
            ...Array.from({ length: 16 }, (_, i) => passage(files[0], shaVersion('wrong'),
                { excerpt_start: i, byte_offset: i })),
            passage(files[0], shaVersion(text), { excerpt_start: 16, byte_offset: 16 }),
            passage(files[0], shaVersion(text)), passage(files[0], shaVersion(text))
        ]);
        const result = await createSearchEngine(gate, backend)('needle');
        assert.equal(result.hits.length, 2);
        assert.equal(result.revalidation_dropped_count, 17);
        assert.equal(reads.length, 1);
        assert.equal(result.truncated, false);
    });
});

test('SR48-sha256-utf8-window — captured windows trim trailing codepoints across hash reads', async () => {
    arm('SR48-sha256-utf8-window');
    for (const start of [0, 65024]) for (const point of ['\u00e9', '\u6771', '\ud83d\ude00'])
        await fixture(async ({ grant, gate, reads }) => {
            const text = 'x'.repeat(start + 1023) + point + 'tail';
            fs.writeFileSync(path.join(grant, 'note.md'), text);
            const result = await createSearchEngine(gate, handBackend(({ files }) =>
                [passage(files[0], shaVersion(text), { excerpt_start: start, byte_offset: start })]))('needle');
            assert.equal(result.hits.length, 1);
            assert.equal(result.revalidation_dropped_count, 0);
            assert.equal(result.hits[0].excerpt, 'x'.repeat(200));
            assert.ok(reads.every(read => read.length > 1024), 'no separate excerpt reads');
        });
});
