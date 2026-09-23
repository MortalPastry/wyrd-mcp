import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { declare as arm } from './manifest.mjs';
import {
    captureOrCompare,
    RawStdioSession,
    tempPathTokens,
    treeSnapshot,
    V1_PROTOCOL_VERSION,
    V2_INVALID_TOOL_NAME_ERROR
} from '../../wyrd/test/raw-stdio.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = path.join(packageRoot, 'dist', 'index.js');
const tierFixture = path.join(packageRoot, 'test', 'fixtures', 'tier-server.mjs');
const goldenPath = path.join(packageRoot, 'test', 'v1-scribe.golden.json');
const FIXED_VAULT_ID = '11111111-2222-4333-8444-555555555555';
const FIXED_EVENT_ID = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const FIXED_TIME = '2026-09-14T12:34:56.789Z';

const SCRIBE_SERVER_VERSION_LEAVES = [
    {
        label: 'initialized-lifecycle first initialize response',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle',
            'normalizedEvents', 1, 'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'initialized-lifecycle duplicate initialize response',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle',
            'normalizedEvents', 4, 'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'initialize-and-list initialize response',
        path: ['cases', 'initializeAndList', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'write-success initialize response',
        path: ['cases', 'writeSuccess', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'schema-errors initialize response',
        path: ['cases', 'schemaErrors', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'fence-refusals initialize response',
        path: ['cases', 'fenceRefusals', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'fixture-B initialize response',
        path: ['cases', 'fixtureB', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'fixture-C initialize response',
        path: ['cases', 'fixtureC', 'normalizedEvents', 1,
            'message', 'result', 'serverInfo', 'version']
    }
];

const SCRIBE_LINEAGE_VERSION_REPRESENTATIONS = [
    {
        label: 'write-success tool result',
        kind: 'tool-result',
        path: ['cases', 'writeSuccess', 'normalizedEvents', 4,
            'message', 'result', 'content', 0, 'text']
    },
    {
        label: 'write-success lineage UTF-8 bytes',
        kind: 'jsonl-utf8',
        path: ['cases', 'writeSuccess', 'filesystemAfter', 1, 'utf8']
    },
    {
        label: 'write-success lineage base64 bytes',
        kind: 'jsonl-base64',
        path: ['cases', 'writeSuccess', 'filesystemAfter', 1, 'base64']
    }
];

const SCRIBE_LINEAGE_FILE_BYTES_PATH =
    ['cases', 'writeSuccess', 'filesystemAfter', 1, 'bytes'];

function serverInfoVersionLeafPaths(value, location = [], result = []) {
    if (value === null || typeof value !== 'object') return result;
    for (const [key, member] of Object.entries(value)) {
        const segment = Array.isArray(value) ? Number(key) : key;
        if (key === 'serverInfo' && member !== null && typeof member === 'object' &&
            Object.hasOwn(member, 'version')) {
            result.push([...location, segment, 'version']);
        }
        serverInfoVersionLeafPaths(member, [...location, segment], result);
    }
    return result;
}

function byteStrictServerInfoVersionLinePaths(value, location = [], result = []) {
    if (value === null || typeof value !== 'object') return result;
    if (Object.hasOwn(value, 'byteStrictStaticStdoutLines')) {
        for (const [index, line] of value.byteStrictStaticStdoutLines.entries()) {
            const message = JSON.parse(Buffer.from(line.base64, 'base64').toString('utf8'));
            if (message?.result?.serverInfo !== null &&
                typeof message?.result?.serverInfo === 'object' &&
                Object.hasOwn(message.result.serverInfo, 'version')) {
                result.push([...location, 'byteStrictStaticStdoutLines', index]);
            }
        }
    }
    for (const [key, member] of Object.entries(value)) {
        const segment = Array.isArray(value) ? Number(key) : key;
        byteStrictServerInfoVersionLinePaths(member, [...location, segment], result);
    }
    return result;
}

function reviewedScribeVersionLeaf(corpus, leaf) {
    let value = corpus;
    for (const segment of leaf.path) {
        assert.ok(
            value !== null && typeof value === 'object' && Object.hasOwn(value, segment),
            `the ${leaf.label} version leaf no longer exists at its reviewed path`
        );
        value = value[segment];
    }
    assert.equal(typeof value, 'string', `the ${leaf.label} version must remain a string`);
    return value;
}

function setReviewedScribeVersionLeaf(corpus, leaf, value) {
    let parent = corpus;
    for (const segment of leaf.path.slice(0, -1)) parent = parent[segment];
    parent[leaf.path.at(-1)] = value;
}

function sortedPathKeys(paths) {
    return paths.map(leafPath => JSON.stringify(leafPath)).sort();
}

function reviewedPathValue(corpus, reviewed) {
    let value = corpus;
    for (const segment of reviewed.path) {
        assert.ok(
            value !== null && typeof value === 'object' && Object.hasOwn(value, segment),
            `the ${reviewed.label} no longer exists at its reviewed path`
        );
        value = value[segment];
    }
    return value;
}

function setReviewedPathValue(corpus, reviewed, value) {
    let parent = corpus;
    for (const segment of reviewed.path.slice(0, -1)) parent = parent[segment];
    parent[reviewed.path.at(-1)] = value;
}

function lineageRecords(value, result = []) {
    if (value === null || typeof value !== 'object') return result;
    if (value.schema === 'wyrd.lineage/v1' && value.writer !== null &&
        typeof value.writer === 'object' && Object.hasOwn(value.writer, 'version')) {
        result.push(value);
    }
    for (const member of Object.values(value)) lineageRecords(member, result);
    return result;
}

function parsedJsonValues(text) {
    try {
        return [JSON.parse(text)];
    } catch {
        // Tool results put a human-readable prefix before their JSON body.
    }
    const parsed = [];
    for (const line of text.split('\n')) {
        if (line.length === 0) continue;
        try {
            parsed.push(JSON.parse(line));
        } catch {
            // A human-readable prefix, ordinary file text, or non-JSON base64 is not a record.
        }
    }
    return parsed;
}

/** Find every string representation in the corpus that structurally contains a lineage record. */
function lineageWriterVersionRepresentationPaths(value, location = [], result = []) {
    if (typeof value === 'string') {
        const texts = [value];
        if (location.at(-1) === 'base64') {
            const bytes = Buffer.from(value, 'base64');
            const decoded = bytes.toString('utf8');
            if (bytes.toString('base64') === value &&
                Buffer.compare(bytes, Buffer.from(decoded, 'utf8')) === 0) {
                texts.push(decoded);
            }
        }
        const records = texts.flatMap(text =>
            parsedJsonValues(text).flatMap(parsed => lineageRecords(parsed))
        );
        if (records.length > 0) {
            assert.equal(
                records.length,
                1,
                `the lineage representation at ${JSON.stringify(location)} must contain one record`
            );
            result.push(location);
        }
        return result;
    }
    if (value === null || typeof value !== 'object') return result;
    if (value.schema === 'wyrd.lineage/v1' && value.writer !== null &&
        typeof value.writer === 'object' && Object.hasOwn(value.writer, 'version')) {
        result.push(location);
    }
    for (const [key, member] of Object.entries(value)) {
        const segment = Array.isArray(value) ? Number(key) : key;
        lineageWriterVersionRepresentationPaths(member, [...location, segment], result);
    }
    return result;
}

function parseCanonicalJsonLine(text, label) {
    assert.equal(typeof text, 'string', `the ${label} must remain a string`);
    const lines = text.split('\n');
    assert.equal(lines.length, 2, `the ${label} must remain exactly one LF-terminated JSON line`);
    assert.equal(lines[1], '', `the ${label} must retain its terminating LF`);
    const record = JSON.parse(lines[0]);
    assert.equal(
        `${JSON.stringify(record)}\n`,
        text,
        `the ${label} must retain canonical JSONL bytes`
    );
    assert.deepStrictEqual(
        lineageRecords(record),
        [record],
        `the ${label} must contain exactly one lineage record at its root`
    );
    return record;
}

function parseLineageRepresentation(representation, encoded) {
    if (representation.kind === 'tool-result') {
        assert.equal(typeof encoded, 'string', `the ${representation.label} must remain a string`);
        const prefix = 'wyrd-scribe completed write_page.\n';
        assert.ok(encoded.startsWith(prefix), `the ${representation.label} must retain its prefix`);
        const bodyText = encoded.slice(prefix.length);
        const body = JSON.parse(bodyText);
        assert.equal(
            JSON.stringify(body),
            bodyText,
            `the ${representation.label} must retain canonical JSON bytes after its prefix`
        );
        assert.deepStrictEqual(
            lineageRecords(body),
            [body.record],
            `the ${representation.label} must contain exactly one lineage record at record`
        );
        const lineBytes = Buffer.byteLength(`${JSON.stringify(body.record)}\n`, 'utf8');
        assert.equal(
            body.appended,
            lineBytes,
            `the ${representation.label} appended count must equal its record's JSONL byte length`
        );
        return {
            record: body.record,
            rebuild() {
                body.appended = Buffer.byteLength(`${JSON.stringify(body.record)}\n`, 'utf8');
                return `${prefix}${JSON.stringify(body)}`;
            }
        };
    }

    if (representation.kind === 'jsonl-base64') {
        assert.equal(typeof encoded, 'string', `the ${representation.label} must remain a string`);
        const bytes = Buffer.from(encoded, 'base64');
        assert.equal(
            bytes.toString('base64'),
            encoded,
            `the ${representation.label} must retain canonical base64`
        );
        const text = bytes.toString('utf8');
        assert.equal(
            Buffer.compare(bytes, Buffer.from(text, 'utf8')),
            0,
            `the ${representation.label} must remain UTF-8 bytes`
        );
        const record = parseCanonicalJsonLine(text, representation.label);
        return {
            record,
            rebuild: () => Buffer.from(`${JSON.stringify(record)}\n`, 'utf8').toString('base64')
        };
    }

    assert.equal(representation.kind, 'jsonl-utf8', `unknown ${representation.label} codec`);
    const record = parseCanonicalJsonLine(encoded, representation.label);
    return { record, rebuild: () => `${JSON.stringify(record)}\n` };
}

function reconcileApprovedLineageVersions(expected, actual, adjusted, manifestVersion) {
    const enumeratedPaths = sortedPathKeys(
        SCRIBE_LINEAGE_VERSION_REPRESENTATIONS.map(representation => representation.path)
    );
    assert.deepStrictEqual(
        sortedPathKeys(lineageWriterVersionRepresentationPaths(expected)),
        enumeratedPaths,
        'the frozen Scribe lineage writer.version representations must exactly match the reviewed set'
    );
    assert.deepStrictEqual(
        sortedPathKeys(lineageWriterVersionRepresentationPaths(actual)),
        enumeratedPaths,
        'the live Scribe lineage writer.version representations must exactly match the reviewed set'
    );

    for (const representation of SCRIBE_LINEAGE_VERSION_REPRESENTATIONS) {
        const frozen = parseLineageRepresentation(
            representation,
            reviewedPathValue(expected, representation)
        );
        const live = parseLineageRepresentation(
            representation,
            reviewedPathValue(actual, representation)
        );
        assert.equal(
            frozen.record.writer.version,
            '0.0.0',
            `the frozen ${representation.label} no longer carries the reviewed v1 writer version`
        );
        assert.equal(
            live.record.writer.version,
            manifestVersion,
            `the live ${representation.label} writer version must equal the Scribe manifest version`
        );
        live.record.writer.version = '0.0.0';
        const rebuilt = live.rebuild();
        assert.equal(
            rebuilt,
            reviewedPathValue(expected, representation),
            `the ${representation.label} must differ from the frozen bytes only by writer.version`
        );
        setReviewedPathValue(adjusted, representation, rebuilt);
    }

    const bytesLeaf = {
        label: 'write-success lineage file byte count',
        path: SCRIBE_LINEAGE_FILE_BYTES_PATH
    };
    const expectedUtf8 = reviewedPathValue(expected, SCRIBE_LINEAGE_VERSION_REPRESENTATIONS[1]);
    const actualUtf8 = reviewedPathValue(actual, SCRIBE_LINEAGE_VERSION_REPRESENTATIONS[1]);
    assert.equal(
        reviewedPathValue(expected, bytesLeaf),
        Buffer.byteLength(expectedUtf8, 'utf8'),
        'the frozen lineage file byte count must equal its reviewed UTF-8 representation'
    );
    assert.equal(
        reviewedPathValue(actual, bytesLeaf),
        Buffer.byteLength(actualUtf8, 'utf8'),
        'the live lineage file byte count must equal its reviewed UTF-8 representation'
    );
    setReviewedPathValue(
        adjusted,
        bytesLeaf,
        Buffer.byteLength(
            reviewedPathValue(adjusted, SCRIBE_LINEAGE_VERSION_REPRESENTATIONS[1]),
            'utf8'
        )
    );
}

/**
 * Reconcile only the reviewed initialize-result and lineage writer version leaves. The Scribe's
 * manifest is the live source of truth; the frozen v1 value remains asserted rather than being
 * normalized away. Every representation is parsed, rebuilt, and required to equal the frozen
 * bytes so no neighboring difference can be hidden.
 */
function withApprovedScribeServerVersionDelta(expected, actual) {
    const enumeratedPaths = sortedPathKeys(SCRIBE_SERVER_VERSION_LEAVES.map(leaf => leaf.path));
    assert.deepStrictEqual(
        sortedPathKeys(serverInfoVersionLeafPaths(expected)),
        enumeratedPaths,
        'the frozen Scribe corpus serverInfo.version leaves must exactly match the reviewed set'
    );
    assert.deepStrictEqual(
        sortedPathKeys(serverInfoVersionLeafPaths(actual)),
        enumeratedPaths,
        'the live Scribe corpus serverInfo.version leaves must exactly match the reviewed set'
    );
    assert.deepStrictEqual(
        byteStrictServerInfoVersionLinePaths(expected),
        [],
        'the frozen Scribe byte-strict lines must not carry an unreviewed serverInfo.version'
    );
    assert.deepStrictEqual(
        byteStrictServerInfoVersionLinePaths(actual),
        [],
        'the live Scribe byte-strict lines must not carry an unreviewed serverInfo.version'
    );

    const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
    assert.equal(typeof manifest.version, 'string', 'the Scribe manifest version must be a string');

    const adjusted = structuredClone(actual);
    for (const leaf of SCRIBE_SERVER_VERSION_LEAVES) {
        assert.equal(
            reviewedScribeVersionLeaf(expected, leaf),
            '0.0.0',
            `the frozen ${leaf.label} no longer carries the reviewed v1 version`
        );
        assert.equal(
            reviewedScribeVersionLeaf(actual, leaf),
            manifest.version,
            `the live ${leaf.label} must carry the Scribe manifest version`
        );
        setReviewedScribeVersionLeaf(adjusted, leaf, '0.0.0');
    }
    reconcileApprovedLineageVersions(expected, actual, adjusted, manifest.version);
    return adjusted;
}

/*
 * These are inputs to the existing test-only Scribe port, not normalisations. The resulting UUID,
 * timestamp, page and ledger bytes stay present and are compared exactly in the corpus. Letting
 * production randomness through and erasing it afterward would add forbidden oracle blind spots.
 */

function makeVault(parent, name, { config = false } = {}) {
    const base = path.join(parent, name);
    const grant = path.join(base, 'grant');
    const outside = path.join(base, 'outside');
    fs.mkdirSync(path.join(grant, 'Arc'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'Mage'), { recursive: true });
    fs.mkdirSync(path.join(grant, '.wyrd'), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(grant, 'Arc', 'source.md'), 'A source with a precise quotation.');
    fs.writeFileSync(path.join(outside, 'outside.md'), 'OUTSIDE');
    if (config) {
        fs.writeFileSync(path.join(grant, '.wyrd', 'scribe.json'), JSON.stringify({
            schema: 'wyrd.scribe/v1',
            vault_id: FIXED_VAULT_ID,
            write_frontmatter: false
        }));
    }
    return { base, grant, outside };
}

function production(options) {
    return new RawStdioSession({
        entrypoint,
        entrypointLabel: 'dist/index.js',
        ...options
    });
}

function fixture(options) {
    return new RawStdioSession({
        entrypoint: tierFixture,
        entrypointLabel: 'test/fixtures/tier-server.mjs',
        ...options
    });
}

test('SV15-v1-raw-baseline — SDK-free JSON-RPC pins Scribe wire, lifecycle and tool behavior', { timeout: 180_000 }, async () => {
    arm('SV15-v1-raw-baseline');
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-v1-scribe-'));
    const pathTokens = tempPathTokens(temporary);
    const processes = [];
    const openProduction = options => {
        const child = production(options);
        processes.push(child);
        return child;
    };
    const openFixture = options => {
        const child = fixture(options);
        processes.push(child);
        return child;
    };

    try {
        const tierRefusals = {};
        const invalidTiers = [
            ['empty', ''],
            ['lowercase', 'a'],
            ['unknown', 'tier-z'],
            ['padded-both', ' A '],
            ['newline', 'A\n'],
            ['tab-prefix', '\tA'],
            ['space-suffix', 'A ']
        ];
        for (const [label, tier] of invalidTiers) {
            const child = openProduction({
                env: { WYRD_GRANT: 'must-not-open', WYRD_SCRIBE_TIER: tier },
                pathTokens
            });
            tierRefusals[label] = await child.waitForExit();
        }
        for (const tier of ['B', 'C']) {
            const child = openProduction({
                env: { WYRD_GRANT: 'must-not-open', WYRD_SCRIBE_TIER: tier },
                pathTokens
            });
            tierRefusals[`unavailable-${tier.toLowerCase()}`] = await child.waitForExit();
        }

        const characterizationWorld = makeVault(temporary, 'expanded-characterization');
        const preInitializeChild = openProduction({
            env: {
                WYRD_GRANT: characterizationWorld.grant,
                WYRD_SCRIBE_TIER: 'A'
            },
            pathTokens
        });
        await preInitializeChild.listTools({}, {
            byteStrictLabel: 'pre-initialize tools/list response'
        });
        const preInitialize = await preInitializeChild.finish();

        const lifecycleChild = openProduction({
            env: {
                WYRD_GRANT: characterizationWorld.grant,
                WYRD_SCRIBE_TIER: 'A'
            },
            pathTokens
        });
        const nonEmptyCapabilities = { roots: { listChanged: true } };
        await lifecycleChild.initialise({ capabilities: nonEmptyCapabilities });
        // ⚠ NO byteStrictLabel HERE, and the omission is the point. An `initialize` response
        // embeds the grant's absolute path in its instructions, so its bytes carry a per-run temp
        // directory (`wyrd-v1-scribe-eIOQK9` on one run, `-LaU2uw` on the next). Byte-strict
        // retention deliberately bypasses `normalise`, so a byte check here can never compare
        // equal on a second run. Measured: capture passed and compare failed on exactly this line.
        // The duplicate-initialize CASE is still characterized — through the normalized event,
        // which is what the path normalizer exists for.
        await lifecycleChild.initializeRequest(nonEmptyCapabilities);
        await lifecycleChild.listTools({ cursor: 'v1-characterization-cursor' });
        const invalidToolName = await lifecycleChild.request('tools/call', { name: 7 }, {
            byteStrictLabel: 'tools/call name-number response'
        });
        // The golden remains v1 -32603 evidence. The live v2 envelope is checked here and the
        // comparator substitutes only this response before its whole-corpus deepStrictEqual.
        assert.deepStrictEqual(
            invalidToolName.error,
            V2_INVALID_TOOL_NAME_ERROR,
            'v2 must return the one reviewed -32602 protocol-validation envelope'
        );
        const initializedLifecycle = await lifecycleChild.finish();

        const listWorld = makeVault(temporary, 'production-list');
        const listBefore = treeSnapshot(listWorld.grant);
        const listChild = openProduction({
            env: { WYRD_GRANT: listWorld.grant, WYRD_SCRIBE_TIER: 'A' },
            pathTokens
        });
        await listChild.initialise();
        await listChild.listTools();
        const initializeAndList = await listChild.finish();
        const listAfter = treeSnapshot(listWorld.grant);

        const writeWorld = makeVault(temporary, 'write-success');
        const writeBefore = treeSnapshot(writeWorld.grant);
        const writeChild = openFixture({
            env: {
                WYRD_GRANT: writeWorld.grant,
                WYRD_SCRIBE_TIER: 'A',
                WYRD_TEST_PORT_MODE: 'normal',
                WYRD_TEST_FIXED_UUID: FIXED_VAULT_ID,
                WYRD_TEST_FIXED_EVENT_ID: FIXED_EVENT_ID,
                WYRD_TEST_FIXED_TIME: FIXED_TIME
            },
            pathTokens
        });
        await writeChild.initialise();
        await writeChild.callTool('write_page', {
            path: 'Mage/answer.md',
            content: 'the answer',
            derived_from: [{
                source: 'Arc/source.md',
                spans: [{ quote: 'precise quotation' }]
            }]
        });
        const writeSuccess = await writeChild.finish();
        const writeAfter = treeSnapshot(writeWorld.grant);

        const schemaWorld = makeVault(temporary, 'schema-errors', { config: true });
        const portCalls = path.join(temporary, 'schema-port-calls.txt');
        const schemaBefore = treeSnapshot(schemaWorld.grant);
        const schemaChild = openFixture({
            env: {
                WYRD_GRANT: schemaWorld.grant,
                WYRD_SCRIBE_TIER: 'A',
                WYRD_TEST_PORT_MODE: 'normal',
                WYRD_TEST_PORT_COUNT: portCalls
            },
            pathTokens
        });
        await schemaChild.initialise();
        await schemaChild.callTool('write_page', {
            path: 'Mage/extra.md', content: 'x', derived_from: [], extra: true
        });
        await schemaChild.callTool('write_page', {
            path: 'Mage/negative.md', content: 'x',
            derived_from: [{ source: 'Arc/source.md', spans: [{ offset: -1, length: 1 }] }]
        });
        await schemaChild.callTool('write_page', {
            path: 'Mage/empty-spans.md', content: 'x',
            derived_from: [{ source: 'Arc/source.md', spans: [] }]
        });
        await schemaChild.callTool('write_page', {
            path: 'Mage/missing-source.md', content: 'x',
            derived_from: [{ spans: [{ quote: 'precise quotation' }] }]
        });
        await schemaChild.callTool('write_page', {
            path: 'Mage/zero-length.md', content: 'x',
            derived_from: [{
                source: 'Arc/source.md',
                spans: [{ offset: 0, length: 0, quote: 'precise quotation' }]
            }]
        });
        const schemaErrors = await schemaChild.finish();
        const schemaAfter = treeSnapshot(schemaWorld.grant);

        const fenceWorld = makeVault(temporary, 'fence-refusals', { config: true });
        fs.writeFileSync(path.join(fenceWorld.grant, 'Mage', 'occupied.md'), 'original');
        const fenceBefore = treeSnapshot(fenceWorld.base);
        const fenceChild = openProduction({
            env: { WYRD_GRANT: fenceWorld.grant, WYRD_SCRIBE_TIER: 'A' },
            pathTokens
        });
        await fenceChild.initialise();
        await fenceChild.callTool('write_page', {
            path: 'Arc/no.md', content: 'x', derived_from: []
        });
        await fenceChild.callTool('write_page', {
            path: 'Mage/occupied.md', content: 'new', derived_from: []
        });
        await fenceChild.callTool('write_page', {
            path: '../outside/new.md', content: 'x', derived_from: []
        });
        await fenceChild.callTool('write_page', {
            path: 'Mage/from-escape.md', content: 'x',
            derived_from: [{ source: '../outside/outside.md', spans: [{ quote: 'OUTSIDE' }] }]
        });
        const fenceRefusals = await fenceChild.finish();
        const fenceAfter = treeSnapshot(fenceWorld.base);

        const fixtureBChild = openFixture({
            env: {
                WYRD_GRANT: undefined,
                WYRD_SCRIBE_TIER: 'B',
                WYRD_TEST_PORT_MODE: undefined
            },
            pathTokens
        });
        await fixtureBChild.initialise();
        await fixtureBChild.listTools();
        await fixtureBChild.callTool('overwrite_page', {});
        const fixtureB = await fixtureBChild.finish();

        const fixtureCChild = openFixture({
            env: {
                WYRD_GRANT: undefined,
                WYRD_SCRIBE_TIER: 'C',
                WYRD_TEST_PORT_MODE: undefined
            },
            pathTokens
        });
        await fixtureCChild.initialise();
        await fixtureCChild.listTools();
        await fixtureCChild.callTool('delete_page', {});
        await fixtureCChild.callTool('rename_page', {});
        const fixtureC = await fixtureCChild.finish();

        const actual = {
            captured: true,
            protocolVersion: V1_PROTOCOL_VERSION,
            cases: {
                tierRefusals,
                expandedCharacterization: {
                    preInitialize,
                    initializedLifecycle
                },
                initializeAndList: {
                    ...initializeAndList,
                    filesystemBefore: listBefore,
                    filesystemAfter: listAfter
                },
                writeSuccess: {
                    ...writeSuccess,
                    filesystemBefore: writeBefore,
                    filesystemAfter: writeAfter
                },
                schemaErrors: {
                    ...schemaErrors,
                    filesystemBefore: schemaBefore,
                    filesystemAfter: schemaAfter,
                    portCallFileExists: fs.existsSync(portCalls)
                },
                fenceRefusals: {
                    ...fenceRefusals,
                    filesystemBefore: fenceBefore,
                    filesystemAfter: fenceAfter
                },
                fixtureB,
                fixtureC
            }
        };
        const expected = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
        captureOrCompare(
            goldenPath,
            withApprovedScribeServerVersionDelta(expected, actual)
        );
    } finally {
        await Promise.allSettled(processes.map(child => child.dispose()));
        fs.rmSync(temporary, { recursive: true, force: true });
    }
});
