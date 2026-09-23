import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { main } from '../dist/main.js';
import { declare as arm } from './manifest.mjs';
import { RawMcpClient } from '../../wyrd/test/raw-stdio.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workspaceRoot = path.resolve(packageRoot, '..', '..');
const packageManifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const scribeEntrypoint = path.join(packageRoot, 'dist', 'index.js');
const tierFixture = path.join(packageRoot, 'test', 'fixtures', 'tier-server.mjs');
const readerEntrypoint = path.join(workspaceRoot, 'packages', 'wyrd', 'dist', 'index.js');
const fenceReadme = path.join(workspaceRoot, 'packages', 'wyrd-fence', 'README.md');
const TEST_TIMEOUT_MS = 20_000;
const FIXED_UUID = '11111111-2222-4333-8444-555555555555';

const built = [];
process.on('exit', () => {
    for (const base of built) fs.rmSync(base, { recursive: true, force: true });
});

function vault() {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-scribe-server-'));
    built.push(base);
    const grant = path.join(base, 'vault');
    const outside = path.join(base, 'outside');
    fs.mkdirSync(path.join(grant, 'Arc'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'Mage'), { recursive: true });
    fs.mkdirSync(path.join(grant, '.wyrd'), { recursive: true });
    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(grant, 'Arc', 'source.md'), 'A source with a precise quotation.');
    fs.writeFileSync(path.join(outside, 'outside.md'), 'OUTSIDE');
    return { base, grant, outside };
}

function childEnv(extra = {}, withoutTier = false) {
    const env = { ...process.env };
    if (withoutTier) delete env.WYRD_SCRIBE_TIER;
    return Object.assign(env, extra);
}

async function openClient(entrypoint, env) {
    const client = new RawMcpClient({
        entrypoint,
        entrypointLabel: path.relative(workspaceRoot, entrypoint).replaceAll('\\', '/'),
        env,
        clientInfo: { name: 'wyrd-scribe-test-client', version: '0.0.0' }
    });
    await client.connect();
    return client;
}

async function withClient(entrypoint, env, assertions) {
    const client = await openClient(entrypoint, env);
    try {
        await assertions(client);
    } finally {
        await client.close();
    }
}

function names(tools) {
    return tools.map(tool => tool.name);
}

function resultJson(result, expectedPrefix) {
    if (expectedPrefix.includes('refused')) assert.equal(result.isError, true);
    assert.equal(result.content.length, 1, 'one text block carries the result');
    const text = result.content[0].text;
    assert.ok(text.startsWith(`${expectedPrefix}\n`), text);
    return JSON.parse(text.slice(text.indexOf('\n') + 1));
}

test('SV1-default-a-handshake — an absent tier initialises as A', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV1-default-a-handshake');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant }, true), client => {
        assert.deepEqual(client.getServerVersion(), { name: 'wyrd-scribe', version: packageManifest.version });
        assert.deepEqual(client.getServerCapabilities(), { tools: {} });
        assert.match(client.getInstructions(), /active write tier is A/i);
    });
});

test('SV2-a-structural-list — tier A exposes exactly write_page', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV2-a-structural-list');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), async client => {
        const { tools } = await client.listTools();
        assert.deepEqual(names(tools), ['write_page']);
        assert.ok(!names(tools).some(name => /overwrite|delete|rename|lineage.*(?:query|read|search)/i.test(name)));
        const outer = tools[0].inputSchema;
        assert.equal(outer.additionalProperties, false);
        assert.equal(outer.properties.derived_from.items.additionalProperties, false);
        for (const branch of outer.properties.derived_from.items.properties.spans.items.oneOf) {
            assert.equal(branch.additionalProperties, false);
        }
    });
});

test('SV3-b-positive-list — fixture B exposes A plus overwrite_page', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV3-b-positive-list');
    await withClient(tierFixture, childEnv({ WYRD_SCRIBE_TIER: 'B' }), async client => {
        const { tools } = await client.listTools();
        assert.deepEqual(names(tools), ['write_page', 'overwrite_page']);
        for (const tool of tools) assert.match(tool.description, /Tier B:/);
        const called = await client.callTool({ name: 'overwrite_page', arguments: {} });
        assert.equal(called.content[0].text, 'fixture:B:overwrite_page');
    });
});

test('SV4-c-positive-list — fixture C exposes all four cumulative registrations', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV4-c-positive-list');
    await withClient(tierFixture, childEnv({ WYRD_SCRIBE_TIER: 'C' }), async client => {
        const { tools } = await client.listTools();
        assert.deepEqual(names(tools), ['write_page', 'overwrite_page', 'delete_page', 'rename_page']);
        for (const tool of tools) assert.match(tool.description, /Tier C:/);
        for (const name of ['delete_page', 'rename_page']) {
            const called = await client.callTool({ name, arguments: {} });
            assert.equal(called.content[0].text, `fixture:C:${name}`);
        }
    });
});

test('SV5-invalid-tier-no-open — every raw invalid value is named before factories run', async () => {
    arm('SV5-invalid-tier-no-open');
    for (const raw of ['', 'a', 'tier-z', ' A ', 'A\n', '\tA', 'A ']) {
        let gates = 0;
        let transports = 0;
        let exitCode = null;
        const stderr = [];
        const result = await main({
            argv: [],
            env: { WYRD_GRANT: 'not opened', WYRD_SCRIBE_TIER: raw },
            makeFsGate: () => { gates += 1; throw new Error('gate must not open'); },
            makeTransport: () => { transports += 1; throw new Error('transport must not open'); },
            stderr: line => stderr.push(line),
            setExitCode: code => { exitCode = code; }
        });
        assert.deepEqual(result, { started: false, reason: 'UNRECOGNISED_TIER' });
        assert.equal(gates, 0);
        assert.equal(transports, 0);
        assert.equal(exitCode, 2);
        assert.equal(stderr[0], `UNRECOGNISED_TIER: wyrd-scribe does not recognise tier ${JSON.stringify(raw)}`);
    }
});

test('SV6-known-tier-unavailable — production B and C refuse instead of capping to A', async () => {
    arm('SV6-known-tier-unavailable');
    for (const tier of ['B', 'C']) {
        let gates = 0;
        let transports = 0;
        const stderr = [];
        const result = await main({
            argv: [],
            env: { WYRD_GRANT: 'not opened', WYRD_SCRIBE_TIER: tier },
            makeFsGate: () => { gates += 1; throw new Error('gate must not open'); },
            makeTransport: () => { transports += 1; throw new Error('transport must not open'); },
            stderr: line => stderr.push(line),
            setExitCode: () => {}
        });
        assert.deepEqual(result, { started: false, reason: 'TIER_UNAVAILABLE' });
        assert.equal(gates, 0);
        assert.equal(transports, 0);
        assert.equal(stderr[0], `TIER_UNAVAILABLE: tier ${tier} is recognised but unavailable in this build`);
    }
});

test('SV7-disclosure-as-received — instructions carry the canonical grant, tier and tool set', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV7-disclosure-as-received');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), client => {
        const instructions = client.getInstructions();
        assert.equal(typeof instructions, 'string');
        assert.match(instructions, /active write tier is A/i);
        assert.match(instructions, /Exactly these tools are registered: `write_page`/);
        assert.ok(instructions.includes(fs.realpathSync.native(world.grant)));
        assert.match(instructions, /spelled and resolved paths differ after case-folding/);
        const flat = instructions.replace(/\s+/g, ' ');
        assert.ok(flat.includes('The fence rechecks root object identity before each operation that touches the filesystem; component/leaf/link/rename races and the interval between that recheck and opening the file remain. Append refusals may retain a partial or complete line.'), flat);
        assert.match(instructions, /page stays in place/);
    });
});

test('SV8-description-as-received — the decisive first sentence fits the client budget', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV8-description-as-received');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), async client => {
        const { tools } = await client.listTools();
        for (const tool of tools) assert.match(tool.description, /Tier A:/);
        const first = tools[0].description.split('\n')[0];
        assert.equal(first, 'Tier A: attempt to create a page outside Arc/; target and sources use the grant fence.');
        assert.equal(first.length, 86);
        assert.ok(first.length <= 88);
        assert.match(first, /Tier A:/);
        assert.match(first, /Arc\//);
        assert.match(first, /fence/);
    });
});

test('SV9-write-and-lineage — a real call creates one page and exactly one ledger line', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV9-write-and-lineage');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), async client => {
        const result = await client.callTool({
            name: 'write_page',
            arguments: {
                path: 'Mage/answer.md',
                content: 'the answer',
                derived_from: [{ source: 'Arc/source.md', spans: [{ quote: 'precise quotation' }] }]
            }
        });
        assert.notEqual(result.isError, true);
        const body = resultJson(result, 'wyrd-scribe completed write_page.');
        assert.equal(body.ok, true);
        assert.equal(fs.readFileSync(path.join(world.grant, 'Mage', 'answer.md'), 'utf8'), 'the answer');
        const ledger = fs.readFileSync(path.join(world.grant, '.wyrd', 'lineage.jsonl'), 'utf8');
        const lines = ledger.split('\n');
        assert.equal(lines.at(-1), '');
        assert.equal(lines.length, 2, 'one JSON document and its terminating LF');
        assert.equal(JSON.parse(lines[0]).page.identity.path, 'Mage/answer.md');
    });
});

test('SV10-refusals-on-wire — exact write results survive the MCP envelope', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV10-refusals-on-wire');
    const world = vault();
    fs.writeFileSync(path.join(world.grant, '.wyrd', 'scribe.json'), JSON.stringify({
        schema: 'wyrd.scribe/v1', vault_id: FIXED_UUID, write_frontmatter: false
    }));
    fs.writeFileSync(path.join(world.grant, 'Mage', 'occupied.md'), 'original');
    const ledgerPath = path.join(world.grant, '.wyrd', 'lineage.jsonl');
    const before = fs.existsSync(ledgerPath) ? fs.readFileSync(ledgerPath) : null;

    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), async client => {
        const call = arguments_ => client.callTool({ name: 'write_page', arguments: arguments_ });
        const arc = resultJson(await call({ path: 'Arc/no.md', content: 'x', derived_from: [] }), 'wyrd-scribe refused write_page.');
        assert.deepEqual(Object.keys(arc).sort(), ['detail', 'ok', 'reason']);
        assert.equal(arc.reason, 'ARC_IMMUTABLE');

        const exists = resultJson(await call({ path: 'Mage/occupied.md', content: 'new', derived_from: [] }), 'wyrd-scribe refused write_page.');
        assert.deepEqual(Object.keys(exists).sort(), ['detail', 'ok', 'reason', 'resolvedPath', 'retained']);
        assert.equal(exists.reason, 'EXISTS');
        assert.equal(exists.retained, null);
        assert.equal(fs.readFileSync(path.join(world.grant, 'Mage', 'occupied.md'), 'utf8'), 'original');

        const target = resultJson(await call({ path: '../outside/new.md', content: 'x', derived_from: [] }), 'wyrd-scribe refused write_page.');
        assert.deepEqual(Object.keys(target).sort(), ['detail', 'ok', 'reason', 'resolvedPath', 'retained']);
        assert.equal(target.reason, 'ESCAPES');
        assert.equal(target.retained, null);
        assert.equal(fs.existsSync(path.join(world.outside, 'new.md')), false);

        const source = resultJson(await call({
            path: 'Mage/from-escape.md', content: 'x',
            derived_from: [{ source: '../outside/outside.md', spans: [{ quote: 'OUTSIDE' }] }]
        }), 'wyrd-scribe refused write_page.');
        assert.deepEqual(Object.keys(source).sort(), ['detail', 'ok', 'reason', 'resolvedPath']);
        assert.equal(source.reason, 'ESCAPES');
        assert.equal(fs.existsSync(path.join(world.grant, 'Mage', 'from-escape.md')), false);
    });

    const after = fs.existsSync(ledgerPath) ? fs.readFileSync(ledgerPath) : null;
    assert.deepEqual(after, before, 'every refusal leaves the ledger byte-identical');
});

test('SV12-schema-enforced-on-wire — invalid arguments stop before the injected port', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV12-schema-enforced-on-wire');
    const world = vault();
    const countPath = path.join(world.base, 'port-calls.txt');
    const cases = [
        {
            name: 'extra property',
            arguments: { path: 'Mage/extra.md', content: 'x', derived_from: [], extra: true },
            violation: /arguments\/extra is not allowed by inputSchema/
        },
        {
            name: 'negative offset',
            arguments: {
                path: 'Mage/negative.md', content: 'x',
                derived_from: [{ source: 'Arc/source.md', spans: [{ offset: -1, length: 1 }] }]
            },
            violation: /arguments\/derived_from\/0\/spans\/0\/offset must be >= 0/
        },
        {
            name: 'empty spans',
            arguments: {
                path: 'Mage/empty-spans.md', content: 'x',
                derived_from: [{ source: 'Arc/source.md', spans: [] }]
            },
            violation: /arguments\/derived_from\/0\/spans must NOT have fewer than 1 items/
        },
        {
            name: 'missing source',
            arguments: {
                path: 'Mage/missing-source.md', content: 'x',
                derived_from: [{ spans: [{ quote: 'precise quotation' }] }]
            },
            violation: /arguments\/derived_from\/0\/source is required by inputSchema/
        },
        {
            name: 'zero length in the three-key span',
            arguments: {
                path: 'Mage/zero-length.md', content: 'x',
                derived_from: [{
                    source: 'Arc/source.md',
                    spans: [{ offset: 0, length: 0, quote: 'precise quotation' }]
                }]
            },
            violation: /arguments\/derived_from\/0\/spans\/0\/length must be >= 1/
        }
    ];

    await withClient(tierFixture, childEnv({
        WYRD_GRANT: world.grant,
        WYRD_SCRIBE_TIER: 'A',
        WYRD_TEST_PORT_MODE: 'normal',
        WYRD_TEST_PORT_COUNT: countPath
    }), async client => {
        for (const fixture of cases) {
            const result = await client.callTool({ name: 'write_page', arguments: fixture.arguments });
            assert.equal(result.isError, true, fixture.name);
            assert.match(result.content[0].text, fixture.violation, fixture.name);
            assert.equal(fs.existsSync(countPath), false, `${fixture.name}: port must not be called`);
        }
    });
});

test('SV13-rich-results-on-wire — exact rich port results survive the envelope', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV13-rich-results-on-wire');

    const fresh = vault();
    const freshCapture = path.join(fresh.base, 'fresh-result.json');
    await withClient(tierFixture, childEnv({
        WYRD_GRANT: fresh.grant,
        WYRD_SCRIBE_TIER: 'A',
        WYRD_TEST_PORT_MODE: 'normal',
        WYRD_TEST_PORT_RESULT: freshCapture
    }), async client => {
        const result = await client.callTool({
            name: 'write_page',
            arguments: { path: 'Mage/first.md', content: 'first', derived_from: [] }
        });
        assert.notEqual(result.isError, true);
        const text = result.content[0].text;
        const prefix = 'wyrd-scribe completed write_page.';
        assert.ok(text.startsWith(`${prefix}\n`), text);
        const wire = text.slice(prefix.length + 1);
        const port = fs.readFileSync(freshCapture, 'utf8');
        assert.equal(wire, port, 'success envelope is byte-identical to the port result');
        assert.equal(JSON.parse(wire).config_created, true);
    });

    const failed = vault();
    const failedCapture = path.join(failed.base, 'ledger-failed-result.json');
    await withClient(tierFixture, childEnv({
        WYRD_GRANT: failed.grant,
        WYRD_SCRIBE_TIER: 'A',
        WYRD_TEST_PORT_MODE: 'ledger-failure',
        WYRD_TEST_PORT_RESULT: failedCapture
    }), async client => {
        const result = await client.callTool({
            name: 'write_page',
            arguments: { path: 'Mage/orphan.md', content: 'orphan', derived_from: [] }
        });
        assert.equal(result.isError, true);
        const prefix = 'wyrd-scribe created the page, but no lineage append was confirmed; inspect `cause` and, when present, `cause.retained`, because the ledger may contain no new line, a fragment, or the complete line.';
        const text = result.content[0].text;
        assert.ok(text.startsWith(`${prefix}\n`), text);
        const wire = text.slice(prefix.length + 1);
        const port = fs.readFileSync(failedCapture, 'utf8');
        assert.equal(wire, port, 'ledger-failure envelope is byte-identical to the port result');
        const body = JSON.parse(wire);
        assert.equal(body.reason, 'PAGE_WRITTEN_LEDGER_FAILED');
        assert.equal(body.cause.detail, 'fixture ledger refusal');
        assert.equal(body.created.rel, path.join('Mage', 'orphan.md'));
        assert.equal(fs.existsSync(path.join(failed.grant, 'Mage', 'orphan.md')), true);
    });
});

test('SV14-fence-claims-are-the-fences — both disclosures point to the authoritative limits', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV14-fence-claims-are-the-fences');
    const readme = fs.readFileSync(fenceReadme, 'utf8');
    const heading = readme.match(/^## (Security boundary and limits)$/m)?.[1];
    assert.equal(heading, 'Security boundary and limits', 'the authoritative README heading exists');
    const world = vault();
    await withClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }), async client => {
        const tools = (await client.listTools()).tools;
        const surfaces = [client.getInstructions(), ...tools.map(tool => tool.description)];
        const claim = 'Direct normalized `Arc/` targets are refused. The fence rejects a pre-existing parent alias when its spelled and resolved paths differ after case-folding; its documented fold-equal-alias limit still applies. The fence rechecks root object identity before each operation that touches the filesystem; component/leaf/link/rename races and the interval between that recheck and opening the file remain. Append refusals may retain a partial or complete line.';
        for (const surface of surfaces) {
            const flat = surface.replace(/\s+/g, ' ');
            assert.ok(flat.includes(claim), flat);
            assert.ok(flat.includes(heading), flat);
            assert.ok(flat.includes('`createFileInGrant` / `appendLineInGrant` API documentation'), flat);
        }
    });
});

test('SV11-reader-unchanged — both configured servers leave the Reader at exactly read', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('SV11-reader-unchanged');
    assert.equal(fs.existsSync(readerEntrypoint), true, 'build the Reader before running this arm');
    const world = vault();
    const reader = await openClient(readerEntrypoint, childEnv({ WYRD_GRANT: world.grant }, true));
    const scribe = await openClient(scribeEntrypoint, childEnv({ WYRD_GRANT: world.grant, WYRD_SCRIBE_TIER: 'A' }));
    try {
        assert.deepEqual(names((await reader.listTools()).tools), ['read']);
        assert.deepEqual(names((await scribe.listTools()).tools), ['write_page']);
    } finally {
        await Promise.all([reader.close(), scribe.close()]);
    }
});
