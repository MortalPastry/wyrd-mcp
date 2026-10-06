import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { createFsGate } from 'wyrd-fence';
import { startHttp as startSharedHttp } from 'wyrd-http';
import { createCertificateFiles } from '../../wyrd/dist/cert.js';
import { gateAppender } from '../dist/ledger.js';
import { startScribeHttp } from '../dist/http.js';
import { SCRIBE_HTTP_REFUSALS } from '../dist/http-policy.js';
import { main } from '../dist/main.js';
import { SourceCache } from '../dist/source.js';
import { writePage } from '../dist/stamp.js';
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


const token = Buffer.alloc(32, 13).toString('base64url');
const meta = {
    [PROTOCOL_VERSION_META_KEY]: '2026-07-28',
    [CLIENT_INFO_META_KEY]: { name: 'scribe-http-arm', version: '1.0.0' },
    [CLIENT_CAPABILITIES_META_KEY]: {}
};
const body = (name = 'page.md') => JSON.stringify({
    jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
        name: 'write_page',
        arguments: { path: name, content: 'HTTP page\n', derived_from: [
            { source: 'Arc/source.md', spans: [{ offset: 0, length: 6 }] }
        ] },
        _meta: meta
    }
});

function vault() {
    const root = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-scribe-listener-'));
    const grant = path.join(root, 'grant');
    fs.mkdirSync(path.join(grant, 'Arc'), { recursive: true });
    fs.mkdirSync(path.join(grant, '.wyrd'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'Arc', 'source.md'), 'source bytes\n');
    return { root, grant };
}

function snapshot(grant) {
    const rows = [];
    const walk = (dir, prefix = '') => {
        for (const name of fs.readdirSync(dir).sort()) {
            const full = path.join(dir, name);
            const relative = `${prefix}${name}`;
            rows.push([relative, fs.statSync(full).isDirectory() ? 'dir' :
                crypto.createHash('sha256').update(fs.readFileSync(full)).digest('hex')]);
            if (fs.statSync(full).isDirectory()) walk(full, `${relative}/`);
        }
    };
    walk(grant);
    return rows;
}

async function listen(grant, extra = {}) {
    const errors = [];
    const result = await main({
        argv: ['--grant', grant, '--http', '0', ...(extra.argv ?? [])],
        env: { WYRD_WRITE_TOKEN: token },
        makeFsGate: createFsGate,
        stderr: line => errors.push(line),
        setExitCode: code => errors.push(`exit ${code}`),
        ...(extra.makeScribe === undefined ? {} : { makeScribe: extra.makeScribe }),
        ...(extra.startHttp === undefined ? {} : { startHttp: extra.startHttp })
    });
    assert.equal(result.started, true, errors.join('\n'));
    assert.ok(result.http);
    return result.http;
}

function headers(authorization = `Bearer ${token}`) {
    return {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-method': 'tools/call',
        'mcp-name': 'write_page',
        ...(authorization === null ? {} : { authorization })
    };
}

async function post(handle, options = {}) {
    return fetch(`http://${handle.address}${options.route ?? '/mcp'}`, {
        method: options.method ?? 'POST',
        ...(options.signal === undefined ? {} : { signal: options.signal }),
        headers: { ...headers(options.authorization), ...(options.headers ?? {}) },
        ...(options.method === 'GET' ? {} : { body: options.body ?? body() })
    });
}

async function postFresh(handle, options = {}) {
    const payload = options.method === 'GET' ? undefined : options.body ?? body();
    return new Promise((resolve, reject) => {
        const request = http.request(`http://${handle.address}${options.route ?? '/mcp'}`, {
            method: options.method ?? 'POST', agent: false,
            headers: { ...headers(options.authorization), ...(options.headers ?? {}) }
        }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('end', () => resolve({
                status: incoming.statusCode,
                text: async () => Buffer.concat(chunks).toString()
            }));
            incoming.on('error', reject);
        });
        request.on('error', reject);
        request.end(payload);
    });
}

test('SH5-http-write-on-disk', async () => {
    arm('SH5-http-write-on-disk');
    const { root, grant } = vault();
    let handle;
    try {
        handle = await listen(grant);
        const response = await post(handle);
        assert.equal(response.status, 200, await response.text());
        assert.equal(fs.readFileSync(path.join(grant, 'page.md'), 'utf8'), 'HTTP page\n');
        const line = JSON.parse(fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8').trim());
        assert.equal(line.event, 'page_written');
        assert.equal(line.page.identity.path, 'page.md');
    } finally { await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH6-http-refusals-no-disk-effects', async t => {
    arm('SH6-http-refusals-no-disk-effects');
    const { root, grant } = vault();
    let handle;
    try {
        handle = await listen(grant);
        const before = snapshot(grant);
        const cases = [
            [{ authorization: 'Bearer wrong' }, 401],
            [{ authorization: null }, 401],
            [{ headers: { origin: 'https://wrong.example' } }, 403],
            [{ headers: { 'content-length': '1048577' }, body: Buffer.alloc(1048577, 0x20) }, 413],
            [{ route: '/other' }, 404],
            [{ method: 'GET' }, 405]
        ];
        for (const [options, status] of cases) {
            let response;
            try { response = await postFresh(handle, options); }
            catch (error) {
                t.diagnostic(`refusal ${status}: method=${options.method ?? 'POST'}, route=${options.route ?? '/mcp'}, bodyBytes=${Buffer.byteLength(options.body ?? body())}, vaultUnchanged=${JSON.stringify(snapshot(grant)) === JSON.stringify(before)}, error=${error}`);
                throw error;
            }
            await response.text();
            assert.deepEqual(snapshot(grant), before, `HTTP ${status} changed vault`);
            assert.equal(response.status, status);
        }
        const errors = [];
        const refused = await main({
            argv: ['--grant', grant, '--http', '192.0.2.1:0', '--http-public'],
            env: { WYRD_WRITE_TOKEN: token }, makeFsGate: createFsGate,
            startHttp: () => assert.fail('listener created without TLS'),
            stderr: line => errors.push(line), setExitCode: () => {}
        });
        assert.equal(refused.started, false);
        assert.match(errors.join('\n'), /network write endpoint.*requires TLS/);
        await assert.rejects(startScribeHttp({
            kind: 'network', host: '192.0.2.1', port: 0,
            makeServer: () => assert.fail('server factory reached'),
            readAuthInfo: () => ({ kind: 'unauthenticated' }),
            refusals: SCRIBE_HTTP_REFUSALS
        }, { run: () => assert.fail('write tracker reached'), close: async () => {} },
        () => assert.fail('listener constructed without TLS')), /without TLS/);
        assert.deepEqual(snapshot(grant), before);
    } finally { await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH7-https-write-on-disk', async () => {
    arm('SH7-https-write-on-disk');
    const { root, grant } = vault();
    let handle;
    try {
        const pair = await createCertificateFiles('localhost', root);
        const errors = [];
        const result = await main({
            argv: ['--grant', grant, '--http', '127.0.0.1:0', '--tls-cert', pair.certificatePath,
                '--tls-key', pair.privateKeyPath],
            env: { WYRD_WRITE_TOKEN: token }, makeFsGate: createFsGate,
            stderr: line => errors.push(line), setExitCode: code => errors.push(`exit ${code}`)
        });
        assert.equal(result.started, true, errors.join('\n'));
        handle = result.http;
        assert.equal(handle.endpoint.tlsEnabled, true);
        const response = await new Promise((resolve, reject) => {
            const request = https.request({ host: '127.0.0.1', port: handle.port, path: '/mcp',
                method: 'POST', ca: pair.certificatePem, headers: headers() }, incoming => {
                incoming.resume(); incoming.on('end', () => resolve(incoming.statusCode));
            });
            request.on('error', reject);
            request.end(body());
        });
        assert.equal(response, 200);
        assert.equal(fs.readFileSync(path.join(grant, 'page.md'), 'utf8'), 'HTTP page\n');
        const rows = fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8')
            .trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        assert.equal(rows.length, 1);
        assert.equal(rows[0].event, 'page_written');
        assert.equal(rows[0].page.identity.path, 'page.md');
    } finally { await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH8-http-disconnect-drain', async () => {
    arm('SH8-http-disconnect-drain');
    const { root, grant } = vault();
    let handle;
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    try {
        handle = await listen(grant, { makeScribe: ({ gate, version }) => ({
            writePage: request => writePage(request, {
                gate, version, cache: new SourceCache(),
                appender: { appendLine: async line => { await hold; return gateAppender(gate).appendLine(line); } }
            }),
            overwritePage: () => assert.fail('unexpected overwrite')
        }) });
        const controller = new AbortController();
        const request = post(handle, { body: body('held.md'), headers: {}, signal: controller.signal }).catch(() => {});
        const page = path.join(grant, 'held.md');
        const until = Date.now() + 5_000;
        while (!fs.existsSync(page) && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
        assert.ok(fs.existsSync(page), 'write was not admitted');
        controller.abort();
        const closing = handle.close();
        let settled = false;
        void closing.then(() => { settled = true; });
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.equal(settled, false);
        release();
        await closing;
        await request;
        assert.equal(settled, true);
        assert.equal(fs.readFileSync(page, 'utf8'), 'HTTP page\n');
        assert.equal(JSON.parse(fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8').trim()).event, 'page_written');
    } finally { release(); await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH11-https-admitted-write-response-during-close', async () => {
    arm('SH11-https-admitted-write-response-during-close');
    const { root, grant } = vault();
    let handle;
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    try {
        const pair = await createCertificateFiles('localhost', root);
        const errors = [];
        const result = await main({
            argv: ['--grant', grant, '--http', '127.0.0.1:0', '--tls-cert', pair.certificatePath,
                '--tls-key', pair.privateKeyPath],
            env: { WYRD_WRITE_TOKEN: token }, makeFsGate: createFsGate,
            stderr: line => errors.push(line), setExitCode: code => errors.push(`exit ${code}`),
            makeScribe: ({ gate, version }) => ({
                writePage: request => writePage(request, {
                    gate, version, cache: new SourceCache(),
                    appender: { appendLine: async line => { await hold; return gateAppender(gate).appendLine(line); } }
                }),
                overwritePage: () => assert.fail('unexpected overwrite')
            })
        });
        assert.equal(result.started, true, errors.join('\n'));
        handle = result.http;
        const response = new Promise((resolve, reject) => {
            const request = https.request({ host: '127.0.0.1', port: handle.port, path: '/mcp',
                method: 'POST', ca: pair.certificatePem, headers: headers() }, incoming => {
                const chunks = [];
                incoming.on('data', chunk => chunks.push(chunk));
                incoming.on('end', () => resolve({ status: incoming.statusCode, body: Buffer.concat(chunks).toString() }));
                incoming.on('aborted', () => reject(new Error('HTTPS response aborted')));
                incoming.on('error', reject);
            });
            request.on('error', reject);
            request.end(body('https-held.md'));
        }).then(value => ({ value }), error => ({ error }));
        const page = path.join(grant, 'https-held.md');
        const until = Date.now() + 5_000;
        while (!fs.existsSync(page) && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
        assert.ok(fs.existsSync(page), 'write was not admitted');
        const closing = handle.close();
        let settled = false;
        void closing.then(() => { settled = true; });
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.equal(settled, false);
        release();
        const received = await response;
        assert.deepEqual(received.error, undefined, received.error?.message);
        assert.equal(received.value.status, 200);
        assert.match(received.value.body, /https-held\.md/);
        await closing;
        assert.equal(fs.readFileSync(page, 'utf8'), 'HTTP page\n');
        assert.equal(JSON.parse(fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8').trim()).event, 'page_written');
    } finally { release(); await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH9-http-close-awaits-tracker', async () => {
    arm('SH9-http-close-awaits-tracker');
    const { root, grant } = vault();
    let handle;
    let tracker;
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    try {
        handle = await listen(grant, {
            startHttp: (options, writes) => {
                tracker = writes;
                return startScribeHttp(options, writes);
            }
        });
        let entered = false;
        const write = tracker.run(async () => {
            entered = true;
            await hold;
            fs.writeFileSync(path.join(grant, 'tracked.md'), 'completed');
        });
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(entered, true);
        const closing = handle.close();
        let settled = false;
        void closing.then(() => { settled = true; });
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.equal(settled, false);
        release();
        await write;
        await closing;
        assert.equal(fs.readFileSync(path.join(grant, 'tracked.md'), 'utf8'), 'completed');
    } finally { release(); await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});

test('SH10-runtime-server-error-drain', async () => {
    arm('SH10-runtime-server-error-drain');
    const { root, grant } = vault();
    const messages = [];
    const exits = [];
    let server;
    let handle;
    let release;
    const hold = new Promise(resolve => { release = resolve; });
    try {
        const result = await main({
            argv: ['--grant', grant, '--http', '0'],
            env: { WYRD_WRITE_TOKEN: token }, makeFsGate: createFsGate,
            stderr: line => messages.push(line), setExitCode: code => exits.push(code),
            makeScribe: ({ gate, version }) => ({
                writePage: request => writePage(request, {
                    gate, version, cache: new SourceCache(),
                    appender: { appendLine: async line => { await hold; return gateAppender(gate).appendLine(line); } }
                }),
                overwritePage: () => assert.fail('unexpected overwrite')
            }),
            startHttp: (options, writes) => startScribeHttp(options, writes, shared =>
                startSharedHttp(shared, { makeListener: requestListener => {
                    server = http.createServer(requestListener);
                    return server;
                } }))
        });
        assert.equal(result.started, true, messages.join('\n'));
        handle = result.http;
        const controller = new AbortController();
        const request = post(handle, { body: body('error-held.md'), signal: controller.signal }).catch(() => {});
        const page = path.join(grant, 'error-held.md');
        const until = Date.now() + 5_000;
        while (!fs.existsSync(page) && Date.now() < until) await new Promise(resolve => setTimeout(resolve, 10));
        assert.ok(fs.existsSync(page), 'write was not admitted');
        controller.abort();
        await request;
        server.emit('error', new Error('injected runtime fault'));
        const closing = handle.close();
        let settled = false;
        void closing.then(() => { settled = true; });
        await new Promise(resolve => setTimeout(resolve, 25));
        assert.equal(settled, false);
        assert.deepEqual(exits, []);
        assert.ok(messages.includes('wyrd-scribe: HTTP listener failed — injected runtime fault'));
        release();
        await closing;
        await request;
        assert.equal(fs.readFileSync(page, 'utf8'), 'HTTP page\n');
        const rows = fs.readFileSync(path.join(grant, '.wyrd', 'lineage.jsonl'), 'utf8')
            .trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
        assert.equal(rows.length, 1);
        assert.equal(rows[0].event, 'page_written');
        assert.equal(rows[0].page.identity.path, 'error-held.md');
        await new Promise(resolve => setImmediate(resolve));
        assert.deepEqual(exits, [1]);
    } finally { release(); await handle?.close(); fs.rmSync(root, { recursive: true, force: true }); }
});
