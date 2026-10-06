import assert from 'node:assert/strict';
import { createHook } from 'node:async_hooks';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { CLIENT_CAPABILITIES_META_KEY, CLIENT_INFO_META_KEY, PROTOCOL_VERSION_META_KEY } from '@modelcontextprotocol/server';
import { createFsGate, isRefusal } from 'wyrd-fence';

import { MAX_HTTP_REQUEST_BYTES, loadTlsConfiguration, startHttp } from '../dist/index.js';
import { createCertificateFiles } from '../../wyrd/dist/cert.js';
import { createServer as createReaderServer } from '../../wyrd/dist/server.js';
import { declare } from './manifest.mjs';

const temporaryBases = new Set();
process.once('exit', () => {
    for (const base of temporaryBases) fs.rmSync(base, { recursive: true, force: true });
});

function temporaryDirectory(prefix) {
    const base = fs.mkdtempSync(prefix);
    temporaryBases.add(base);
    return base;
}


const refusals = {
    route: { body: 'route\n' },
    method: { body: 'method\n', headers: { allow: 'POST' } },
    origin: { body: 'origin\n' },
    length: { body: 'length\n' },
    unauthenticated: { body: 'auth\n', headers: { 'www-authenticate': 'Bearer realm="test"' } },
    unavailable: { body: 'unavailable\n', headers: { 'cache-control': 'no-store' } },
    internal: { body: 'internal\n' }
};
const authenticated = { kind: 'authenticated', authInfo: { token: '', clientId: 'test', scopes: [] } };

async function listener({ readAuthInfo = () => authenticated, fetch = () => new Response('ok'), close = async () => {} } = {}) {
    let calls = 0;
    const handle = await startHttp({
        kind: 'loopback', host: '127.0.0.1', port: 0,
        makeServer: () => ({}), readAuthInfo, refusals
    }, {
        makeHandler: () => ({ fetch: request => { calls++; return fetch(request); }, close })
    });
    return { handle, calls: () => calls };
}

function request(handle, { host = '127.0.0.1', path = '/mcp', method = 'POST', headers = {}, body = '', ca } = {}) {
    return new Promise((resolve, reject) => {
        const transport = ca === undefined ? http : https;
        const req = transport.request({ host, port: handle.port, path, method, headers, ca }, res => {
            const chunks = [];
            res.on('data', chunk => chunks.push(chunk));
            res.on('end', () => resolve({ status: res.statusCode, statusMessage: res.statusMessage,
                headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks).toString() }));
        });
        req.on('error', reject);
        req.end(body);
    });
}

async function tlsListener() {
    const dir = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-http-413-tls-'));
    try {
        const pair = await createCertificateFiles('localhost', dir);
        const loaded = await loadTlsConfiguration(pair);
        assert.equal(loaded.ok, true, loaded.detail);
        let calls = 0;
        const handle = await startHttp({
            kind: 'loopback', host: '127.0.0.1', port: 0, tls: loaded.configuration,
            makeServer: () => ({}), readAuthInfo: () => authenticated, refusals
        }, { makeHandler: () => ({ fetch: () => { calls++; return new Response('ok'); }, close: async () => {} }) });
        return { handle, ca: pair.certificatePem, calls: () => calls,
            cleanup: async () => { await handle.close(); fs.rmSync(dir, { recursive: true, force: true }); } };
    } catch (error) {
        fs.rmSync(dir, { recursive: true, force: true });
        throw error;
    }
}

function oversizeSocket(handle) {
    const socket = net.createConnection({ host: '127.0.0.1', port: handle.port });
    const chunks = [];
    let firstData;
    const received = new Promise(resolve => { firstData = resolve; });
    let finished;
    const closed = new Promise(resolve => { finished = resolve; });
    let error = null;
    const started = Date.now();
    socket.setTimeout(5_000, () => socket.destroy(new Error('oversize socket timed out')));
    socket.on('connect', () => socket.write(
        `POST /mcp HTTP/1.1\r\nHost: ${handle.address}\r\nConnection: close\r\nContent-Length: ${MAX_HTTP_REQUEST_BYTES + 1}\r\n\r\n`));
    socket.on('data', chunk => { chunks.push(chunk); firstData(); });
    socket.on('error', cause => { error = cause; });
    socket.on('close', () => finished({ response: Buffer.concat(chunks).toString(),
        elapsed: Date.now() - started, error }));
    return { socket, received, closed };
}

function rawExchange(handle, bytes) {
    return new Promise((resolve, reject) => {
        const socket = net.createConnection({ host: '127.0.0.1', port: handle.port });
        const chunks = [];
        let failure = null;
        socket.setTimeout(5_000, () => socket.destroy(new Error('raw response timed out')));
        socket.on('connect', () => socket.write(bytes));
        socket.on('data', chunk => chunks.push(chunk));
        socket.on('error', error => { failure = error; });
        socket.on('close', () => {
            if (chunks.length === 0 && failure !== null) reject(failure);
            else resolve(Buffer.concat(chunks).toString());
        });
    });
}

async function uploadRefusal(handle, { path = '/mcp', method = 'POST', headers = {}, expectedHeaders = {}, ca, status, body, bytes = MAX_HTTP_REQUEST_BYTES, firstBytes = 1 }) {
    const payload = Buffer.alloc(bytes, 0x20);
    const counts = { envelope: 0, early: 0, reset: 0, incomplete: 0, timeout: 0 };
    for (let i = 0; i < 32; i++) {
        const mode = i % 2 === 0 ? { 'content-length': payload.length } : { 'transfer-encoding': 'chunked' };
        const outcome = await new Promise(resolve => {
            let settled = false;
            let hold;
            let uploadFinished = false;
            const done = value => {
                if (!settled) {
                    settled = true;
                    clearTimeout(hold);
                    req.destroy();
                    resolve(value);
                }
            };
            const transport = ca === undefined ? http : https;
            const req = transport.request({ host: '127.0.0.1', port: handle.port, path, method,
                headers: { ...headers, ...mode }, ca }, res => {
                const chunks = [];
                res.on('data', chunk => chunks.push(chunk));
                res.on('end', () => done(!uploadFinished ? 'early' :
                    res.complete && res.statusCode === status &&
                    res.statusMessage === http.STATUS_CODES[status] &&
                    res.headers['content-type'] === 'text/plain; charset=utf-8' &&
                    res.headers.connection === 'close' &&
                    res.headers['transfer-encoding'] === 'chunked' &&
                    Number.isFinite(Date.parse(res.headers.date)) &&
                    Object.entries(expectedHeaders).every(([key, value]) => res.headers[key] === value) &&
                    Buffer.concat(chunks).toString() === body ? 'envelope' : 'incomplete'));
                res.on('aborted', () => done('reset'));
                res.on('error', () => done('reset'));
                // The status has arrived while the request is unfinished. Keep it that way
                // after another write: a direct response ends before the final upload bytes.
                req.write(payload.subarray(firstBytes, Math.min(payload.length, Math.max(firstBytes, 64 * 1024))));
                hold = setTimeout(() => {
                    if (settled) return;
                    uploadFinished = true;
                    req.end(payload.subarray(Math.min(payload.length, Math.max(firstBytes, 64 * 1024))));
                }, 100);
            });
            req.on('error', () => done('reset'));
            req.setTimeout(5_000, () => { req.destroy(); done('timeout'); });
            req.write(payload.subarray(0, firstBytes));
        });
        counts[outcome]++;
    }
    return counts;
}

async function requireUploadRefusal(t, handle, options) {
    const counts = await uploadRefusal(handle, options);
    t.diagnostic('envelope ' + counts.envelope + '/32; early ' + counts.early + '/32; reset ' + counts.reset + '/32; incomplete ' + counts.incomplete + '/32; timeout ' + counts.timeout + '/32');
    assert.deepEqual(counts, { envelope: 32, early: 0, reset: 0, incomplete: 0, timeout: 0 });
}

test('HH1-route-method', async () => {
    declare('HH1-route-method');
    const { handle, calls } = await listener();
    try {
        const route = await request(handle, { path: '/mcp?x=1' });
        assert.deepEqual([route.status, route.body], [404, 'route\n']);
        const method = await request(handle, { method: 'GET' });
        assert.deepEqual([method.status, method.body, method.headers.allow], [405, 'method\n', 'POST']);
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH2-origin-exact', async () => {
    declare('HH2-origin-exact');
    const { handle, calls } = await listener();
    try {
        assert.equal((await request(handle, { headers: { origin: handle.allowedOrigins[0] } })).status, 200);
        const denied = await request(handle, { headers: { origin: `${handle.allowedOrigins[0]}/` } });
        assert.deepEqual([denied.status, denied.body], [403, 'origin\n']);
        assert.equal(calls(), 1);
    } finally { await handle.close(); }
});

test('HH3-declared-length-cap', async () => {
    declare('HH3-declared-length-cap');
    let authCalls = 0;
    const { handle, calls } = await listener({ readAuthInfo: () => { authCalls++; return authenticated; } });
    try {
        const response = await request(handle, { headers: { 'content-length': MAX_HTTP_REQUEST_BYTES + 1 } });
        assert.deepEqual([response.status, response.body], [413, 'length\n']);
        assert.equal(authCalls, 0);
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH4-streamed-body-cap', async () => {
    declare('HH4-streamed-body-cap');
    const { handle, calls } = await listener();
    try {
        const body = Buffer.alloc(MAX_HTTP_REQUEST_BYTES + 1, 0x20);
        const response = await rawExchange(handle, Buffer.concat([
            Buffer.from(`POST /mcp HTTP/1.1\r\nHost: ${handle.address}\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n${body.length.toString(16)}\r\n`),
            body, Buffer.from('\r\n0\r\n\r\n')
        ]));
        assert.match(response, /^HTTP\/1\.1 413 Payload Too Large\r\n/);
        assert.match(response, /7\r\nlength\n\r\n0\r\n\r\n$/);
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

function assertLengthRefusal(response) {
    assert.equal(response.status, 413);
    assert.equal(response.statusMessage, 'Payload Too Large');
    assert.equal(response.headers['content-type'], 'text/plain; charset=utf-8');
    assert.equal(response.headers.connection, 'close');
    assert.equal(response.headers['transfer-encoding'], 'chunked');
    assert.ok(Number.isFinite(Date.parse(response.headers.date)));
    assert.deepEqual(response.rawHeaders.map((value, index) =>
        response.rawHeaders[index - 1] === 'Date' ? '<variable>' : value), [
        'content-type', 'text/plain; charset=utf-8', 'connection', 'close',
        'Date', '<variable>', 'Transfer-Encoding', 'chunked'
    ]);
    assert.equal(response.body, 'length\n');
}

test('HH11-declared-upload-413-delivered', async () => {
    declare('HH11-declared-upload-413-delivered');
    let authCalls = 0;
    const { handle, calls } = await listener({ readAuthInfo: () => { authCalls++; return authenticated; } });
    try {
        const body = Buffer.alloc(MAX_HTTP_REQUEST_BYTES * 4, 0x20);
        assertLengthRefusal(await request(handle, {
            headers: { 'content-length': body.length }, body
        }));
        assert.equal(authCalls, 0);
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH12-chunked-upload-413-delivered', async () => {
    declare('HH12-chunked-upload-413-delivered');
    const { handle, calls } = await listener();
    try {
        const body = Buffer.alloc(MAX_HTTP_REQUEST_BYTES * 4, 0x20);
        assertLengthRefusal(await request(handle, {
            headers: { 'transfer-encoding': 'chunked' }, body
        }));
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH13-oversize-drain-deadline', async () => {
    declare('HH13-oversize-drain-deadline');
    const { handle, calls } = await listener();
    try {
        const response = await rawExchange(handle,
            `POST /mcp HTTP/1.1\r\nHost: ${handle.address}\r\nConnection: close\r\nContent-Length: ${MAX_HTTP_REQUEST_BYTES + 1}\r\n\r\n`);
        assert.match(response, /^HTTP\/1\.1 413 Payload Too Large\r\n/);
        assert.match(response, /7\r\nlength\n\r\n0\r\n\r\n$/);
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH14-oversize-drain-concurrency-cap', async () => {
    declare('HH14-oversize-drain-concurrency-cap');
    const { handle, calls } = await listener();
    const held = [];
    try {
        for (let i = 0; i < 8; i++) held.push(oversizeSocket(handle));
        await Promise.all(held.map(item => item.received));
        const overflow = [oversizeSocket(handle), oversizeSocket(handle)];
        const refused = await Promise.all(overflow.map(item => item.closed));
        for (const result of refused) {
            assert.equal(result.error, null);
            assert.match(result.response, /^HTTP\/1\.1 413 Payload Too Large\r\n/);
            assert.match(result.response, /7\r\nlength\n\r\n0\r\n\r\n$/);
            assert.ok(result.elapsed < 750, `overflow close took ${result.elapsed} ms`);
        }
        for (const item of held) item.socket.write(Buffer.alloc(MAX_HTTP_REQUEST_BYTES + 1));
        for (const result of await Promise.all(held.map(item => item.closed))) {
            assert.equal(result.error, null);
            assert.match(result.response, /7\r\nlength\n\r\n0\r\n\r\n$/);
        }
        const reused = oversizeSocket(handle);
        await reused.received;
        const early = await Promise.race([reused.closed.then(() => true),
            new Promise(resolve => setTimeout(() => resolve(false), 100))]);
        assert.equal(early, false, 'released cap must admit another drain');
        reused.socket.write(Buffer.alloc(MAX_HTTP_REQUEST_BYTES + 1));
        assert.match((await reused.closed).response, /7\r\nlength\n\r\n0\r\n\r\n$/);
        assert.equal(calls(), 0);
    } finally {
        for (const item of held) item.socket.destroy();
        await handle.close();
    }
});

test('HH15-https-declared-upload-413-delivered', async () => {
    declare('HH15-https-declared-upload-413-delivered');
    const tls = await tlsListener();
    try {
        const body = Buffer.alloc(MAX_HTTP_REQUEST_BYTES * 4, 0x20);
        assertLengthRefusal(await request(tls.handle, {
            headers: { 'content-length': body.length }, body, ca: tls.ca
        }));
        assert.equal(tls.calls(), 0);
    } finally { await tls.cleanup(); }
});

test('HH16-https-chunked-upload-413-delivered', async () => {
    declare('HH16-https-chunked-upload-413-delivered');
    const tls = await tlsListener();
    try {
        const body = Buffer.alloc(MAX_HTTP_REQUEST_BYTES * 4, 0x20);
        assertLengthRefusal(await request(tls.handle, {
            headers: { 'transfer-encoding': 'chunked' }, body, ca: tls.ca
        }));
        assert.equal(tls.calls(), 0);
    } finally { await tls.cleanup(); }
});

test('HH17-close-aborts-oversize-drain', async () => {
    declare('HH17-close-aborts-oversize-drain');
    const { handle, calls } = await listener();
    const timers = [];
    const hook = createHook({ init(_id, type, _trigger, resource) {
        if (type === 'Timeout' && resource._idleTimeout === 1_500) timers.push(resource);
    } });
    hook.enable();
    const upload = oversizeSocket(handle);
    try {
        await upload.received;
        const started = Date.now();
        await Promise.race([handle.close(), new Promise((_, reject) =>
            setTimeout(() => reject(new Error('shutdown waited for drain deadline')), 500))]);
        assert.ok(Date.now() - started < 500);
        await upload.closed;
        assert.equal(upload.socket.destroyed, true);
        assert.equal(timers.length, 1);
        assert.equal(timers[0]._destroyed, true, 'drain deadline timer was not cleared');
        assert.equal(calls(), 0);
    } finally { hook.disable(); upload.socket.destroy(); await handle.close(); }
});

test('HH18-route-upload-404-delivered', async t => {
    declare('HH18-route-upload-404-delivered');
    const { handle, calls } = await listener();
    try {
        await requireUploadRefusal(t, handle, { path: '/missing', status: 404, body: 'route\n' });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH19-method-upload-405-delivered', async t => {
    declare('HH19-method-upload-405-delivered');
    const { handle, calls } = await listener();
    try {
        await requireUploadRefusal(t, handle, { method: 'PUT', status: 405, body: 'method\n', expectedHeaders: { allow: 'POST' } });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH20-origin-upload-403-delivered', async t => {
    declare('HH20-origin-upload-403-delivered');
    const { handle, calls } = await listener();
    try {
        await requireUploadRefusal(t, handle, { headers: { origin: 'https://invalid.example' }, status: 403, body: 'origin\n' });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH21-unauth-upload-401-delivered', async t => {
    declare('HH21-unauth-upload-401-delivered');
    const { handle, calls } = await listener({ readAuthInfo: () => ({ kind: 'unauthenticated' }) });
    try {
        await requireUploadRefusal(t, handle, { status: 401, body: 'auth\n', expectedHeaders: { 'www-authenticate': 'Bearer realm="test"' } });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH22-unavailable-upload-503-delivered', async t => {
    declare('HH22-unavailable-upload-503-delivered');
    const { handle, calls } = await listener({ readAuthInfo: () => ({ kind: 'unavailable' }) });
    try {
        await requireUploadRefusal(t, handle, { status: 503, body: 'unavailable\n', expectedHeaders: { 'cache-control': 'no-store' } });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH23-https-route-upload-404-delivered', async t => {
    declare('HH23-https-route-upload-404-delivered');
    const tls = await tlsListener();
    try {
        await requireUploadRefusal(t, tls.handle, { path: '/missing', status: 404, body: 'route\n', ca: tls.ca, bytes: MAX_HTTP_REQUEST_BYTES * 7 });
        assert.equal(tls.calls(), 0);
    } finally { await tls.cleanup(); }
});

test('HH24-complete-refusal-no-drain-slot', async () => {
    declare('HH24-complete-refusal-no-drain-slot');
    const { handle, calls } = await listener({ readAuthInfo: async () => {
        await new Promise(resolve => setImmediate(resolve));
        return { kind: 'unavailable' };
    } });
    const held = [];
    const timers = [];
    const hook = createHook({ init(_id, type, _trigger, resource) {
        if (type === 'Timeout' && resource._idleTimeout === 1_500) timers.push(resource);
    } });
    hook.enable();
    try {
        for (let i = 0; i < 7; i++) held.push(oversizeSocket(handle));
        await Promise.all(held.map(item => item.received));
        assert.equal(timers.length, 7);
        const before = timers.length;
        const direct = await request(handle);
        assert.equal(direct.status, 503);
        assert.equal(direct.statusMessage, 'Service Unavailable');
        assert.equal(direct.headers['content-type'], 'text/plain; charset=utf-8');
        assert.equal(direct.headers.connection, 'close');
        assert.equal(direct.headers['transfer-encoding'], 'chunked');
        assert.ok(Number.isFinite(Date.parse(direct.headers.date)));
        assert.equal(direct.headers['cache-control'], 'no-store');
        assert.equal(direct.body, 'unavailable\n');
        assert.equal(timers.length, before, 'complete refusal must not start a drain timer');
        held.push(oversizeSocket(handle));
        await held[7].received;
        assert.equal(timers.length, 8, 'the eighth drain slot remains available');
        const closedEarly = await Promise.race([held[7].closed.then(() => true),
            new Promise(resolve => setTimeout(() => resolve(false), 100))]);
        assert.equal(closedEarly, false, 'eighth drain must remain admitted');
        for (const item of held) item.socket.write(Buffer.alloc(MAX_HTTP_REQUEST_BYTES + 1));
        await Promise.all(held.map(item => item.closed));
        assert.equal(calls(), 0);
    } finally {
        hook.disable();
        for (const item of held) item.socket.destroy();
        await handle.close();
    }
});

test('HH25-internal-upload-500-delivered', async t => {
    declare('HH25-internal-upload-500-delivered');
    const { handle, calls } = await listener({ readAuthInfo: () => { throw new Error('auth callback failed'); } });
    try {
        await requireUploadRefusal(t, handle, { status: 500, body: 'internal\n', firstBytes: 512 * 1024 });
        assert.equal(calls(), 0);
    } finally { await handle.close(); }
});

test('HH5-auth-decisions', async () => {
    declare('HH5-auth-decisions');
    let decision = { kind: 'unauthenticated' };
    let seen;
    const { handle, calls } = await listener({ readAuthInfo: request => { seen = request; return decision; } });
    try {
        const denied = await request(handle, { headers: { authorization: 'Bearer denied' } });
        assert.deepEqual([denied.status, denied.body, denied.headers['www-authenticate']],
            [401, 'auth\n', 'Bearer realm="test"']);
        assert.equal(seen.authorization, 'Bearer denied');
        assert.ok(seen.signal instanceof AbortSignal);
        decision = { kind: 'unavailable' };
        const unavailable = await request(handle);
        assert.deepEqual([unavailable.status, unavailable.body, unavailable.headers['cache-control']],
            [503, 'unavailable\n', 'no-store']);
        decision = authenticated;
        assert.equal((await request(handle)).status, 200);
        assert.equal(calls(), 1);
    } finally { await handle.close(); }
});

test('HH6-actual-bound-address', async () => {
    declare('HH6-actual-bound-address');
    const { handle, calls } = await listener();
    try {
        assert.equal(handle.endpoint.interfaceAddress, '127.0.0.1');
        assert.equal(handle.endpoint.exposure, 'loopback');
        assert.equal(handle.endpoint.scheme, 'http');
        assert.equal(handle.endpoint.tlsEnabled, false);
        assert.equal(handle.address, `127.0.0.1:${handle.port}`);
        assert.ok(handle.port > 0);
        assert.deepEqual(handle.allowedOrigins, [`http://127.0.0.1:${handle.port}`, `http://localhost:${handle.port}`]);
        const response = await request(handle, { host: handle.endpoint.interfaceAddress });
        assert.deepEqual([response.status, response.body, calls()], [200, 'ok', 1]);
    } finally { await handle.close(); }
});

test('HH7-response-stream', async () => {
    declare('HH7-response-stream');
    let release;
    const tail = new Promise(resolve => { release = resolve; });
    const { handle } = await listener({ fetch: () => new Response(new ReadableStream({
        async start(controller) {
            controller.enqueue(new TextEncoder().encode('first'));
            await tail;
            controller.enqueue(new TextEncoder().encode('second'));
            controller.close();
        }
    })) });
    try {
        const first = new Promise((resolve, reject) => {
            const req = http.request({ host: '127.0.0.1', port: handle.port, path: '/mcp', method: 'POST' }, res => {
                res.once('data', chunk => resolve({ res, chunk }));
                res.once('error', reject);
            });
            req.once('error', reject);
            req.end();
        });
        const { res, chunk } = await first;
        assert.equal(chunk.toString(), 'first');
        const end = new Promise(resolve => res.on('end', resolve));
        release();
        await end;
    } finally { release(); await handle.close(); }
});

test('HH8-ordered-shutdown', async () => {
    declare('HH8-ordered-shutdown');
    let release;
    const held = new Promise(resolve => { release = resolve; });
    const events = [];
    let entered;
    const admitted = new Promise(resolve => { entered = resolve; });
    const { handle } = await listener({
        fetch: async () => { events.push('fetch'); entered(); await held; return new Response('done'); },
        close: async () => { events.push('handler-close'); }
    });
    try {
        const response = request(handle);
        await admitted;
        const closing = handle.close();
        assert.equal(handle.close(), closing);
        await Promise.resolve();
        assert.deepEqual(events, ['fetch']);
        release();
        assert.deepEqual([...(await response).body], [...'done']);
        await closing;
        assert.deepEqual(events, ['fetch', 'handler-close']);
    } finally { release(); await handle.close(); }
});


test('HH10-https-executing-response-during-close', async () => {
    declare('HH10-https-executing-response-during-close');
    const dir = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-http-https-close-'));
    let handle;
    let release;
    const held = new Promise(resolve => { release = resolve; });
    let entered;
    const executing = new Promise(resolve => { entered = resolve; });
    try {
        const pair = await createCertificateFiles('localhost', dir);
        const loaded = await loadTlsConfiguration(pair);
        assert.equal(loaded.ok, true, loaded.detail);
        handle = await startHttp({
            kind: 'loopback', host: '127.0.0.1', port: 0, tls: loaded.configuration,
            makeServer: () => ({}), readAuthInfo: () => authenticated, refusals
        }, {
            makeHandler: () => ({ fetch: async () => {
                entered();
                await held;
                return new Response('full TLS response');
            }, close: async () => {} })
        });
        const response = new Promise((resolve, reject) => {
            const req = https.request({ host: '127.0.0.1', port: handle.port, path: '/mcp',
                method: 'POST', ca: pair.certificatePem }, incoming => {
                const chunks = [];
                incoming.on('data', chunk => chunks.push(chunk));
                incoming.on('end', () => resolve({ status: incoming.statusCode, body: Buffer.concat(chunks).toString() }));
                incoming.on('aborted', () => reject(new Error('HTTPS response aborted')));
                incoming.on('error', reject);
            });
            req.on('error', reject);
            req.end();
        }).then(value => ({ value }), error => ({ error }));
        await executing;
        const closing = handle.close();
        release();
        const received = await response;
        assert.deepEqual(received.error, undefined, received.error?.message);
        assert.deepEqual(received.value, { status: 200, body: 'full TLS response' });
        await closing;
    } finally { release(); await handle?.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test('HH9-runtime-server-error', async () => {
    declare('HH9-runtime-server-error');
    let server;
    let reported;
    let reports = 0;
    let shutdown;
    let handlerClosed = false;
    const fault = new Error('injected listener failure');
    const handle = await startHttp({
        kind: 'loopback', host: '127.0.0.1', port: 0,
        makeServer: () => ({}), readAuthInfo: () => authenticated, refusals,
        onServerError: (error, draining) => { reports++; reported = error; shutdown = draining; }
    }, {
        makeListener: requestListener => {
            server = http.createServer(requestListener);
            return server;
        },
        makeHandler: () => ({ fetch: () => new Response('ok'), close: async () => { handlerClosed = true; } })
    });
    try {
        server.emit('error', fault);
        server.emit('error', new Error('later listener failure'));
        assert.equal(reported, fault);
        assert.equal(reports, 1);
        assert.ok(shutdown, 'runtime error did not begin shutdown');
        await shutdown;
        assert.equal(handlerClosed, true);
        assert.equal(server.listening, false);
        assert.equal(handle.close(), shutdown);
    } finally { await handle.close(); }
});

test('HH26-reader-listener-state-bounded', async t => {
    declare('HH26-reader-listener-state-bounded');
    assert.equal(typeof global.gc, 'function', 'HTTP arm process must run with --expose-gc');
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-http-state-'));
    fs.writeFileSync(path.join(base, 'note.md'), 'small fixture note\n');
    const gate = createFsGate({ rawGrant: base });
    assert.ok(!isRefusal(gate), `fixture grant refused: ${JSON.stringify(gate)}`);
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: {
        name: 'read', arguments: { path: 'note.md' }, _meta: {
            [PROTOCOL_VERSION_META_KEY]: '2026-07-28',
            [CLIENT_INFO_META_KEY]: { name: 'http-state-arm', version: '1.0.0' },
            [CLIENT_CAPABILITIES_META_KEY]: {}
        }
    } });
    let snapshot;
    let handle;
    const samples = [];
    let firstRetainedState = null;
    const started = performance.now();
    try {
        handle = await startHttp({
            kind: 'loopback', host: '127.0.0.1', port: 0,
            makeServer: () => createReaderServer({ fsgate: gate, transport: 'http' }),
            readAuthInfo: ({ authorization }) => authorization === 'Bearer state-arm' ? authenticated : { kind: 'unauthenticated' },
            refusals
        }, { inspectState: getState => { snapshot = getState; } });
        for (let count = 1; count <= 1_000; count++) {
            const received = await new Promise((resolve, reject) => {
                let response;
                let closed = false;
                const finish = () => { if (response !== undefined && closed) resolve(response); };
                const req = http.request({ host: '127.0.0.1', port: handle.port, path: '/mcp',
                    method: 'POST', agent: false, headers: {
                        authorization: 'Bearer state-arm', connection: 'close',
                        accept: 'application/json, text/event-stream',
                        'content-type': 'application/json', 'mcp-method': 'tools/call', 'mcp-name': 'read'
                    } }, incoming => {
                    const chunks = [];
                    incoming.on('data', chunk => chunks.push(chunk));
                    incoming.on('end', () => { response = { status: incoming.statusCode,
                        body: Buffer.concat(chunks).toString() }; finish(); });
                    incoming.on('error', reject);
                });
                req.on('socket', socket => socket.once('close', () => { closed = true; finish(); }));
                req.on('error', reject);
                req.setTimeout(5_000, () => req.destroy(new Error('read request timed out')));
                req.end(body);
            });
            assert.equal(received.status, 200, `read ${count}: ${received.body}`);
            const answer = JSON.parse(received.body);
            assert.match(answer.result.content[1].text, /small fixture note/);
            if (firstRetainedState === null) {
                for (let attempt = 0; attempt < 20 && Object.values(snapshot()).some(value => value !== 0); attempt++) {
                    await new Promise(resolve => setTimeout(resolve, 5));
                }
                const state = snapshot();
                if (Object.values(state).some(value => value !== 0)) firstRetainedState = { count, state };
            }
            if ([100, 500, 1_000].includes(count)) {
                global.gc();
                samples.push({ count, heap: process.memoryUsage().heapUsed });
            }
        }
        const growth = samples.at(-1).heap - samples[0].heap;
        t.diagnostic(`retained heap ${samples.map(({ count, heap }) => `${count}=${heap}`).join(' ')}; growth=${growth}; elapsedMs=${Math.round(performance.now() - started)}`);
        assert.deepEqual(firstRetainedState, null, `listener state remained after closed read: ${JSON.stringify(firstRetainedState)}`);
        assert.ok(growth < 1_572_864, `retained heap growth ${growth} bytes exceeded 1.5 MiB`);
    } finally {
        await handle?.close();
        fs.rmSync(base, { recursive: true, force: true });
    }
});
