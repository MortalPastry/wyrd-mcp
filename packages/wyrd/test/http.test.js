import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import { test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
    SERVER_INFO_META_KEY,
    Server
} from '@modelcontextprotocol/server';
import { createFsGate, isRefusal } from 'wyrd-fence';

import { createReadTokenVerifier, loadReadToken } from '../dist/auth.js';
import {
    CERTIFICATE_FILENAME,
    PRIVATE_KEY_FILENAME,
    createCertificateFiles,
    generateSelfSignedCertificate,
    parseCertificateHost
} from '../dist/cert.js';
import { httpDisclosure, main, readHttpArg } from '../dist/main.js';
import { MAX_HTTP_REQUEST_BYTES, startHttp } from '../dist/http.js';
import { createServer as createReaderServer, MAX_WINDOW_BYTES } from '../dist/server.js';
import { loadTlsConfiguration, readTlsArgs } from '../dist/tls-config.js';
import { assertMinimalDerIntegers, certificateSerialNumber } from './der.mjs';
import { declare as arm } from './manifest.mjs';

const CONFIGURED_TOKEN = Buffer.alloc(32, 0x11).toString('base64url');

function authenticated(token = 'test-token') {
    return {
        kind: 'authenticated',
        authInfo: { token, clientId: 'http-arm', scopes: ['read'] }
    };
}

function stubServer(name = 'http-stub') {
    return new Server(
        { name, version: '1.0.0' },
        { capabilities: {} }
    );
}

function fakeGate() {
    return {
        disclosedRoot: () => 'C:\\canonical-grant',
        probeInGrant: async () => ({
            ok: false,
            reason: 'MISSING',
            detail: 'missing',
            resolvedPath: ''
        })
    };
}

function fakeHttpHandle() {
    return {
        address: '127.0.0.1:43210',
        port: 43210,
        endpoint: {
            scheme: 'http',
            tlsEnabled: false,
            interfaceAddress: '127.0.0.1',
            exposure: 'loopback'
        },
        allowedOrigins: ['http://127.0.0.1:43210', 'http://localhost:43210'],
        close: async () => {}
    };
}

function mainDeps(overrides) {
    return {
        argv: ['--grant', 'C:\\granted'],
        env: { WYRD_READ_TOKEN: CONFIGURED_TOKEN },
        makeFsGate: () => fakeGate(),
        stderr: () => {},
        setExitCode: () => {},
        ...overrides
    };
}

/**
 * ⚠⚠ `initialize` IS THE LEGACY HANDSHAKE UNLESS IT CARRIES A MODERN ENVELOPE CLAIM, and an arm
 * that hand-builds the 2025-era shape gets refused by a correct server in a way that reads as an
 * SDK bug. The first version of these arms sent `params.protocolVersion: '2026-07-28'` with no
 * `_meta` and got back `-32022 Unsupported protocol version: 2026-07-28` with
 * `supported: ["2026-07-28"]` and `requested: "2026-07-28"` — the SAME STRING rejected against a
 * list containing it. That is not a defect: `classifyRequestBody` treats any envelope-less
 * `initialize` as legacy by definition, `legacy: 'reject'` refuses it, and the modern path (which
 * owns that error answer) deliberately echoes the requested version back so a legacy client can
 * discover what the endpoint serves from the error alone.
 *
 * ⚠ **`LATEST_PROTOCOL_VERSION` is `2025-11-25` and `SUPPORTED_PROTOCOL_VERSIONS` does not contain
 * `2026-07-28`** — both describe the LEGACY era. Reaching for either here silently rebuilds the
 * legacy handshake. The modern revision is named by the envelope claim and nothing else.
 *
 * All three `_meta` keys are required; `carriesValidModernEnvelopeClaim` fails on any missing one.
 * The keys come from the SDK's exported constants so a revision bump cannot leave a stale literal.
 */
const MODERN_WIRE_REVISION = '2026-07-28';

/** The modern negotiation method. `initialize` is the 2025-era handshake and answers -32601 here. */
const DISCOVER_METHOD = 'server/discover';

function discoverBody() {
    return JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: DISCOVER_METHOD,
        params: {
            _meta: {
                [PROTOCOL_VERSION_META_KEY]: MODERN_WIRE_REVISION,
                [CLIENT_INFO_META_KEY]: { name: 'wyrd-http-arm', version: '1.0.0' },
                [CLIENT_CAPABILITIES_META_KEY]: {}
            }
        }
    });
}

/**
 * One modern MCP exchange against the listening endpoint, used by every arm that needs a request
 * to reach the application layer. Measured against the built surface: 200 with
 * `result.supportedVersions == ["2026-07-28"]` and the server's name under
 * `result._meta["io.modelcontextprotocol/serverInfo"]`.
 */
async function discover(handle, origin, authorization) {
    const headers = {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        // SEP-2243 standard headers: the modern path requires `Mcp-Method` on EVERY request and
        // answers its absence with -32020, separately from the envelope claim above. `Mcp-Name` is
        // required only for tools/call, prompts/get and resources/read, so this request omits it.
        'mcp-method': DISCOVER_METHOD
    };
    if (origin !== undefined) headers.origin = origin;
    if (authorization !== undefined) headers.authorization = authorization;
    return fetch(`http://${handle.address}/mcp`, {
        method: 'POST',
        headers,
        body: discoverBody()
    });
}

async function listeningServer(
    readAuthInfo = () => authenticated(),
    makeServer = () => stubServer()
) {
    return startHttp({
        kind: 'loopback',
        host: '127.0.0.1',
        port: 0,
        readAuthInfo,
        makeServer
    });
}

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

async function bounded(promise, milliseconds, label) {
    let timer;
    try {
        return await Promise.race([
            promise,
            new Promise((_, reject) => {
                timer = setTimeout(() => reject(new Error(`${label} exceeded ${milliseconds} ms`)), milliseconds);
            })
        ]);
    } finally {
        clearTimeout(timer);
    }
}

async function rawClient(handle) {
    const socket = net.createConnection({ host: '127.0.0.1', port: handle.port });
    socket.setNoDelay(true);
    await bounded(new Promise((resolve, reject) => {
        const cleanup = () => {
            socket.off('connect', onConnect);
            socket.off('error', onError);
        };
        const onConnect = () => { cleanup(); resolve(); };
        const onError = error => { cleanup(); reject(error); };
        socket.once('connect', onConnect);
        socket.once('error', onError);
    }), 3_000, 'raw loopback connect');

    let bytes = Buffer.alloc(0);
    const waiters = new Set();
    let closed = false;
    const inspect = () => {
        for (const waiter of waiters) {
            if (bytes.includes(waiter.needle)) {
                waiters.delete(waiter);
                waiter.resolve(bytes);
            } else if (closed) {
                waiters.delete(waiter);
                waiter.reject(new Error(`socket closed before ${JSON.stringify(waiter.needle.toString())}`));
            }
        }
    };
    socket.on('data', chunk => {
        bytes = Buffer.concat([bytes, chunk]);
        inspect();
    });
    // Intentional disconnect arms must not turn the expected socket error into an uncaught event.
    socket.on('error', () => {});
    const closedPromise = new Promise(resolve => {
        socket.once('close', () => {
            closed = true;
            inspect();
            resolve();
        });
    });

    return {
        socket,
        bytes: () => bytes,
        closed: closedPromise,
        waitFor: (needle, milliseconds = 3_000) => bounded(new Promise((resolve, reject) => {
            const waiter = { needle: Buffer.from(needle), resolve, reject };
            waiters.add(waiter);
            inspect();
        }), milliseconds, `raw response containing ${JSON.stringify(needle)}`)
    };
}

function rawHead(handle, length, extra = {}) {
    const headers = {
        Host: handle.address,
        Connection: 'close',
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
        'Mcp-Method': DISCOVER_METHOD,
        ...(length === null ? {} : { 'Content-Length': String(length) }),
        ...extra
    };
    return `POST /mcp HTTP/1.1\r\n${Object.entries(headers)
        .map(([name, value]) => `${name}: ${value}\r\n`).join('')}\r\n`;
}

function toolCallBody(name = 'hold') {
    return JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: {
            name,
            arguments: {},
            _meta: {
                [PROTOCOL_VERSION_META_KEY]: MODERN_WIRE_REVISION,
                [CLIENT_INFO_META_KEY]: { name: 'wyrd-http-arm', version: '1.0.0' },
                [CLIENT_CAPABILITIES_META_KEY]: {}
            }
        }
    });
}

function readCallBody(arguments_, id = 1) {
    return JSON.stringify({
        jsonrpc: '2.0',
        id,
        method: 'tools/call',
        params: {
            name: 'read',
            arguments: arguments_,
            _meta: {
                [PROTOCOL_VERSION_META_KEY]: MODERN_WIRE_REVISION,
                [CLIENT_INFO_META_KEY]: { name: 'wyrd-http-cost-arm', version: '1.0.0' },
                [CLIENT_CAPABILITIES_META_KEY]: {}
            }
        }
    });
}

async function readCall(handle, arguments_, id = 1) {
    return fetch(`http://${handle.address}/mcp`, {
        method: 'POST',
        headers: {
            accept: 'application/json, text/event-stream',
            'content-type': 'application/json',
            'mcp-method': 'tools/call',
            'mcp-name': 'read'
        },
        body: readCallBody(arguments_, id)
    });
}

function realReaderFactory(grant, readCalls) {
    const gate = createFsGate({ rawGrant: grant });
    assert.ok(!isRefusal(gate), `real cost fixture gate refused: ${JSON.stringify(gate)}`);
    const measuredGate = {
        ...gate,
        readFileInGrant: async (...arguments_) => {
            const [target, offset, limit] = arguments_;
            readCalls.push({ target, offset, limit });
            return gate.readFileInGrant(...arguments_);
        }
    };
    return () => createReaderServer({ fsgate: measuredGate, transport: 'http' });
}

function heldToolServer(onCall, name = 'held-http-tool') {
    const server = new Server(
        { name, version: '1.0.0' },
        { capabilities: { tools: {} } }
    );
    server.setRequestHandler('tools/call', onCall);
    return server;
}

function finalResponse(raw) {
    const text = raw.toString('utf8');
    const starts = [...text.matchAll(/HTTP\/1\.1 (\d{3})/g)];
    assert.ok(starts.length > 0, `no HTTP response in ${JSON.stringify(text)}`);
    const last = starts.at(-1);
    const start = last.index;
    const headerEnd = text.indexOf('\r\n\r\n', start);
    assert.notEqual(headerEnd, -1, `incomplete HTTP headers in ${JSON.stringify(text)}`);
    const headerLines = text.slice(start, headerEnd).split('\r\n').slice(1);
    const headers = new Map(headerLines.map(line => {
        const colon = line.indexOf(':');
        return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
    }));
    let body = text.slice(headerEnd + 4);
    if (headers.get('transfer-encoding')?.toLowerCase().includes('chunked')) {
        const chunks = [];
        let cursor = 0;
        for (;;) {
            const lineEnd = body.indexOf('\r\n', cursor);
            assert.notEqual(lineEnd, -1, 'incomplete chunk-size line');
            const size = Number.parseInt(body.slice(cursor, lineEnd).split(';', 1)[0], 16);
            assert.ok(Number.isFinite(size), 'invalid response chunk size');
            cursor = lineEnd + 2;
            if (size === 0) break;
            chunks.push(body.slice(cursor, cursor + size));
            cursor += size + 2;
        }
        body = chunks.join('');
    } else if (headers.has('content-length')) {
        body = body.slice(0, Number(headers.get('content-length')));
    }
    return {
        status: Number(last[1]),
        body
    };
}

async function toolCall(handle, authorization, route = '/mcp') {
    const headers = {
        accept: 'application/json, text/event-stream',
        'content-type': 'application/json',
        'mcp-method': 'tools/call',
        'mcp-name': 'hold'
    };
    if (authorization !== undefined) headers.authorization = authorization;
    return fetch(`http://${handle.address}${route}`, {
        method: 'POST',
        headers,
        body: toolCallBody()
    });
}

async function responseShape(response) {
    return {
        status: response.status,
        challenge: response.headers.get('www-authenticate'),
        cacheControl: response.headers.get('cache-control'),
        contentType: response.headers.get('content-type'),
        body: await response.text()
    };
}

async function reservePort(host) {
    const server = net.createServer();
    await bounded(new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, host, resolve);
    }), 3_000, `temporary listener on ${host}`);
    const address = server.address();
    assert.notEqual(address, null);
    assert.notEqual(typeof address, 'string');
    await bounded(new Promise((resolve, reject) => {
        server.close(error => error === undefined ? resolve() : reject(error));
    }), 3_000, `temporary listener close on ${host}`);
    return address.port;
}

async function reserveLoopbackPort() {
    return reservePort('127.0.0.1');
}

async function assertAddressRefused(host, port) {
    const socket = net.createConnection({ host, port });
    try {
        const error = await bounded(new Promise(resolve => {
            socket.once('connect', () => resolve(null));
            socket.once('error', resolve);
        }), 3_000, `refused connection to ${host}:${port}`);
        assert.equal(error?.code, 'ECONNREFUSED');
    } finally {
        socket.destroy();
    }
}

async function assertLoopbackRefused(port) {
    return assertAddressRefused('127.0.0.1', port);
}

function networkFixture() {
    const candidates = [];
    for (const entries of Object.values(os.networkInterfaces())) {
        for (const entry of entries ?? []) {
            if (entry.internal || net.isIP(entry.address) === 0 || entry.address.includes('%')) continue;
            if (net.isIP(entry.address) === 6 && entry.scopeid !== 0) continue;
            const lower = entry.address.toLowerCase();
            const first = Number(entry.address.split('.')[0]);
            if (lower === '0.0.0.0' || lower === '::' || lower === '::1') continue;
            if (lower.startsWith('::ffff:') || lower.startsWith('ff')) continue;
            if (net.isIP(entry.address) === 4 && first >= 224) continue;
            candidates.push(entry.address);
        }
    }
    candidates.sort((left, right) => net.isIP(left) - net.isIP(right));
    assert.ok(
        candidates.length > 0,
        'off-loopback HTTP arms require an assigned, internal:false unicast interface address'
    );
    const address = candidates[0];
    return {
        address,
        argumentHost: net.isIP(address) === 6 ? `[${address}]` : address,
        urlHost: net.isIP(address) === 6 ? `[${address}]` : address
    };
}

async function runTokenCommand(indexPath, observePath) {
    const child = spawn(process.execPath, [indexPath, 'token'], {
        cwd: path.dirname(indexPath),
        env: { ...process.env, WYRD_OBSERVE: observePath },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const exited = new Promise(resolve => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
    });
    try {
        const result = await bounded(exited, 3_000, 'token command');
        return { ...result, stdout, stderr };
    } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await bounded(exited, 3_000, 'token command cleanup');
    }
}

async function runCertCommand(indexPath, cwd, arguments_) {
    const { WYRD_GRANT: _grant, WYRD_OBSERVE: _observe, ...cleanEnv } = process.env;
    const child = spawn(process.execPath, [indexPath, 'cert', ...arguments_], {
        cwd,
        env: cleanEnv,
        stdio: ['ignore', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const exited = new Promise(resolve => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
    });
    try {
        const result = await bounded(exited, 15_000, 'certificate command');
        return { ...result, stdout, stderr };
    } finally {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await bounded(exited, 3_000, 'certificate command cleanup');
    }
}

async function trustedTlsHandshake(handle, ca) {
    return bounded(new Promise((resolve, reject) => {
        const socket = tls.connect({
            host: '127.0.0.1',
            port: handle.port,
            servername: 'localhost',
            rejectUnauthorized: true,
            ...(ca === undefined ? {} : { ca })
        });
        const cleanup = () => {
            socket.off('secureConnect', onSecure);
            socket.off('error', onError);
        };
        const onSecure = () => {
            cleanup();
            const result = { authorized: socket.authorized, authorizationError: socket.authorizationError };
            socket.destroy();
            resolve(result);
        };
        const onError = error => {
            cleanup();
            socket.destroy();
            reject(error);
        };
        socket.once('secureConnect', onSecure);
        socket.once('error', onError);
    }), 5_000, 'TLS handshake');
}

test('H1-transport-selection — no flag selects stdio and network HTTP requires consent', async () => {
    arm('H1-transport-selection');
    const configured = [];
    let stdioFactory;
    const stdio = await main(mainDeps({
        makeConfiguredServer: context => {
            configured.push(context);
            return stubServer('stdio-stub');
        },
        serveStdio: async (factory, options) => {
            stdioFactory = factory;
            assert.deepEqual(options, { legacy: 'serve' });
            assert.equal(factory().constructor, Server);
        }
    }));
    assert.equal(stdio.started, true);
    assert.equal(stdio.http, null);
    assert.equal(typeof stdioFactory, 'function');
    assert.equal(configured.length, 1);
    assert.equal(configured[0].gate.disclosedRoot(), 'C:\\canonical-grant');
    assert.equal(configured[0].transport, 'stdio');

    let received;
    const handle = fakeHttpHandle();
    const lines = [];
    const overHttp = await main(mainDeps({
        argv: ['--grant', 'C:\\granted', '--http', '0'],
        stderr: line => lines.push(line),
        makeConfiguredServer: context => {
            configured.push(context);
            return stubServer('configured-http-stub');
        },
        serveStdio: async () => assert.fail('stdio must not start when --http is present'),
        startHttp: async options => {
            received = options;
            assert.equal(options.makeServer().constructor, Server);
            return handle;
        }
    }));
    assert.equal(overHttp.started, true);
    assert.equal(overHttp.http, handle);
    assert.equal(received.kind, 'loopback');
    assert.equal(received.host, '127.0.0.1');
    assert.equal(received.port, 0);
    assert.equal(configured.length, 2);
    assert.equal(configured[1].transport, 'http');
    assert.deepEqual(await received.readAuthInfo({
        authorization: 'Bearer wrong',
        signal: AbortSignal.timeout(1_000)
    }), { kind: 'unauthenticated' });
    assert.equal((await received.readAuthInfo({
        authorization: `Bearer ${CONFIGURED_TOKEN}`,
        signal: AbortSignal.timeout(1_000)
    })).kind, 'authenticated');
    assert.deepEqual(lines, [httpDisclosure(handle, 'C:\\canonical-grant')]);

    assert.deepEqual(readHttpArg(['--http', 'localhost:81']).bind, {
        kind: 'loopback', host: 'localhost', port: 81
    });
    assert.deepEqual(readHttpArg(['--http', '[::1]:82']).bind, {
        kind: 'loopback', host: '[::1]', port: 82
    });
    assert.equal(readHttpArg(['--http']).bind, null);
    assert.equal(readHttpArg(['--http', '0.0.0.0:80']).bind, null);
    assert.equal(readHttpArg(['--http', 'localhost']).bind, null);

    const codes = [];
    const refused = await main(mainDeps({
        argv: ['--grant', 'C:\\granted', '--http', '192.0.2.1:80'],
        setExitCode: code => codes.push(code),
        startHttp: async () => assert.fail('a non-loopback bind must be refused before listen')
    }));
    assert.equal(refused.started, false);
    assert.equal(refused.reason, 'HTTP_BIND');
    assert.deepEqual(codes, [2]);
});

test('H2-factory-local-roundtrip — an injected factory serves a real localhost MCP POST', async () => {
    arm('H2-factory-local-roundtrip');
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => authenticated(),
        () => {
            factoryCalls += 1;
            return stubServer('injected-http-reader');
        }
    );
    try {
        assert.notEqual(handle.port, 0);
        // ⚠ The previous check was `every(o => o.endsWith(':' + port))`, which is vacuous on an
        // empty array and only looks at the suffix. A cold read measured that replacing the second
        // entry with `http://attacker.invalid:<port>` passed ALL SIX arms, because H4 and H5 only
        // ever exercise element zero. Assert the exact derived set instead.
        assert.deepEqual([...handle.allowedOrigins], [
            `http://127.0.0.1:${handle.port}`,
            `http://localhost:${handle.port}`
        ]);
        const response = await discover(handle);
        const body = await response.text();
        assert.equal(response.status, 200, body);
        // The negotiated revision and the injected server's identity both come back, which is what
        // makes this a round-trip through the factory rather than a transport-layer 200.
        const { result } = JSON.parse(body);
        assert.deepEqual(result.supportedVersions, [MODERN_WIRE_REVISION]);
        assert.equal(result._meta[SERVER_INFO_META_KEY].name, 'injected-http-reader');
        assert.equal(factoryCalls, 1);
    } finally {
        await handle.close();
        await handle.close();
    }
});

test('H3-route-method — every non-POST method on /mcp is 405 and no GET stream path exists', async () => {
    arm('H3-route-method');
    let authCalls = 0;
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => { authCalls += 1; return authenticated(); },
        () => { factoryCalls += 1; return stubServer(); }
    );
    try {
        const wrongPath = await fetch(`http://${handle.address}/else`, {
            method: 'POST',
            headers: { origin: 'https://not-allowed.invalid' }
        });
        assert.equal(wrongPath.status, 404);
        await wrongPath.text();
        // ⚠ EVERY non-POST method, not just GET. A cold read measured that the two-probe version
        // of this arm stayed green against a mutation accepting `PUT /mcp` or adding `GET /sse`,
        // so criterion 2's "POST-only" clause was asserted by sampling rather than proven.
        for (const method of ['GET', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']) {
            const response = await fetch(`http://${handle.address}/mcp`, {
                method,
                headers: { origin: 'https://not-allowed.invalid' }
            });
            assert.equal(response.status, 405, `${method} /mcp must be 405`);
            assert.equal(response.headers.get('allow'), 'POST', `${method} /mcp must Allow: POST`);
            await response.text();
        }
        // The 2025-era GET stream endpoint must not exist under any spelling.
        for (const path of ['/sse', '/mcp/sse', '/message', '/messages']) {
            const response = await fetch(`http://${handle.address}${path}`, {
                headers: { origin: 'https://not-allowed.invalid' }
            });
            assert.equal(response.status, 404, `GET ${path} must be 404`);
            await response.text();
        }
        assert.equal(authCalls, 0);
        assert.equal(factoryCalls, 0);
    } finally {
        await handle.close();
    }
});

test('H4-invalid-origin-order — an inexact Origin is 403 before the auth seam', async () => {
    arm('H4-invalid-origin-order');
    let authCalls = 0;
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => { authCalls += 1; return authenticated(); },
        () => { factoryCalls += 1; return stubServer(); }
    );
    try {
        const wrongScheme = handle.allowedOrigins[0].replace('http://', 'https://');
        const wrongPort = handle.allowedOrigins[0].replace(`:${handle.port}`, `:${handle.port + 1}`);
        for (const origin of [wrongScheme, wrongPort]) {
            const response = await discover(handle, origin);
            assert.equal(response.status, 403);
            await response.text();
        }
        assert.equal(authCalls, 0);
        assert.equal(factoryCalls, 0);
    } finally {
        await handle.close();
    }
});

test('H5-allowed-origin-order — every exact allowed Origin reaches the auth seam', async () => {
    arm('H5-allowed-origin-order');
    let authCalls = 0;
    const handle = await listeningServer(() => { authCalls += 1; return authenticated(); });
    try {
        // ⚠ EVERY allow-list entry, not element zero. A cold read measured that testing only the
        // first one lets a mutation reject any other entry while this arm stays green.
        assert.ok(handle.allowedOrigins.length > 1);
        for (const origin of handle.allowedOrigins) {
            const response = await discover(handle, origin);
            const body = await response.text();
            assert.equal(response.status, 200, `${origin}: ${body}`);
        }
        assert.equal(authCalls, handle.allowedOrigins.length);
    } finally {
        await handle.close();
    }
});

test('H6-absent-origin-order — an absent Origin also reaches the auth seam', async () => {
    arm('H6-absent-origin-order');
    let authCalls = 0;
    const handle = await listeningServer(() => { authCalls += 1; return authenticated(); });
    try {
        const response = await discover(handle);
        const body = await response.text();
        assert.equal(response.status, 200, body);
        assert.equal(authCalls, 1);
    } finally {
        await handle.close();
    }
});

/**
 * ⚠ THIS ARM EXISTS BECAUSE A COLD READ FOUND CRITERION 2's SECOND CLAUSE ASSERTED BY NOTHING.
 * H2 proves the factory RUNS; it counts one call across one request, which a handler that memoized
 * a single `Server` forever would also satisfy. That mutation would introduce cross-request
 * protocol state while every other HTTP arm stayed green — and "no protocol-level session state is
 * kept" is exactly what criterion 2 promises. Two requests, two distinct server instances, and no
 * session header offered or required.
 */
test('H7-stateless-per-exchange — each exchange builds its own server and carries no session', async () => {
    arm('H7-stateless-per-exchange');
    const built = [];
    const handle = await listeningServer(
        () => authenticated(),
        () => {
            const server = stubServer(`per-exchange-${built.length}`);
            built.push(server);
            return server;
        }
    );
    try {
        const first = await discover(handle);
        const firstBody = await first.text();
        assert.equal(first.status, 200, firstBody);
        const second = await discover(handle);
        const secondBody = await second.text();
        assert.equal(second.status, 200, secondBody);

        // A fresh server per exchange: two requests, two distinct instances, named in order.
        assert.equal(built.length, 2);
        assert.notEqual(built[0], built[1]);
        assert.equal(JSON.parse(firstBody).result._meta[SERVER_INFO_META_KEY].name, 'per-exchange-0');
        assert.equal(JSON.parse(secondBody).result._meta[SERVER_INFO_META_KEY].name, 'per-exchange-1');

        // No protocol session layer: the 2025-era session header is neither issued nor demanded.
        assert.equal(first.headers.get('mcp-session-id'), null);
        assert.equal(second.headers.get('mcp-session-id'), null);
    } finally {
        await handle.close();
    }
});

/**
 * Mutation caught: remove admission-socket destruction at shutdown — the request then waits on
 * Node's live partial body and `close()` hangs.
 *
 * ⚠ It does NOT catch deleting the post-body lifecycle recheck, and a cold read measured why:
 * shutdown aborts `collectBody()`, so this arm's partial body never reaches that check either way
 * and the factory count stays zero under both. **The missed mutant is a request whose body
 * completes exactly as shutdown starts**, which no arm here produces.
 */
test('H8-partial-body-shutdown — shutdown rejects a request still collecting its body', async () => {
    arm('H8-partial-body-shutdown');
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => authenticated(),
        () => { factoryCalls += 1; return stubServer(); }
    );
    const client = await rawClient(handle);
    try {
        client.socket.write(rawHead(handle, 200, { Expect: '100-continue' }));
        await client.waitFor('HTTP/1.1 100 Continue');
        client.socket.write('0123456789');

        const began = performance.now();
        await bounded(handle.close(), 750, 'shutdown with a partial request body');
        const elapsed = performance.now() - began;
        assert.ok(elapsed < 750, `shutdown took ${elapsed.toFixed(2)} ms`);

        // Try the exact late-body action whose old path admitted work after shutdown began.
        client.socket.write('x'.repeat(190), () => {});
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(factoryCalls, 0);
    } finally {
        client.socket.destroy();
        await handle.close();
    }
});

/** Mutation caught: check the lifecycle only when the IncomingMessage first arrives. */
test('H9-auth-race-shutdown — auth released after shutdown cannot cross admission', async () => {
    arm('H9-auth-race-shutdown');
    const authStarted = deferred();
    const releaseAuth = deferred();
    let factoryCalls = 0;
    let toolCalls = 0;
    const handle = await listeningServer(
        async () => {
            authStarted.resolve();
            await releaseAuth.promise;
            return authenticated();
        },
        () => {
            factoryCalls += 1;
            return heldToolServer(async () => {
                toolCalls += 1;
                return { content: [{ type: 'text', text: 'must not run' }] };
            });
        }
    );
    const client = await rawClient(handle);
    try {
        const body = toolCallBody();
        client.socket.end(rawHead(handle, Buffer.byteLength(body), {
            'Mcp-Method': 'tools/call',
            'Mcp-Name': 'hold'
        }) + body);
        await bounded(authStarted.promise, 3_000, 'auth seam entry');

        const closing = handle.close();
        releaseAuth.resolve();
        await bounded(closing, 750, 'shutdown held at auth');
        assert.equal(factoryCalls, 0);
        assert.equal(toolCalls, 0);
    } finally {
        releaseAuth.resolve();
        client.socket.destroy();
        await handle.close();
    }
});

/** Mutation caught: call handler.close(), closeAllConnections(), or destroy sockets at shutdown start. */
test('H10-graceful-execution-shutdown — admitted tool work drains its complete response', async () => {
    arm('H10-graceful-execution-shutdown');
    const toolStarted = deferred();
    const releaseTool = deferred();
    const handle = await listeningServer(
        () => authenticated(),
        () => heldToolServer(async () => {
            toolStarted.resolve();
            await releaseTool.promise;
            return { content: [{ type: 'text', text: 'complete after drain' }] };
        })
    );
    const client = await rawClient(handle);
    try {
        const body = toolCallBody();
        // ⚠⚠ `write`, NEVER `end`, IN ANY ARM THAT EXPECTS A RESPONSE. Measured against a plain
        // `node:http` server, so this is Node's behaviour and not this bridge's: a client that
        // half-closes with `socket.end(request)` makes Node destroy the socket on the FIN, and the
        // client then receives ZERO bytes of a response produced afterwards — identical socket
        // state to a real hangup, with no half-open window. The first version of this arm used
        // `end` and failed with an empty response, which read as a drain defect and was not one.
        client.socket.write(rawHead(handle, Buffer.byteLength(body), {
            'Mcp-Method': 'tools/call',
            'Mcp-Name': 'hold'
        }) + body);
        await bounded(toolStarted.promise, 3_000, 'held tool entry');

        let closeSettled = false;
        const first = handle.close();
        const closing = first.finally(() => { closeSettled = true; });
        // ⚠ The ordered close is MEMOIZED, and this is the only assertion that proves it. A cold
        // read measured that H12's child-process arm passes with the `orderedClose` guard removed,
        // because both signal-driven calls still share the inner listener and handler promises and
        // exit cleanly. Promise identity is what distinguishes one ordered close from two.
        assert.equal(handle.close(), first, 'close() must return the same ordered-close promise');
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(closeSettled, false, 'shutdown must drain the executing tool');
        releaseTool.resolve();

        await bounded(client.closed, 3_000, 'complete held-tool response');
        const response = finalResponse(client.bytes());
        assert.equal(response.status, 200, response.body);
        assert.equal(JSON.parse(response.body).result.content[0].text, 'complete after drain');
        await bounded(closing, 3_000, 'graceful executing-request shutdown');
    } finally {
        releaseTool.resolve();
        client.socket.destroy();
        await handle.close();
    }
});

/**
 * Mutation caught: remove BOTH cancellation listeners, or abort a signal other than the one handed
 * to the SDK, or fire it more than once.
 *
 * ⚠⚠ THE CLAIM IS DELIBERATELY NARROWER THAN THE ARM'S FIRST WORDING, WHICH WAS FALSE. It said it
 * caught "listen only for IncomingMessage.aborted and omit the socket close signal." **Measured: it
 * does not.** With the socket-`close` listener deleted this arm still passed, and with the
 * `IncomingMessage` `aborted` listener deleted it still passed — the two are REDUNDANT for this
 * scenario, because destroying the socket mid-request fires both. So the arm proves the signal the
 * SDK received is the one that aborts, exactly once, and it does NOT isolate which listener did it.
 *
 * ⚠ Isolating them would need a hangup on a request that is COMPLETE but still awaiting its
 * response — the one case only socket `close` carries. That case is not reachable here: Node
 * destroys the socket on the client's FIN and delivers zero bytes either way (measured; see the
 * comment on the socket listener in `src/http.ts`). **Recorded rather than faked with an assertion
 * that cannot fail.**
 */
test('H11-disconnect-propagation — a hangup aborts the exact Fetch signal the SDK received, once', async () => {
    arm('H11-disconnect-propagation');
    const toolStarted = deferred();
    const releaseTool = deferred();
    const signalAborted = deferred();
    let capturedSignal;
    let abortEvents = 0;
    const handle = await listeningServer(
        request => {
            capturedSignal = request.signal;
            request.signal.addEventListener('abort', () => {
                abortEvents += 1;
                signalAborted.resolve();
            });
            return authenticated();
        },
        () => heldToolServer(async () => {
            toolStarted.resolve();
            await releaseTool.promise;
            return { content: [{ type: 'text', text: 'released' }] };
        })
    );
    const client = await rawClient(handle);
    try {
        const body = toolCallBody();
        client.socket.write(rawHead(handle, Buffer.byteLength(body), {
            'Mcp-Method': 'tools/call',
            'Mcp-Name': 'hold'
        }) + body);
        await bounded(toolStarted.promise, 3_000, 'held tool entry before disconnect');
        assert.equal(capturedSignal.aborted, false);

        client.socket.destroy();
        await bounded(signalAborted.promise, 750, 'Fetch signal abort after socket close');
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(capturedSignal.aborted, true);
        assert.equal(abortEvents, 1);
    } finally {
        releaseTool.resolve();
        client.socket.destroy();
        await handle.close();
    }
});

/**
 * Mutation caught: `process.exit()` from a signal handler, or a signal handler that does not reach
 * the ordered shutdown at all — the child then fails to exit cleanly after both signals.
 *
 * ⚠ It does NOT prove the outer `orderedClose` memoization, measured by a cold read: with the
 * `if (orderedClose !== null)` guard removed, both signal-driven calls still share `listenerClose`
 * and `handlerClose`, abort and destroy idempotently, and exit cleanly. **Proving that guard needs
 * a count of ordered-close executions or a comparison of the returned promises**, and this arm does
 * neither.
 */
test('H12-concurrent-signal-shutdown — SIGINT and SIGTERM share one orderly close', async () => {
    arm('H12-concurrent-signal-shutdown');
    const grant = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-signals-'));
    // ⚠ Resolve from THIS FILE, never the process CWD. `path.resolve('dist/index.js')` pointed at
    // the workspace root when the suite ran from there, and the release gate's `references` phase
    // correctly refused it as naming a target outside the public package roots.
    const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const indexPath = path.join(packageRoot, 'dist', 'index.js');
    // Windows child.kill() may terminate instead of delivering POSIX signals. IPC makes the child
    // emit the same two process events through the real executable listeners, in a fixed order.
    /**
     * ⚠ THE SETUP RUNS IN A `--import` PRELOAD AND THE EXECUTABLE IS THE MAIN ENTRY, rather than
     * the executable being pulled in by a dynamic `import()` inside an `--eval` string.
     *
     * The release gate's `imports` phase scans this file's TEXT for unresolvable specifiers and
     * cannot tell that an `import(...)` call lives inside a string meant for a child process. It
     * refused, and correctly by its own standard: an unresolved dependency must not read as a
     * checked one. So no `import(` appears in this file at all.
     *
     * ⚠ Ordering is load-bearing and is why the preload holds the SETUP rather than the server:
     * `--import` runs BEFORE the main entry, so `process.argv` and the message listener are both
     * in place before the executable reads its grant and binds. Putting the executable in the
     * preload instead starts it before argv exists, and it exits without a grant — measured.
     */
    const preload = 'data:text/javascript,' + encodeURIComponent([
        'process.argv = [process.execPath, process.env.WYRD_HTTP_TEST_INDEX,',
        "    '--grant', process.env.WYRD_HTTP_TEST_GRANT, '--http', '0'];",
        "process.on('message', signals => {",
        '    for (const signal of signals) process.emit(signal);',
        '    process.disconnect();',
        '});'
    ].join('\n'));
    const child = spawn(process.execPath, ['--import', preload, indexPath], {
        cwd: path.resolve('.'),
        env: {
            ...process.env,
            WYRD_HTTP_TEST_GRANT: grant,
            WYRD_HTTP_TEST_INDEX: indexPath,
            WYRD_HTTP_TEST_URL: pathToFileURL(indexPath).href,
            WYRD_READ_TOKEN: CONFIGURED_TOKEN
        },
        stdio: ['ignore', 'pipe', 'pipe', 'ipc']
    });
    let stderr = '';
    const listening = deferred();
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', chunk => {
        stderr += chunk;
        const match = stderr.match(
            /wyrd Reader is listening only on this machine, through the loopback interface at 127\.0\.0\.1, port (\d+)\./
        );
        if (match) listening.resolve(Number(match[1]));
    });
    const exited = new Promise(resolve => {
        child.once('exit', (code, signal) => resolve({ code, signal }));
    });
    let client;
    try {
        const bootstrap = fs.readFileSync(indexPath, 'utf8');
        assert.doesNotMatch(bootstrap, /\bprocess\.exit\s*\(/,
            'signal shutdown must not force process exit before the ordered close settles');
        const port = await bounded(listening.promise, 5_000, 'child HTTP listener');
        client = await rawClient({ port });
        client.socket.write(rawHead({ address: `127.0.0.1:${port}` }, 200, {
            Expect: '100-continue',
            Authorization: `Bearer ${CONFIGURED_TOKEN}`
        }));
        await client.waitFor('HTTP/1.1 100 Continue');
        client.socket.write('0123456789');

        assert.equal(child.send(['SIGINT', 'SIGTERM']), true);
        const result = await bounded(exited, 3_000, 'signal-driven child shutdown');
        assert.deepEqual(result, { code: 0, signal: null }, stderr);
        assert.doesNotMatch(stderr, /shutdown failed|ERR_SERVER_NOT_RUNNING|uncaught/i);
    } finally {
        client?.socket.destroy();
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        await bounded(exited, 3_000, 'child cleanup');
        fs.rmSync(grant, { recursive: true, force: true });
    }
});

/**
 * Mutation caught: buffer before Origin or auth (the partial clients would then be awaited), or
 * run the auth seam before Origin.
 *
 * ⚠ It does NOT catch handing the request to the SDK before the body completes, and a cold read
 * measured why: **the SDK itself awaits JSON parsing before it constructs the server**, so the
 * auth and factory counters can both read zero while `handler.fetch` has already been called.
 * Catching that needs a counter on the handler call itself, which this arm does not have.
 */
test('H13-security-ordering — Origin and auth precede intake, which precedes SDK admission', async () => {
    arm('H13-security-ordering');
    let authCalls = 0;
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => { authCalls += 1; return authenticated(); },
        () => { factoryCalls += 1; return stubServer(); }
    );
    let invalid;
    let partial;
    try {
        invalid = await rawClient(handle);
        invalid.socket.write(rawHead(handle, 200, {
            Origin: 'https://not-allowed.invalid'
        }) + '0123456789');
        await invalid.waitFor('HTTP/1.1 403');
        assert.equal(authCalls, 0);
        assert.equal(factoryCalls, 0);

        partial = await rawClient(handle);
        const body = discoverBody();
        const head = rawHead(handle, Buffer.byteLength(body));
        partial.socket.write(head + body.slice(0, 10));
        await new Promise(resolve => setTimeout(resolve, 50));
        assert.equal(authCalls, 1);
        assert.equal(factoryCalls, 0);

        // ⚠ `write`, not `end` — this arm expects a 200. It passed with `end` only by winning a race
        // against the FIN; see the socket-listener comment in `src/http.ts` for the measurement.
        partial.socket.write(body.slice(10));
        await partial.waitFor('HTTP/1.1 200');
        await bounded(partial.closed, 3_000, 'authorized response after full body');
        assert.equal(authCalls, 1);
        assert.equal(factoryCalls, 1);
    } finally {
        invalid?.socket.destroy();
        partial?.socket.destroy();
        await handle.close();
    }
});

/** Mutation caught: remove the bounded collector's maximum-size refusal. */
test('H14-request-body-cap — a chunked body beyond the fixed maximum is 413 before factory', async () => {
    arm('H14-request-body-cap');
    let factoryCalls = 0;
    const handle = await listeningServer(
        () => authenticated(),
        () => { factoryCalls += 1; return stubServer(); }
    );
    const client = await rawClient(handle);
    try {
        const payload = Buffer.alloc(MAX_HTTP_REQUEST_BYTES + 1, 0x20);
        const head = rawHead(handle, null, { 'Transfer-Encoding': 'chunked' });
        // ⚠ `write`, not `end` — this arm expects a 413 back. Same measurement as H10 and H13.
        client.socket.write(Buffer.concat([
            Buffer.from(head),
            Buffer.from(`${payload.length.toString(16)}\r\n`),
            payload,
            Buffer.from('\r\n0\r\n\r\n')
        ]));
        await client.waitFor('HTTP/1.1 413', 5_000);
        await bounded(client.closed, 3_000, 'oversize 413 response');
        assert.equal(finalResponse(client.bytes()).status, 413);
        assert.equal(factoryCalls, 0);
    } finally {
        client.socket.destroy();
        await handle.close();
    }
});

test('H15-auth-401-no-tool — missing, malformed and wrong bearer values share one denial', async () => {
    arm('H15-auth-401-no-tool');
    const token = Buffer.alloc(32, 0x21).toString('base64url');
    const wrong = Buffer.alloc(32, 0x22).toString('base64url');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const nonCanonical = wrong.slice(0, -1)
        + alphabet[alphabet.indexOf(wrong.at(-1)) + 1];
    assert.equal(Buffer.from(nonCanonical, 'base64url').equals(Buffer.from(wrong, 'base64url')), true);
    let factoryCalls = 0;
    let toolCalls = 0;
    const handle = await listeningServer(
        createReadTokenVerifier(Buffer.from(token, 'base64url')),
        () => {
            factoryCalls += 1;
            return heldToolServer(async () => {
                toolCalls += 1;
                return { content: [{ type: 'text', text: 'authenticated' }] };
            });
        }
    );
    let partial;
    try {
        // No body byte is sent. Receiving the complete denial proves collectBody() was not entered:
        // the previous ordering would wait indefinitely for the declared body before authenticating.
        partial = await rawClient(handle);
        const partialBody = toolCallBody();
        partial.socket.write(rawHead(handle, Buffer.byteLength(partialBody), {
            'Mcp-Method': 'tools/call',
            'Mcp-Name': 'hold'
        }));
        await partial.waitFor('Authentication required. Send Authorization: Bearer <Reader token>.');
        assert.match(partial.bytes().toString('utf8'), /HTTP\/1\.1 401 Unauthorized/);
        assert.match(partial.bytes().toString('utf8'), /WWW-Authenticate: Bearer realm="wyrd"/i);
        partial.socket.destroy();

        const denials = [];
        for (const authorization of [
            undefined,
            'Basic not-a-bearer',
            'Bearer malformed',
            `Bearer ${nonCanonical}`,
            `Bearer ${wrong}`
        ]) {
            denials.push(await responseShape(await toolCall(handle, authorization)));
        }
        const expected = {
            status: 401,
            challenge: 'Bearer realm="wyrd"',
            cacheControl: 'no-store',
            contentType: 'text/plain; charset=utf-8',
            body: 'Authentication required. Send Authorization: Bearer <Reader token>.\n'
        };
        for (const denial of denials) assert.deepEqual(denial, expected);
        assert.doesNotMatch(JSON.stringify(denials), /error_description|missing|malformed|wrong/i);
        assert.equal(factoryCalls, 0);
        assert.equal(toolCalls, 0);

        const accepted = await toolCall(handle, `Bearer ${token}`);
        const acceptedBody = await accepted.text();
        assert.equal(accepted.status, 200, acceptedBody);
        assert.equal(JSON.parse(acceptedBody).result.content[0].text, 'authenticated');
        assert.equal(factoryCalls, 1);
        assert.equal(toolCalls, 1);
    } finally {
        partial?.socket.destroy();
        await handle.close();
    }
});

test('H16-verifier-injection-real-socket — main uses the injected verifier factory', async () => {
    arm('H16-verifier-injection-real-socket');
    const configured = Buffer.alloc(32, 0x31).toString('base64url');
    const sentinel = Buffer.alloc(32, 0x32).toString('base64url');
    let verifierFactoryCalls = 0;
    let verifierCalls = 0;
    const lines = [];
    const result = await main(mainDeps({
        argv: ['--grant', 'C:\\granted', '--http', '0'],
        env: { WYRD_READ_TOKEN: configured },
        stderr: line => lines.push(line),
        makeConfiguredServer: () => stubServer('injected-verifier-reader'),
        makeReadAuthInfo: () => {
            verifierFactoryCalls += 1;
            return ({ authorization }) => {
                verifierCalls += 1;
                if (authorization === 'Bearer verifier-unavailable') return { kind: 'unavailable' };
                return authorization === `Bearer ${sentinel}`
                    ? authenticated(sentinel)
                    : { kind: 'unauthenticated' };
            };
        }
    }));
    assert.notEqual(result.http, null);
    try {
        const denied = await discover(result.http);
        assert.equal(denied.status, 401);
        await denied.text();

        const unavailable = await discover(result.http, undefined, 'Bearer verifier-unavailable');
        assert.equal(unavailable.status, 503);
        assert.equal(unavailable.headers.get('cache-control'), 'no-store');
        assert.equal(await unavailable.text(), 'Authentication service unavailable.\n');

        const accepted = await discover(result.http, undefined, `Bearer ${sentinel}`);
        const body = await accepted.text();
        assert.equal(accepted.status, 200, body);
        assert.equal(JSON.parse(body).result._meta[SERVER_INFO_META_KEY].name, 'injected-verifier-reader');
        assert.equal(verifierFactoryCalls, 1);
        assert.equal(verifierCalls, 3);
        assert.doesNotMatch(lines.join('\n'), new RegExp(`${configured}|${sentinel}`));
    } finally {
        await result.http.close();
    }
});

test('H17-no-query-token-or-leak — query-bearing /mcp is refused before the verifier', async () => {
    arm('H17-no-query-token-or-leak');
    const sentinel = Buffer.alloc(32, 0x41).toString('base64url');
    let verifierCalls = 0;
    let factoryCalls = 0;
    const lines = [];
    const result = await main(mainDeps({
        argv: ['--grant', 'C:\\granted', '--http', '0'],
        env: { WYRD_READ_TOKEN: sentinel },
        stderr: line => lines.push(line),
        makeReadAuthInfo: expected => {
            const production = createReadTokenVerifier(expected);
            return request => {
                verifierCalls += 1;
                return production(request);
            };
        },
        makeConfiguredServer: () => {
            factoryCalls += 1;
            return stubServer();
        }
    }));
    assert.notEqual(result.http, null);
    try {
        const bodies = [];
        for (const route of [
            `/mcp?access_token=${encodeURIComponent(sentinel)}`,
            '/mcp?x=1'
        ]) {
            const response = await toolCall(result.http, undefined, route);
            const body = await response.text();
            assert.equal(response.status, 404);
            assert.equal(body, 'Not Found\n');
            bodies.push(body);
        }
        assert.equal(verifierCalls, 0);
        assert.equal(factoryCalls, 0);
        const sinks = `${lines.join('\n')}\n${bodies.join('\n')}`;
        assert.equal(sinks.includes(sentinel), false);
        assert.doesNotMatch(sinks, /access_token|\/mcp\?/);
    } finally {
        await result.http.close();
    }
});

test('H18-no-token-refuses-before-listen — every invalid source refuses before startHttp', async () => {
    arm('H18-no-token-refuses-before-listen');
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-read-token-'));
    const validFile = path.join(temporary, 'reader-token');
    const invalidFile = path.join(temporary, 'invalid-token');
    const missingFile = path.join(temporary, 'missing-token');
    const observeFile = path.join(temporary, 'must-not-be-written.jsonl');
    const token = Buffer.alloc(32, 0x51).toString('base64url');
    const unexpectedHandles = [];
    let startCalls = 0;
    try {
        fs.writeFileSync(validFile, `${token}\r\n`);
        fs.writeFileSync(invalidFile, 'not a token\n');
        if (process.platform !== 'win32') {
            fs.chmodSync(validFile, 0o600);
            fs.chmodSync(invalidFile, 0o600);
        }
        const loaded = loadReadToken(['--read-token-file', validFile], {});
        assert.equal(loaded.ok, true);
        assert.equal(loaded.token.toString('base64url'), token);

        const port = await reserveLoopbackPort();
        const cases = [
            { name: 'absent', argv: [], env: {} },
            {
                name: 'both sources',
                argv: ['--read-token-file', validFile],
                env: { WYRD_READ_TOKEN: token }
            },
            { name: 'malformed environment', argv: [], env: { WYRD_READ_TOKEN: 'not-a-token' } },
            { name: 'malformed file', argv: ['--read-token-file', invalidFile], env: {} },
            { name: 'unreadable file', argv: ['--read-token-file', missingFile], env: {} }
        ];
        if (process.platform !== 'win32') {
            const insecureFile = path.join(temporary, 'insecure-token');
            fs.writeFileSync(insecureFile, token, { mode: 0o644 });
            fs.chmodSync(insecureFile, 0o644);
            cases.push({ name: 'insecure POSIX mode', argv: ['--read-token-file', insecureFile], env: {} });
        }

        const bindModes = [
            { name: 'loopback', argv: ['--http', `127.0.0.1:${port}`] },
            {
                name: 'network',
                argv: ['--http', `192.0.2.1:${port}`, '--http-public']
            }
        ];
        for (const bindMode of bindModes) {
            for (const sourceCase of cases) {
                const label = `${bindMode.name}: ${sourceCase.name}`;
                const lines = [];
                const result = await main(mainDeps({
                    argv: [
                        '--grant',
                        'C:\\granted',
                        ...bindMode.argv,
                        ...sourceCase.argv
                    ],
                    env: sourceCase.env,
                    stderr: line => lines.push(line),
                    startHttp: async options => {
                        startCalls += 1;
                        const handle = await startHttp(options);
                        unexpectedHandles.push(handle);
                        return handle;
                    }
                }));
                if (result.http !== null) unexpectedHandles.push(result.http);
                assert.equal(result.started, false, label);
                assert.equal(result.reason, 'READ_TOKEN', label);
                const disclosure = lines.join('\n');
                assert.equal(disclosure.includes(token), false, label);
                assert.equal(disclosure.includes(validFile), false, label);
                assert.equal(disclosure.includes(invalidFile), false, label);
                assert.equal(disclosure.includes(missingFile), false, label);
            }
        }
        assert.equal(startCalls, 0, 'startHttp must never be called for a refused token source');
        await assertLoopbackRefused(port);

        const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
        const indexPath = path.join(packageRoot, 'dist', 'index.js');
        const first = await runTokenCommand(indexPath, observeFile);
        const second = await runTokenCommand(indexPath, observeFile);
        assert.deepEqual({ code: first.code, signal: first.signal, stderr: first.stderr }, {
            code: 0,
            signal: null,
            stderr: ''
        });
        assert.deepEqual({ code: second.code, signal: second.signal, stderr: second.stderr }, {
            code: 0,
            signal: null,
            stderr: ''
        });
        assert.match(first.stdout, /^[A-Za-z0-9_-]{43}\n$/);
        assert.match(second.stdout, /^[A-Za-z0-9_-]{43}\n$/);
        assert.notEqual(first.stdout, second.stdout);
        /**
         * ⚠⚠ THIS ASSERTION WAS INVERTED WHEN THE ARM WAS WRITTEN, AND THE TWO ARMS CONTRADICTED
         * EACH OTHER. It read `existsSync(observeFile) === false` — "token generation must not
         * install the write-capable observer" — which forced the `token` branch ABOVE
         * `installObserver()` in `src/index.ts`, and that **reddened `S10-bootstrap-order`**, whose
         * whole job is to assert nothing is imported before the hook is armed.
         *
         * Resolved on the measurement rather than by picking an arm: `installObserver` is a **no-op
         * unless `WYRD_OBSERVE` is set** (`src/observe.ts:45`–`:46`), so in production
         * `wyrd-mcp token` writes nothing either way and the conflict exists only under the
         * harness's own instrumentation. Arming before every branch keeps `S10`'s guarantee
         * universal; a log file on this path appears only when an operator has explicitly opted into
         * observation.
         *
         * What matters to a user, and what is asserted instead: **the token never reaches the
         * observation log.** That is the property worth pinning — a secret must not leak into a
         * debugging artifact.
         */
        if (fs.existsSync(observeFile)) {
            const observed = fs.readFileSync(observeFile, 'utf8');
            assert.doesNotMatch(observed, /[A-Za-z0-9_-]{43}/,
                'the generated token must never appear in the observation log');
            assert.ok(!observed.includes(first.stdout.trim()),
                'the generated token must never appear in the observation log');
        }
    } finally {
        for (const handle of new Set(unexpectedHandles)) await handle.close();
        fs.rmSync(temporary, { recursive: true, force: true });
    }
});

/**
 * Criterion 16, STRUCTURAL ONLY.
 *
 * What implementation would still pass this? One that tees `source.body`, forwards one branch
 * immediately, and retains every chunk from the other branch: it streams and uses no whole-body
 * Response method while still adding a resident copy. The platform exposes no stable allocation
 * hook that can distinguish that copy from its own networking buffers. That gap is why this arm
 * does NOT claim comparative HTTP/stdio heap parity or a resident-copy count.
 *
 * The injected two-part Response is the SDK's normal JSON bytes with its tail held back. Receiving
 * the first part before releasing the tail proves the bridge does not manually accumulate the
 * stream to EOF; the throwing method sentinels cover the platform's whole-body materializers. The
 * final client accumulation is test observation after the network boundary, not the Reader path.
 */
test('H19-response-stream — a real maximum-window read streams before source EOF', async () => {
    arm('H19-response-stream');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-stream-'));
    const file = path.join(base, 'page.md');
    const payload = Buffer.alloc(MAX_WINDOW_BYTES, 0x61);
    const payloadText = payload.toString('utf8');
    fs.writeFileSync(file, payload);
    const readCalls = [];
    const handle = await listeningServer(
        () => authenticated(),
        realReaderFactory(base, readCalls)
    );
    const materializers = ['arrayBuffer', 'text', 'json', 'bytes', 'blob', 'formData'];
    const originals = new Map(materializers.map(name => [
        name,
        Object.getOwnPropertyDescriptor(Response.prototype, name)
    ]));
    const responseJsonDescriptor = Object.getOwnPropertyDescriptor(Response, 'json');
    const originalResponseJson = Response.json;
    const releaseTail = deferred();
    const attempted = [];
    let splitResponses = 0;
    try {
        for (const name of materializers) {
            Response.prototype[name] = function forbiddenWholeBodyMaterializer() {
                attempted.push(name);
                throw new Error(`whole-body Response.${name}() is forbidden in H19`);
            };
        }
        Response.json = function splitCostResponse(value, init) {
            const ordinary = originalResponseJson.call(Response, value, init);
            if (value?.result?.content?.[1]?.text !== payloadText) return ordinary;
            splitResponses += 1;
            const encoded = new TextEncoder().encode(JSON.stringify(value));
            const split = Math.floor(encoded.byteLength / 2);
            const body = new ReadableStream({
                start(controller) {
                    controller.enqueue(encoded.subarray(0, split));
                    void releaseTail.promise.then(() => {
                        controller.enqueue(encoded.subarray(split));
                        controller.close();
                    }, error => controller.error(error));
                }
            });
            return new Response(body, {
                status: ordinary.status,
                statusText: ordinary.statusText,
                headers: ordinary.headers
            });
        };

        const response = await bounded(
            readCall(handle, { path: 'page.md', limit: MAX_WINDOW_BYTES }),
            3_000,
            'H19 response headers before source EOF'
        );
        assert.notEqual(response.body, null, 'the HTTP response must carry a body stream');
        const reader = response.body.getReader();
        const first = await bounded(reader.read(), 3_000, 'H19 first client chunk before source EOF');
        assert.equal(first.done, false);
        assert.equal(splitResponses, 1, 'the real read response must use the controlled two-part body');
        releaseTail.resolve();

        const decoder = new TextDecoder();
        let body = decoder.decode(first.value, { stream: true });
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                body += decoder.decode();
                break;
            }
            body += decoder.decode(value, { stream: true });
        }
        assert.equal(response.status, 200, body);
        const answer = JSON.parse(body);
        assert.equal(answer.result.content[1].text, payloadText);
        assert.deepEqual(readCalls, [
            { target: 'page.md', offset: 0, limit: MAX_WINDOW_BYTES }
        ]);
        assert.deepEqual(attempted, []);
    } finally {
        releaseTail.resolve();
        Object.defineProperty(Response, 'json', responseJsonDescriptor);
        for (const [name, descriptor] of originals) {
            if (descriptor === undefined) delete Response.prototype[name];
            else Object.defineProperty(Response.prototype, name, descriptor);
        }
        await handle.close();
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * Criterion 18.
 *
 * What implementation would still pass this? One specialised for this exact ASCII size and the
 * explicitly requested 262,144-byte window; this arm says nothing about the 32,768-byte default,
 * multi-byte boundary trimming, other file sizes, remote hosts, or sustained throughput. Those are
 * outside the fixed criterion. A whole-file buffer elsewhere could also pass; H19 is the separate,
 * explicitly bounded structural observation for that concern.
 *
 * Exactly 1 MiB is deliberate: four full maximum windows land exactly on EOF. Each window uses a
 * different ASCII byte, so a fence that ignores the offset cannot pass by returning four identical
 * chunks. The arm follows the returned pagination headers and records the real fence calls, so an
 * erroneous fifth call or an early `truncated: false` cannot be hidden by arithmetic in the test.
 */
test('H20-localhost-read-budget — 1 MiB is four explicit maximum-window calls under 400 ms', async () => {
    arm('H20-localhost-read-budget');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-budget-'));
    const file = path.join(base, 'one-mib.md');
    const fileBytes = 1_048_576;
    assert.equal(MAX_WINDOW_BYTES, 262_144, 'this cost criterion explicitly requests 262,144 bytes');
    let payload = Buffer.alloc(fileBytes);
    for (let window = 0; window < 4; window += 1) {
        payload.fill(0x41 + window, window * MAX_WINDOW_BYTES, (window + 1) * MAX_WINDOW_BYTES);
    }
    const expectedHash = createHash('sha256').update(payload).digest('hex');
    fs.writeFileSync(file, payload);
    payload = null;
    const readCalls = [];
    const handle = await listeningServer(
        () => authenticated(),
        realReaderFactory(base, readCalls)
    );
    try {
        let offset = 0;
        let callCount = 0;
        let returnedBytes = 0;
        const returnedHash = createHash('sha256');
        const started = performance.now();
        for (;;) {
            const response = await readCall(
                handle,
                { path: 'one-mib.md', offset, limit: MAX_WINDOW_BYTES },
                callCount + 1
            );
            const body = await response.text();
            assert.equal(response.status, 200, body);
            const answer = JSON.parse(body);
            const header = answer.result.content[0].text;
            const text = answer.result.content[1].text;
            const bytes = Buffer.byteLength(text, 'utf8');
            assert.equal(bytes, MAX_WINDOW_BYTES, `call ${callCount + 1} must return one full window`);
            returnedBytes += bytes;
            returnedHash.update(text, 'utf8');
            callCount += 1;

            if (/truncated: false/.test(header)) break;
            assert.match(header, /truncated: true/);
            const next = header.match(/next_offset: (\d+)/);
            assert.notEqual(next, null, header);
            offset = Number(next[1]);
            assert.ok(callCount < 5, 'a 1 MiB ASCII file must terminate within four calls');
        }
        const elapsedMs = performance.now() - started;

        assert.equal(callCount, 4);
        assert.equal(returnedBytes, fileBytes);
        assert.equal(returnedHash.digest('hex'), expectedHash);
        assert.deepEqual(readCalls, [0, 262_144, 524_288, 786_432].map(offset_ => ({
            target: 'one-mib.md',
            offset: offset_,
            limit: MAX_WINDOW_BYTES
        })));
        assert.ok(elapsedMs < 400, `four localhost reads took ${elapsedMs.toFixed(1)} ms; budget is <400 ms`);
    } finally {
        await handle.close();
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * Criteria 7 and 12: Origins are URL serializations, not host/port display strings.
 *
 * What implementation would still pass this? One that handles only the sampled address families
 * and spellings. The bracketed ::1 leg catches an IPv4-only formatter, but this arm says nothing
 * about hostname Origins (browser CORS is out of scope) or every equivalent IPv6 spelling.
 *
 * Port 80 is load-bearing: URL.origin omits its default port. A port-zero-only arm would stay green
 * if production blindly appended `:80`, then rejected the only Origin a conforming client sends.
 */
test('H21-origin-serialization — default-port and bracketed Origins use URL semantics', async () => {
    arm('H21-origin-serialization');
    const fixture = networkFixture();
    let networkHandle;
    try {
        try {
            const result = await main(mainDeps({
                argv: [
                    '--grant', 'C:\\granted',
                    '--http', `${fixture.argumentHost}:80`,
                    '--http-public'
                ],
                makeConfiguredServer: () => stubServer('default-port-network')
            }));
            assert.equal(result.started, true, 'main must accept port 80 on a consented network bind');
            assert.notEqual(result.http, null);
            networkHandle = result.http;
        } catch (error) {
            assert.fail(
                `H21 prerequisite: port 80 must be bindable on ${fixture.address}: ${error instanceof Error ? error.message : String(error)}`
            );
        }
        const expectedOrigin = `http://${fixture.urlHost}`;
        assert.equal(networkHandle.port, 80);
        assert.deepEqual([...networkHandle.allowedOrigins], [expectedOrigin]);
        assert.equal(networkHandle.address, fixture.urlHost);
        const response = await discover(
            networkHandle,
            expectedOrigin,
            `Bearer ${CONFIGURED_TOKEN}`
        );
        const body = await response.text();
        assert.equal(response.status, 200, body);
    } finally {
        await networkHandle?.close();
    }

    assert.deepEqual(readHttpArg(['--http', '0']).bind, {
        kind: 'loopback', host: '127.0.0.1', port: 0
    });
    const loopback = await startHttp({
        kind: 'loopback',
        host: '127.0.0.1',
        port: 0,
        readAuthInfo: () => authenticated(),
        makeServer: () => stubServer('zero-port-loopback')
    });
    try {
        assert.deepEqual([...loopback.allowedOrigins], [
            `http://127.0.0.1:${loopback.port}`,
            `http://localhost:${loopback.port}`
        ]);
    } finally {
        await loopback.close();
    }

    let ipv6;
    try {
        try {
            ipv6 = await startHttp({
                kind: 'loopback',
                host: '[::1]',
                port: 80,
                readAuthInfo: () => authenticated(),
                makeServer: () => stubServer('bracketed-ipv6-loopback')
            });
        } catch (error) {
            assert.fail(
                `H21 prerequisite: the local IPv6 loopback must be bindable: ${error instanceof Error ? error.message : String(error)}`
            );
        }
        assert.deepEqual([...ipv6.allowedOrigins], [
            'http://[::1]',
            'http://localhost'
        ]);
    } finally {
        await ipv6?.close();
    }
});

/**
 * Criterion 12: explicit consent plus independent pre- and post-listen consistency guards.
 *
 * What implementation would still pass this? A table-driven parser that recognizes only these
 * sampled spellings could accept an unsampled malformed address. The real-interface mismatch proves
 * startup cleanup and kernel-address agreement, but cannot prove reachability from another device,
 * through a firewall, or over any particular ingress route; this slice has no such instrument.
 */
test('H22-consent-and-guards — refusal table and both listener guards are enforced', async () => {
    arm('H22-consent-and-guards');

    assert.deepEqual(
        readHttpArg(['--http-public', '--http', '192.0.2.20:7777']).bind,
        { kind: 'network', host: '192.0.2.20', port: 7777 }
    );
    assert.deepEqual(
        readHttpArg(['--http', '[2001:db8::20]:7777', '--http-public']).bind,
        { kind: 'network', host: '[2001:db8::20]', port: 7777 }
    );
    assert.deepEqual(readHttpArg(['--http', '127.0.0.2:7777']).bind, {
        kind: 'loopback', host: '127.0.0.2', port: 7777
    });

    const refusals = [
        {
            name: 'network address without consent',
            argv: ['--http', '192.0.2.20:7777'],
            detail: /requires --http-public/
        },
        {
            name: 'IPv4 wildcard',
            argv: ['--http', '0.0.0.0:7777', '--http-public'],
            detail: /wildcard 0\.0\.0\.0/
        },
        {
            name: 'IPv6 wildcard',
            argv: ['--http', '[::]:7777', '--http-public'],
            detail: /wildcard ::/
        },
        {
            name: 'hostname',
            argv: ['--http', 'desktop.local:7777', '--http-public'],
            detail: /concrete numeric interface address/
        },
        {
            name: 'unbracketed IPv6',
            argv: ['--http', '2001:db8::20:7777', '--http-public'],
            detail: /must be bracketed/
        },
        {
            name: 'scoped IPv6',
            argv: ['--http', '[fe80::20%12]:7777', '--http-public'],
            detail: /scoped IPv6/
        },
        {
            name: 'IPv4 multicast',
            argv: ['--http', '239.1.2.3:7777', '--http-public'],
            detail: /multicast/
        },
        {
            name: 'IPv6 multicast',
            argv: ['--http', '[ff02::1]:7777', '--http-public'],
            detail: /multicast/
        },
        {
            name: 'broadcast',
            argv: ['--http', '255.255.255.255:7777', '--http-public'],
            detail: /broadcast/
        },
        {
            name: 'IPv4-mapped IPv6',
            argv: ['--http', '[::ffff:192.168.1.20]:7777', '--http-public'],
            detail: /IPv4-mapped IPv6/
        },
        {
            name: 'redundant loopback consent',
            argv: ['--http', '127.0.0.2:7777', '--http-public'],
            detail: /redundant or misplaced/
        },
        {
            name: 'orphan consent',
            argv: ['--http-public'],
            detail: /requires one --http address/
        },
        {
            name: 'duplicate HTTP selector',
            argv: ['--http', '80', '--http', '81'],
            detail: /only once/
        },
        {
            name: 'duplicate consent',
            argv: ['--http', '192.0.2.20:7777', '--http-public', '--http-public'],
            detail: /only once/
        },
        {
            name: 'valued consent',
            argv: ['--http', '192.0.2.20:7777', '--http-public=true'],
            detail: /value-less/
        },
        {
            name: 'malformed network port',
            argv: ['--http', '192.0.2.20:not-a-port', '--http-public'],
            detail: /port must be decimal/
        },
        {
            name: 'out-of-range network port',
            argv: ['--http', '192.0.2.20:65536', '--http-public'],
            detail: /outside 0\.\.65535/
        }
    ];
    for (const refusal of refusals) {
        const result = readHttpArg(refusal.argv);
        assert.equal(result.present, true, refusal.name);
        assert.equal(result.bind, null, refusal.name);
        assert.match(result.detail ?? '', refusal.detail, refusal.name);
    }

    let unconsentedStarts = 0;
    const unconsented = await main(mainDeps({
        argv: ['--grant', 'C:\\granted', '--http', '192.0.2.20:7777'],
        startHttp: async () => {
            unconsentedStarts += 1;
            assert.fail('main must refuse an unconsented network bind before startHttp');
        }
    }));
    assert.equal(unconsented.started, false);
    assert.equal(unconsented.reason, 'HTTP_BIND');
    assert.equal(unconsentedStarts, 0);

    let handlerConstructions = 0;
    const guardTwoCases = [
        { kind: 'loopback', host: '192.0.2.20' },
        { kind: 'network', host: '127.0.0.1' },
        { kind: 'unknown', host: '192.0.2.20' }
    ];
    for (const bind of guardTwoCases) {
        await assert.rejects(startHttp({
            ...bind,
            port: 0,
            readAuthInfo: () => authenticated(),
            makeServer: () => stubServer()
        }, {
            makeHandler: () => {
                handlerConstructions += 1;
                assert.fail('guard 2 must run before handler construction');
            }
        }), /bind kind (?:.* does not match host|is invalid)/);
    }
    assert.equal(handlerConstructions, 0);

    const fixture = networkFixture();
    const port = await reservePort(fixture.address);
    const reportedAddress = net.isIP(fixture.address) === 6
        ? '2001:db8::ffff'
        : '198.51.100.254';
    let handlerCloses = 0;
    let listenerCloses = 0;
    let listener;
    const fakeHandler = {
        fetch: async () => new Response('not reached'),
        close: async () => { handlerCloses += 1; }
    };
    let unexpectedHandle = null;
    let mismatchError = null;
    try {
        unexpectedHandle = await startHttp({
            kind: 'network',
            host: fixture.argumentHost,
            port,
            readAuthInfo: () => authenticated(),
            makeServer: () => stubServer()
        }, {
            makeHandler: (_factory, options) => {
                assert.deepEqual(options, { legacy: 'reject' });
                return fakeHandler;
            },
            makeListener: requestListener => {
                listener = http.createServer(requestListener);
                const realAddress = listener.address.bind(listener);
                const realClose = listener.close.bind(listener);
                listener.address = () => {
                    const value = realAddress();
                    return value === null || typeof value === 'string'
                        ? value
                        : { ...value, address: reportedAddress };
                };
                listener.close = callback => {
                    listenerCloses += 1;
                    return realClose(callback);
                };
                return listener;
            }
        });
    } catch (error) {
        mismatchError = error;
    }
    const handlerClosesAtSettlement = handlerCloses;
    const listenerClosesAtSettlement = listenerCloses;
    const listeningAtSettlement = listener?.listening ?? false;
    if (unexpectedHandle !== null) await unexpectedHandle.close();
    else if (listener?.listening) {
        await new Promise((resolve, reject) => {
            listener.close(error => error === undefined ? resolve() : reject(error));
        });
    }
    assert.ok(mismatchError instanceof Error, 'guard 3 must reject a reported-address mismatch');
    assert.match(mismatchError.message, /network listener reported .* not requested address/);
    assert.equal(handlerClosesAtSettlement, 1, 'guard 3 must close the MCP handler before rejecting');
    assert.equal(listenerClosesAtSettlement, 1, 'guard 3 must close the listener before rejecting');
    assert.equal(listeningAtSettlement, false, 'guard 3 must settle only after listener closure');
    await assertAddressRefused(fixture.address, port);
});

/**
 * Criteria 12 and 14: the human disclosure carries the exact limits of the network observation.
 *
 * What implementation would still pass this? One that prints these statements without them being
 * true of the machine. That is deliberate: they state what Wyrd does not observe. This arm does not
 * prove routing, firewall state, later network changes, packet secrecy, or hard-link containment.
 */
test('H23-network-disclosure-honesty — fixed-port network warning is exact and mode-scoped', async () => {
    arm('H23-network-disclosure-honesty');
    const fixture = networkFixture();
    const networkPort = await reservePort(fixture.address);
    assert.notEqual(networkPort, 0);
    const networkLines = [];
    const network = await main(mainDeps({
        argv: [
            '--grant', 'C:\\granted',
            '--http', `${fixture.argumentHost}:${networkPort}`,
            '--http-public'
        ],
        stderr: line => networkLines.push(line),
        makeConfiguredServer: () => stubServer('network-disclosure')
    }));
    assert.notEqual(network.http, null);
    try {
        const interfaceAddress = network.http.endpoint.interfaceAddress;
        const displayHost = net.isIP(interfaceAddress) === 6
            ? `[${interfaceAddress}]`
            : interfaceAddress;
        const origin = `http://${displayHost}:${networkPort}`;
        const networkOnlyLines = [
            'WHAT THIS MEANS, AND WHAT WYRD DOES NOT KNOW:',
            `  · Any device that can route packets to ${interfaceAddress} may reach this server.`,
            '  · wyrd does not know, and does not check, what can route to it. Firewalls, VPN',
            '    routes, container port publication and virtual-machine forwarding can all',
            '    deliver traffic here from outside the network you are thinking of.',
            '  · This address was checked ONCE, just now. If this machine later joins a VPN or',
            '    changes networks, wyrd will not re-check it and will not print this again.',
            '  · TLS is off, so the bearer token travels in the clear and can be replayed by',
            '    anyone who captures it.',
            '  · A hard link that already exists inside the granted folder serves the file it',
            '    points at, even when that file lives outside the folder.'
        ];
        const expectedNetwork = [
            `wyrd Reader is listening on the network interface at ${interfaceAddress}, port ${networkPort}.`,
            `Endpoint: ${origin}/mcp.`,
            'Transport: plain HTTP. TLS is off.',
            '',
            ...networkOnlyLines,
            '',
            'It accepts POST /mcp only.',
            `Allowed Origin values: ${origin}. An absent Origin proceeds.`,
            'Bearer authentication is required to use POST /mcp.',
            'The one canonical grant is: C:\\canonical-grant',
            'Its only tool is `read`; the tool surface is read-only.'
        ].join('\n');
        assert.deepEqual(networkLines, [expectedNetwork]);

        const loopbackPort = await reserveLoopbackPort();
        assert.notEqual(loopbackPort, 0);
        const loopbackLines = [];
        const loopback = await main(mainDeps({
            argv: ['--grant', 'C:\\granted', '--http', `127.0.0.1:${loopbackPort}`],
            stderr: line => loopbackLines.push(line),
            makeConfiguredServer: () => stubServer('loopback-disclosure')
        }));
        assert.notEqual(loopback.http, null);
        try {
            const expectedLoopback = [
                `wyrd Reader is listening only on this machine, through the loopback interface at 127.0.0.1, port ${loopbackPort}.`,
                `Endpoint: http://127.0.0.1:${loopbackPort}/mcp.`,
                'Transport: plain HTTP. TLS is off.',
                'It accepts POST /mcp only.',
                `Allowed Origin values: http://127.0.0.1:${loopbackPort}, http://localhost:${loopbackPort}. An absent Origin proceeds.`,
                'Bearer authentication is required to use POST /mcp.',
                'The one canonical grant is: C:\\canonical-grant',
                'Its only tool is `read`; the tool surface is read-only.'
            ].join('\n');
            assert.deepEqual(loopbackLines, [expectedLoopback]);
            for (const networkOnlyLine of networkOnlyLines) {
                assert.equal(
                    loopbackLines[0].includes(networkOnlyLine),
                    false,
                    `loopback disclosure must omit ${JSON.stringify(networkOnlyLine)}`
                );
            }
        } finally {
            await loopback.http.close();
        }
    } finally {
        await network.http.close();
    }
});

/**
 * Criterion 14: a real non-loopback listener remains plain HTTP and enforces the real bearer token.
 *
 * What implementation would still pass this? One that leaks the token through an unexercised path
 * or exposes a different route. This arm does not capture packets, prove secrecy, prove any remote
 * machine can route to the address, or establish TLS; it proves the intentionally clear-text path.
 */
test('H24-network-plain-http-auth — fixed-port off-loopback requests require the bearer token', async () => {
    arm('H24-network-plain-http-auth');
    const fixture = networkFixture();
    const port = await reservePort(fixture.address);
    assert.notEqual(port, 0);
    const result = await main(mainDeps({
        argv: [
            '--grant', 'C:\\granted',
            '--http', `${fixture.argumentHost}:${port}`,
            '--http-public'
        ],
        makeConfiguredServer: () => stubServer('authenticated-network-reader')
    }));
    assert.notEqual(result.http, null);
    try {
        assert.equal(result.http.port, port);
        assert.deepEqual(result.http.endpoint, {
            scheme: 'http',
            tlsEnabled: false,
            interfaceAddress: fixture.address,
            exposure: 'network'
        });
        assert.equal(result.http.allowedOrigins.length, 1);
        assert.match(result.http.allowedOrigins[0], /^http:\/\//);

        const missing = await discover(result.http);
        assert.equal(missing.status, 401);
        await missing.text();
        const wrong = await discover(result.http, undefined, 'Bearer wrong');
        assert.equal(wrong.status, 401);
        await wrong.text();
        const accepted = await discover(
            result.http,
            undefined,
            `Bearer ${CONFIGURED_TOKEN}`
        );
        const body = await accepted.text();
        assert.equal(accepted.status, 200, body);
        assert.equal(
            JSON.parse(body).result._meta[SERVER_INFO_META_KEY].name,
            'authenticated-network-reader'
        );
    } finally {
        await result.http.close();
    }
});

/**
 * The certificate command grammar and host screen.
 *
 * What implementation would still pass this? One that recognizes only this refusal table and
 * mishandles an unsampled IDNA or address spelling. It does not perform DNS resolution, prove the
 * host belongs to this machine, or assert that any generated certificate is trusted.
 */
test('H25-cert-host-grammar — the exact command accepts canonical hosts and refuses unsafe shapes', async () => {
    arm('H25-cert-host-grammar');
    assert.deepEqual(parseCertificateHost('BÜCHER.Example'), {
        canonical: 'xn--bcher-kva.example', kind: 'dns'
    });
    assert.deepEqual(parseCertificateHost('192.0.2.10'), {
        canonical: '192.0.2.10', kind: 'ip'
    });
    assert.deepEqual(parseCertificateHost('2001:0db8::1'), {
        canonical: '2001:db8::1', kind: 'ip'
    });

    const refusals = [
        '*.example.test',
        'https://example.test',
        'example.test:443',
        '[::1]',
        'fe80::1%12',
        '0.0.0.0',
        '::',
        '239.1.2.3',
        'ff02::1',
        '255.255.255.255',
        '::ffff:127.0.0.1',
        '999.1.2.3',
        '2001:::1'
    ];
    for (const host of refusals) {
        assert.throws(() => parseCertificateHost(host), Error, host);
    }

    const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-cert-grammar-'));
    try {
        const result = await runCertCommand(
            path.join(packageRoot, 'dist', 'index.js'),
            temporary,
            ['--host=localhost']
        );
        assert.deepEqual({ code: result.code, signal: result.signal, stdout: result.stdout }, {
            code: 2,
            signal: null,
            stdout: ''
        });
        assert.match(result.stderr, /usage: wyrd-mcp cert --host/);
        assert.equal(fs.existsSync(path.join(temporary, CERTIFICATE_FILENAME)), false);
        assert.equal(fs.existsSync(path.join(temporary, PRIVATE_KEY_FILENAME)), false);
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
});

/**
 * Refuse-to-overwrite, exclusive creation, permissions, and bounded rollback.
 *
 * What implementation would still pass this? One whose identity check is defeated by a filesystem
 * that reports unstable or non-unique dev/ino values, or whose rollback races after the sampled
 * check. The arm does not promise atomic commitment across the two directory entries.
 */
test('H26-cert-exclusive-write — existing entries and races never overwrite either destination', async () => {
    arm('H26-cert-exclusive-write');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-cert-exclusive-'));
    const generated = await generateSelfSignedCertificate(parseCertificateHost('localhost'));
    try {
        for (const existingName of [CERTIFICATE_FILENAME, PRIVATE_KEY_FILENAME]) {
            const directory = path.join(base, `existing-${existingName}`);
            fs.mkdirSync(directory);
            const existingPath = path.join(directory, existingName);
            fs.writeFileSync(existingPath, 'sentinel');
            let generations = 0;
            await assert.rejects(createCertificateFiles('localhost', directory, {
                generate: async () => { generations += 1; return generated; }
            }), /refusing to overwrite existing path/);
            assert.equal(generations, 0, `${existingName}: generation must follow both lstat checks`);
            assert.equal(fs.readFileSync(existingPath, 'utf8'), 'sentinel');
            const other = existingName === CERTIFICATE_FILENAME
                ? PRIVATE_KEY_FILENAME
                : CERTIFICATE_FILENAME;
            assert.equal(fs.existsSync(path.join(directory, other)), false);
        }

        const danglingDirectory = path.join(base, 'dangling');
        fs.mkdirSync(danglingDirectory);
        const danglingCertificate = path.join(danglingDirectory, CERTIFICATE_FILENAME);
        fs.symlinkSync(path.join(danglingDirectory, 'missing-target'), danglingCertificate, 'file');
        let danglingGenerations = 0;
        await assert.rejects(createCertificateFiles('localhost', danglingDirectory, {
            generate: async () => { danglingGenerations += 1; return generated; }
        }), /refusing to overwrite existing path/);
        assert.equal(danglingGenerations, 0);
        assert.equal(fs.existsSync(danglingCertificate), false, 'the fixture must remain dangling');
        assert.equal(fs.lstatSync(danglingCertificate).isSymbolicLink(), true);
        assert.equal(fs.existsSync(path.join(danglingDirectory, PRIVATE_KEY_FILENAME)), false);

        const raced = path.join(base, 'raced');
        fs.mkdirSync(raced);
        let arrivals = 0;
        const release = deferred();
        const generateAtBarrier = async () => {
            arrivals += 1;
            if (arrivals === 2) release.resolve();
            await release.promise;
            return generated;
        };
        const outcomes = await Promise.allSettled([
            createCertificateFiles('localhost', raced, { generate: generateAtBarrier }),
            createCertificateFiles('localhost', raced, { generate: generateAtBarrier })
        ]);
        assert.equal(arrivals, 2, 'both invocations must pass their prechecks before either open');
        assert.equal(outcomes.filter(result => result.status === 'fulfilled').length, 1);
        assert.equal(outcomes.filter(result => result.status === 'rejected').length, 1);
        assert.equal(fs.readFileSync(path.join(raced, CERTIFICATE_FILENAME), 'utf8'), generated.certificatePem);
        assert.equal(fs.readFileSync(path.join(raced, PRIVATE_KEY_FILENAME), 'utf8'), generated.privateKeyPem);
        if (process.platform !== 'win32') {
            assert.equal(fs.statSync(path.join(raced, PRIVATE_KEY_FILENAME)).mode & 0o077, 0);
        }

        const rollback = path.join(base, 'rollback');
        fs.mkdirSync(rollback);
        await assert.rejects(createCertificateFiles('localhost', rollback, {
            generate: async () => {
                fs.writeFileSync(path.join(rollback, PRIVATE_KEY_FILENAME), 'racing-owner');
                return generated;
            }
        }), error => {
            assert.equal(error?.code, 'EEXIST');
            return true;
        });
        assert.equal(fs.existsSync(path.join(rollback, CERTIFICATE_FILENAME)), false);
        assert.equal(fs.readFileSync(path.join(rollback, PRIVATE_KEY_FILENAME), 'utf8'), 'racing-owner');
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * Certificate content, computed output, and freshness across command executions.
 *
 * What implementation would still pass this? One using a weak or predictable random source that
 * happens to differ twice, or a library that emits these sampled extensions while adding an
 * unasserted one. It does not prove any platform trust instructions are correct.
 */
test('H27-cert-content-and-freshness — generated parameters, printed facts, serial and key are live', async () => {
    arm('H27-cert-content-and-freshness');
    const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-cert-content-'));
    const firstDirectory = path.join(base, 'first');
    const secondDirectory = path.join(base, 'second');
    fs.mkdirSync(firstDirectory);
    fs.mkdirSync(secondDirectory);
    try {
        const indexPath = path.join(packageRoot, 'dist', 'index.js');
        const first = await runCertCommand(indexPath, firstDirectory, ['--host', 'BÜCHER.Example']);
        const second = await runCertCommand(indexPath, secondDirectory, ['--host', 'BÜCHER.Example']);
        for (const result of [first, second]) {
            assert.deepEqual({ code: result.code, signal: result.signal, stderr: result.stderr }, {
                code: 0,
                signal: null,
                stderr: ''
            });
        }

        const firstPem = fs.readFileSync(path.join(firstDirectory, CERTIFICATE_FILENAME), 'utf8');
        const firstKey = fs.readFileSync(path.join(firstDirectory, PRIVATE_KEY_FILENAME), 'utf8');
        const secondPem = fs.readFileSync(path.join(secondDirectory, CERTIFICATE_FILENAME), 'utf8');
        const firstCertificate = new X509Certificate(firstPem);
        const secondCertificate = new X509Certificate(secondPem);
        assert.equal(firstCertificate.checkPrivateKey(createPrivateKey(firstKey)), true);
        assert.equal(firstCertificate.ca, true);
        assert.equal(firstCertificate.publicKey.asymmetricKeyType, 'rsa');
        assert.equal(firstCertificate.publicKey.asymmetricKeyDetails?.modulusLength, 2048);
        assert.equal(
            firstCertificate.subjectAltName,
            'DNS:xn--bcher-kva.example, IP Address:127.0.0.1, DNS:localhost'
        );

        const imported = await import('node-forge');
        const forge = imported.default ?? imported;
        const forgeCertificate = forge.pki.certificateFromPem(firstPem);
        assert.equal(forgeCertificate.signatureOid, forge.pki.oids.sha256WithRSAEncryption);
        assert.deepEqual(
            {
                ca: forgeCertificate.getExtension('basicConstraints').cA,
                pathLength: forgeCertificate.getExtension('basicConstraints').pathLenConstraint,
                serverAuth: forgeCertificate.getExtension('extKeyUsage').serverAuth,
                clientAuth: forgeCertificate.getExtension('extKeyUsage').clientAuth
            },
            { ca: true, pathLength: 0, serverAuth: true, clientAuth: undefined }
        );

        const validFrom = new Date(firstCertificate.validFrom);
        const validTo = new Date(firstCertificate.validTo);
        assert.equal(validTo.getTime() - validFrom.getTime(), 397 * 24 * 60 * 60 * 1_000);
        assert.ok(validFrom.getTime() <= Date.now());
        assert.ok(validFrom.getTime() >= Date.now() - 6 * 60 * 1_000);
        assert.match(first.stdout, /Created wyrd-cert\.pem and wyrd-key\.pem for xn--bcher-kva\.example\./);
        assert.ok(first.stdout.includes(`Certificate SHA-256 fingerprint: ${firstCertificate.fingerprint256}`));
        assert.ok(first.stdout.includes(`Subject alternative names: ${firstCertificate.subjectAltName}`));
        assert.ok(first.stdout.includes(`Valid from: ${validFrom.toISOString()}`));
        assert.ok(first.stdout.includes(`Valid until: ${validTo.toISOString()}`));
        for (const platform of ['Windows:', 'macOS:', 'iOS/iPadOS:', 'Android:']) {
            assert.ok(first.stdout.includes(platform), platform);
        }
        assert.notEqual(firstCertificate.serialNumber, secondCertificate.serialNumber);
        assert.notDeepEqual(
            firstCertificate.publicKey.export({ type: 'spki', format: 'der' }),
            secondCertificate.publicKey.export({ type: 'spki', format: 'der' })
        );
        if (process.platform !== 'win32') {
            assert.equal(fs.statSync(path.join(firstDirectory, PRIVATE_KEY_FILENAME)).mode & 0o077, 0);
        } else {
            assert.match(first.stdout, /inherits this directory's NTFS permissions/);
        }
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * Directed serial boundaries and an independent walk of the emitted certificate's DER INTEGERs.
 *
 * What implementation would still pass this? A future entropy-derived INTEGER whose rare boundary
 * is not injected here, or a non-INTEGER DER defect. Freshness and serial policy remain H27's job.
 */
test('H33-certificate-der-minimal-integers — directed serial boundaries keep every INTEGER canonical', async () => {
    arm('H33-certificate-der-minimal-integers');
    const fill = (prefix, octet) => Buffer.from([...prefix, ...Array(16 - prefix.length).fill(octet)]);
    const cases = [
        {
            label: '00 01',
            candidates: [fill([0x00, 0x01], 0x11)],
            expectedSerial: Buffer.from([0x01, ...Array(14).fill(0x11)])
        },
        {
            label: '00 80',
            candidates: [fill([0x00, 0x80], 0x22)],
            expectedSerial: fill([0x00, 0x80], 0x22)
        },
        {
            label: '7f',
            candidates: [fill([0x7f], 0x33)],
            expectedSerial: fill([0x7f], 0x33)
        },
        {
            label: '80',
            candidates: [fill([0x80], 0x44)],
            expectedSerial: Buffer.from([0x00, ...fill([0x80], 0x44)])
        },
        {
            label: '00 00 01',
            candidates: [fill([0x00, 0x00, 0x01], 0x55)],
            expectedSerial: Buffer.from([0x01, ...Array(13).fill(0x55)])
        },
        {
            label: 'all-zero retry then 00 01',
            candidates: [Buffer.alloc(16), fill([0x00, 0x01], 0x66)],
            expectedSerial: Buffer.from([0x01, ...Array(14).fill(0x66)])
        }
    ];

    for (const fixture of cases) {
        let calls = 0;
        const generated = await generateSelfSignedCertificate(
            parseCertificateHost('localhost'),
            count => {
                assert.equal(count, 16, `${fixture.label}: serial entropy request size`);
                assert.ok(calls < fixture.candidates.length, `${fixture.label}: unexpected entropy call`);
                const candidate = fixture.candidates[calls];
                calls += 1;
                return candidate;
            }
        );
        assert.equal(calls, fixture.candidates.length, `${fixture.label}: serial entropy call count`);

        const base64 = generated.certificatePem
            .replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/gu, '');
        const { root, integers } = assertMinimalDerIntegers(Buffer.from(base64, 'base64'));
        const serial = certificateSerialNumber(root);
        assert.ok(integers.includes(serial), `${fixture.label}: serial must be among walked INTEGERs`);
        assert.ok((serial.content[0] & 0x80) === 0, `${fixture.label}: serial must be positive`);
        assert.ok(serial.content.some(octet => octet !== 0), `${fixture.label}: serial must be non-zero`);
        assert.deepEqual(serial.content, fixture.expectedSerial, `${fixture.label}: directed serial bytes`);
    }
});

/**
 * Criterion 15: the generated certificate succeeds only when explicitly trusted.
 *
 * What implementation would still pass this? One that generates a fresh valid certificate but
 * prints unusable platform instructions, or one whose server fails after the handshake at HTTP or
 * MCP. H27, not this arm, prevents a hard-coded pair and checks the requested SAN and parameters.
 */
test('H28-generated-cert-trust-control — trusted handshake succeeds and the untrusted control fails', async () => {
    arm('H28-generated-cert-trust-control');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-cert-handshake-'));
    let handle;
    try {
        const created = await createCertificateFiles('localhost', directory);
        const loaded = await loadTlsConfiguration({
            certificatePath: created.certificatePath,
            privateKeyPath: created.privateKeyPath
        });
        assert.equal(loaded.ok, true);
        handle = await startHttp({
            kind: 'loopback',
            host: '127.0.0.1',
            port: 0,
            tls: loaded.configuration,
            readAuthInfo: () => authenticated(),
            makeServer: () => stubServer('tls-handshake-reader')
        });
        const trusted = await trustedTlsHandshake(handle, created.certificatePem);
        assert.deepEqual(trusted, { authorized: true, authorizationError: null });
        await assert.rejects(trustedTlsHandshake(handle), error => {
            assert.equal(error?.code, 'DEPTH_ZERO_SELF_SIGNED_CERT');
            return true;
        });
    } finally {
        await handle?.close();
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

/**
 * Both-or-neither arguments and pre-bind material validation.
 *
 * What implementation would still pass this? One that validates only the first certificate and
 * key in multi-PEM inputs, ignores EKU/SAN suitability, or accepts an encrypted key through an
 * untested password path. This arm proves parse, match, and time checks before startHttp only.
 */
test('H29-tls-startup-validation — incomplete, malformed, mismatched, early and expired material refuse pre-bind', async () => {
    arm('H29-tls-startup-validation');
    assert.deepEqual(readTlsArgs([]), { ok: true, paths: null });
    assert.deepEqual(readTlsArgs(['--tls-cert', 'cert.pem', '--tls-key=key.pem']), {
        ok: true,
        paths: { certificatePath: 'cert.pem', privateKeyPath: 'key.pem' }
    });
    for (const argv of [
        ['--tls-cert', 'cert.pem'],
        ['--tls-key', 'key.pem'],
        ['--tls-cert'],
        ['--tls-key='],
        ['--tls-cert', 'a', '--tls-cert', 'b', '--tls-key', 'c']
    ]) {
        assert.equal(readTlsArgs(argv).ok, false, argv.join(' '));
    }

    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-tls-validation-'));
    const firstDirectory = path.join(base, 'first');
    const secondDirectory = path.join(base, 'second');
    fs.mkdirSync(firstDirectory);
    fs.mkdirSync(secondDirectory);
    try {
        const first = await createCertificateFiles('localhost', firstDirectory);
        const second = await createCertificateFiles('localhost', secondDirectory);
        const paths = {
            certificatePath: first.certificatePath,
            privateKeyPath: first.privateKeyPath
        };
        const valid = await loadTlsConfiguration(paths);
        assert.equal(valid.ok, true);
        const mismatch = await loadTlsConfiguration({
            certificatePath: first.certificatePath,
            privateKeyPath: second.privateKeyPath
        });
        assert.deepEqual(mismatch, {
            ok: false,
            detail: 'TLS certificate and private key do not match'
        });
        const malformedCertificatePath = path.join(base, 'malformed-cert');
        const malformedKeyPath = path.join(base, 'malformed-key');
        fs.writeFileSync(malformedCertificatePath, 'not a certificate');
        fs.writeFileSync(malformedKeyPath, 'not a private key');
        const malformedCertificate = await loadTlsConfiguration({
            certificatePath: malformedCertificatePath,
            privateKeyPath: first.privateKeyPath
        });
        assert.equal(malformedCertificate.ok, false);
        assert.match(malformedCertificate.detail, /not a parseable X\.509 certificate/);
        const malformedKey = await loadTlsConfiguration({
            certificatePath: first.certificatePath,
            privateKeyPath: malformedKeyPath
        });
        assert.equal(malformedKey.ok, false);
        assert.match(malformedKey.detail, /private key is not parseable/);
        const early = await loadTlsConfiguration(paths, {
            now: new Date(Date.parse(valid.configuration.certificate.validFrom) - 1)
        });
        assert.deepEqual(early, { ok: false, detail: 'TLS certificate is not yet valid' });
        const expired = await loadTlsConfiguration(paths, {
            now: new Date(Date.parse(valid.configuration.certificate.validTo))
        });
        assert.deepEqual(expired, { ok: false, detail: 'TLS certificate has expired' });

        let startCalls = 0;
        const lines = [];
        const result = await main(mainDeps({
            argv: [
                '--grant', 'C:\\granted', '--http', '0',
                '--tls-cert', first.certificatePath,
                '--tls-key', second.privateKeyPath
            ],
            stderr: line => lines.push(line),
            startHttp: async () => {
                startCalls += 1;
                assert.fail('mismatched TLS material must refuse before startHttp');
            }
        }));
        assert.equal(result.started, false);
        assert.equal(result.reason, 'TLS_CONFIG');
        assert.equal(startCalls, 0);
        assert.match(lines.join('\n'), /certificate and private key do not match/);
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

/**
 * TLS disclosure is derived from the same correlated value that created the HTTPS listener.
 *
 * What implementation would still pass this? One that prints truthful lines for this sampled real
 * network listener but lies on loopback or after a later certificate reload. It does not prove the
 * routing statements, and H28 owns actual trust rather than this prose assertion.
 */
test('H30-tls-disclosure — HTTPS facts print and the clear-text warning is absent', async () => {
    arm('H30-tls-disclosure');
    const fixture = networkFixture();
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-tls-disclosure-'));
    let result;
    try {
        const created = await createCertificateFiles(fixture.address, directory);
        const port = await reservePort(fixture.address);
        const lines = [];
        result = await main(mainDeps({
            argv: [
                '--grant', 'C:\\granted',
                '--http', `${fixture.argumentHost}:${port}`,
                '--http-public',
                '--tls-cert', created.certificatePath,
                '--tls-key', created.privateKeyPath
            ],
            stderr: line => lines.push(line),
            makeConfiguredServer: () => stubServer('tls-disclosure-reader')
        }));
        assert.notEqual(result.http, null);
        assert.equal(result.http.endpoint.scheme, 'https');
        assert.equal(result.http.endpoint.tlsEnabled, true);
        assert.equal(result.http.endpoint.certificate.fingerprint256, created.fingerprint256);
        assert.deepEqual([...result.http.allowedOrigins], [
            `https://${fixture.urlHost}:${port}`
        ]);
        const disclosure = lines.join('\n');
        assert.match(disclosure, /Transport: HTTPS\. TLS is on\./);
        assert.ok(disclosure.includes(`Certificate SHA-256 fingerprint: ${created.fingerprint256}.`));
        assert.ok(disclosure.includes(`Certificate expires: ${created.validTo}.`));
        assert.match(disclosure, /WHAT THIS MEANS, AND WHAT WYRD DOES NOT KNOW:/);
        assert.doesNotMatch(disclosure, /TLS is off|bearer token travels in the clear/);

        const expiringHandle = {
            ...result.http,
            endpoint: {
                ...result.http.endpoint,
                certificate: {
                    ...result.http.endpoint.certificate,
                    validTo: new Date(Date.now() + 29 * 24 * 60 * 60 * 1_000).toISOString()
                }
            }
        };
        assert.match(
            httpDisclosure(expiringHandle, 'C:\\canonical-grant'),
            /WARNING: the TLS certificate expires in fewer than 30 days\./
        );
    } finally {
        await result?.http?.close();
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

/**
 * Shutdown owns sockets that have connected but have not completed a TLS handshake.
 *
 * What implementation would still pass this? One whose fixed TLS handshake timeout happens to be
 * below this arm's 750 ms bound, or one that tracks raw handshake sockets but mishandles admitted
 * HTTPS requests. The existing HTTP drain arms cover requests, not encrypted handshakes.
 */
test('H31-tls-handshake-shutdown — a stalled pre-handshake socket cannot hold close open', async () => {
    arm('H31-tls-handshake-shutdown');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-tls-shutdown-'));
    let handle;
    let socket;
    try {
        const created = await createCertificateFiles('localhost', directory);
        const loaded = await loadTlsConfiguration({
            certificatePath: created.certificatePath,
            privateKeyPath: created.privateKeyPath
        });
        assert.equal(loaded.ok, true);
        handle = await startHttp({
            kind: 'loopback',
            host: '127.0.0.1',
            port: 0,
            tls: loaded.configuration,
            readAuthInfo: () => authenticated(),
            makeServer: () => stubServer('tls-shutdown-reader')
        });
        socket = net.createConnection({ host: '127.0.0.1', port: handle.port });
        await bounded(new Promise((resolve, reject) => {
            socket.once('connect', resolve);
            socket.once('error', reject);
        }), 3_000, 'raw connection to TLS listener');
        const socketClosed = new Promise(resolve => socket.once('close', resolve));
        await bounded(handle.close(), 750, 'TLS listener close with stalled handshake');
        await bounded(socketClosed, 750, 'stalled TLS socket close');
    } finally {
        socket?.destroy();
        await handle?.close();
        fs.rmSync(directory, { recursive: true, force: true });
    }
});

test('H32-network-instructions-truth — HTTP discovery receives transport-true instructions', async () => {
    arm('H32-network-instructions-truth');
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-instructions-'));
    let result;
    try {
        result = await main(mainDeps({
            argv: ['--grant', directory, '--http', '0'],
            makeFsGate: createFsGate
        }));
        assert.equal(result.started, true);
        assert.notEqual(result.http, null);

        const response = await discover(
            result.http,
            undefined,
            `Bearer ${CONFIGURED_TOKEN}`
        );
        const body = await response.text();
        assert.equal(response.status, 200, body);
        const instructions = JSON.parse(body).result?.instructions;
        assert.equal(typeof instructions, 'string', 'server/discover must return instructions');
        assert.match(
            instructions,
            // ⚠ The wrap falls after "outbound", not before it (`src/server.ts:285`). `\s+` spans
            // the newline and its indent wherever the line actually breaks, so this matches the
            // rendered string rather than a guess about its layout.
            /In HTTP mode, this server is listening for connections and does not make outbound\s+connections of its own\./i
        );
        assert.match(
            instructions,
            /That is NOT a promise your\s+content stays local/i
        );
        assert.ok(
            !instructions.includes('This server opens no network connection of its own.'),
            'HTTP instructions must not contain the retired transport-neutral sentence'
        );
    } finally {
        await result?.http?.close();
        fs.rmSync(directory, { recursive: true, force: true });
    }
});
