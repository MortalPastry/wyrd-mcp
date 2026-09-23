import { spawn } from 'node:child_process';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';

/**
 * Copied from the v1 SDK 1.30.0 distribution's `LATEST_PROTOCOL_VERSION` declaration.
 * This module deliberately does not import or execute that package: the point of this harness is
 * to remain an independent wire-level observer when the server changes SDKs.
 */
export const V1_PROTOCOL_VERSION = '2025-11-25';

const V1_INVALID_TOOL_NAME_MESSAGE = `[
  {
    "expected": "string",
    "code": "invalid_type",
    "path": [
      "params",
      "name"
    ],
    "message": "Invalid input: expected string, received number"
  }
]`;

/** The one reviewed v2 protocol-validation delta admitted by the v1 corpus comparator. */
export const V2_INVALID_TOOL_NAME_ERROR = Object.freeze({
    code: -32602,
    message: `Invalid tools/call request: ${V1_INVALID_TOOL_NAME_MESSAGE}`
});

const TIMEOUT_MS = 20_000;
const CAPTURE = process.env['WYRD_CAPTURE_V1_GOLDENS'] === '1';

function idKey(id) {
    return `${typeof id}:${String(id)}`;
}

function replacePaths(text, pathTokens) {
    let result = text;
    for (const [actual, token] of pathTokens) {
        result = result.split(actual).join(token);
    }
    return result;
}

function normalise(value, pathTokens, requestIds, topLevel = true) {
    if (typeof value === 'string') return replacePaths(value, pathTokens);
    if (Array.isArray(value)) {
        return value.map(item => normalise(item, pathTokens, requestIds, false));
    }
    if (value === null || typeof value !== 'object') return value;

    const result = {};
    for (const [key, member] of Object.entries(value)) {
        if (topLevel && key === 'id' && requestIds.has(idKey(member))) {
            result[key] = requestIds.get(idKey(member));
        } else {
            result[key] = normalise(member, pathTokens, requestIds, false);
        }
    }
    return result;
}

function childEnvironment(overrides) {
    const env = { ...process.env };
    for (const name of Object.keys(env)) {
        if (name.startsWith('WYRD_')) delete env[name];
    }
    for (const [name, value] of Object.entries(overrides)) {
        if (value === undefined) delete env[name];
        else env[name] = value;
    }
    return env;
}

function recordedEnvironment(overrides, pathTokens) {
    return Object.fromEntries(Object.keys(overrides).sort().map(name => [
        name,
        overrides[name] === undefined
            ? { unset: true }
            : replacePaths(String(overrides[name]), pathTokens)
    ]));
}

function lineCollector(onLine) {
    let held = Buffer.alloc(0);
    return {
        push(chunk) {
            held = Buffer.concat([held, chunk]);
            for (;;) {
                const end = held.indexOf(0x0a);
                if (end === -1) return;
                const line = Buffer.from(held.subarray(0, end + 1));
                held = Buffer.from(held.subarray(end + 1));
                onLine(line);
            }
        },
        end() {
            if (held.length !== 0) onLine(held);
            held = Buffer.alloc(0);
        }
    };
}

function byteStrictLine(label, line) {
    return {
        label,
        byteLength: line.length,
        base64: line.toString('base64'),
        utf8ForReview: line.toString('utf8')
    };
}

function byteStrictRepresentations(value, location = '$', result = []) {
    if (value === null || typeof value !== 'object') return result;
    if (Object.hasOwn(value, 'byteStrictStaticStdoutLines')) {
        result.push({ location, lines: value.byteStrictStaticStdoutLines });
    }
    for (const [key, member] of Object.entries(value)) {
        byteStrictRepresentations(member, `${location}.${key}`, result);
    }
    return result;
}

/** A raw newline-delimited JSON-RPC client over one child process's stdin/stdout. */
export class RawStdioSession {
    constructor({
        entrypoint,
        entrypointLabel,
        args = [],
        env = {},
        pathTokens = [],
        clientInfo = { name: 'wyrd-v1-baseline-oracle', version: '1.0.0' }
    }) {
        this.pathTokens = [...pathTokens].sort((left, right) => right[0].length - left[0].length);
        this.clientInfo = clientInfo;
        this.requestIds = new Map();
        this.byteStrictRequestLabels = new Map();
        this.pending = new Map();
        this.nextId = 1;
        this.failure = null;
        this.closedDone = false;
        this.transcript = {
            command: {
                runtime: 'node',
                entrypoint: entrypointLabel,
                args: args.map(argument => replacePaths(argument, this.pathTokens)),
                env: recordedEnvironment(env, this.pathTokens)
            },
            byteStrictStaticStdoutLines: [],
            normalizedEvents: []
        };

        this.child = spawn(process.execPath, [entrypoint, ...args], {
            env: childEnvironment(env),
            stdio: ['pipe', 'pipe', 'pipe'],
            windowsHide: true
        });

        const stdout = lineCollector(line => this.onStdout(line));
        const stderr = lineCollector(line => {
            this.transcript.normalizedEvents.push({
                stream: 'stderr',
                text: replacePaths(line.toString('utf8'), this.pathTokens)
            });
        });
        this.child.stdout.on('data', chunk => stdout.push(chunk));
        this.child.stderr.on('data', chunk => stderr.push(chunk));
        this.child.stdout.on('end', () => stdout.end());
        this.child.stderr.on('end', () => stderr.end());

        this.closed = new Promise((resolve, reject) => {
            this.child.once('error', error => {
                this.failure = error;
                this.closedDone = true;
                reject(error);
            });
            this.child.once('close', (code, signal) => {
                this.closedDone = true;
                this.transcript.normalizedEvents.push({ stream: 'exit', code, signal });
                for (const pending of this.pending.values()) {
                    pending.reject(new Error(`server exited ${code} before responding`));
                }
                this.pending.clear();
                resolve(this.transcript);
            });
        });
    }

    onStdout(line) {
        // Keep a copy of the wire line before decoding or parsing it. Selected static responses
        // are encoded directly from this Buffer; they never pass through normalise(). Stream
        // chunks are intentionally discarded as an implementation detail of the host OS.
        const rawLine = Buffer.from(line);
        const text = rawLine.toString('utf8');
        let message;
        try {
            message = JSON.parse(text);
        } catch (error) {
            this.failure = new Error(`server stdout was not JSON-RPC: ${JSON.stringify(text)}`, { cause: error });
            this.transcript.normalizedEvents.push({
                stream: 'stdout',
                text: replacePaths(text, this.pathTokens)
            });
            return;
        }

        const requestKey = idKey(message.id);
        const byteStrictLabel = this.byteStrictRequestLabels.get(requestKey);
        if (byteStrictLabel !== undefined) {
            this.byteStrictRequestLabels.delete(requestKey);
            this.transcript.byteStrictStaticStdoutLines.push(byteStrictLine(byteStrictLabel, rawLine));
        }

        this.transcript.normalizedEvents.push({
            stream: 'stdout',
            message: normalise(message, this.pathTokens, this.requestIds),
            ending: rawLine.at(-1) === 0x0a ? '\n' : ''
        });
        const pending = this.pending.get(requestKey);
        if (pending !== undefined) {
            this.pending.delete(requestKey);
            pending.resolve(message);
        }
    }

    send(message) {
        this.transcript.normalizedEvents.push({
            stream: 'stdin',
            message: normalise(message, this.pathTokens, this.requestIds),
            ending: '\n'
        });
        this.child.stdin.write(`${JSON.stringify(message)}\n`);
    }

    async request(method, params = {}, { byteStrictLabel } = {}) {
        const id = this.nextId;
        this.nextId += 1;
        this.requestIds.set(idKey(id), `<REQUEST_ID_${id}>`);
        if (byteStrictLabel !== undefined) {
            this.byteStrictRequestLabels.set(idKey(id), byteStrictLabel);
        }
        const response = new Promise((resolve, reject) => {
            this.pending.set(idKey(id), { resolve, reject });
        });
        this.send({ jsonrpc: '2.0', id, method, params });
        const timer = new Promise((_, reject) => {
            setTimeout(() => reject(new Error(`timed out waiting for ${method}`)), TIMEOUT_MS).unref();
        });
        return Promise.race([response, timer]);
    }

    notify(method, params = undefined) {
        this.send({
            jsonrpc: '2.0',
            method,
            ...(params === undefined ? {} : { params })
        });
    }

    initializeRequest(capabilities = {}, options = {}) {
        return this.request('initialize', {
            protocolVersion: V1_PROTOCOL_VERSION,
            capabilities,
            clientInfo: this.clientInfo
        }, options);
    }

    async initialise({ capabilities = {}, byteStrictLabel } = {}) {
        const response = await this.initializeRequest(capabilities, { byteStrictLabel });
        assert.equal(
            response.result?.protocolVersion,
            V1_PROTOCOL_VERSION,
            'the v1 server must negotiate the source-pinned protocol revision'
        );
        this.notify('notifications/initialized');
        return response;
    }

    listTools(params = {}, options = {}) {
        return this.request('tools/list', params, options);
    }

    callTool(name, arguments_, options = {}) {
        return this.request('tools/call', { name, arguments: arguments_ }, options);
    }

    async finish() {
        this.transcript.normalizedEvents.push({ stream: 'stdin', end: true });
        this.child.stdin.end();
        const timer = new Promise((_, reject) => {
            setTimeout(() => {
                this.child.kill();
                reject(new Error('timed out waiting for the stdio server to exit'));
            }, TIMEOUT_MS).unref();
        });
        const transcript = await Promise.race([this.closed, timer]);
        if (this.failure !== null) throw this.failure;
        return transcript;
    }

    async waitForExit() {
        const timer = new Promise((_, reject) => {
            setTimeout(() => {
                this.child.kill();
                reject(new Error('timed out waiting for the child process to exit'));
            }, TIMEOUT_MS).unref();
        });
        const transcript = await Promise.race([this.closed, timer]);
        if (this.failure !== null) throw this.failure;
        return transcript;
    }

    /** Best-effort cleanup for a test assertion or timeout that interrupted the normal close path. */
    async dispose() {
        if (this.closedDone) return;
        if (!this.child.stdin.destroyed) this.child.stdin.end();
        const stopped = await Promise.race([
            this.closed.then(() => true, () => true),
            new Promise(resolve => setTimeout(() => resolve(false), 2_000))
        ]);
        if (!stopped && !this.closedDone) {
            this.child.kill();
            await this.closed.catch(() => {});
        }
    }
}

function responseResult(response, method) {
    if (response.error !== undefined) {
        const error = new Error(response.error.message);
        error.code = response.error.code;
        if (response.error.data !== undefined) error.data = response.error.data;
        throw error;
    }
    if (response.result === undefined) {
        throw new Error(`${method} response carried neither a result nor an error`);
    }
    return response.result;
}

/**
 * The small high-level client surface used by Wyrd's tests and manual driver, implemented over the
 * same SDK-independent wire session as the v1 oracle. It deliberately offers only operations those
 * callers exercise; protocol behavior stays observable in RawStdioSession rather than being
 * hidden behind whichever server SDK is under test.
 */
export class RawMcpClient {
    constructor(options) {
        this.session = new RawStdioSession(options);
        this.initializeResult = null;
        this.closed = false;
    }

    get stderr() {
        return this.session.child.stderr;
    }

    async connect() {
        if (this.initializeResult !== null) return;
        const response = await this.session.initialise();
        this.initializeResult = responseResult(response, 'initialize');
    }

    getServerVersion() {
        return this.initializeResult?.serverInfo;
    }

    getServerCapabilities() {
        return this.initializeResult?.capabilities;
    }

    getInstructions() {
        return this.initializeResult?.instructions;
    }

    async listTools(params = {}) {
        return responseResult(await this.session.listTools(params), 'tools/list');
    }

    async callTool({ name, arguments: arguments_ }) {
        return responseResult(await this.session.callTool(name, arguments_), 'tools/call');
    }

    async close() {
        if (this.closed) return;
        this.closed = true;
        await this.session.finish();
    }
}

export function tempPathTokens(root, token = '<TEMP>') {
    const roots = new Set([path.resolve(root)]);
    try {
        roots.add(fs.realpathSync.native(root));
    } catch {
        // A caller may establish its fixture after constructing this list; the resolved form is
        // only an additional spelling of the same temporary path.
    }
    return [...roots].map(actual => [actual, token]);
}

/** Exact bytes, with UTF-8 beside them only when the bytes round-trip losslessly. */
export function treeSnapshot(root) {
    const entries = [];
    const visit = relative => {
        const absolute = path.join(root, relative);
        const names = fs.readdirSync(absolute).sort((left, right) => left.localeCompare(right));
        for (const name of names) {
            const childRelative = path.join(relative, name);
            const childAbsolute = path.join(root, childRelative);
            const stat = fs.lstatSync(childAbsolute);
            if (stat.isDirectory()) {
                entries.push({ path: childRelative, kind: 'directory' });
                visit(childRelative);
            } else if (stat.isSymbolicLink()) {
                entries.push({ path: childRelative, kind: 'symlink', target: fs.readlinkSync(childAbsolute) });
            } else {
                const bytes = fs.readFileSync(childAbsolute);
                const decoded = bytes.toString('utf8');
                entries.push({
                    path: childRelative,
                    kind: 'file',
                    bytes: bytes.length,
                    base64: bytes.toString('base64'),
                    ...(Buffer.compare(bytes, Buffer.from(decoded, 'utf8')) === 0 ? { utf8: decoded } : {})
                });
            }
        }
    };
    visit('');
    return entries;
}

const INVALID_TOOL_NAME_REQUEST = {
    stream: 'stdin',
    message: {
        jsonrpc: '2.0',
        id: '<REQUEST_ID_4>',
        method: 'tools/call',
        params: { name: 7 }
    },
    ending: '\n'
};

const V1_INVALID_TOOL_NAME_RESPONSE = {
    stream: 'stdout',
    message: {
        jsonrpc: '2.0',
        id: '<REQUEST_ID_4>',
        error: { code: -32603, message: V1_INVALID_TOOL_NAME_MESSAGE }
    },
    ending: '\n'
};

const V2_INVALID_TOOL_NAME_RESPONSE = {
    stream: 'stdout',
    message: {
        jsonrpc: '2.0',
        id: '<REQUEST_ID_4>',
        error: V2_INVALID_TOOL_NAME_ERROR
    },
    ending: '\n'
};

function byteStrictInvalidToolName(error) {
    return byteStrictLine('tools/call name-number response', Buffer.from(`${JSON.stringify({
        jsonrpc: '2.0', id: 4, error
    })}\n`, 'utf8'));
}

const V1_INVALID_TOOL_NAME_BYTES = byteStrictInvalidToolName(
    V1_INVALID_TOOL_NAME_RESPONSE.message.error
);
const V2_INVALID_TOOL_NAME_BYTES = byteStrictInvalidToolName(V2_INVALID_TOOL_NAME_ERROR);

function initializedLifecycle(corpus) {
    return corpus?.cases?.expandedCharacterization?.initializedLifecycle;
}

function matchingRequestIndices(events) {
    const indices = [];
    for (let index = 0; index < events.length; index += 1) {
        if (isDeepStrictEqual(events[index], INVALID_TOOL_NAME_REQUEST)) indices.push(index);
    }
    return indices;
}

/**
 * Substitute the single accepted v2 response with its recorded v1 representation so the final
 * comparison remains one deepStrictEqual over the whole corpus. Both representations of that one
 * response are exact: the normalized event and the adjacent Buffer-derived static line.
 */
function withApprovedInvalidToolNameDelta(expected, actual) {
    const expectedLifecycle = initializedLifecycle(expected);
    const actualLifecycle = initializedLifecycle(actual);
    assert.ok(expectedLifecycle && actualLifecycle,
        'the approved v2 delta exists only in the post-initialization characterization case');

    const expectedIndices = matchingRequestIndices(expectedLifecycle.normalizedEvents);
    const actualIndices = matchingRequestIndices(actualLifecycle.normalizedEvents);
    assert.equal(expectedIndices.length, 1,
        'the v1 golden must contain exactly one post-initialization tools/call with numeric name');
    assert.deepStrictEqual(actualIndices, expectedIndices,
        'the ported corpus must contain that same single invalid-name request in the same position');

    const responseIndex = expectedIndices[0] + 1;
    assert.deepStrictEqual(
        expectedLifecycle.normalizedEvents[responseIndex],
        V1_INVALID_TOOL_NAME_RESPONSE,
        'the preserved golden no longer contains the reviewed v1 -32603 envelope'
    );
    assert.deepStrictEqual(
        expectedLifecycle.byteStrictStaticStdoutLines,
        [V1_INVALID_TOOL_NAME_BYTES],
        'the preserved golden no longer contains the reviewed v1 invalid-name response bytes'
    );

    const actualResponse = actualLifecycle.normalizedEvents[responseIndex];
    if (isDeepStrictEqual(actualResponse, V1_INVALID_TOOL_NAME_RESPONSE)) return actual;

    assert.deepStrictEqual(
        actualResponse,
        V2_INVALID_TOOL_NAME_RESPONSE,
        'the only approved parsed delta is the reviewed v2 -32602 invalid-name envelope'
    );
    assert.deepStrictEqual(
        actualLifecycle.byteStrictStaticStdoutLines,
        [V2_INVALID_TOOL_NAME_BYTES],
        'the only approved byte delta is the reviewed v2 invalid-name response line'
    );

    const adjusted = structuredClone(actual);
    const adjustedLifecycle = initializedLifecycle(adjusted);
    adjustedLifecycle.normalizedEvents[responseIndex] = structuredClone(V1_INVALID_TOOL_NAME_RESPONSE);
    adjustedLifecycle.byteStrictStaticStdoutLines = [structuredClone(V1_INVALID_TOOL_NAME_BYTES)];
    return adjusted;
}

/** The complete reviewed set of Reader initialize-result version leaves. */
const READER_SERVER_VERSION_LEAVES = [
    {
        label: 'grant-precedence initialize response',
        path: ['cases', 'grantPrecedence', 'normalizedEvents', 55,
            'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'initialized-lifecycle first initialize response',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle',
            'normalizedEvents', 55, 'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'initialized-lifecycle duplicate initialize response',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle',
            'normalizedEvents', 58, 'message', 'result', 'serverInfo', 'version']
    },
    {
        label: 'exchange initialize response',
        path: ['cases', 'exchange', 'normalizedEvents', 55,
            'message', 'result', 'serverInfo', 'version']
    }
];

/**
 * Initialize lines contain per-run grant paths, so none is retained in the byte-strict subset.
 * This empty reviewed set is still asserted in both corpora: adding a raw initialize line must be
 * a named delta rather than a representation the structured-leaf list silently overlooks.
 */
const READER_SERVER_VERSION_BYTE_LINES = [];

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
            const bytes = Buffer.from(line.base64, 'base64');
            const text = bytes.toString('utf8');
            assert.equal(line.base64, bytes.toString('base64'),
                `the byte-strict line at ${JSON.stringify(location)} must retain canonical base64`);
            assert.equal(line.byteLength, bytes.length,
                `the byte-strict line at ${JSON.stringify(location)} must retain its byte length`);
            assert.equal(line.utf8ForReview, text,
                `the byte-strict line at ${JSON.stringify(location)} review text must equal its bytes`);
            const message = JSON.parse(text);
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

function sortedPathKeys(paths) {
    return paths.map(leafPath => JSON.stringify(leafPath)).sort();
}

/** Reader-only structural discriminator; the Scribe corpus has no grantPrecedence case. */
function corpusCarriesReaderServerVersion(corpus) {
    let value = corpus;
    for (const segment of READER_SERVER_VERSION_LEAVES[0].path) {
        if (value === null || typeof value !== 'object' || !Object.hasOwn(value, segment)) {
            return false;
        }
        value = value[segment];
    }
    return typeof value === 'string';
}

const V1_NETWORK_DISCLOSURE_SENTENCE =
    'This server opens no network connection of its own.';
const STDIO_NETWORK_DISCLOSURE_SENTENCE =
    'In stdio mode, this server opens no network connection of its own.';

/**
 * The frozen sentence occurs in exactly these eight reviewed string leaves: four stderr lines and
 * four initialize results. Paths are explicit so no corpus-wide replacement can bless an unrelated
 * wire change that happens to contain the same words.
 */
const STDIO_NETWORK_DISCLOSURE_LEAVES = [
    {
        label: 'grant-precedence stderr line',
        path: ['cases', 'grantPrecedence', 'normalizedEvents', 14, 'text']
    },
    {
        label: 'exchange stderr line',
        path: ['cases', 'exchange', 'normalizedEvents', 14, 'text']
    },
    {
        label: 'pre-initialize stderr line',
        path: ['cases', 'expandedCharacterization', 'preInitialize', 'normalizedEvents', 14, 'text']
    },
    {
        label: 'initialized-lifecycle stderr line',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle', 'normalizedEvents', 14, 'text']
    },
    {
        label: 'grant-precedence initialize instructions',
        path: ['cases', 'grantPrecedence', 'normalizedEvents', 55, 'message', 'result', 'instructions']
    },
    {
        label: 'exchange initialize instructions',
        path: ['cases', 'exchange', 'normalizedEvents', 55, 'message', 'result', 'instructions']
    },
    {
        label: 'initialized-lifecycle first initialize instructions',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle', 'normalizedEvents', 55, 'message', 'result', 'instructions']
    },
    {
        label: 'initialized-lifecycle duplicate initialize instructions',
        path: ['cases', 'expandedCharacterization', 'initializedLifecycle', 'normalizedEvents', 58, 'message', 'result', 'instructions']
    }
];

function reviewedLeaf(corpus, path, label) {
    let value = corpus;
    for (const segment of path) {
        assert.ok(
            value !== null && typeof value === 'object' && Object.hasOwn(value, segment),
            `the ${label} leaf no longer exists at its reviewed path`
        );
        value = value[segment];
    }
    assert.equal(typeof value, 'string', `the ${label} leaf must remain a string`);
    return value;
}

function setReviewedLeaf(corpus, path, value) {
    let parent = corpus;
    for (const segment of path.slice(0, -1)) parent = parent[segment];
    parent[path.at(-1)] = value;
}

/**
 * Reconcile only the four reviewed Reader initialize-result version leaves. The manifest is the
 * live source of truth and the frozen v1 value remains asserted. Structured leaves and the raw
 * byte subset are inventoried independently so neither representation can widen the exception.
 */
function withApprovedReaderServerVersionDelta(expected, actual) {
    const enumeratedLeaves = sortedPathKeys(
        READER_SERVER_VERSION_LEAVES.map(leaf => leaf.path)
    );
    assert.deepStrictEqual(
        sortedPathKeys(serverInfoVersionLeafPaths(expected)),
        enumeratedLeaves,
        'the frozen Reader corpus serverInfo.version leaves must exactly match the reviewed set'
    );
    assert.deepStrictEqual(
        sortedPathKeys(serverInfoVersionLeafPaths(actual)),
        enumeratedLeaves,
        'the live Reader corpus serverInfo.version leaves must exactly match the reviewed set'
    );

    const enumeratedByteLines = sortedPathKeys(READER_SERVER_VERSION_BYTE_LINES);
    assert.deepStrictEqual(
        sortedPathKeys(byteStrictServerInfoVersionLinePaths(expected)),
        enumeratedByteLines,
        'the frozen Reader byte-strict serverInfo.version lines must exactly match the reviewed set'
    );
    assert.deepStrictEqual(
        sortedPathKeys(byteStrictServerInfoVersionLinePaths(actual)),
        enumeratedByteLines,
        'the live Reader byte-strict serverInfo.version lines must exactly match the reviewed set'
    );

    const manifest = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.equal(typeof manifest.version, 'string', 'the Reader manifest version must be a string');

    const adjusted = structuredClone(actual);
    for (const { label, path } of READER_SERVER_VERSION_LEAVES) {
        assert.equal(
            reviewedLeaf(expected, path, label),
            '0.0.0',
            `the frozen ${label} no longer carries the reviewed v1 version`
        );
        assert.equal(
            reviewedLeaf(actual, path, label),
            manifest.version,
            `the live ${label} must carry the Reader manifest version`
        );
        setReviewedLeaf(adjusted, path, '0.0.0');
    }
    return adjusted;
}

/**
 * Reconcile only the reviewed stdio qualification. Each live leaf must equal its frozen value with
 * exactly one sentence changed; every other byte and parsed value remains for the final strict
 * whole-corpus comparison.
 */
function withApprovedStdioNetworkDisclosureDelta(expected, actual) {
    const adjusted = structuredClone(actual);
    for (const { label, path } of STDIO_NETWORK_DISCLOSURE_LEAVES) {
        const frozenValue = reviewedLeaf(expected, path, label);
        const liveValue = reviewedLeaf(actual, path, label);
        assert.equal(
            frozenValue.split(V1_NETWORK_DISCLOSURE_SENTENCE).length - 1,
            1,
            `the frozen ${label} must contain the retired sentence exactly once`
        );
        const reviewedLiveValue = frozenValue.replace(
            V1_NETWORK_DISCLOSURE_SENTENCE,
            STDIO_NETWORK_DISCLOSURE_SENTENCE
        );
        assert.equal(
            liveValue,
            reviewedLiveValue,
            `the live ${label} may differ only by the reviewed stdio qualification`
        );
        setReviewedLeaf(adjusted, path, frozenValue);
    }
    return adjusted;
}

/**
 * ⚠⚠ THIS HARNESS SERVES MORE THAN ONE PACKAGE, AND THE REVIEWED DELTAS ARE NOT ALL UNIVERSAL.
 * Another workspace package's v1-baseline arm imports `captureOrCompare` from this file, so every
 * delta declared here is applied to that package's corpus too.
 *
 * The invalid-tool-name delta is shared: both servers went through the same v1→v2 envelope change.
 * **The stdio-disclosure delta is this package's alone** — it reconciles eight leaves of this
 * server's own `initialize.instructions` and startup stderr, which the other corpus does not
 * contain. Applying it there asserted a leaf that does not exist and reddened that arm.
 *
 * ⚠ Caught 2026-09-15 by running the other package's suite AFTER this one's change rather than
 * before it — this package's own 62 arms were green throughout, because the defect is entirely in
 * the importer. A shared harness change is not verified by the suite of the package you changed.
 *
 * So the disclosure delta applies only to a corpus that actually carries those leaves, and the
 * detection is structural: probe the reviewed paths, do not guess from a package name.
 */
function corpusCarriesStdioDisclosure(corpus) {
    const [{ path: probe }] = STDIO_NETWORK_DISCLOSURE_LEAVES;
    let value = corpus;
    for (const segment of probe) {
        if (value === null || typeof value !== 'object' || !Object.hasOwn(value, segment)) {
            return false;
        }
        value = value[segment];
    }
    return typeof value === 'string' && value.includes(V1_NETWORK_DISCLOSURE_SENTENCE);
}

function withApprovedV2Delta(expected, actual) {
    let adjusted = withApprovedInvalidToolNameDelta(expected, actual);
    if (corpusCarriesReaderServerVersion(expected)) {
        adjusted = withApprovedReaderServerVersionDelta(expected, adjusted);
    }
    if (!corpusCarriesStdioDisclosure(expected)) return adjusted;
    return withApprovedStdioNetworkDisclosureDelta(expected, adjusted);
}

/**
 * The recapture refusal, exported so an arm can drive it directly.
 *
 * ⚠ `CAPTURE` is read from the environment at import time into a module constant, so a test
 * cannot re-arm capture mode by setting the variable at run time. That is deliberate — the flag
 * governs a destructive path and should not be togglable mid-process — but it means the refusal
 * must be reachable on its own for anything to assert it. Hence this function rather than an arm
 * that tries to fake the flag.
 */
export function refuseRecapture(goldenPath) {
    // ⚠⚠ RECAPTURE IS REFUSED ONCE A GOLDEN EXISTS, AND THE REASON IS EVIDENCE RATHER THAN
    // TIDINESS. This corpus is a FROZEN RECORDING of v1 wire behaviour — its whole job is to
    // hold bytes the current program no longer produces, such as the reviewed v1 `-32603`
    // invalid-tool-name envelope that `withApprovedV2Delta` exists to reconcile. A recapture
    // overwrites those bytes with today's output, which does not fail: it silently converts
    // the oracle into a photograph of the present and destroys the only copy of the past.
    //
    // ⚠ AND NOTHING CAUGHT THAT UNTIL 2026-09-15. The capture branch wrote and returned
    // BEFORE any comparison, so `E17` — the arm credited in `NEXT.md` and in a prior run log
    // with catching a recapture overwrite — structurally could not have. In capture mode no
    // assertion ran at all. Whatever caught the 2026-09-14 incident, it was not this file.
    //
    // To legitimately re-record against built v1 binaries, delete the golden deliberately
    // first. That makes the destruction an explicit act with a diff, which is the point.
    if (fs.existsSync(goldenPath)) {
        throw new Error(
            `${goldenPath} already exists and WYRD_CAPTURE_V1_GOLDENS=1 would overwrite it. ` +
            'This corpus preserves v1 bytes the current program no longer emits; recapturing ' +
            'destroys that evidence silently. Delete the file deliberately if you really mean ' +
            'to re-record it against the built v1 binaries.'
        );
    }
}

export function captureOrCompare(goldenPath, actual) {
    if (CAPTURE) {
        refuseRecapture(goldenPath);
        fs.writeFileSync(goldenPath, `${JSON.stringify(actual, null, 2)}\n`, 'utf8');
        return;
    }
    const expected = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
    if (expected.captured !== true) {
        throw new Error(
            `${goldenPath} is explicitly uncaptured; run with WYRD_CAPTURE_V1_GOLDENS=1 ` +
            'against the built v1 binaries before treating this oracle as green'
        );
    }
    const comparable = withApprovedV2Delta(expected, actual);
    // Compare the Buffer-derived static-line representations first. Full raw lines make framing,
    // LF versus CRLF, whitespace and JSON member order byte-strict without treating stream chunks
    // as wire behaviour. The whole normalized-plus-byte corpus remains exact below.
    assert.deepStrictEqual(
        byteStrictRepresentations(comparable),
        byteStrictRepresentations(expected),
        'static stdout wire bytes differ from the v1 characterization baseline'
    );
    assert.deepStrictEqual(comparable, expected);
}
