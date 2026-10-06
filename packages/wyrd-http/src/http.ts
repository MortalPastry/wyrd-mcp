import http, {
    type IncomingMessage,
    type RequestListener,
    type Server as NodeHttpServer,
    type ServerResponse
} from 'node:http';
import https from 'node:https';
import { isIP, type Socket } from 'node:net';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

import { createMcpHandler, type AuthInfo, type Server } from '@modelcontextprotocol/server';
import { isLoopbackHost, type HttpBind } from './bind.js';
import type { TlsCertificateInfo, ValidatedTlsConfiguration } from './tls-config.js';

/** Cap each HTTP request body at 1 MiB, including its JSON envelope. */
export const MAX_HTTP_REQUEST_BYTES = 1_048_576;

type McpHandler = ReturnType<typeof createMcpHandler>;
type LifecycleState = 'STARTING' | 'OPEN' | 'CLOSING' | 'CLOSED';
type RequestPhase = 'ADMISSION' | 'EXECUTING';

interface RequestRecord {
    readonly incoming: IncomingMessage;
    readonly outgoing: ServerResponse;
    readonly socket: Socket;
    readonly controller: AbortController;
    readonly abort: () => void;
    readonly done: Promise<void>;
    readonly settle: () => void;
    phase: RequestPhase;
    finished: boolean;
}

class RequestTooLargeError extends Error {}
interface EndpointLocation {
    readonly interfaceAddress: string;
    readonly exposure: HttpBind['kind'];
}

/** Listener construction and disclosure are correlated: the HTTPS trio cannot be separated. */
export type HttpEndpointMetadata =
    | (EndpointLocation & {
        readonly scheme: 'http';
        readonly tlsEnabled: false;
    })
    | (EndpointLocation & {
        readonly scheme: 'https';
        readonly tlsEnabled: true;
        readonly certificate: TlsCertificateInfo;
    });

export interface HttpAuthRequest {
    readonly authorization: string | null;
    readonly signal: AbortSignal;
}

export type HttpAuthDecision =
    | { readonly kind: 'authenticated'; readonly authInfo: AuthInfo }
    | { readonly kind: 'unauthenticated' }
    | { readonly kind: 'unavailable' };

export type HttpAuthDecisionFn =
    (request: Readonly<HttpAuthRequest>) => HttpAuthDecision | Promise<HttpAuthDecision>;

export interface HttpRefusal {
    readonly body: string;
    readonly headers?: Readonly<Record<string, string>>;
}

export interface HttpRefusals {
    readonly route: HttpRefusal;
    readonly method: HttpRefusal;
    readonly origin: HttpRefusal;
    readonly length: HttpRefusal;
    readonly unauthenticated: HttpRefusal;
    readonly unavailable: HttpRefusal;
    readonly internal: HttpRefusal;
}

type StartHttpCommon = {
    readonly makeServer: () => Server;
    readonly readAuthInfo: HttpAuthDecisionFn;
    readonly refusals: HttpRefusals;
    /** Called for a listening server error. Shutdown has begun; its promise drains admitted work. */
    readonly onServerError?: (error: Error, shutdown: Promise<void>) => void;
};

export type StartHttpOptions = HttpBind & StartHttpCommon & (
    | { readonly tls?: undefined }
    | { readonly tls: ValidatedTlsConfiguration }
);

/** Narrow construction seams used to force otherwise kernel-owned startup outcomes in arms. */
export interface StartHttpDeps {
    /** Test seam for the listener's per-connection state. */
    readonly inspectState?: (snapshot: () => Readonly<Record<'sockets' | 'pendingTlsSockets' | 'records' |
        'recordsBySocket' | 'socketCleanup' | 'activeOversizeDrains', number>>) => void;
    readonly makeHandler?: (
        makeServer: () => Server,
        options: { readonly legacy: 'reject' }
    ) => McpHandler;
    readonly makeListener?: (
        requestListener: RequestListener,
        tls: ValidatedTlsConfiguration | null
    ) => NodeHttpServer;
}

export interface HttpServerHandle {
    readonly address: string;
    readonly port: number;
    readonly endpoint: HttpEndpointMetadata;
    readonly allowedOrigins: readonly string[];
    /**
     * The ordered shutdown, idempotent under repeated calls and concurrent signals: stop accepting,
     * abort requests still in admission, drain the ones already handed to the SDK, then close the
     * handler and the listener.
     *
     * ⚠⚠ THIS IS THE ONLY SHUTDOWN ENTRY POINT, AND THE THREE THAT USED TO SIT BESIDE IT WERE
     * REMOVED RATHER THAN DOCUMENTED. `stopAccepting`, `closeHandler` and `closeListener` were
     * exported, called by no production code and no arm, and their only reachable effect was a
     * hazard a cold read measured: `closeHandler()` invoked after `close()` begins but before its
     * drain runs closes the SDK's in-flight servers AHEAD of the ordered drain, truncating a
     * response that was already executing. **An exported method whose sole use is to break the
     * invariant its neighbour maintains is a defect, not an API.** Anything needing finer control
     * should get a shutdown that still owns the ordering.
     */
    close(): Promise<void>;
}

function urlHost(host: string): string {
    const bare = bareHost(host);
    return bare.includes(':') ? `[${bare}]` : bare;
}

function bareHost(host: string): string {
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function canonicalIpAddress(host: string): string {
    const bare = bareHost(host);
    if (isIP(bare) === 4) return bare;
    const value = new URL('http://localhost');
    value.hostname = `[${bare}]`;
    return value.hostname.slice(1, -1);
}

function isIpv4Mapped(address: string): boolean {
    return isIP(bareHost(address)) === 6
        && canonicalIpAddress(address).startsWith('::ffff:');
}

function networkHostRefusal(host: string): string | null {
    const bare = bareHost(host);
    if (bare.includes('%')) return 'scoped IPv6 addresses are not supported';
    const version = isIP(bare);
    if (version === 0) return 'hostnames are not interface addresses';
    if (version === 4 && host.startsWith('[')) return 'IPv4 addresses must not be bracketed';

    if (version === 4) {
        const octets = bare.split('.').map(Number);
        const first = octets[0] as number;
        if (bare === '0.0.0.0') return 'the IPv4 wildcard names every interface';
        if (first === 127) return 'the address is loopback';
        if (first >= 224 && first <= 239) return 'multicast is not a unicast interface endpoint';
        if (first === 255) return 'broadcast is not a unicast interface endpoint';
        return null;
    }

    const canonical = canonicalIpAddress(bare);
    if (canonical === '::') return 'the IPv6 wildcard names every interface';
    if (canonical === '::1') return 'the address is loopback';
    if (canonical.startsWith('ff')) return 'multicast is not a unicast interface endpoint';
    if (isIpv4Mapped(canonical)) return 'IPv4-mapped IPv6 is not an interface endpoint';
    return null;
}

export function httpEndpointUrl(endpoint: HttpEndpointMetadata, port: number): URL {
    const value = new URL('http://localhost');
    value.protocol = `${endpoint.scheme}:`;
    value.hostname = urlHost(endpoint.interfaceAddress);
    value.port = String(port);
    return value;
}

function defaultAllowedOrigins(
    endpoint: HttpEndpointMetadata,
    port: number
): readonly string[] {
    const hosts = endpoint.exposure === 'network'
        ? [endpoint.interfaceAddress]
        : [endpoint.interfaceAddress, 'localhost'];
    return Object.freeze(hosts.map(interfaceAddress => httpEndpointUrl(
        Object.freeze({ ...endpoint, interfaceAddress }),
        port
    ).origin));
}

function isBoundLoopback(address: string): boolean {
    if (isLoopbackHost(address)) return true;
    if (!isIpv4Mapped(address)) return false;
    const match = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u.exec(
        canonicalIpAddress(address)
    );
    return match !== null && (Number.parseInt(match[1] as string, 16) >> 8) === 127;
}

function requestHeaders(request: IncomingMessage): Headers {
    const headers = new Headers();
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
        const name = request.rawHeaders[index];
        const value = request.rawHeaders[index + 1];
        if (name !== undefined && value !== undefined) headers.append(name, value);
    }
    return headers;
}

function authorizationHeader(request: IncomingMessage): string | null {
    let authorization: string | null = null;
    for (let index = 0; index < request.rawHeaders.length; index += 2) {
        const name = request.rawHeaders[index];
        const value = request.rawHeaders[index + 1];
        if (name?.toLowerCase() !== 'authorization' || value === undefined) continue;
        if (authorization !== null) return null;
        authorization = value;
    }
    return authorization;
}

function toFetchRequest(
    request: IncomingMessage,
    endpoint: HttpEndpointMetadata,
    port: number,
    headers: Headers,
    body: Buffer,
    signal: AbortSignal
): Request {
    const init: RequestInit = {
        method: 'POST',
        headers,
        signal
    };
    if (body.length > 0) init.body = new Uint8Array(body);
    return new Request(new URL(request.url ?? '/', httpEndpointUrl(endpoint, port)), init);
}

function sendStatus(response: ServerResponse, status: number, body: string, headers = {}): void {
    response.writeHead(status, {
        'content-type': 'text/plain; charset=utf-8',
        connection: 'close',
        ...headers
    });
    response.end(body);
}

const MAX_CONCURRENT_OVERSIZE_DRAINS = 8;

/** Write the refusal before discarding the upload; bound time, bytes, and concurrent drains. The eight slots are shared by every early refusal, reachable without credentials, and bounded by bytes, time, and shutdown. */
function sendBoundedRefusal(incoming: IncomingMessage, response: ServerResponse, signal: AbortSignal,
    shutdownSignal: AbortSignal, reserveDrain: () => (() => void) | null,
    status: number, body: string, headers: Record<string, string> = {}): void {
    const releaseDrain = reserveDrain();
    if (releaseDrain === null) {
        incoming.pause();
        sendStatus(response, status, body, headers);
        return;
    }
    const maxDiscardBytes = 8 * MAX_HTTP_REQUEST_BYTES;
    let discarded = 0;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (): void => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        incoming.off('data', onData);
        incoming.off('end', finish);
        incoming.off('error', finish);
        incoming.off('aborted', finish);
        incoming.socket.off('error', finish);
        incoming.socket.off('close', finish);
        response.off('close', finish);
        signal.removeEventListener('abort', finish);
        shutdownSignal.removeEventListener('abort', finish);
        incoming.pause();
        releaseDrain();
        if (!response.destroyed && !response.writableEnded) response.end();
    };
    const onData = (chunk: Buffer): void => {
        discarded += chunk.length;
        if (discarded >= maxDiscardBytes) finish();
    };
    try {
        response.writeHead(status, {
            'content-type': 'text/plain; charset=utf-8',
            connection: 'close',
            ...headers
        });
        response.write(body);
        timer = setTimeout(finish, 1_500);
        incoming.on('data', onData);
        incoming.once('end', finish);
        incoming.once('error', finish);
        incoming.once('aborted', finish);
        incoming.socket.once('error', finish);
        incoming.socket.once('close', finish);
        response.once('close', finish);
        signal.addEventListener('abort', finish, { once: true });
        shutdownSignal.addEventListener('abort', finish, { once: true });
        if (signal.aborted || shutdownSignal.aborted || incoming.readableEnded) finish();
        else incoming.resume();
    } catch (error) {
        finish();
        throw error;
    }
}

/** A fully received request needs no drain; every unfinished upload uses the shared bounded drain. */
function sendEarlyRefusal(incoming: IncomingMessage, response: ServerResponse, signal: AbortSignal,
    shutdownSignal: AbortSignal, reserveDrain: () => (() => void) | null,
    status: number, body: string, headers: Record<string, string> = {}): void {
    if (!incoming.complete) {
        sendBoundedRefusal(incoming, response, signal, shutdownSignal, reserveDrain, status, body, headers);
        return;
    }
    sendStatus(response, status, body, headers);
}

function collectBody(incoming: IncomingMessage, signal: AbortSignal): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        let size = 0;

        const cleanup = (): void => {
            incoming.off('data', onData);
            incoming.off('end', onEnd);
            incoming.off('error', onError);
            signal.removeEventListener('abort', onAbort);
        };
        const onData = (value: Buffer | string): void => {
            const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
            size += chunk.length;
            if (size > MAX_HTTP_REQUEST_BYTES) {
                cleanup();
                incoming.pause();
                reject(new RequestTooLargeError('request body exceeds the HTTP limit'));
                return;
            }
            chunks.push(chunk);
        };
        const onEnd = (): void => {
            cleanup();
            resolve(Buffer.concat(chunks, size));
        };
        const onError = (error: Error): void => {
            cleanup();
            reject(error);
        };
        const onAbort = (): void => {
            cleanup();
            reject(signal.reason instanceof Error ? signal.reason : new Error('request aborted'));
        };

        incoming.on('data', onData);
        incoming.once('end', onEnd);
        incoming.once('error', onError);
        signal.addEventListener('abort', onAbort, { once: true });
        if (signal.aborted) onAbort();
    });
}

async function writeFetchResponse(source: Response, target: ServerResponse): Promise<void> {
    target.statusCode = source.status;
    target.statusMessage = source.statusText;
    // ⚠ `Set-Cookie` is the one header that may legitimately repeat, and `Headers.forEach` yields
    // each copy separately — so a plain `setHeader` per iteration keeps only the LAST one. Node
    // takes an array for exactly this case. Preserve every cookie from the handler response.
    const setCookie = source.headers.getSetCookie();
    if (setCookie.length > 0) target.setHeader('set-cookie', setCookie);
    source.headers.forEach((value, name) => {
        if (name.toLowerCase() === 'set-cookie') return;
        target.setHeader(name, value);
    });
    target.setHeader('connection', 'close');
    if (source.body === null) {
        target.end();
        return;
    }
    await pipeline(
        Readable.fromWeb(source.body as import('node:stream/web').ReadableStream<Uint8Array>),
        target
    );
}

async function serveRequest(
    record: RequestRecord,
    endpoint: HttpEndpointMetadata,
    port: number,
    allowedOrigins: readonly string[],
    readAuthInfo: HttpAuthDecisionFn,
    refusals: HttpRefusals,
    handler: McpHandler,
    isOpen: () => boolean,
    shutdownSignal: AbortSignal,
    reserveDrain: () => (() => void) | null
): Promise<void> {
    const { incoming, outgoing } = record;
    // The ordering is a security contract: no later boundary is entered after an earlier refusal.
    if (incoming.url !== '/mcp') {
        sendEarlyRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            404, refusals.route.body, refusals.route.headers);
        return;
    }
    if (incoming.method !== 'POST') {
        sendEarlyRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            405, refusals.method.body, refusals.method.headers);
        return;
    }

    const headers = requestHeaders(incoming);
    // D7 is exact serialized-origin equality. Do not parse the value or add the SDK hostname gate.
    const origin = headers.get('origin');
    if (origin !== null && !allowedOrigins.includes(origin)) {
        sendEarlyRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            403, refusals.origin.body, refusals.origin.headers);
        return;
    }

    if (!isOpen()) {
        record.abort();
        record.socket.destroy();
        return;
    }

    const declaredLength = headers.get('content-length');
    if (declaredLength !== null && /^\d+$/.test(declaredLength)
        && Number(declaredLength) > MAX_HTTP_REQUEST_BYTES) {
        sendBoundedRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            413, refusals.length.body, refusals.length.headers);
        return;
    }

    const authDecision = await readAuthInfo({
        authorization: authorizationHeader(incoming),
        signal: record.controller.signal
    });
    if (!isOpen()) {
        record.abort();
        record.socket.destroy();
        return;
    }
    if (authDecision.kind === 'unauthenticated') {
        sendEarlyRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            401, refusals.unauthenticated.body, refusals.unauthenticated.headers);
        return;
    }
    if (authDecision.kind === 'unavailable') {
        sendEarlyRefusal(incoming, outgoing, record.controller.signal, shutdownSignal, reserveDrain,
            503, refusals.unavailable.body, refusals.unavailable.headers);
        return;
    }

    let body: Buffer;
    try {
        body = await collectBody(incoming, record.controller.signal);
    } catch (error) {
        if (error instanceof RequestTooLargeError) {
            if (!outgoing.destroyed) sendBoundedRefusal(incoming, outgoing, record.controller.signal, shutdownSignal,
                reserveDrain, 413, refusals.length.body, refusals.length.headers);
            return;
        }
        if (record.controller.signal.aborted) return;
        throw error;
    }
    if (!isOpen()) {
        record.abort();
        record.socket.destroy();
        return;
    }

    const request = toFetchRequest(
        incoming,
        endpoint,
        port,
        headers,
        body,
        record.controller.signal
    );
    // THE ADMISSION LINE: there must be no await between this transition and handler.fetch().
    record.phase = 'EXECUTING';
    const responsePromise = handler.fetch(request, { authInfo: authDecision.authInfo });
    const response = await responsePromise;
    await writeFetchResponse(response, outgoing);
}

/** Start a stateless Streamable HTTP endpoint on its validated concrete interface. */
export async function startHttp(
    options: StartHttpOptions,
    deps: StartHttpDeps = {}
): Promise<HttpServerHandle> {
    const requestedKind: unknown = options.kind;
    if (requestedKind !== 'loopback' && requestedKind !== 'network') {
        throw new Error(`HTTP bind kind is invalid: ${JSON.stringify(requestedKind)}`);
    }
    const requestedLoopback = isLoopbackHost(options.host);
    if ((requestedKind === 'loopback') !== requestedLoopback) {
        throw new Error(
            `HTTP bind kind ${JSON.stringify(requestedKind)} does not match host ${JSON.stringify(options.host)}`
        );
    }
    if (options.kind === 'network') {
        const refusal = networkHostRefusal(options.host);
        if (refusal !== null) throw new Error(`HTTP network host is invalid: ${refusal}`);
    }

    const makeHandler = deps.makeHandler ?? createMcpHandler;
    const handler = makeHandler(options.makeServer, { legacy: 'reject' });
    let address = '';
    let port = 0;
    let endpoint: HttpEndpointMetadata | null = null;
    let allowedOrigins: readonly string[] = Object.freeze([]);
    let state: LifecycleState = 'STARTING';
    const sockets = new Set<Socket>();
    const pendingTlsSockets = new Map<string, Socket>();
    const records = new Set<RequestRecord>();
    const recordsBySocket = new Map<Socket, Set<RequestRecord>>();
    const socketCleanup = new Map<Socket, () => void>();
    const drainShutdown = new AbortController();
    let activeOversizeDrains = 0;
    const reserveDrain = (): (() => void) | null => {
        if (activeOversizeDrains >= MAX_CONCURRENT_OVERSIZE_DRAINS) return null;
        activeOversizeDrains++;
        return () => { activeOversizeDrains--; };
    };
    deps.inspectState?.(() => ({
        sockets: sockets.size,
        pendingTlsSockets: pendingTlsSockets.size,
        records: records.size,
        recordsBySocket: recordsBySocket.size,
        socketCleanup: socketCleanup.size,
        activeOversizeDrains
    }));

    const finishRecord = (record: RequestRecord): void => {
        if (record.finished) return;
        record.finished = true;
        record.incoming.off('aborted', record.abort);
        record.socket.off('close', record.abort);
        records.delete(record);
        const onSocket = recordsBySocket.get(record.socket);
        onSocket?.delete(record);
        if (onSocket?.size === 0) recordsBySocket.delete(record.socket);
        record.settle();
    };

    const tls = options.tls ?? null;
    const makeListener = deps.makeListener ?? ((requestListener, configuration) => (
        configuration === null
            ? http.createServer(requestListener)
            : https.createServer(configuration.serverOptions, requestListener) as unknown as NodeHttpServer
    ));
    const listener = makeListener((request, response) => {
        const controller = new AbortController();
        let settle = (): void => {};
        const done = new Promise<void>(resolve => { settle = resolve; });
        const record: RequestRecord = {
            incoming: request,
            outgoing: response,
            socket: request.socket,
            controller,
            abort: () => controller.abort(),
            done,
            settle,
            phase: 'ADMISSION',
            finished: false
        };
        // Keep stream error listeners for their full lifetime, including after an early refusal.
        request.on('error', record.abort);
        response.on('error', record.abort);
        records.add(record);
        const onSocket = recordsBySocket.get(record.socket) ?? new Set<RequestRecord>();
        onSocket.add(record);
        recordsBySocket.set(record.socket, onSocket);
        request.once('aborted', record.abort);
        /**
         * ⚠ THE SOCKET'S `close`, NOT THE `IncomingMessage`'s — the latter fires on normal
         * completion too, so it cannot carry a completed-request hangup.
         *
         * ⚠⚠ AND IT CANNOT DISTINGUISH A HALF-CLOSE FROM A HANGUP, BECAUSE ON THIS PLATFORM THERE
         * IS NOTHING TO DISTINGUISH. Measured against a plain `node:http` server, so it is Node's
         * behaviour rather than ours: a client that calls `socket.end(request)` and one that writes
         * then `destroy()`s produce **identical** socket state at `close` — `writable=false`,
         * `readable=false`, `destroyed=true` — and in BOTH cases the client receives **zero bytes**
         * of the response. Node destroys the socket on the client's FIN; there is no half-open
         * window in which a late response can still be delivered.
         *
         * So aborting here loses nothing that was ever deliverable, and the arms must keep the
         * socket open (`write`, never `end`) when they expect an answer. `H10` is where that was
         * measured. → `designs/2026-09-14-http-shutdown-and-cancellation-selected.md`
         */
        record.socket.once('close', record.abort);

        const activeEndpoint = endpoint;
        if (state !== 'OPEN' || activeEndpoint === null) {
            record.abort();
            record.socket.destroy();
            finishRecord(record);
            return;
        }

        void serveRequest(
            record,
            activeEndpoint,
            port,
            allowedOrigins,
            options.readAuthInfo,
            options.refusals,
            handler,
            () => state === 'OPEN',
            drainShutdown.signal,
            reserveDrain
        ).catch(error => {
            if (record.controller.signal.aborted) return;
            if (!response.headersSent) sendEarlyRefusal(request, response, record.controller.signal, drainShutdown.signal, reserveDrain,
                500, options.refusals.internal.body, options.refusals.internal.headers);
            else response.destroy(error instanceof Error ? error : undefined);
        }).finally(() => finishRecord(record));
    }, tls);
    listener.maxRequestsPerSocket = 1;
    const socketKey = (socket: Socket): string => `${socket.remoteAddress ?? ''}:${socket.remotePort ?? ''}`;
    const trackSocket = (socket: Socket): void => {
        sockets.add(socket);
        const onError = (): void => {
            for (const record of recordsBySocket.get(socket) ?? []) record.abort();
        };
        const onClose = (): void => {
            for (const record of recordsBySocket.get(socket) ?? []) record.abort();
            sockets.delete(socket);
            const key = socketKey(socket);
            if (pendingTlsSockets.get(key) === socket) pendingTlsSockets.delete(key);
            socket.off('error', onError);
            socketCleanup.delete(socket);
        };
        socket.on('error', onError);
        socket.once('close', onClose);
        socketCleanup.set(socket, () => {
            socket.off('error', onError);
            socket.off('close', onClose);
        });
    };
    listener.on('connection', socket => {
        if (tls !== null) pendingTlsSockets.set(socketKey(socket), socket);
        trackSocket(socket);
    });
    if (tls !== null) listener.on('secureConnection', secureSocket => {
        // A completed handshake changes the request socket from raw TCP to TLSSocket.
        const raw = pendingTlsSockets.get(socketKey(secureSocket));
        if (raw !== undefined) {
            pendingTlsSockets.delete(socketKey(secureSocket));
            sockets.delete(raw);
        }
        trackSocket(secureSocket);
    });

    const listenHost = bareHost(options.host);
    try {
        await new Promise<void>((resolve, reject) => {
            const onError = (error: Error): void => {
                listener.off('listening', onListening);
                reject(error);
            };
            const onListening = (): void => {
                listener.off('error', onError);
                resolve();
            };
            listener.once('error', onError);
            listener.once('listening', onListening);
            listener.listen(options.port, listenHost);
        });
    } catch (error) {
        await handler.close();
        throw error;
    }

    const bound = listener.address();
    const rejectBoundAddress = async (detail: string): Promise<never> => {
        const results = await Promise.allSettled([
            Promise.resolve().then(() => handler.close()),
            new Promise<void>(resolve => listener.close(() => resolve()))
        ]);
        state = 'CLOSED';
        const cleanupFailures = results
            .filter((result): result is PromiseRejectedResult => result.status === 'rejected')
            .map(result => result.reason);
        if (cleanupFailures.length > 0) {
            throw new AggregateError(cleanupFailures, `${detail}; startup cleanup failed`);
        }
        throw new Error(detail);
    };
    if (bound === null || typeof bound === 'string') {
        return rejectBoundAddress('HTTP listener did not report an IP address');
    }
    if (options.kind === 'loopback') {
        if (!isBoundLoopback(bound.address)) {
            return rejectBoundAddress(`HTTP loopback host resolved outside loopback: ${bound.address}`);
        }
    } else {
        const refusal = networkHostRefusal(bound.address);
        const requestedAddress = canonicalIpAddress(options.host);
        const reportedAddress = refusal === null ? canonicalIpAddress(bound.address) : null;
        if (refusal !== null || reportedAddress !== requestedAddress) {
            return rejectBoundAddress(
                `HTTP network listener reported ${JSON.stringify(bound.address)}, not requested address ${JSON.stringify(bareHost(options.host))}`
            );
        }
    }
    endpoint = tls === null
        ? Object.freeze({
            scheme: 'http',
            tlsEnabled: false,
            interfaceAddress: bound.address,
            exposure: options.kind
        })
        : Object.freeze({
            scheme: tls.scheme,
            tlsEnabled: tls.tlsEnabled,
            certificate: tls.certificate,
            interfaceAddress: bound.address,
            exposure: options.kind
        });
    port = bound.port;
    address = httpEndpointUrl(endpoint, port).host;
    allowedOrigins = defaultAllowedOrigins(endpoint, port);
    state = 'OPEN';

    let listenerClose: Promise<void> | null = null;
    let handlerClose: Promise<void> | null = null;
    let orderedClose: Promise<void> | null = null;

    const stopAccepting = (): Promise<void> => {
        listenerClose ??= new Promise<void>((resolve, reject) => {
            listener.close(error => error === undefined ? resolve() : reject(error));
        });
        return listenerClose;
    };
    const closeHandler = (): Promise<void> => {
        handlerClose ??= Promise.resolve(handler.close());
        return handlerClose;
    };
    const close = (): Promise<void> => {
        if (orderedClose !== null) return orderedClose;
        state = 'CLOSING';
        const closed = stopAccepting();
        void closed.catch(() => {});
        listener.closeIdleConnections();
        // Defer abort delivery until orderedClose itself is installed: AbortSignal listeners run
        // synchronously and may otherwise re-enter close() before its memoized promise is visible.
        orderedClose = Promise.resolve().then(async () => {
            drainShutdown.abort();
            for (const record of records) {
                if (record.phase === 'ADMISSION') record.abort();
            }
            for (const socket of sockets) {
                const onSocket = recordsBySocket.get(socket);
                const executing = [...(onSocket ?? [])]
                    .some(record => record.phase === 'EXECUTING');
                if (!executing) socket.destroy();
            }

            const executing = [...records]
                .filter(record => record.phase === 'EXECUTING')
                .map(record => record.done);
            // The listener applies no shutdown timeout. The embedding server must bound its
            // in-flight work; slice 4 adds Scribe write tracking to this drain.
            await Promise.all(executing);
            try {
                await closeHandler();
            } finally {
                try {
                    await closed;
                } finally {
                    for (const cleanup of socketCleanup.values()) cleanup();
                    socketCleanup.clear();
                    sockets.clear();
                    pendingTlsSockets.clear();
                    state = 'CLOSED';
                }
            }
        });
        return orderedClose;
    };

    let serverErrorReported = false;
    listener.on('error', error => {
        if (serverErrorReported) return;
        serverErrorReported = true;
        const shutdown = close();
        options.onServerError?.(error, shutdown);
        void shutdown.catch(() => {});
    });

    return Object.freeze({
        address,
        port,
        endpoint,
        allowedOrigins,
        close
    });
}
