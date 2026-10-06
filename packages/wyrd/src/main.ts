import { randomUUID } from 'node:crypto';
import { isAbsolute } from 'node:path';
import { stat } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { SCAN_BYTES, LexicalScanBackend, type SearchBackend, type SearchBackendDisclosure, type SearchBackendModule } from './search.js';
import { searchBackendParagraph } from './server.js';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import type { Server } from '@modelcontextprotocol/server';

import { createFsGate, isRefusal, type FsGate, type FenceRefusal } from 'wyrd-fence';
import { readHttpArg, type HttpBind } from 'wyrd-http';
export { readHttpArg } from 'wyrd-http';
export type { HttpArgResult } from 'wyrd-http';
import { createReadTokenVerifier, loadReadToken } from './auth.js';
import {
    httpEndpointUrl,
    startHttp,
    type HttpServerHandle,
    type ReadAuthInfo,
    type StartHttpOptions
} from './http.js';
import {
    createServer,
    detectLayers,
    disclosure,
    type ServerTransport
} from './server.js';
import { loadTlsConfiguration, readTlsArgs } from './tls-config.js';

/**
 * The application seam. Every dependency that touches the world arrives as an argument, so a
 * startup arm exercises the real sequence rather than a stand-in for it.
 *
 * ⚠ Startup arms exercise THIS, not `createServer`. Injecting at `createServer` replaces the
 * fence, and a suite can go green having exercised a fake.
 */
export interface MainDeps {
    readonly argv: readonly string[];
    readonly env: Record<string, string | undefined>;
    readonly makeFsGate: (options: { rawGrant: string }) => FsGate | FenceRefusal;
    readonly stderr: (line: string) => void;
    readonly setExitCode: (code: number) => void;
    readonly makeConfiguredServer?: ((context: ConfiguredServerContext) => Server) | undefined;
    readonly serveStdio?: ((factory: () => Server, options: { legacy: 'serve' }) => unknown) | undefined;
    readonly startHttp?: ((options: StartHttpOptions) => Promise<HttpServerHandle>) | undefined;
    readonly makeReadAuthInfo?: ((expectedToken: Uint8Array) => ReadAuthInfo) | undefined;
    readonly importSearchBackend?: (fileUrl: string) => Promise<unknown>;
    /** Compatibility adapter for the pre-HTTP startup harness. Production never supplies it. */
    readonly connect?: ((server: Server) => Promise<void>) | undefined;
}

export interface MainResult {
    readonly started: boolean;
    readonly reason: string | null;
    readonly http: HttpServerHandle | null;
    readonly closeSearchBackend: (() => Promise<void>) | null;
}

export interface ConfiguredServerContext {
    readonly searchBackend?: SearchBackend;
    readonly searchBackendDisclosure?: SearchBackendDisclosure;
    readonly gate: FsGate;
    readonly transport: ServerTransport;
    readonly layers: readonly string[];
    readonly listingFailed: boolean;
}

export function httpDisclosure(handle: HttpServerHandle, canonicalGrant: string, module?: SearchBackendDisclosure): string {
    const endpoint = httpEndpointUrl(handle.endpoint, handle.port);
    endpoint.pathname = '/mcp';
    const common = [
        'It accepts POST /mcp only.',
        `Allowed Origin values: ${handle.allowedOrigins.join(', ')}. An absent Origin proceeds.`,
        'Bearer authentication is required to use POST /mcp.',
        `The one canonical grant is: ${canonicalGrant}`,
        module ? 'Its built-in read tool and search reads are read-only; the additional module has its own permissions.' : 'Its tools are `read` and `search`; both are read-only.',
        ...searchBackendParagraph(module)
    ];
    if (handle.endpoint.tlsEnabled) {
        const certificateLines = [
            'Transport: HTTPS. TLS is on.',
            `Certificate SHA-256 fingerprint: ${handle.endpoint.certificate.fingerprint256}.`,
            `Certificate expires: ${handle.endpoint.certificate.validTo}.`
        ];
        if (Date.parse(handle.endpoint.certificate.validTo) - Date.now() < 30 * 24 * 60 * 60 * 1_000) {
            certificateLines.push('WARNING: the TLS certificate expires in fewer than 30 days.');
        }
        if (handle.endpoint.exposure === 'loopback') {
            return [
                `wyrd Reader is listening only on this machine, through the loopback interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,
                `Endpoint: ${endpoint.href}.`,
                ...certificateLines,
                ...common
            ].join('\n');
        }
        return [
            `wyrd Reader is listening on the network interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,
            `Endpoint: ${endpoint.href}.`,
            ...certificateLines,
            '',
            'WHAT THIS MEANS, AND WHAT WYRD DOES NOT KNOW:',
            `  · Any device that can route packets to ${handle.endpoint.interfaceAddress} may reach this server.`,
            `  · wyrd does not know, and does not check, what can route to it. Firewalls, VPN`,
            '    routes, container port publication and virtual-machine forwarding can all',
            '    deliver traffic here from outside the network you are thinking of.',
            '  · This address was checked ONCE, just now. If this machine later joins a VPN or',
            '    changes networks, wyrd will not re-check it and will not print this again.',
            '  · A hard link that already exists inside the granted folder makes the file it',
            '    points at readable and searchable, even when that file lives outside the folder.',
            '',
            ...common
        ].join('\n');
    }
    if (handle.endpoint.exposure === 'loopback') {
        return [
            `wyrd Reader is listening only on this machine, through the loopback interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,
            `Endpoint: ${endpoint.href}.`,
            'Transport: plain HTTP. TLS is off.',
            ...common
        ].join('\n');
    }
    return [
        `wyrd Reader is listening on the network interface at ${handle.endpoint.interfaceAddress}, port ${handle.port}.`,
        `Endpoint: ${endpoint.href}.`,
        'Transport: plain HTTP. TLS is off.',
        '',
        'WHAT THIS MEANS, AND WHAT WYRD DOES NOT KNOW:',
        `  · Any device that can route packets to ${handle.endpoint.interfaceAddress} may reach this server.`,
        `  · wyrd does not know, and does not check, what can route to it. Firewalls, VPN`,
        '    routes, container port publication and virtual-machine forwarding can all',
        '    deliver traffic here from outside the network you are thinking of.',
        '  · This address was checked ONCE, just now. If this machine later joins a VPN or',
        '    changes networks, wyrd will not re-check it and will not print this again.',
        '  · TLS is off, so the bearer token travels in the clear and can be replayed by',
        '    anyone who captures it.',
        '  · A hard link that already exists inside the granted folder makes the file it',
        '    points at readable and searchable, even when that file lives outside the folder.',
        '',
        ...common
    ].join('\n');
}

/**
 * The refusal printed when no folder has been granted.
 *
 * ⚠ STATIC, and that is the whole point. Nothing is known at refusal time and nothing may be
 * probed to find out — probing would breach the fence in order to write the fence's own error
 * message. The layer taxonomy below is fixed text, not detection.
 */
export const NO_GRANT_MESSAGE = [
    'wyrd: refusing to start — no folder has been granted.',
    '',
    'Grant one, either way:',
    '  --grant <absolute path>       on the command line (wins over the environment)',
    '  WYRD_GRANT=<absolute path>    in the environment',
    '',
    'Wyrd serves the folder you name. It registers `read` and `search`; neither writes, moves',
    'or deletes. Every request is checked against that folder before a file is opened, subject to',
    'the known limits below. ANY PATH INSIDE IT CAN BE REQUESTED, of any type, hidden entries',
    'included, such as .env and .git/config: there is no extension filter and no ignore-file',
    'support. What comes back is narrower than what can be requested, because a directory is',
    'refused and so are bytes that are not valid UTF-8; that limits what is READABLE, not what is',
    'REACHABLE. Grant a subfolder containing only what you mean to share.',
    '',
    'A handful of NAME SPELLINGS are refused as input before anything is opened, so a file whose',
    'name takes one sits on the disk and cannot be requested: a name beginning with a drive letter',
    'and a colon, such as C:notes, on every host — including the hosts where that is an ordinary',
    'filename — and, on Windows, a component containing a colon (which names a data stream rather',
    'than a file) or a reserved device name such as NUL.md or COM1.',
    '',
    'Known limits: a hard link that already exists inside the folder makes the file it points at',
    'readable and searchable wherever on the disk that file lives, and ordinary folder inspection will not show',
    'it as a link. A path component swapped between validation and opening may be read instead of',
    'the one checked; that one needs write access to the folder. Some filesystem reparse points',
    'cannot be classified by this runtime; a path resolving through one is still checked against',
    'the folder, so it cannot be used to read outside it, but if it leads to a file outside that is',
    'missing or unreadable the refusal distinguishes those two cases. That one needs no attacker',
    'and can occur in an ordinary cloud-synced folder. Measured on Windows; macOS and Linux are',
    'reasoned but unmeasured. This list is what is known, not a proof that nothing else exists.',
    '',
    'Setting WYRD_OBSERVE makes the process itself ATTEMPT, at exit, to write a diagnostic log of',
    'the PATHNAMES it touches, to exactly the path you supply, which is not checked and may be a',
    'network share. The write is attempted, not guaranteed — if it fails it fails silently.',
    '',
    'If that folder is a Mage vault, granting it exposes these layers:',
    '  Arc/     immutable source — may hold private material',
    '  Mage/    agent-curated structure',
    '  Forum/   non-canonical staging, including Forum/Antechamber/ pre-canon drafts',
    '',
    'Grant a subfolder instead to expose only that subfolder.',
    'No folder is inspected until one is granted.'
].join('\n');

/** `--grant <value>` and `--grant=<value>`. Nothing else is read from the command line. */
export function readGrantArg(argv: readonly string[]): string | null {
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index] as string;
        if (argument === '--grant') {
            const value = argv[index + 1];
            return value === undefined ? '' : value;
        }
        if (argument.startsWith('--grant=')) return argument.slice('--grant='.length);
    }
    return null;
}

export function readSearchBackendArg(argv: readonly string[]): string | null {
    for (let index = 0; index < argv.length; index++) {
        const argument = argv[index]!;
        if (argument === '--search-backend') return argv[index + 1] ?? '';
        if (argument.startsWith('--search-backend=')) return argument.slice('--search-backend='.length);
    }
    return null;
}

const grantId = randomUUID();

export async function main(deps: MainDeps): Promise<MainResult> {
    let closeSearchBackend: (() => Promise<void>) | null = null;
    // Step 2 — the command line wins over the environment; nothing else is read.
    const fromArgv = readGrantArg(deps.argv);
    const rawGrant = fromArgv !== null ? fromArgv : (deps.env['WYRD_GRANT'] ?? null);

    // Step 3 — absent. Static refusal, non-zero exit, nothing touched.
    if (rawGrant === null || rawGrant === '') {
        deps.stderr(NO_GRANT_MESSAGE);
        deps.setExitCode(2);
        return { started: false, reason: 'NO_GRANT', http: null, closeSearchBackend };
    }

    // Steps 4 to 6 — lexical validation, then the two primitives on the named root, inside the
    // factory so a direct caller cannot skip them.
    const gate = deps.makeFsGate({ rawGrant });
    if (isRefusal(gate)) {
        deps.stderr(`wyrd: refusing to start — ${gate.detail}`);
        if (gate.resolvedPath !== '' && !gate.detail.includes(gate.resolvedPath)) {
            deps.stderr(`wyrd: the path resolved to ${gate.resolvedPath}`);
        }
        deps.setExitCode(2);
        return { started: false, reason: gate.reason, http: null, closeSearchBackend };
    }

    // Step 7 — detect which Mage layers are actually present, so the disclosure names what is
    // really there instead of asserting a structure the folder may not have (D1: Mage structure is
    // a detected bonus, not a requirement).
    //
    // ⚠ A FAILED PROBE IS NOT A REASON TO REFUSE TO START. The grant already passed the fence's
    // own startup checks; these reads are for wording only, and a folder whose layer names cannot
    // be checked still gets the existing honest failure disclosure with no vault paragraph.
    const backendArg = readSearchBackendArg(deps.argv);
    const backendPath = backendArg !== null ? backendArg : (deps.env['WYRD_SEARCH_BACKEND'] ?? '');
    const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name),
        backendPath === '' ? undefined : () => gate.listGrantRoot());
    let searchBackend: SearchBackend | undefined;
    let searchBackendDisclosure: SearchBackendDisclosure | undefined;
    if (backendPath !== '') {
        try {
            if (!isAbsolute(backendPath)) throw new Error('search backend path must be absolute');
            if (!(await stat(backendPath)).isFile()) throw new Error('search backend path must name a file');
            const imported = await (deps.importSearchBackend ?? (url => import(url)))(pathToFileURL(backendPath).href);
            const factory = (imported as Partial<SearchBackendModule> | null)?.createSearchBackend;
            if (typeof factory !== 'function') throw new Error('search backend module must export createSearchBackend');
            const lexical = new LexicalScanBackend();
            const host = Object.freeze({ contractVersion: 1 as const, grantId, maxSliceBytes: SCAN_BYTES,
                layers: Object.freeze([...layers]), listingFailed,
                lexical: Object.freeze({ search: lexical.search.bind(lexical) }) });
            const result = await factory(host);
            if (result === null || typeof result !== 'object') throw new Error('search backend factory must return an object');
            if (typeof result.backend?.search !== 'function') throw new Error('search backend must have a search function');
            const suppliedLines = result.disclosure;
            if (!Array.isArray(suppliedLines) || suppliedLines.length < 1 || suppliedLines.length > 40) throw new Error('search backend disclosure must have 1 to 40 lines');
            const lines = Object.freeze(Array.from({ length: suppliedLines.length }, (_, index) => suppliedLines[index]));
            // A Unicode code point takes at most two UTF-16 code units.
            for (const line of lines) {
                if (typeof line !== 'string' || line.length > 400 || line.trim().length === 0 || [...line].length > 200 || /[\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(line))
                    throw new Error('search backend disclosure lines must be non-empty strings of at most 200 characters without controls');
            }
            if (result.close !== undefined && typeof result.close !== 'function') throw new Error('search backend close must be a function');
            const selectedBackend = result.backend;
            searchBackend = Object.freeze({ search: selectedBackend.search.bind(selectedBackend) });
            searchBackendDisclosure = Object.freeze({ path: backendPath, lines });
            if (result.close !== undefined) {
                const close = result.close.bind(result);
                let closing: Promise<void> | null = null;
                closeSearchBackend = () => closing ??= new Promise<void>((resolve, reject) => {
                    const timer = setTimeout(() => reject(new Error('deadline exceeded (10 seconds)')), 10_000);
                    Promise.resolve().then(() => close()).then(resolve, reject).finally(() => clearTimeout(timer));
                });
            }
        } catch (error) {
            const detail = (error instanceof Error ? error.message : String(error)).replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, ' ');
            deps.stderr(`wyrd: refusing to start — ${detail}`);
            deps.setExitCode(2);
            return { started: false, reason: 'SEARCH_BACKEND', http: null, closeSearchBackend: null };
        }
    }

    const httpArg = readHttpArg(deps.argv);
    const transport: ServerTransport = httpArg.present ? 'http' : 'stdio';
    const context = Object.freeze({ gate, transport, layers, listingFailed,
        ...(searchBackend === undefined ? {} : { searchBackend }),
        ...(searchBackendDisclosure === undefined ? {} : { searchBackendDisclosure }) });
    const configure = deps.makeConfiguredServer
        ?? (configured => createServer({
            fsgate: configured.gate,
            transport: configured.transport,
            layers: configured.layers,
            listingFailed: configured.listingFailed,
            ...(configured.searchBackend === undefined ? {} : { searchBackend: configured.searchBackend }),
            ...(configured.searchBackendDisclosure === undefined ? {} : { searchBackendDisclosure: configured.searchBackendDisclosure })
        }));
    // Both transports receive this exact factory shape. It captures only validated, detected state;
    // each invocation performs server registration and no startup I/O or human disclosure.
    const makeConfiguredServer = (): Server => configure(context);
    const tlsArg = readTlsArgs(deps.argv);
    if (!tlsArg.ok) {
        deps.stderr(`wyrd: refusing to start — ${tlsArg.detail}`);
        deps.setExitCode(2);
        return { started: false, reason: 'TLS_CONFIG', http: null, closeSearchBackend };
    }
    if (!httpArg.present && tlsArg.paths !== null) {
        deps.stderr('wyrd: refusing to start — --tls-cert and --tls-key require --http');
        deps.setExitCode(2);
        return { started: false, reason: 'TLS_CONFIG', http: null, closeSearchBackend };
    }
    if (httpArg.present) {
        if (httpArg.bind === null) {
            deps.stderr(`wyrd: refusing to start — ${httpArg.detail}`);
            deps.setExitCode(2);
            return { started: false, reason: 'HTTP_BIND', http: null, closeSearchBackend };
        }
        let tlsConfiguration = null;
        if (tlsArg.paths !== null) {
            const loaded = await loadTlsConfiguration(tlsArg.paths);
            if (!loaded.ok) {
                deps.stderr(`wyrd: refusing to start — ${loaded.detail}`);
                deps.setExitCode(2);
                return { started: false, reason: 'TLS_CONFIG', http: null, closeSearchBackend };
            }
            tlsConfiguration = loaded.configuration;
        }
        const readToken = loadReadToken(deps.argv, deps.env);
        if (!readToken.ok) {
            deps.stderr(`wyrd: refusing to start — ${readToken.detail}`);
            deps.setExitCode(2);
            return { started: false, reason: 'READ_TOKEN', http: null, closeSearchBackend };
        }
        const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;
        const readAuthInfo = makeReadAuthInfo(readToken.token);
        const beginHttp = deps.startHttp ?? startHttp;
        const handle = await beginHttp({
            ...httpArg.bind,
            makeServer: makeConfiguredServer,
            readAuthInfo,
            onServerError: (error, shutdown) => {
                deps.stderr(`wyrd: HTTP listener failed — ${error.message}`);
                void shutdown.catch(closeError => {
                    deps.stderr(`wyrd: HTTP shutdown failed — ${String(closeError)}`);
                }).finally(() => {
                    deps.setExitCode(1);
                    void closeSearchBackend?.().catch(() => undefined);
                });
            },
            ...(tlsConfiguration === null ? {} : { tls: tlsConfiguration })
        }).catch(async (error: unknown) => {
            // The module's close must run when the transport never starts.
            await closeSearchBackend?.().catch(() => undefined);
            throw error;
        });
        deps.stderr(httpDisclosure(handle, gate.disclosedRoot(), searchBackendDisclosure));
        return { started: true, reason: null, http: handle, closeSearchBackend };
    }

    try {
        if (deps.connect !== undefined) {
            // Compatibility for startup.test.js: adapt its old Server injection to the factory seam.
            await deps.connect(makeConfiguredServer());
        } else {
            const beginStdio = deps.serveStdio ?? serveStdio;
            await beginStdio(makeConfiguredServer, { legacy: 'serve' });
        }
    } catch (error) {
        // The module's close must run when the transport never starts.
        await closeSearchBackend?.().catch(() => undefined);
        throw error;
    }

    // ⚠⚠ THE DISCLOSURE GOES TO THE HUMAN TOO, AND THIS IS THE ONLY CHANNEL WHOSE DELIVERY IS
    // CERTAIN. It previously went only into `initialize.instructions` — where the audience is the
    // MODEL, and where the fence plan's own §8 records that no client documents surfacing it at
    // all. So the person who owns the notes was told one word about what they had just exposed:
    // "(read-only)". The rule this server is built to is "say exactly what happens REGARDLESS",
    // and a channel that may reach nobody does not satisfy it.
    //
    // Convention, not invention: printing what you are operating on to stderr is ordinary CLI
    // practice and is what the reference filesystem MCP server does with its allowed directories.
    deps.stderr(disclosure(gate.disclosedRoot(), context.transport, layers, listingFailed, searchBackendDisclosure));
    return { started: true, reason: null, http: null, closeSearchBackend };
}

/*
 * ⚠ `export { createFsGate };` STOOD HERE AND IS DELIBERATELY GONE, 2026-08-31. Do not restore it.
 *
 * It had no internal consumer — `index.ts` imports the fence itself, and every arm imports the
 * fence package directly — so its only effect was to make this package a SECOND public path to
 * `createFsGate`, alongside the deep import of `dist/fsgate.js` that `files: ["dist"]` allowed.
 * The fence now lives in `wyrd-fence`, which is where a consumer gets it; re-exporting it here
 * would put the extraction back where it started while looking like a convenience.
 */
