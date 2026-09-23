import { serveStdio } from '@modelcontextprotocol/server/stdio';
import type { Server } from '@modelcontextprotocol/server';
import { isIP } from 'node:net';

import { createFsGate, isRefusal, type FsGate, type FenceRefusal } from 'wyrd-fence';
import { createReadTokenVerifier, loadReadToken } from './auth.js';
import {
    httpEndpointUrl,
    isLoopbackHost,
    startHttp,
    type HttpBind,
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
    /** Compatibility adapter for the pre-HTTP startup harness. Production never supplies it. */
    readonly connect?: ((server: Server) => Promise<void>) | undefined;
}

export interface MainResult {
    readonly started: boolean;
    readonly reason: string | null;
    readonly http: HttpServerHandle | null;
}

export interface ConfiguredServerContext {
    readonly gate: FsGate;
    readonly transport: ServerTransport;
    readonly layers: readonly string[];
    readonly listingFailed: boolean;
}

export type HttpArgResult =
    | { readonly present: false }
    | { readonly present: true; readonly bind: HttpBind | null; readonly detail: string | null };

/** `--http <port>` or `--http <host>:<port>`; there is deliberately no default port. */
export function readHttpArg(argv: readonly string[]): HttpArgResult {
    const httpIndexes = argv.flatMap((argument, index) => argument === '--http' ? [index] : []);
    const publicIndexes = argv.flatMap(
        (argument, index) => argument === '--http-public' ? [index] : []
    );
    if (argv.some(argument => argument.startsWith('--http-public='))) {
        return {
            present: true,
            bind: null,
            detail: '--http-public is value-less; use the flag by itself'
        };
    }
    if (httpIndexes.length === 0) {
        if (publicIndexes.length > 0) {
            return {
                present: true,
                bind: null,
                detail: '--http-public requires one --http address'
            };
        }
        return { present: false };
    }
    if (httpIndexes.length > 1) {
        return { present: true, bind: null, detail: '--http may be specified only once' };
    }
    if (publicIndexes.length > 1) {
        return { present: true, bind: null, detail: '--http-public may be specified only once' };
    }

    const index = httpIndexes[0] as number;
    const value = argv[index + 1];
    if (value === undefined || value === '' || value.startsWith('--')) {
        return { present: true, bind: null, detail: '--http requires a port or host:port' };
    }

    let host: string;
    let portText: string;
    if (/^\d+$/.test(value)) {
        host = '127.0.0.1';
        portText = value;
    } else if (value.startsWith('[')) {
        const explicit = /^\[([^\]]+)\]:(.*)$/u.exec(value);
        if (explicit === null) {
            return {
                present: true,
                bind: null,
                detail: `HTTP IPv6 address must use [address]:port: ${value}`
            };
        }
        host = `[${explicit[1] as string}]`;
        portText = explicit[2] as string;
    } else {
        const firstColon = value.indexOf(':');
        if (firstColon === -1) {
            return { present: true, bind: null, detail: `HTTP address is missing its port: ${value}` };
        }
        if (firstColon !== value.lastIndexOf(':')) {
            return {
                present: true,
                bind: null,
                detail: `HTTP IPv6 address must be bracketed: ${value}`
            };
        }
        host = value.slice(0, firstColon);
        portText = value.slice(firstColon + 1);
    }

    if (!/^\d+$/.test(portText)) {
        return { present: true, bind: null, detail: `HTTP port must be decimal: ${portText}` };
    }
    const port = Number(portText);
    if (!Number.isSafeInteger(port) || port < 0 || port > 65_535) {
        return { present: true, bind: null, detail: `HTTP port is outside 0..65535: ${portText}` };
    }

    const publicRequested = publicIndexes.length === 1;
    if (isLoopbackHost(host)) {
        if (publicRequested) {
            return {
                present: true,
                bind: null,
                detail: '--http-public is redundant or misplaced for a loopback address'
            };
        }
        return {
            present: true,
            bind: Object.freeze({ kind: 'loopback', host, port }),
            detail: null
        };
    }

    const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
    if (bare.includes('%')) {
        return {
            present: true,
            bind: null,
            detail: 'scoped IPv6 cannot be serialized into a valid Origin'
        };
    }
    const version = isIP(bare);
    if (version === 0) {
        return {
            present: true,
            bind: null,
            detail: `HTTP host must be a concrete numeric interface address: ${host}`
        };
    }
    if (version === 4 && host.startsWith('[')) {
        return { present: true, bind: null, detail: 'HTTP IPv4 addresses must not be bracketed' };
    }
    if (version === 4) {
        const first = Number(bare.split('.')[0]);
        if (bare === '0.0.0.0') {
            return { present: true, bind: null, detail: 'HTTP wildcard 0.0.0.0 names every interface' };
        }
        if (first >= 224 && first <= 239) {
            return { present: true, bind: null, detail: 'HTTP multicast is not a unicast interface endpoint' };
        }
        if (first === 255) {
            return { present: true, bind: null, detail: 'HTTP broadcast is not a unicast interface endpoint' };
        }
    } else {
        const normalized = new URL(`http://[${bare}]`).hostname.slice(1, -1);
        if (normalized === '::') {
            return { present: true, bind: null, detail: 'HTTP wildcard :: names every interface' };
        }
        if (normalized.startsWith('ff')) {
            return { present: true, bind: null, detail: 'HTTP multicast is not a unicast interface endpoint' };
        }
        if (normalized.startsWith('::ffff:')) {
            return { present: true, bind: null, detail: 'HTTP IPv4-mapped IPv6 is not an interface endpoint' };
        }
    }
    if (!publicRequested) {
        return {
            present: true,
            bind: null,
            detail: 'a non-loopback HTTP address requires --http-public'
        };
    }
    return {
        present: true,
        bind: Object.freeze({ kind: 'network', host, port }),
        detail: null
    };
}

export function httpDisclosure(handle: HttpServerHandle, canonicalGrant: string): string {
    const endpoint = httpEndpointUrl(handle.endpoint, handle.port);
    endpoint.pathname = '/mcp';
    const common = [
        'It accepts POST /mcp only.',
        `Allowed Origin values: ${handle.allowedOrigins.join(', ')}. An absent Origin proceeds.`,
        'Bearer authentication is required to use POST /mcp.',
        `The one canonical grant is: ${canonicalGrant}`,
        'Its only tool is `read`; the tool surface is read-only.'
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
            '  · A hard link that already exists inside the granted folder serves the file it',
            '    points at, even when that file lives outside the folder.',
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
        '  · A hard link that already exists inside the granted folder serves the file it',
        '    points at, even when that file lives outside the folder.',
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
    'Wyrd serves the folder you name. The only tool it registers is `read`; none writes, moves',
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
    'readable wherever on the disk that file lives, and ordinary folder inspection will not show',
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

export async function main(deps: MainDeps): Promise<MainResult> {
    // Step 2 — the command line wins over the environment; nothing else is read.
    const fromArgv = readGrantArg(deps.argv);
    const rawGrant = fromArgv !== null ? fromArgv : (deps.env['WYRD_GRANT'] ?? null);

    // Step 3 — absent. Static refusal, non-zero exit, nothing touched.
    if (rawGrant === null || rawGrant === '') {
        deps.stderr(NO_GRANT_MESSAGE);
        deps.setExitCode(2);
        return { started: false, reason: 'NO_GRANT', http: null };
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
        return { started: false, reason: gate.reason, http: null };
    }

    // Step 7 — detect which Mage layers are actually present, so the disclosure names what is
    // really there instead of asserting a structure the folder may not have (D1: Mage structure is
    // a detected bonus, not a requirement).
    //
    // ⚠ A FAILED PROBE IS NOT A REASON TO REFUSE TO START. The grant already passed the fence's
    // own startup checks; these reads are for wording only, and a folder whose layer names cannot
    // be checked still gets the existing honest failure disclosure with no vault paragraph.
    const { layers, listingFailed } = await detectLayers(name => gate.probeInGrant(name));

    const httpArg = readHttpArg(deps.argv);
    const transport: ServerTransport = httpArg.present ? 'http' : 'stdio';
    const context = Object.freeze({ gate, transport, layers, listingFailed });
    const configure = deps.makeConfiguredServer
        ?? (configured => createServer({
            fsgate: configured.gate,
            transport: configured.transport,
            layers: configured.layers,
            listingFailed: configured.listingFailed
        }));
    // Both transports receive this exact factory shape. It captures only validated, detected state;
    // each invocation performs server registration and no startup I/O or human disclosure.
    const makeConfiguredServer = (): Server => configure(context);
    const tlsArg = readTlsArgs(deps.argv);
    if (!tlsArg.ok) {
        deps.stderr(`wyrd: refusing to start — ${tlsArg.detail}`);
        deps.setExitCode(2);
        return { started: false, reason: 'TLS_CONFIG', http: null };
    }
    if (!httpArg.present && tlsArg.paths !== null) {
        deps.stderr('wyrd: refusing to start — --tls-cert and --tls-key require --http');
        deps.setExitCode(2);
        return { started: false, reason: 'TLS_CONFIG', http: null };
    }
    if (httpArg.present) {
        if (httpArg.bind === null) {
            deps.stderr(`wyrd: refusing to start — ${httpArg.detail}`);
            deps.setExitCode(2);
            return { started: false, reason: 'HTTP_BIND', http: null };
        }
        let tlsConfiguration = null;
        if (tlsArg.paths !== null) {
            const loaded = await loadTlsConfiguration(tlsArg.paths);
            if (!loaded.ok) {
                deps.stderr(`wyrd: refusing to start — ${loaded.detail}`);
                deps.setExitCode(2);
                return { started: false, reason: 'TLS_CONFIG', http: null };
            }
            tlsConfiguration = loaded.configuration;
        }
        const readToken = loadReadToken(deps.argv, deps.env);
        if (!readToken.ok) {
            deps.stderr(`wyrd: refusing to start — ${readToken.detail}`);
            deps.setExitCode(2);
            return { started: false, reason: 'READ_TOKEN', http: null };
        }
        const makeReadAuthInfo = deps.makeReadAuthInfo ?? createReadTokenVerifier;
        const readAuthInfo = makeReadAuthInfo(readToken.token);
        const beginHttp = deps.startHttp ?? startHttp;
        const handle = await beginHttp({
            ...httpArg.bind,
            makeServer: makeConfiguredServer,
            readAuthInfo,
            ...(tlsConfiguration === null ? {} : { tls: tlsConfiguration })
        });
        deps.stderr(httpDisclosure(handle, gate.disclosedRoot()));
        return { started: true, reason: null, http: handle };
    }

    if (deps.connect !== undefined) {
        // Compatibility for startup.test.js: adapt its old Server injection to the factory seam.
        await deps.connect(makeConfiguredServer());
    } else {
        const beginStdio = deps.serveStdio ?? serveStdio;
        await beginStdio(makeConfiguredServer, { legacy: 'serve' });
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
    deps.stderr(disclosure(gate.disclosedRoot(), context.transport, layers, listingFailed));
    return { started: true, reason: null, http: null };
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
