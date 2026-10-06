import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import type { Server, Tool, Transport } from '@modelcontextprotocol/server';

import { isRefusal } from 'wyrd-fence';
import type { FenceRefusal, FsGate } from 'wyrd-fence';
import {
    loadTlsConfiguration, readHttpArg, readTlsArgs, type HttpServerHandle,
    type StartHttpOptions
} from 'wyrd-http';

import { gateAppender } from './ledger.js';
import { startScribeHttp, scribeHttpDisclosure } from './http.js';
import { createWriteAuthInfo, loadWriteToken, SCRIBE_HTTP_REFUSALS } from './http-policy.js';
import type { LedgerAppender } from './ledger.js';
import {
    createServer,
    FENCE_DISCLOSURE,
    planTier as defaultPlanTier,
    productionInstructions,
    SERVER_VERSION
} from './server.js';
import type { ServerContext, Tier, TierLayers, TierPlan, ToolRegistration } from './server.js';
import { SourceCache } from './source.js';
import { overwritePage } from './mutate.js';
import type { OverwritePageRequest, OverwritePageResult } from './mutate.js';
import { writePage } from './stamp.js';
import type { WritePageRequest, WritePageResult } from './stamp.js';
import { createWriteCompletionTracker } from './write-completion.js';
import type { WriteCompletionTracker } from './write-completion.js';

interface ScribeOptions {
    readonly gate: FsGate;
    readonly appender?: LedgerAppender;
    readonly version: string;
}

interface Scribe {
    writePage(request: WritePageRequest): Promise<WritePageResult>;
    overwritePage(request: OverwritePageRequest): Promise<OverwritePageResult>;
}

interface ProductionContext extends ServerContext {
    readonly scribe: Scribe;
    readonly writes: WriteCompletionTracker;
}

export interface MainDeps {
    readonly argv: readonly string[];
    readonly env: Record<string, string | undefined>;
    readonly planTier?: typeof defaultPlanTier;
    readonly makeFsGate: (options: { rawGrant: string }) => FsGate | FenceRefusal;
    readonly makeScribe?: (options: { readonly gate: FsGate; readonly version: string }) => Scribe;
    readonly makeTransport?: () => Transport;
    readonly serveStdio?: (makeServer: ConfiguredServerFactory) => Promise<void>;
    readonly startHttp?: (options: StartHttpOptions, writes: WriteCompletionTracker) => Promise<HttpServerHandle>;
    readonly stderr: (line: string) => void;
    readonly setExitCode: (code: number) => void;
}

export type ConfiguredServerFactory = () => Server;

export interface MainResult {
    readonly started: boolean;
    readonly reason: string | null;
    readonly http?: HttpServerHandle;
}

function createScribe(options: ScribeOptions): Scribe {
    const cache = new SourceCache();
    const appender = options.appender ?? gateAppender(options.gate);
    return Object.freeze({
        writePage: (request: WritePageRequest) => writePage(request, {
            gate: options.gate,
            appender,
            version: options.version,
            cache
        }),
        overwritePage: (request: OverwritePageRequest) => overwritePage(request, {
            gate: options.gate,
            appender,
            version: options.version,
            cache
        })
    });
}

function overwritePageRegistration(context: ProductionContext, activeTier: Tier): ToolRegistration {
    const derivedSchema = (writePageRegistration(context, activeTier).declaration.inputSchema.properties as
        Record<string, unknown>)['derived_from'];
    const registration: ToolRegistration = {
        declaration: {
            name: 'overwrite_page',
            title: 'Replace a page with lineage',
            description: [
                `Tier ${activeTier}: replace an existing page outside Arc/ and .wyrd/ when its stored SHA-256 matches.`,
                'The path and every derived_from.source are grant-relative. expected_sha256 is the',
                'lowercase SHA-256 of the exact existing file bytes. The fence stages the replacement',
                'and reports effect.target and effect.stage on every fence outcome. A refusal can retain',
                'a stage or leave the target effect indeterminate; inspect effect before retrying.',
                FENCE_DISCLOSURE,
                'A confirmed replacement appends one page_overwritten lineage line. If that append',
                'fails, the replacement remains and the result carries overwritten and cause.'
            ].join('\n'),
            inputSchema: {
                type: 'object',
                properties: {
                    path: { type: 'string', minLength: 1 },
                    content: { type: 'string' },
                    derived_from: derivedSchema,
                    expected_sha256: { type: 'string', pattern: '^[0-9a-f]{64}$' }
                },
                required: ['path', 'content', 'derived_from', 'expected_sha256'],
                additionalProperties: false
            } as Tool['inputSchema']
        },
        call: async args => {
            const { derived_from, expected_sha256, ...rest } = args;
            const result = await context.writes.run(() => context.scribe.overwritePage({
                ...rest, derivedFrom: derived_from, expectedSha256: expected_sha256
            } as unknown as OverwritePageRequest));
            const prefix = result.ok
                ? 'wyrd-scribe completed overwrite_page.'
                : result.reason === 'OVERWRITE_LEDGER_FAILED'
                    ? 'wyrd-scribe replaced the page, but no lineage append was confirmed; inspect overwritten.effect and cause.'
                    : 'wyrd-scribe refused overwrite_page; inspect effect when present.';
            return {
                ...(result.ok ? {} : { isError: true }),
                content: [{ type: 'text' as const, text: `${prefix}\n${JSON.stringify(result)}` }]
            };
        }
    };
    return Object.freeze(registration);
}

function writePageRegistration(context: ProductionContext, activeTier: Tier): ToolRegistration {
    const description = [
        `Tier ${activeTier}: attempt to create a page outside Arc/; target and sources use the grant fence.`,
        '',
        'The target is created exclusively. An occupied leaf refuses EXISTS; this tool does not',
        'overwrite, delete or rename. The target and every derived_from.source are grant-relative',
        'and go through the imported wyrd-fence implementation.',
        '',
        FENCE_DISCLOSURE,
        '',
        'Success creates the page and appends one lineage line. The vault configuration may also',
        'project lineage into frontmatter. If the ledger fails after creation, the page stays in',
        'place and the refusal includes both the created page and the underlying cause.'
    ].join('\n');

    const span = {
        oneOf: [
            {
                type: 'object',
                properties: {
                    offset: { type: 'integer', minimum: 0 },
                    length: { type: 'integer', minimum: 1 }
                },
                required: ['offset', 'length'],
                additionalProperties: false
            },
            {
                type: 'object',
                properties: { quote: { type: 'string', minLength: 1 } },
                required: ['quote'],
                additionalProperties: false
            },
            {
                type: 'object',
                properties: {
                    offset: { type: 'integer', minimum: 0 },
                    length: { type: 'integer', minimum: 1 },
                    quote: { type: 'string', minLength: 1 }
                },
                required: ['offset', 'length', 'quote'],
                additionalProperties: false
            }
        ]
    } as const;

    const registration: ToolRegistration = {
        declaration: {
            name: 'write_page',
            title: 'Create a page with lineage',
            description,
            inputSchema: {
                type: 'object',
                properties: {
                    path: { type: 'string', minLength: 1 },
                    content: { type: 'string' },
                    derived_from: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                source: { type: 'string', minLength: 1 },
                                spans: { type: 'array', minItems: 1, items: span }
                            },
                            required: ['source', 'spans'],
                            additionalProperties: false
                        }
                    }
                },
                required: ['path', 'content', 'derived_from'],
                additionalProperties: false
                /*
                 * ⚠ `span` above is `as const`, so its arrays are `readonly`, and v2's schema type
                 * wants mutable ones. Same cause as the Reader's `READ_INPUT_SCHEMA_FOR_TOOL`
                 * (`wyrd/src/server.ts`), and found the same way: by BUILDING against v2, which no
                 * read-only review lane could do — three lanes read this plan and approved it.
                 *
                 * Widened at the boundary rather than by dropping `as const`. The literal types
                 * document the three legal span shapes (offset+length, quote, or all three), and
                 * that precision is enforced at runtime by the Scribe's own AJV validation, which
                 * is the check that actually protects the vault. Structurally identical; only
                 * readonly modifiers differ.
                 */
            } as unknown as Tool['inputSchema']
        },
        call: async args => {
            const { derived_from, ...rest } = args;
            const result = await context.writes.run(() => context.scribe.writePage({
                ...rest,
                derivedFrom: derived_from
            } as unknown as WritePageRequest));
            const prefix = result.ok
                ? 'wyrd-scribe completed write_page.'
                : result.reason === 'PAGE_WRITTEN_LEDGER_FAILED'
                    ? 'wyrd-scribe created the page, but no lineage append was confirmed; inspect `cause` and, when present, `cause.retained`, because the ledger may contain no new line, a fragment, or the complete line.'
                    : 'wyrd-scribe refused write_page.';
            const serialised = JSON.stringify(result);
            return {
                ...(result.ok ? {} : { isError: true }),
                content: [{ type: 'text' as const, text: `${prefix}\n${serialised}` }]
            };
        }
    };
    return Object.freeze(registration);
}

const PRODUCTION_LAYERS: TierLayers<ProductionContext> = Object.freeze({
    A: (context: ProductionContext, activeTier: Tier) => Object.freeze([
        writePageRegistration(context, activeTier)
    ]),
    B: (context: ProductionContext, activeTier: Tier) => Object.freeze([
        overwritePageRegistration(context, activeTier)
    ]),
    C: null
});

export interface ConfiguredScribe {
    readonly makeServer: ConfiguredServerFactory;
    readonly writes: WriteCompletionTracker;
}

/** One grant and one validated tier plan produce servers for stdio and future HTTP. */
export function configureScribeServer(
    gate: FsGate,
    planned: TierPlan<ProductionContext>,
    makeScribe?: (options: { readonly gate: FsGate; readonly version: string }) => Scribe
): ConfiguredScribe {
    const writes = createWriteCompletionTracker();
    const context: ProductionContext = Object.freeze({
        instructions: (tier: Tier, names: readonly string[]) =>
            productionInstructions(gate.disclosedRoot(), tier, names),
        scribe: makeScribe?.({ gate, version: SERVER_VERSION })
            ?? createScribe({ gate, version: SERVER_VERSION }),
        writes
    });
    return Object.freeze({ makeServer: () => createServer(planned, context), writes });
}

function readGrantArg(argv: readonly string[]): string | null {
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index] as string;
        if (argument === '--grant') return argv[index + 1] ?? '';
        if (argument.startsWith('--grant=')) return argument.slice('--grant='.length);
    }
    return null;
}

/** Plan the tier first; only a successful plan may reach the grant or transport factories. */
export async function main(deps: MainDeps): Promise<MainResult> {
    const planTier = deps.planTier ?? defaultPlanTier;
    const planned = planTier(deps.env['WYRD_SCRIBE_TIER'], PRODUCTION_LAYERS);
    if (!planned.ok) {
        deps.stderr(planned.message);
        deps.setExitCode(2);
        return { started: false, reason: planned.reason };
    }

    const fromArgv = readGrantArg(deps.argv);
    const rawGrant = fromArgv !== null ? fromArgv : (deps.env['WYRD_GRANT'] ?? null);
    if (rawGrant === null || rawGrant === '') {
        deps.stderr('wyrd-scribe: refusing to start — no folder has been granted; use --grant or WYRD_GRANT.');
        deps.setExitCode(2);
        return { started: false, reason: 'NO_GRANT' };
    }

    const gate = deps.makeFsGate({ rawGrant });
    if (isRefusal(gate)) {
        deps.stderr(`wyrd-scribe: refusing to start — ${gate.detail}`);
        deps.setExitCode(2);
        return { started: false, reason: gate.reason };
    }

    const httpArg = readHttpArg(deps.argv);
    const tlsArg = readTlsArgs(deps.argv, { certificate: '--tls-cert', privateKey: '--tls-key' });
    const refuseHttp = (reason: string, detail: string): MainResult => {
        deps.stderr(`wyrd-scribe: refusing to start — ${detail}`);
        deps.setExitCode(2);
        return { started: false, reason };
    };
    if (deps.argv.some(arg => arg.startsWith('--http=') || arg.startsWith('--write-token-file=')
        || arg === '--write-token' || arg.startsWith('--write-token='))) {
        return refuseHttp('HTTP_BIND', 'invalid Scribe HTTP flag spelling');
    }
    if (!tlsArg.ok) return refuseHttp('TLS_CONFIG', tlsArg.detail);
    if (!httpArg.present) {
        if (tlsArg.paths !== null || deps.argv.includes('--write-token-file')) {
            return refuseHttp('HTTP_BIND', 'Scribe TLS and write-token flags require --http');
        }
    } else {
        if (httpArg.bind === null) return refuseHttp('HTTP_BIND', httpArg.detail ?? 'invalid HTTP bind');
        const token = loadWriteToken(deps.argv, deps.env);
        if (!token.ok) return refuseHttp('WRITE_TOKEN', token.detail);
        if (httpArg.bind.kind === 'network' && tlsArg.paths === null) {
            return refuseHttp('TLS_CONFIG', `network write endpoint ${httpArg.bind.host}:${httpArg.bind.port} requires TLS for grant ${gate.disclosedRoot()}`);
        }
        let tls = null;
        if (tlsArg.paths !== null) {
            const loaded = await loadTlsConfiguration(tlsArg.paths);
            if (!loaded.ok) return refuseHttp('TLS_CONFIG', loaded.detail);
            tls = loaded.configuration;
        }
        const { makeServer, writes } = configureScribeServer(gate, planned, deps.makeScribe);
        const begin = deps.startHttp ?? startScribeHttp;
        const handle = await begin({
            ...httpArg.bind,
            makeServer,
            readAuthInfo: createWriteAuthInfo(token.token, planned.tier),
            refusals: SCRIBE_HTTP_REFUSALS,
            onServerError: (error, shutdown) => {
                deps.stderr(`wyrd-scribe: HTTP listener failed — ${error.message}`);
                void shutdown.catch(closeError => {
                    deps.stderr(`wyrd-scribe: HTTP shutdown failed — ${String(closeError)}`);
                }).finally(() => deps.setExitCode(1));
            },
            ...(tls === null ? {} : { tls })
        }, writes);
        deps.stderr(scribeHttpDisclosure(handle, gate.disclosedRoot(), planned.tier));
        return { started: true, reason: null, http: handle };
    }

    // Captures only successfully validated startup state. Building another configured server
    // registers handlers in memory; it does not inspect or write the grant.
    const { makeServer: makeConfiguredServer } = configureScribeServer(gate, planned, deps.makeScribe);
    if (deps.serveStdio !== undefined) {
        await deps.serveStdio(makeConfiguredServer);
        return { started: true, reason: null };
    }

    const server = makeConfiguredServer();
    const transport = deps.makeTransport?.() ?? new StdioServerTransport();
    await server.connect(transport);
    return { started: true, reason: null };
}
