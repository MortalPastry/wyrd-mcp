import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import type { Server, Tool, Transport } from '@modelcontextprotocol/server';

import { isRefusal } from 'wyrd-fence';
import type { FenceRefusal, FsGate } from 'wyrd-fence';

import { gateAppender } from './ledger.js';
import type { LedgerAppender } from './ledger.js';
import {
    createServer,
    FENCE_DISCLOSURE,
    planTier,
    productionInstructions,
    SERVER_VERSION
} from './server.js';
import type { ServerContext, Tier, TierLayers, ToolRegistration } from './server.js';
import { SourceCache } from './source.js';
import { writePage } from './stamp.js';
import type { WritePageRequest, WritePageResult } from './stamp.js';

interface ScribeOptions {
    readonly gate: FsGate;
    readonly appender?: LedgerAppender;
    readonly version: string;
}

interface Scribe {
    writePage(request: WritePageRequest): Promise<WritePageResult>;
}

interface ProductionContext extends ServerContext {
    readonly scribe: Scribe;
}

export interface MainDeps {
    readonly argv: readonly string[];
    readonly env: Record<string, string | undefined>;
    readonly makeFsGate: (options: { rawGrant: string }) => FsGate | FenceRefusal;
    readonly makeScribe?: (options: { readonly gate: FsGate; readonly version: string }) => Scribe;
    readonly makeTransport?: () => Transport;
    readonly stderr: (line: string) => void;
    readonly setExitCode: (code: number) => void;
}

export interface MainResult {
    readonly started: boolean;
    readonly reason: string | null;
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
        })
    });
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
            const result = await context.scribe.writePage({
                ...rest,
                derivedFrom: derived_from
            } as unknown as WritePageRequest);
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
    B: null,
    C: null
});

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

    const context: ProductionContext = Object.freeze({
        instructions: (tier: Tier, names: readonly string[]) =>
            productionInstructions(gate.disclosedRoot(), tier, names),
        scribe: deps.makeScribe?.({ gate, version: SERVER_VERSION })
            ?? createScribe({ gate, version: SERVER_VERSION })
    });
    const server: Server = createServer(planned, context);
    const transport = deps.makeTransport?.() ?? new StdioServerTransport();
    await server.connect(transport);
    return { started: true, reason: null };
}
