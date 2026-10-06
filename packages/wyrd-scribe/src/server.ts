import { Ajv } from 'ajv';
import type { ErrorObject, ValidateFunction } from 'ajv';
import { Server } from '@modelcontextprotocol/server';
import type { CallToolResult, Tool } from '@modelcontextprotocol/server';

import { SERVER_VERSION } from './version.js';

export { SERVER_VERSION } from './version.js';

export const SERVER_NAME = 'wyrd-scribe';

export type Tier = 'A' | 'B' | 'C';

export interface ServerContext {
    readonly instructions: (activeTier: Tier, toolNames: readonly string[]) => string;
}

export interface ToolRegistration {
    readonly declaration: Tool;
    readonly call: (args: Record<string, unknown>) => Promise<CallToolResult>;
}

export type ToolLayerFactory<C extends ServerContext> = (
    context: C,
    activeTier: Tier
) => readonly ToolRegistration[];

export interface TierLayers<C extends ServerContext> {
    readonly A: ToolLayerFactory<C>;
    readonly B: ToolLayerFactory<C> | null;
    readonly C: ToolLayerFactory<C> | null;
}

export interface TierPlan<C extends ServerContext> {
    readonly ok: true;
    readonly tier: Tier;
    readonly factories: readonly ToolLayerFactory<C>[];
}

export interface StartupRefusal {
    readonly ok: false;
    readonly reason: 'UNRECOGNISED_TIER' | 'TIER_UNAVAILABLE';
    readonly message: string;
}

const ORDER: readonly Tier[] = Object.freeze(['A', 'B', 'C']);

/** Select every cumulative layer before a grant or transport is opened. */
export function planTier<C extends ServerContext>(
    rawTier: string | undefined,
    layers: TierLayers<C>
): TierPlan<C> | StartupRefusal {
    const selected = rawTier ?? 'A';
    if (selected !== 'A' && selected !== 'B' && selected !== 'C') {
        return Object.freeze({
            ok: false as const,
            reason: 'UNRECOGNISED_TIER' as const,
            message: `UNRECOGNISED_TIER: wyrd-scribe does not recognise tier ${JSON.stringify(selected)}`
        });
    }

    const tier = selected as Tier;
    const needed = ORDER.slice(0, ORDER.indexOf(tier) + 1).map(name => layers[name]);
    if (needed.some(factory => factory === null)) {
        return Object.freeze({
            ok: false as const,
            reason: 'TIER_UNAVAILABLE' as const,
            message: `TIER_UNAVAILABLE: tier ${tier} is recognised but unavailable in this build`
        });
    }

    return Object.freeze({
        ok: true as const,
        tier,
        factories: Object.freeze(needed as ToolLayerFactory<C>[])
    });
}

export const FENCE_DISCLOSURE = [
    'Direct normalized `Arc/` targets are refused. The fence rejects a pre-existing parent alias',
    'when its spelled and resolved paths differ after case-folding; its documented fold-equal-alias',
    'limit still applies. The fence rechecks root object identity before each operation that',
    'touches the filesystem;',
    'component/leaf/link/rename races and the interval between that recheck and opening the file',
    'remain. Append refusals may retain a partial or complete line. See the `wyrd-fence` README',
    'section "Security boundary and limits" and the `createFileInGrant` / `appendLineInGrant` API',
    'documentation for the authoritative contracts.'
].join('\n');

export function productionInstructions(root: string, tier: Tier, names: readonly string[]): string {
    return [
        `wyrd-scribe is serving exactly one canonical grant: ${root}`,
        `The active write tier is ${tier}. Exactly these tools are registered: ${names.map(name => `\`${name}\``).join(', ')}.`,
        '',
        FENCE_DISCLOSURE,
        '',
        'Every write target and every derived_from source is grant-relative and is sent through',
        'the imported `wyrd-fence` operations. Tier A creates files exclusively; an occupied leaf refuses',
        'EXISTS. A successful write_page creates the page and appends one lineage line, and the',
        'vault configuration may also project lineage into frontmatter. If the ledger fails after',
        'the page is created, the page stays in place and the refusal reports that outcome.',
        ...(tier === 'B' ? [
            'Tier B also registers overwrite_page. It requires the existing page SHA-256, stages',
            'replacement through the fence, and appends one page_overwritten lineage line after',
            'replacement. Inspect effect on a fence refusal and cause on a ledger failure.'
        ] : [])
    ].join('\n');
}

interface ValidatedRegistration extends ToolRegistration {
    readonly validate: ValidateFunction;
}

function memberNamedBy(error: ErrorObject): string | null {
    if (error.keyword === 'additionalProperties') {
        return (error.params as { additionalProperty?: string }).additionalProperty ?? null;
    }
    if (error.keyword === 'required') {
        return (error.params as { missingProperty?: string }).missingProperty ?? null;
    }
    return null;
}

function violationPath(error: ErrorObject): string {
    const member = memberNamedBy(error);
    return `arguments${error.instancePath}${member === null ? '' : `/${member}`}`;
}

/** Return one actionable violation. The deepest branch error wins over `oneOf`'s wrapper error. */
function firstViolation(validate: ValidateFunction, args: Record<string, unknown>): string | null {
    if (validate(args)) return null;
    const errors = validate.errors ?? [];
    if (errors.length === 0) return 'arguments did not satisfy inputSchema';
    let chosen = errors[0] as ErrorObject;
    for (const error of errors.slice(1)) {
        if (error.instancePath.split('/').length > chosen.instancePath.split('/').length) {
            chosen = error;
        }
    }
    const path = violationPath(chosen);
    if (chosen.keyword === 'additionalProperties') return `${path} is not allowed by inputSchema`;
    if (chosen.keyword === 'required') return `${path} is required by inputSchema`;
    return `${path} ${chosen.message ?? `violates inputSchema keyword ${chosen.keyword}`}`;
}

/** The sole route to a registration's port: its advertised schema is compiled and enforced here. */
async function callValidated(
    registration: ValidatedRegistration,
    args: Record<string, unknown>
): Promise<CallToolResult> {
    const violation = firstViolation(registration.validate, args);
    if (violation !== null) {
        return {
            isError: true,
            content: [{
                type: 'text' as const,
                text: `wyrd-scribe refused invalid tool arguments: ${violation}.`
            }]
        };
    }
    return registration.call(args);
}

/** Build one frozen registration map; listing and dispatch both consult this object. */
export function createServer<C extends ServerContext>(plan: TierPlan<C>, context: C): Server {
    const ajv = new Ajv({ allErrors: true, strict: true });
    const entries: [string, ValidatedRegistration][] = [];
    for (const factory of plan.factories) {
        for (const registration of factory(context, plan.tier)) {
            const name = registration.declaration.name;
            if (entries.some(([existing]) => existing === name)) {
                throw new Error(`duplicate tool registration: ${name}`);
            }
            entries.push([name, Object.freeze({
                declaration: registration.declaration,
                call: registration.call,
                validate: ajv.compile(registration.declaration.inputSchema)
            })]);
        }
    }
    const registrations: Readonly<Record<string, ValidatedRegistration>> = Object.freeze(
        Object.fromEntries(entries)
    );
    const names = Object.freeze(Object.keys(registrations));

    const server = new Server(
        { name: SERVER_NAME, version: SERVER_VERSION },
        {
            capabilities: { tools: {} },
            instructions: context.instructions(plan.tier, names)
        }
    );

    server.setRequestHandler('tools/list', () => ({
        tools: Object.values(registrations).map(registration => registration.declaration)
    }));

    server.setRequestHandler('tools/call', async request => {
        const registration = registrations[request.params.name];
        if (registration === undefined) {
            return {
                isError: true,
                content: [{
                    type: 'text' as const,
                    text: `wyrd-scribe has no tool named ${request.params.name}.`
                }]
            };
        }
        const args = (request.params.arguments ?? {}) as Record<string, unknown>;
        return callValidated(registration, args);
    });

    return server;
}
