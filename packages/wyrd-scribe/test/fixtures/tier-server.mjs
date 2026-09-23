#!/usr/bin/env node
import fs from 'node:fs';

import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { createFsGate } from 'wyrd-fence';

import { createServer, planTier } from '../../dist/server.js';
import { gateAppender, refusingAppender } from '../../dist/ledger.js';
import { main } from '../../dist/main.js';
import { SourceCache } from '../../dist/source.js';
import { writePage } from '../../dist/stamp.js';

const registration = name => (_context, tier) => Object.freeze([Object.freeze({
    declaration: {
        name,
        title: `Fixture ${name}`,
        description: `Tier ${tier}: test-only inert registration; performs no filesystem operation.`,
        inputSchema: { type: 'object', properties: {}, additionalProperties: false }
    },
    call: async () => ({
        content: [{ type: 'text', text: `fixture:${tier}:${name}` }]
    })
})]);

const layers = Object.freeze({
    A: registration('write_page'),
    B: registration('overwrite_page'),
    C: (_context, tier) => Object.freeze([
        ...registration('delete_page')(_context, tier),
        ...registration('rename_page')(_context, tier)
    ])
});

const portMode = process.env.WYRD_TEST_PORT_MODE;
if (portMode !== undefined) {
    await main({
        argv: [],
        env: process.env,
        makeFsGate: createFsGate,
        makeScribe: ({ gate, version }) => {
            const cache = new SourceCache();
            const appender = portMode === 'ledger-failure'
                ? refusingAppender('fixture ledger refusal')
                : gateAppender(gate);
            return Object.freeze({
                writePage: async request => {
                    if (process.env.WYRD_TEST_PORT_COUNT) {
                        fs.appendFileSync(process.env.WYRD_TEST_PORT_COUNT, 'called\n');
                    }
                    const result = await writePage(request, {
                        gate,
                        appender,
                        version,
                        cache,
                        ...(process.env.WYRD_TEST_FIXED_UUID
                            ? { newUuid: () => process.env.WYRD_TEST_FIXED_UUID }
                            : {}),
                        ...(process.env.WYRD_TEST_FIXED_EVENT_ID
                            ? { newEventId: () => process.env.WYRD_TEST_FIXED_EVENT_ID }
                            : {}),
                        ...(process.env.WYRD_TEST_FIXED_TIME
                            ? { now: () => new Date(process.env.WYRD_TEST_FIXED_TIME) }
                            : {})
                    });
                    if (process.env.WYRD_TEST_PORT_RESULT) {
                        fs.writeFileSync(process.env.WYRD_TEST_PORT_RESULT, JSON.stringify(result));
                    }
                    return result;
                }
            });
        },
        makeTransport: () => new StdioServerTransport(),
        stderr: line => process.stderr.write(`${line}\n`),
        setExitCode: code => { process.exitCode = code; }
    });
} else {
    const planned = planTier(process.env.WYRD_SCRIBE_TIER, layers);
    if (!planned.ok) {
        process.stderr.write(`${planned.message}\n`);
        process.exitCode = 2;
    } else {
        const server = createServer(planned, {
            instructions: (tier, names) =>
                `Test-only inert tier ${tier}; registered tools: ${names.join(', ')}. No filesystem grant is opened.`
        });
        await server.connect(new StdioServerTransport());
    }
}
