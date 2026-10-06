#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { createFsGate } from 'wyrd-fence';

import { main } from './main.js';

const result = await main({
    argv: process.argv.slice(2),
    env: process.env,
    makeFsGate: createFsGate,
    makeTransport: () => new StdioServerTransport(),
    stderr: line => process.stderr.write(`${line}\n`),
    setExitCode: code => {
        process.exitCode = code;
    }
});

if (result.http !== undefined) {
    const handle = result.http;
    let shutdownRequested = false;
    const requestShutdown = (): void => {
        if (shutdownRequested) return;
        shutdownRequested = true;
        process.stderr.write('wyrd-scribe: draining admitted HTTP writes with no deadline\n');
        process.exitCode ??= 0;
        void handle.close().catch(error => {
            const detail = error instanceof Error ? error.message : String(error);
            process.stderr.write(`wyrd-scribe: HTTP shutdown failed — ${detail}\n`);
            process.exitCode = 1;
        });
    };
    process.on('SIGINT', requestShutdown);
    process.on('SIGTERM', requestShutdown);
}
