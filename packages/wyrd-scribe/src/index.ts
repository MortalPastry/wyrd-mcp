#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/server/stdio';
import { createFsGate } from 'wyrd-fence';

import { main } from './main.js';

await main({
    argv: process.argv.slice(2),
    env: process.env,
    makeFsGate: createFsGate,
    makeTransport: () => new StdioServerTransport(),
    stderr: line => process.stderr.write(`${line}\n`),
    setExitCode: code => {
        process.exitCode = code;
    }
});
