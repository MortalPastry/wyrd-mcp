#!/usr/bin/env node
/**
 * The executable bootstrap, and the ORDER here is the whole reason this file is separate.
 *
 * ESM static imports evaluate BEFORE the importing module's body runs, so an instrument
 * installed inside `main()` cannot see import-time filesystem access. The observer goes in
 * first; the application modules arrive by dynamic import afterwards.
 *
 * ⚠ `./observe.js` is the only static import permitted in this file. It imports nothing from
 * `node:fs`, so no filesystem primitive can run before the hook is armed.
 */
import { installObserver } from './observe.js';

installObserver();

const { main } = await import('./main.js');
const { createFsGate } = await import('wyrd-fence');

// stdout carries the JSON-RPC stream, so diagnostics must go to stderr or they corrupt it.
await main({
    argv: process.argv.slice(2),
    env: process.env,
    makeFsGate: createFsGate,
    stderr: line => {
        process.stderr.write(`${line}\n`);
    },
    setExitCode: code => {
        process.exitCode = code;
    }
});
