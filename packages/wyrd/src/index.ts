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

/**
 * ⚠⚠ THE OBSERVER IS ARMED BEFORE ANY BRANCH, INCLUDING `token`, AND THE ORDER IS NOT COSMETIC.
 *
 * The first version of the `token` subcommand sat above this line and reached `node:crypto` by
 * dynamic import, on the reasoning that token generation touches no filesystem so the instrument
 * was pointless there. **`S10-bootstrap-order` went red**, and it was right to: it asserts
 * `installObserver(` appears before any `await import(`, which is the only machine-checkable form
 * of "nothing is imported before the hook is armed." A branch that imports first is indistinguishable
 * from an instrument installed too late, and the arm must not have to tell them apart.
 *
 * Arming costs one hook installation on a path that then writes 44 bytes and exits, which is
 * cheaper than a guarantee that holds only on the branches somebody remembered.
 */
installObserver();

const argv = process.argv.slice(2);
if (argv.length === 1 && argv[0] === 'token') {
    // Pure stdout, no filesystem, no listener: print one secret and exit. It writes nothing,
    // deliberately — where the token is stored is the operator's decision and their risk.
    const { randomBytes } = await import('node:crypto');
    process.stdout.write(`${randomBytes(32).toString('base64url')}\n`);
} else if (argv[0] === 'cert') {
    try {
        if (argv.length !== 3 || argv[1] !== '--host' || argv[2] === undefined) {
            throw new Error('usage: wyrd-mcp cert --host <hostname-or-IP>');
        }
        const { certificateInstructions, createCertificateFiles } = await import('./cert.js');
        const result = await createCertificateFiles(argv[2]);
        process.stdout.write(`${certificateInstructions(result)}\n`);
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        process.stderr.write(`wyrd: certificate generation failed — ${detail}\n`);
        process.exitCode = 2;
    }
} else {
    const { main } = await import('./main.js');
    const { createFsGate } = await import('wyrd-fence');

    // stdout carries the JSON-RPC stream, so diagnostics must go to stderr or they corrupt it.
    const result = await main({
        argv,
        env: process.env,
        makeFsGate: createFsGate,
        stderr: line => {
            process.stderr.write(`${line}\n`);
        },
        setExitCode: code => {
            process.exitCode = code;
        }
    });

    if (result.http !== null) {
        const http = result.http;
        const requestShutdown = (): void => {
            process.exitCode ??= 0;
            void http.close().catch(error => {
                const detail = error instanceof Error ? error.message : String(error);
                process.stderr.write(`wyrd: HTTP shutdown failed — ${detail}\n`);
                process.exitCode = 1;
            });
        };
        process.on('SIGINT', requestShutdown);
        process.on('SIGTERM', requestShutdown);
    }
}
