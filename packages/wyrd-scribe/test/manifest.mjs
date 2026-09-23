import fs from 'node:fs';
import path from 'node:path';

import { ALL_ARMS } from './arms.mjs';

/**
 * Arm registration — the Reader's mechanism (`packages/wyrd/test/manifest.mjs`), copied.
 *
 * `node --test` runs each file in its OWN PROCESS, so a single in-memory set cannot span the
 * suite. Each process writes what it executed to `WYRD_ARM_LOG`; `scripts/run-tests.mjs` unions
 * the logs and compares against the design inventory in `arms.mjs`.
 *
 * ⚠ There is no tier-2 path here. Every Scribe arm is portable, so nothing may ever be skipped and
 * the runner asserts a zero skip count in BOTH modes.
 *
 * ⚠ Running `node --test` directly still works — registration just becomes a no-op, and the
 * inventory check is skipped. `npm test` goes through the runner, which is where the zero-skipped
 * and inventory assertions live.
 */
const EXECUTED = new Set();

export function declare(id) {
    if (!(id in ALL_ARMS)) {
        throw new Error(`arm "${id}" is not in the design inventory (test/arms.mjs)`);
    }
    // ⚠ DUPLICATES THROW. A `Set` enforces MEMBERSHIP, not exactly-once execution — so registering
    // one id twice while another test quietly loses its assertions still yields the full declared
    // set and a green gate. The gate's whole claim is that every declared arm RAN, and set
    // equality cannot carry that claim on its own. Both round-1 code-gate lenses.
    if (EXECUTED.has(id)) {
        throw new Error(`arm "${id}" registered twice — each arm registers exactly once, from its own test`);
    }
    EXECUTED.add(id);
}

export function executed() {
    return EXECUTED;
}

const logDir = process.env['WYRD_ARM_LOG'];
if (logDir) {
    process.on('exit', () => {
        try {
            fs.mkdirSync(logDir, { recursive: true });
            fs.writeFileSync(
                path.join(logDir, `${process.pid}-${Math.random().toString(36).slice(2)}.json`),
                JSON.stringify({ executed: [...EXECUTED], skipped: [] })
            );
        } catch {
            /* a missing log surfaces as a manifest failure in the runner, not as a crash here */
        }
    });
}
