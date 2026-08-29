import fs from 'node:fs';
import path from 'node:path';

import { ALL_ARMS, SYMLINK_PRIVILEGE_ARMS } from './arms.mjs';

/**
 * PORTABLE MODE — set by `scripts/run-tests.mjs --portable`, never by a human on a command line.
 *
 * ⚠ THE DEFAULT IS THE FULL SUITE AND THAT IS DELIBERATE. `npm test` still refuses outright when
 * the symlink privilege is missing, because a green that silently means "the arms that could run,
 * ran" is the exact defect this lane keeps finding elsewhere. Portable mode is the OPT-IN that
 * makes the omission explicit, named, and counted — never the fallback that hides it.
 */
export const PORTABLE = process.env['WYRD_PORTABLE'] === '1';

/**
 * Test options for an arm that needs the symlink privilege. Spread into the `test()` options:
 *
 *   test('...', { ...tier2('A11') }, async () => { ... })
 *
 * Outside portable mode this contributes nothing, so the full suite is untouched. The id is
 * checked against `SYMLINK_PRIVILEGE_ARMS` so a call site and the inventory cannot disagree —
 * mislabelling here would be the quiet way to shrink the suite.
 */
export function tier2(id) {
    if (!SYMLINK_PRIVILEGE_ARMS.has(id)) {
        throw new Error(`arm "${id}" called tier2() but is not in SYMLINK_PRIVILEGE_ARMS (test/arms.mjs)`);
    }
    if (!PORTABLE) return {};
    // ⚠ RECORDED HERE BECAUSE THIS IS THE ONLY PLACE THAT CAN. A skipped test's BODY never runs, so
    // it never reaches `declare()` — which meant the runner could only ever count skips, not
    // identify them. A review lens (2026-08-29) constructed the hole: delete a tier-2 test and add
    // an unrelated skipped one, and the count still reads 21 while the skipped SET is wrong.
    // `tier2()` is called during test REGISTRATION, which happens whether or not the body runs, so
    // the identity is available exactly here and nowhere else.
    SKIPPED.add(id);
    return { skip: 'needs the Windows symlink privilege — tier 2' };
}

/**
 * Arm registration.
 *
 * `node --test` runs each file in its OWN PROCESS, so a single in-memory set cannot span the
 * suite. Each process writes what it executed to `WYRD_ARM_LOG`; `scripts/run-tests.mjs` unions
 * the logs and compares against the design inventory in `arms.mjs`.
 *
 * ⚠ Running `node --test` directly still works — registration just becomes a no-op, and the
 * cross-file manifest check is skipped. `npm test` goes through the runner, which is where the
 * zero-skipped and inventory assertions live.
 */
const EXECUTED = new Set();
/** Arms held back in portable mode, recorded at registration — see `tier2()` for why not later. */
const SKIPPED = new Set();

export function declare(id) {
    if (!(id in ALL_ARMS)) {
        throw new Error(`arm "${id}" is not in the design inventory (test/arms.mjs)`);
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
                JSON.stringify({ executed: [...EXECUTED], skipped: [...SKIPPED] })
            );
        } catch {
            /* a missing log surfaces as a manifest failure in the runner, not as a crash here */
        }
    });
}
