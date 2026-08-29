#!/usr/bin/env node
/**
 * The suite runner.
 *
 * `node --test` alone is not enough for two reasons the plan cares about:
 *
 *   1. §5 requires `failed === 0 && skipped === 0` in the FULL suite, GLOBALLY. A per-file manifest
 *      test cannot see the other files, and `node --test` exits 0 on a fully skipped run.
 *      ⚠ Portable mode deliberately permits skips — exactly the declared tier-2 set, by identity,
 *      never merely by count. That is the one sanctioned exception and it is checked, not trusted.
 *   2. The executed arm set must equal the DECLARED set across every file, not within one.
 *
 * This runs the suite, streams its output unchanged, then asserts both.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_ARMS, SYMLINK_PRIVILEGE_ARMS, PORTABLE_ARMS } from '../test/arms.mjs';
import { preflightJunctionSupport, preflightSymlinkPrivilege } from './preflight.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * ⚠ TWO TIERS, AND THE DEFAULT IS STILL THE WHOLE SUITE.
 *
 * Without `--portable` nothing below changes: the symlink preflight refuses, and a machine lacking
 * the privilege runs nothing. That is deliberate and is not a fallback — a green meaning "the arms
 * that could run, ran" is a defect, not a pass.
 *
 * `--portable` runs TIER 1 — the arms needing no symlink — and reports the denominator: how many
 * ran, how many were held back, and why. The principle is give a partial run DENOMINATORS rather
 * than generality: a partial run that cannot misstate what it skipped is honest; a full run that
 * silently shrinks is not.
 *
 * ⚠ No count is written in this comment ON PURPOSE. Both tier sizes are derived from `arms.mjs` at
 * run time and printed by the run itself; an inlined number here went stale within one commit the
 * first time it was written, and a stale count in a file about honest denominators is the worst
 * possible place for one.
 *
 * ⚠ The skipped set is asserted to equal `SYMLINK_PRIVILEGE_ARMS` EXACTLY. Skipping one arm more
 * than declared fails the run, and so does skipping one fewer. That equality is the whole reason
 * this mode is trustworthy, so do not relax it into a `>=`.
 */
const portable = process.argv.slice(2).includes('--portable');

const preflight = portable ? preflightJunctionSupport() : preflightSymlinkPrivilege();
if (preflight) {
    console.error(`\n⛔ SUITE GATE REFUSED TO RUN${portable ? ' (portable tier)' : ''}`);
    console.error(`   · ${preflight}`);
    if (!portable) {
        console.error('\n   To run the arms that need NO symlink privilege:  npm run test:portable');
        console.error(`   That is ${PORTABLE_ARMS.length} of ${Object.keys(ALL_ARMS).length} arms, and it will say so.`);
    }
    process.exit(1);
}

const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-arms-'));
const FILES = ['test/fsgate.test.js', 'test/handshake.test.js', 'test/startup.test.js'];

const child = spawn(process.execPath, ['--test', ...FILES], {
    cwd: repo,
    env: {
        ...process.env,
        WYRD_ARM_LOG: logDir,
        ...(portable ? { WYRD_PORTABLE: '1' } : {}),
        // ⚠ COLOUR BREAKS THE SUMMARY PARSE, AND ONLY IN A REAL TERMINAL. `node --test` writes its
        // summary in ANSI colour when stdout is a TTY, so `ℹ fail 0` arrives wrapped in escape
        // sequences and the anchored match below finds nothing. Measured 2026-08-29: a run with
        // 71 passing arms reported "could not read the fail count" and refused — correct behaviour
        // for an unparseable summary, but the cause was the terminal, not the tests.
        //
        // ⚠ IT IS INVISIBLE TO A PIPED CALLER. CI and any tool that captures stdout get no colour
        // and parse fine, so this passes every automated check and fails for the person at the
        // keyboard — which is the population that matters most for a first run after `git clone`.
        NO_COLOR: '1',
        FORCE_COLOR: '0'
    },
    stdio: ['ignore', 'pipe', 'inherit']
});

let out = '';
child.stdout.on('data', chunk => {
    out += chunk;
    process.stdout.write(chunk);
});

child.on('close', code => {
    let failures = [];

    // ⚠ BELT AND BRACES WITH THE NO_COLOR ENV ABOVE, DELIBERATELY. Suppressing colour at the source
    // is the fix; stripping it here is the guard for the case where some future runner, reporter or
    // terminal emits it anyway. One mechanism can be defeated by a setting; the pair cannot, and the
    // failure this protects against is a green suite reported as an unreadable one.
    const plain = out.replace(/\[[0-9;]*m/g, '');
    const number = label => {
        const match = plain.match(new RegExp(`^\\u2139 ${label} (\\d+)$`, 'm'));
        return match ? Number(match[1]) : null;
    };
    // In portable mode exactly the tier-2 arms are expected to be skipped; everything else must
    // still be zero. The count is cross-checked against the arm-log equality below, so a wrong
    // number cannot pass by matching one assertion and not the other.
    const expectedSkips = portable ? SYMLINK_PRIVILEGE_ARMS.size : 0;
    for (const label of ['fail', 'skipped', 'cancelled', 'todo']) {
        const value = number(label);
        const allowed = label === 'skipped' ? expectedSkips : 0;
        if (value === null) failures.push(`could not read the "${label}" count from the runner output`);
        else if (value !== allowed) failures.push(`${label} = ${value}, must be ${allowed}`);
    }
    if (code !== 0) failures.push(`the test runner exited ${code}`);

    const executed = new Set();
    const skipped = new Set();
    try {
        for (const file of fs.readdirSync(logDir)) {
            const record = JSON.parse(fs.readFileSync(path.join(logDir, file), 'utf8'));
            for (const id of record.executed) executed.add(id);
            for (const id of record.skipped) skipped.add(id);
        }
    } catch (error) {
        failures.push(`could not read the arm logs: ${error.message}`);
    }
    fs.rmSync(logDir, { recursive: true, force: true });

    const total = Object.keys(ALL_ARMS).length;
    const expected = portable ? PORTABLE_ARMS : Object.keys(ALL_ARMS);
    const missing = expected.filter(id => !executed.has(id));
    const extra = [...executed].filter(id => !expected.includes(id));
    if (missing.length) failures.push(`expected but NOT EXECUTED: ${missing.join(', ')}`);
    // ⚠ In portable mode this catches the dangerous direction: a tier-2 arm that RAN means its
    // fixture was built after all, so the tier list is wrong and the skip set is a fiction.
    if (extra.length) failures.push(`executed but not expected in this tier: ${extra.join(', ')}`);

    // ⚠ THE SKIPPED SET BY IDENTITY, NOT BY COUNT. Until 2026-08-29 this compared only the number
    // node reported, and the comments claimed set equality the mechanism did not provide — a review
    // lens built the passing-but-wrong case: delete one tier-2 test, add an unrelated skipped one,
    // and the count still reads right. Identities come from `tier2()` at registration time, which
    // runs even though the skipped body does not.
    if (portable) {
        const held = [...SYMLINK_PRIVILEGE_ARMS];
        const notHeld = held.filter(id => !skipped.has(id));
        const unexpected = [...skipped].filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
        if (notHeld.length) failures.push(`declared tier 2 but NOT skipped: ${notHeld.join(', ')}`);
        if (unexpected.length) failures.push(`skipped but not declared tier 2: ${unexpected.join(', ')}`);
    } else if (skipped.size > 0) {
        failures.push(`the full suite recorded skips: ${[...skipped].join(', ')}`);
    }

    if (failures.length) {
        console.error(`\n⛔ SUITE GATE FAILED${portable ? ' (portable tier)' : ''}`);
        for (const failure of failures) console.error(`   · ${failure}`);
        process.exit(1);
    }

    if (portable) {
        // ⚠ THE DENOMINATOR IS THE POINT, so it is stated before the pass line rather than after it.
        // A reader who stops at the tick must still have seen what did not run.
        console.log(`\n⚠ PARTIAL RUN — TIER 1 ONLY. ${expected.length} of ${total} arms ran.`);
        console.log(`   ${SYMLINK_PRIVILEGE_ARMS.size} arms were NOT run: they need the Windows symlink privilege.`);
        console.log(`   Held back: ${[...SYMLINK_PRIVILEGE_ARMS].join(', ')}`);
        console.log('   These cover symlink escapes, chains, cycles and the mirror shapes — the');
        console.log('   fence\'s hardest cases. A green here is NOT a green fence.');
        console.log(`   For all ${total}: enable Developer Mode and run \`npm test\`.`);
        console.log(`\n✔ tier-1 gate: ${expected.length} arms all executed; 0 failed, 0 unexpected skips.`);
        return;
    }
    console.log(`\n✔ suite gate: ${total} declared arms all executed; 0 failed, 0 skipped, 0 cancelled.`);
});
