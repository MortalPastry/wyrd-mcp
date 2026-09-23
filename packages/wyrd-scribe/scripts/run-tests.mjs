#!/usr/bin/env node
/**
 * THE SCRIBE'S SUITE RUNNER.
 *
 * ⚠⚠ IT EXISTS BECAUSE NOTHING WOULD OTHERWISE RUN THESE TESTS. Until this slice `wyrd-scribe` had
 * a build script and nothing else, and the root `npm test` invoked only the Reader's runner, which
 * enumerates only the Reader's own files. A test file here would have read as covered while
 * executing never.
 *
 * `node --test` alone is not enough, for the same two reasons the Reader's runner gives:
 *
 *   1. it exits 0 on a fully skipped run, and 0 on a run that enumerated nothing at all;
 *   2. the executed arm set must equal the DECLARED set in `test/arms.mjs`, and no per-file
 *      assertion can see across files.
 *
 * ⚠ THE INVENTORY IS THE MECHANISM, NOT A ONE-TIME PROOF. An earlier draft of the plan proposed
 * proving the wiring with a deliberately failing arm. That proves it once, prevents nothing
 * afterwards, and leaves the root command permanently red. A declared inventory makes "ran
 * nothing" a FAILING state forever.
 *
 * ⚠ `--portable` CHANGES NOTHING HERE AND IS ACCEPTED ON PURPOSE. Every Scribe arm is portable —
 * and the REASON changed when the stamp arms landed. It used to be that this package touched no
 * filesystem at all; the stamp arms build a real grant in the OS temp directory, but none of them
 * creates a SYMLINK, which is the only thing the Windows privilege gates. So both root surfaces
 * still run the identical set. The flag exists so `npm run test:portable` at the root aggregates
 * this package too; leaving it out would produce a supported, green, routinely-run command
 * executing NONE of these tests. ⚠ A symlink-needing arm added later must be held out of
 * `PORTABLE_ARMS` explicitly — that list is DERIVED here, so an unheld one breaks portable mode
 * with no gate going red.
 *
 * ⚠ THIS RUNNER EXTENDS NOTHING BUT `test` AND `test:portable` — that is what the root aggregation
 * added in this slice covers, and it is the only claim about the other root scripts this file is
 * entitled to make. It said "`release:check`, `mutate` and `drive` REMAIN READER-ONLY" until
 * 2026-09-02, by which point two thirds of that was false: `mutate` drives the fence's matrix as
 * well as the Reader's (Reader-only, it would have stopped exercising 66 of the 69 rows with no
 * gate going red), and `release:check` audits both public packages despite being spelled as the
 * Reader's. `drive` is genuinely Reader-only — it drives the MCP server, which only the Reader has.
 * ⚠ The authority on what each root script covers is the root `package.json`'s own `//` note, which
 * sits beside the scripts it describes; a second copy of it here is what went stale.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_ARMS, PORTABLE_ARMS } from '../test/arms.mjs';

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const portable = process.argv.slice(2).includes('--portable');

const FILES = [
    'test/span.test.js',
    'test/stamp.test.js',
    'test/server.test.js',
    'test/package.test.js',
    'test/manifest-schema.test.js',
    'test/v1-baseline.test.js'
];

/**
 * ⚠ THE FILE LIST IS CHECKED BEFORE THE RUN. `node --test` given a path that does not exist is one
 * of the ways a suite silently shrinks; the inventory would catch it afterwards, but the message
 * would name twenty-seven missing arms rather than one missing file.
 */
const absent = FILES.filter(file => !fs.existsSync(path.join(pkg, file)));
if (absent.length || FILES.length === 0) {
    console.error('\n⛔ SUITE GATE REFUSED TO RUN');
    if (FILES.length === 0) console.error('   · the runner enumerates no test files at all');
    for (const file of absent) console.error(`   · ${file} does not exist`);
    process.exit(1);
}

const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-scribe-arms-'));

const child = spawn(process.execPath, ['--test', ...FILES], {
    cwd: pkg,
    env: {
        ...process.env,
        WYRD_ARM_LOG: logDir,
        // ⚠ COLOUR BREAKS THE SUMMARY PARSE, AND ONLY IN A REAL TERMINAL — the Reader measured this
        // on 2026-08-29: a green run reported "could not read the fail count" because `node --test`
        // wraps its summary in ANSI escapes when stdout is a TTY, and a piped caller never sees it.
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
    const failures = [];

    // Belt and braces with NO_COLOR above: suppressing colour at the source is the fix, stripping
    // it here is the guard for a future reporter that emits it anyway.
    const plain = out.replace(/\[[0-9;]*m/g, '');
    const number = label => {
        const match = plain.match(new RegExp(`^\\u2139 ${label} (\\d+)$`, 'm'));
        return match ? Number(match[1]) : null;
    };
    for (const label of ['fail', 'skipped', 'cancelled', 'todo']) {
        const value = number(label);
        if (value === null) failures.push(`could not read the "${label}" count from the runner output`);
        else if (value !== 0) failures.push(`${label} = ${value}, must be 0`);
    }
    // ⚠ A POSITIVE PASS COUNT IS NOT A ZERO-EXECUTION DETECTOR, AND THIS IS THE MEASURED LIMIT
    // RATHER THAN THE INTENT. Pointed at a file containing no tests at all, `node --test` reports
    // `pass 1` — it counts the FILE as a passing test — so this guard stays silent on exactly the
    // case it looks like it covers. The arm-inventory equality below is what actually catches a
    // run of nothing; verified 2026-08-31 by running this runner against `test/manifest.mjs`,
    // where the inventory failed and this line did not.
    const passed = number('pass');
    if (passed === null) failures.push('could not read the "pass" count from the runner output');
    else if (passed === 0) failures.push('the runner executed zero tests');
    if (code !== 0) failures.push(`the test runner exited ${code}`);

    const executed = new Set();
    try {
        for (const file of fs.readdirSync(logDir)) {
            const record = JSON.parse(fs.readFileSync(path.join(logDir, file), 'utf8'));
            for (const id of record.executed) executed.add(id);
            for (const id of record.skipped) failures.push(`an arm was skipped, and nothing here may skip: ${id}`);
        }
    } catch (error) {
        failures.push(`could not read the arm logs: ${error.message}`);
    }
    fs.rmSync(logDir, { recursive: true, force: true });

    const declared = Object.keys(ALL_ARMS);
    // ⚠ ZERO IS A FAILURE ON BOTH SIDES. An empty inventory would make the equality below
    // vacuously true, which is exactly the green-on-nothing this file exists to prevent.
    if (declared.length === 0) failures.push('the design inventory (test/arms.mjs) declares no arms');
    if (executed.size === 0) failures.push('no arm registered itself — the manifest was never reached');

    const expected = portable ? PORTABLE_ARMS : declared;
    const missing = expected.filter(id => !executed.has(id));
    const extra = [...executed].filter(id => !expected.includes(id));
    if (missing.length) failures.push(`expected but NOT EXECUTED: ${missing.join(', ')}`);
    if (extra.length) failures.push(`executed but not expected in this tier: ${extra.join(', ')}`);

    if (failures.length) {
        console.error(`\n⛔ SUITE GATE FAILED${portable ? ' (portable tier)' : ''}`);
        for (const failure of failures) console.error(`   · ${failure}`);
        process.exit(1);
    }

    // ⚠ THE DENOMINATOR IS STATED EVEN WHEN IT IS THE WHOLE SET, so a reader never has to infer it.
    if (portable) {
        console.log(`\n⚠ PORTABLE TIER — ${expected.length} of ${declared.length} scribe arms ran.`);
        console.log('   0 held back: no scribe arm needs the Windows symlink privilege.');
    }
    console.log(`\n✔ scribe gate: ${expected.length} declared arms all executed; 0 failed, 0 skipped, 0 cancelled.`);
});
