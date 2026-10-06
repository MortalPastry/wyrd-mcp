#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALL_ARMS } from '../test/arms.mjs';
import { loadContract, verifyArmInventory } from '../../wyrd/scripts/verify-relocation-contract.mjs';
import { guardBattery, batteryLockFixture } from '../../wyrd-fence/scripts/battery-lock.mjs';

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
guardBattery('http suite');
batteryLockFixture();
const files = ['test/bind.test.js', 'test/primitives.test.js', 'test/http.test.js'];
const declared = Object.keys(ALL_ARMS);
const failures = [];
if (files.length === 0) failures.push('the runner enumerates no test files');
for (const file of files) if (!fs.existsSync(path.join(pkg, file))) failures.push(`${file} is absent`);
if (declared.length === 0) failures.push('the design inventory declares no arms');
const { contract, problems } = loadContract();
failures.push(...problems);
if (contract) failures.push(...verifyArmInventory(contract, 'wyrd-http', ALL_ARMS));
if (failures.length) {
    for (const failure of failures) console.error(`HTTP suite gate: ${failure}`);
    process.exit(1);
}

const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-arms-'));
process.once('exit', () => fs.rmSync(logDir, { recursive: true, force: true }));
try {
    const run = spawnSync(process.execPath, [fileURLToPath(new URL('../../wyrd-fence/scripts/battery-lock.mjs', import.meta.url)),
        'exec', 'http test subprocess', '--', process.execPath, '--expose-gc', '--test', ...files], {
        cwd: pkg,
        env: { ...process.env, WYRD_ARM_LOG: logDir, NO_COLOR: '1', FORCE_COLOR: '0' },
        stdio: 'inherit'
    });
    if (run.error) failures.push(`test process could not start: ${run.error.message}`);
    else if (run.status !== 0) failures.push(`test process exited ${run.status ?? `on signal ${run.signal}`}`);
    const executed = [];
    for (const file of fs.readdirSync(logDir)) {
        executed.push(...JSON.parse(fs.readFileSync(path.join(logDir, file), 'utf8')));
    }
    if (executed.length === 0) failures.push('no arm executed');
    for (const id of declared) if (!executed.includes(id)) failures.push(`declared but not executed: ${id}`);
    for (const id of executed) if (!declared.includes(id)) failures.push(`executed but not declared: ${id}`);
    if (new Set(executed).size !== executed.length) failures.push('an arm executed more than once');
    if (failures.length) {
        for (const failure of failures) console.error(`HTTP suite gate: ${failure}`);
        process.exit(1);
    }
    const record = process.env.WYRD_EXECUTED_OUT;
    if (record) fs.writeFileSync(record, JSON.stringify({ package: 'wyrd-http', declared, executed, skipped: [] }));
    console.log(`HTTP gate: ${declared.length} declared arms all executed; 0 failed, 0 skipped.`);
} finally {
    fs.rmSync(logDir, { recursive: true, force: true });
}
