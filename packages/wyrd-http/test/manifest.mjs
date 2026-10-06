import fs from 'node:fs';
import path from 'node:path';
import { ALL_ARMS } from './arms.mjs';

const EXECUTED = new Set();

export function declare(id) {
    if (!Object.hasOwn(ALL_ARMS, id)) throw new Error(`undeclared arm: ${id}`);
    if (EXECUTED.has(id)) throw new Error(`arm registered twice: ${id}`);
    EXECUTED.add(id);
}

const logDir = process.env.WYRD_ARM_LOG;
if (logDir) {
    process.on('exit', () => {
        fs.writeFileSync(path.join(logDir, `${process.pid}.json`), JSON.stringify([...EXECUTED]));
    });
}
