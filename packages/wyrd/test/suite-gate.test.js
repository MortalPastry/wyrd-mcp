import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { isInsideRealDirectory, isSameRealPath } from '../scripts/path-identity.mjs';
import { declare as arm } from './manifest.mjs';

test('SG1-local-package-case — local identity uses filesystem casing and keeps its directory boundary', () => {
    arm('SG1-local-package-case');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-suite-path-'));
    try {
        const local = path.join(base, 'LocalFence');
        const sibling = path.join(base, 'LocalFence-copy');
        const other = path.join(base, 'RegistryFence');
        fs.mkdirSync(local);
        fs.mkdirSync(sibling);
        fs.mkdirSync(other);
        const localEntry = path.join(local, 'index.js');
        const siblingEntry = path.join(sibling, 'index.js');
        const otherEntry = path.join(other, 'index.js');
        fs.writeFileSync(localEntry, '');
        fs.writeFileSync(siblingEntry, '');
        fs.writeFileSync(otherEntry, '');

        const differentlyCasedLocal = process.platform === 'win32'
            ? path.join(base, 'localFence')
            : local;
        assert.equal(isSameRealPath(differentlyCasedLocal, local), true);
        assert.equal(isInsideRealDirectory(path.join(differentlyCasedLocal, 'index.js'), local), true);
        assert.equal(isInsideRealDirectory(siblingEntry, local), false,
            'a sibling whose name starts with the local directory name is not local');
        assert.equal(isInsideRealDirectory(otherEntry, local), false,
            'a genuinely different package directory is not local');
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});
