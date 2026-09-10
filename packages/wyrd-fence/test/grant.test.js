/**
 * THE GRANT-SHAPE CONTRACT — `S4`, `S8`, `S12`.
 *
 * ⚠⚠ THESE THREE ARMS ARRIVED FROM `wyrd-mcp/test/startup.test.js` AND KEPT THEIR IDS. The
 * relocation contract recorded all three `destination: "undecided"` rather than guessing, and the
 * decision made at move time is recorded here rather than in a commit message: every assertion
 * below is a direct `createFsGate` call against a grant STRING, with no `main()`, no server and no
 * product surface anywhere in it. What the arm asserts is this package's source contract. What put
 * it in a file called `startup` is where the string comes from, which is the Reader's business and
 * not the assertion's.
 *
 * ⚠ THE READER KEEPS ITS INTEGRATION COVERAGE OF THE SAME PATHS, and that is what makes this a
 * split rather than a removal: `S2-missing` and `S3-file-grant` still drive `main()` to a refusal
 * and assert the Reader prints the resolved path, and `S13-grant-source-parity` still proves its
 * three grant SOURCES agree. Those are properties of the Reader; these are properties of the gate.
 *
 * ⚠ `S12` IS THE SLOWEST ARM IN EITHER SUITE (~2.7s, measured). It builds a real directory and
 * spells its path seven ways. It runs here now, so the Reader's suite is that much faster and this
 * one is that much slower; the cost did not disappear, it moved with the assertion.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';

import { createFsGate, isRefusal } from '../dist/fsgate.js';
import { declare as arm, tier2 } from './manifest.mjs';

test('grant — relative, drive-relative, namespaced and malformed grants each refuse with their own reason', () => {
    arm('S4-config-shapes');
    const cases = [
        ['.', 'CONFIG_RELATIVE'],
        ['vault', 'CONFIG_RELATIVE'],
        ['C:notes', 'CONFIG_DRIVE_RELATIVE'],
        ['\\\\?\\C:\\vault', 'CONFIG_NAMESPACED'],
        // ⚠ `path.normalize` absorbs `..` THROUGH the device prefix, giving `\\?\foo` — a
        // path naming a DIFFERENT volume than the one written. That is the malformed case, and
        // the mangling check runs ahead of the namespace check so the user is told the true
        // defect. Plan §2 asks for this exact string measured against the malformed refusal.
        ['\\\\?\\C:\\..\\foo', 'CONFIG_MALFORMED'],
        ['\\\\.\\C:\\vault', 'CONFIG_NAMESPACED'],
        ['\\\\server', 'CONFIG_MALFORMED'],
        ['', 'CONFIG_EMPTY'],
        ['C:\\vault\u0000x', 'CONFIG_NULL_BYTE']
    ];
    for (const [raw, expected] of cases) {
        const made = createFsGate({ rawGrant: raw });
        assert.ok(isRefusal(made), `${JSON.stringify(raw)} must refuse`);
        assert.equal(made.reason, expected, `${JSON.stringify(raw)} refused as ${made.reason}`);
    }
});
test('grant — a grant link that dangles, or that resolves to a FILE, each refuses', { ...tier2('S8-link-grants') }, () => {    arm('S8-link-grants');
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-linkgrant-'));
    const links = [];
    try {
        // A junction whose target never existed: `lstat` on the link SUCCEEDS (measured), so the
        // refusal has to come from the canonicalization, not from the first stat.
        const dangling = path.join(base, 'dangling');
        fs.symlinkSync(path.join(base, 'no-such-target'), dangling, 'junction');
        links.push(dangling);
        const a = createFsGate({ rawGrant: dangling });
        assert.ok(isRefusal(a), 'a dangling grant link must refuse');
        assert.equal(a.reason, 'GRANT_MISSING');
        assert.ok(a.resolvedPath.length > 0, 'the refusal must carry the path the user named');

        // A symlink to a FILE passes `isSymbolicLink()` at step 6a and must still refuse: the
        // not-a-directory check has to be applied to the CANONICAL root, not only the named one.
        const file = path.join(base, 'note.md');
        fs.writeFileSync(file, 'x');
        const toFile = path.join(base, 'grant-to-file');
        fs.symlinkSync(file, toFile, 'file');
        links.push(toFile);
        const b = createFsGate({ rawGrant: toFile });
        assert.ok(isRefusal(b), 'a grant link resolving to a file must refuse');
        assert.equal(b.reason, 'GRANT_NOT_A_DIRECTORY');
    } finally {
        for (const link of links.reverse()) {
            try {
                fs.unlinkSync(link);
            } catch {
                try {
                    fs.rmdirSync(link);
                } catch { /* the rm below reports what survived */ }
            }
        }
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('grant — EVERY separator spelling of one folder is accepted and lands on one root', () => {
    arm('S12-separator-spellings');
    // ⚠ THE PASS HALF IS THE POINT, and its absence shipped a defect. MCP client configs are
    // JSON, where a native Windows path needs every separator doubled — so `C:/Users/joe/notes`
    // is how people actually write it. Refusing that is fail-closed behaviour on a legitimate
    // input, wearing a config error's clothes.
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-seps-'));
    try {
        const vault = path.join(base, 'vault');
        fs.mkdirSync(vault);
        fs.writeFileSync(path.join(vault, 'note.md'), 'SEPARATORS');
        const canonical = fs.realpathSync.native(vault);

        const spellings = {
            'all backslash': vault,
            'all forward slash': vault.replace(/\\/g, '/'),
            'trailing backslash': `${vault}\\`,
            'trailing forward slash': `${vault.replace(/\\/g, '/')}/`,
            'mixed, forward tail': `${path.dirname(vault)}/${path.basename(vault)}`,
            'mixed, forward head': vault.replace(/\\/g, '/').replace(/\/([^/]+)$/, '\\$1'),
            'case folded': vault.toLowerCase()
        };
        for (const [label, raw] of Object.entries(spellings)) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(!isRefusal(made), `${label} (${raw}) must be accepted, got ${made.reason}: ${made.detail}`);
            assert.equal(made.disclosedRoot(), canonical, `${label} must land on the canonical root`);
        }

        // ⚠ A UNC SHARE ROOT IS A LEGITIMATE GRANT AND MUST PASS THE LEXICAL STAGE. This is
        // the shape the UNC validator exists to accept, and it was refused CONFIG_MALFORMED
        // because `path.parse('\\\\nas\\vault').root` carries no trailing separator while its
        // normalized form's root does. No arm used a UNC grant at all, so nothing caught it.
        //
        // No share exists on this machine, so the assertion is that the verdict is a FILESYSTEM
        // one (GRANT_MISSING, reached only after every lexical check passed) and never a
        // CONFIG_ one. That is the distinction the defect erased.
        for (const raw of ['\\\\nas\\vault', '//nas/vault', '\\\\nas\\vault\\', '\\\\nas\\vault\\sub']) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(isRefusal(made), `${raw} has no share behind it, so it cannot be accepted`);
            assert.equal(made.reason, 'GRANT_MISSING', `${raw} was refused lexically as ${made.reason}`);
        }

        // The refusal half: the ONLY inputs on this platform where normalizing genuinely changes
        // the volume. Measured — `path.normalize('\\?\C:\..\foo')` is `\\?\foo`, the `..`
        // absorbed THROUGH the device prefix.
        for (const raw of ['\\\\?\\C:\\..\\foo', '\\\\.\\C:\\..\\foo', '\\\\?\\..\\foo']) {
            const made = createFsGate({ rawGrant: raw });
            assert.ok(isRefusal(made), `${raw} must refuse`);
            assert.equal(made.reason, 'CONFIG_MALFORMED', `${raw} refused as ${made.reason}`);
            // The message must describe what is actually wrong. The shipped defect said
            // "normalizes to a different volume root" about paths whose volume had not changed.
            assert.match(made.detail, /changes the volume it names/);
        }
        // Ordering is load-bearing: a namespaced path whose volume does NOT change is refused
        // by the namespace rule, not by the mangling rule.
        const namespaced = createFsGate({ rawGrant: '\\\\?\\C:\\vault' });
        assert.ok(isRefusal(namespaced));
        assert.equal(namespaced.reason, 'CONFIG_NAMESPACED');
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});
