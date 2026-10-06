import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
    bearerTokenMatches,
    decodeCanonicalToken,
    loadTlsConfiguration,
    readCanonicalTokenFile,
    readTlsArgs
} from '../dist/index.js';
import { declare } from './manifest.mjs';

test('HT1-token-primitives', () => {
    declare('HT1-token-primitives');
    const expected = Buffer.alloc(32, 7);
    const other = Buffer.alloc(32, 8).toString('base64url');
    const canonical = expected.toString('base64url');
    assert.deepEqual(decodeCanonicalToken(canonical), expected);
    assert.equal(decodeCanonicalToken(canonical + '='), null);
    assert.equal(decodeCanonicalToken(canonical.slice(0, -1) + 'B'), null);
    assert.equal(bearerTokenMatches(expected, 'Bearer ' + canonical), true);
    assert.equal(bearerTokenMatches(expected, 'Bearer ' + other), false);
    assert.equal(bearerTokenMatches(expected, canonical), false);
    assert.equal(bearerTokenMatches(expected, null), false);
    assert.throws(() => bearerTokenMatches(Buffer.alloc(31), null), /32 bytes/);

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-token-'));
    try {
        const file = path.join(dir, 'token.txt');
        fs.writeFileSync(file, canonical + '\r\n', { mode: 0o600 });
        assert.deepEqual(readCanonicalTokenFile(file), { ok: true, token: expected });
        fs.writeFileSync(file, canonical + '\r\n' + 'x'.repeat(100));
        assert.deepEqual(readCanonicalTokenFile(file), { ok: false, reason: 'invalid' });
        assert.deepEqual(readCanonicalTokenFile(path.join(dir, 'missing')), { ok: false, reason: 'unreadable' });
        assert.deepEqual(readCanonicalTokenFile(dir), { ok: false, reason: 'not-regular' });
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('HT2-tls-primitives', async () => {
    declare('HT2-tls-primitives');
    const flags = { certificate: '--tls-cert', privateKey: '--tls-key' };
    assert.deepEqual(readTlsArgs([], flags), { ok: true, paths: null });
    assert.deepEqual(readTlsArgs(['--tls-cert', 'cert'], flags), { ok: false, detail: '--tls-cert and --tls-key must be supplied together' });
    assert.deepEqual(readTlsArgs(['--tls-key', 'key'], flags), { ok: false, detail: '--tls-cert and --tls-key must be supplied together' });
    assert.deepEqual(readTlsArgs(['--tls-cert', 'a', '--tls-cert', 'b', '--tls-key', 'k'], flags), { ok: false, detail: '--tls-cert may be specified only once' });
    assert.deepEqual(readTlsArgs(['--tls-cert=cert', '--tls-key=key'], flags).paths, { certificatePath: 'cert', privateKeyPath: 'key' });

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-http-tls-'));
    try {
        const cert = path.join(dir, 'cert.txt');
        const key = path.join(dir, 'key.txt');
        assert.match((await loadTlsConfiguration({ certificatePath: cert, privateKeyPath: key })).detail, /^cannot read TLS certificate /);
        fs.writeFileSync(cert, 'invalid certificate');
        assert.match((await loadTlsConfiguration({ certificatePath: cert, privateKeyPath: key })).detail, /^cannot read TLS private key /);
        fs.writeFileSync(key, 'invalid key');
        assert.match((await loadTlsConfiguration({ certificatePath: cert, privateKeyPath: key })).detail, /^TLS certificate is not a parseable X.509 certificate/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
