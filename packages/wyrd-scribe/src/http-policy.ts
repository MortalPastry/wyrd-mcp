import path from 'node:path';
import type { AuthInfo } from '@modelcontextprotocol/server';
import {
    bearerTokenMatches, decodeCanonicalToken, readCanonicalTokenFile,
    type HttpAuthDecisionFn, type HttpRefusals
} from 'wyrd-http';
import type { Tier } from './server.js';

export type WriteTokenConfig =
    | { readonly ok: true; readonly token: Buffer }
    | { readonly ok: false; readonly detail: string };

const refuse = (detail: string): WriteTokenConfig => ({ ok: false, detail });

/** Scribe's one-token-source policy. Call during startup, before any listener is made. */
export function loadWriteToken(
    argv: readonly string[],
    env: Readonly<Record<string, string | undefined>>
): WriteTokenConfig {
    if (argv.some(arg => arg === '--write-token' || arg.startsWith('--write-token='))) {
        return refuse('Scribe token values are not accepted on the command line');
    }
    const indexes = argv.flatMap((arg, index) => arg === '--write-token-file' ? [index] : []);
    if (argv.some(arg => arg.startsWith('--write-token-file='))) {
        return refuse('--write-token-file requires a separate absolute path');
    }
    if (indexes.length > 1) return refuse('--write-token-file may be supplied only once');
    const value = env['WYRD_WRITE_TOKEN'];
    if ((value !== undefined) === (indexes.length === 1)) {
        return refuse(value === undefined
            ? 'Scribe HTTP requires WYRD_WRITE_TOKEN or --write-token-file'
            : 'configure exactly one Scribe token source: WYRD_WRITE_TOKEN or --write-token-file');
    }
    if (value !== undefined) {
        const token = decodeCanonicalToken(value);
        return token === null
            ? refuse('WYRD_WRITE_TOKEN is not one canonical 32-byte base64url token')
            : { ok: true, token };
    }
    const file = argv[(indexes[0] as number) + 1];
    if (file === undefined || file === '' || file.startsWith('--')) {
        return refuse('--write-token-file requires a separate absolute path');
    }
    if (!path.isAbsolute(file)) return refuse('--write-token-file requires an absolute path');
    const result = readCanonicalTokenFile(file);
    if (result.ok) return result;
    const details = {
        'not-regular': 'the Scribe token file is not a regular file',
        permissions: 'the Scribe token file permits group or world access',
        invalid: 'the Scribe token file does not contain one canonical token',
        unreadable: 'the Scribe token file could not be read'
    } as const;
    return refuse(details[result.reason]);
}

/** Validates the configured tier and token before producing the shared listener's decision seam. */
export function createWriteAuthInfo(expected: Uint8Array, tier: Tier): HttpAuthDecisionFn {
    if (expected.byteLength !== 32) throw new Error('Scribe HTTP token must decode to 32 bytes');
    if (tier !== 'A' && tier !== 'B') throw new Error('Scribe HTTP tier is unavailable');
    const bytes = Buffer.from(expected);
    return ({ authorization }) => {
        if (!bearerTokenMatches(bytes, authorization)) return { kind: 'unauthenticated' };
        const authInfo: AuthInfo = {
            token: authorization!.slice('Bearer '.length),
            clientId: 'wyrd-scribe',
            scopes: tier === 'B' ? ['write', 'overwrite'] : ['write']
        };
        return { kind: 'authenticated', authInfo };
    };
}

export const SCRIBE_HTTP_REFUSALS: HttpRefusals = Object.freeze({
    route: { body: 'Scribe endpoint not found.\n' },
    method: { body: 'Scribe requires POST.\n', headers: { allow: 'POST' } },
    origin: { body: 'Scribe origin refused.\n' },
    length: { body: 'Scribe request too large.\n' },
    unauthenticated: {
        body: 'Scribe authentication required. Send Authorization: Bearer <Scribe token>.\n',
        headers: { 'www-authenticate': 'Bearer realm="wyrd-scribe"', 'cache-control': 'no-store' }
    },
    unavailable: { body: 'Scribe authentication unavailable.\n', headers: { 'cache-control': 'no-store' } },
    internal: { body: 'Scribe request failed.\n' }
});
