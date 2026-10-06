import path from 'node:path';
import { bearerTokenMatches, decodeCanonicalToken, readCanonicalTokenFile } from 'wyrd-http';
import type { AuthInfo } from '@modelcontextprotocol/server';

import type { ReadAuthInfo } from './http.js';

export type ReadTokenConfig =
    | { readonly ok: true; readonly token: Buffer }
    | { readonly ok: false; readonly detail: string };

function refusal(detail: string): ReadTokenConfig {
    return { ok: false, detail };
}

const TOKEN_FILE_DIAGNOSTICS = {
    'not-regular': 'the Reader token file is not a regular file',
    permissions: 'the Reader token file permits group or world access',
    invalid: 'the Reader token file does not contain one canonical token',
    unreadable: 'the Reader token file could not be read'
} as const;

function readTokenFile(file: string): ReadTokenConfig {
    const result = readCanonicalTokenFile(file);
    return result.ok ? result : refusal(TOKEN_FILE_DIAGNOSTICS[result.reason]);
}

/** Load and validate the one allowed HTTP Reader-token source, once, before listening. */
export function loadReadToken(
    argv: readonly string[],
    env: Readonly<Record<string, string | undefined>>
): ReadTokenConfig {
    const valueFlags = argv.filter(argument =>
        argument === '--read-token' || argument.startsWith('--read-token='));
    if (valueFlags.length > 0) {
        return refusal('Reader token values are not accepted on the command line');
    }

    const fileIndexes = argv.flatMap((argument, index) =>
        argument === '--read-token-file' ? [index] : []);
    if (argv.some(argument => argument.startsWith('--read-token-file='))) {
        return refusal('--read-token-file requires a separate absolute path');
    }
    if (fileIndexes.length > 1) {
        return refusal('--read-token-file may be supplied only once');
    }

    const fromEnvironment = env['WYRD_READ_TOKEN'];
    const fileIndex = fileIndexes[0];
    const hasEnvironment = fromEnvironment !== undefined;
    const hasFile = fileIndex !== undefined;
    if (hasEnvironment === hasFile) {
        return refusal(
            hasEnvironment
                ? 'configure exactly one Reader token source, not both WYRD_READ_TOKEN and --read-token-file'
                : 'HTTP requires a Reader token from WYRD_READ_TOKEN or --read-token-file'
        );
    }

    if (hasEnvironment) {
        const decoded = decodeCanonicalToken(fromEnvironment as string);
        return decoded === null
            ? refusal('WYRD_READ_TOKEN is not one canonical 32-byte base64url token')
            : { ok: true, token: decoded };
    }

    const file = argv[(fileIndex as number) + 1];
    if (file === undefined || file === '' || file.startsWith('--')) {
        return refusal('--read-token-file requires a separate absolute path');
    }
    if (!path.isAbsolute(file)) {
        return refusal('--read-token-file requires an absolute path');
    }
    return readTokenFile(file);
}

/** Build the fixed-cost pre-shared verifier that can later be replaced by an OAuth adapter. */
export function createReadTokenVerifier(expected: Uint8Array): ReadAuthInfo {
    if (expected.byteLength !== 32) {
        throw new Error('the configured Reader token must decode to 32 bytes');
    }
    const expectedBytes = Buffer.from(expected);
    return ({ authorization }) => {
        if (!bearerTokenMatches(expectedBytes, authorization)) {
            return { kind: 'unauthenticated' };
        }
        const encoded = authorization!.slice('Bearer '.length);
        const authInfo: AuthInfo = {
            token: encoded,
            clientId: 'wyrd-reader',
            scopes: ['read']
        };
        return { kind: 'authenticated', authInfo };
    };
}
