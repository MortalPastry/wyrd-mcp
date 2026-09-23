import {
    closeSync,
    fstatSync,
    openSync,
    readSync
} from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';

import type { AuthInfo } from '@modelcontextprotocol/server';

import type { ReadAuthInfo } from './http.js';

const TOKEN_BYTES = 32;
const TOKEN_CHARACTERS = 43;
const MAX_TOKEN_FILE_BYTES = TOKEN_CHARACTERS + 2;
// Thirty-two bytes encode as 42 unconstrained base64url characters plus one character whose two
// padding bits are zero. Encoding the allowed final alphabet indices directly avoids comparing the
// presented secret as a string while still rejecting decoders' non-canonical aliases.
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export type ReadTokenConfig =
    | { readonly ok: true; readonly token: Buffer }
    | { readonly ok: false; readonly detail: string };

function refusal(detail: string): ReadTokenConfig {
    return { ok: false, detail };
}

function decodeToken(value: string): Buffer | null {
    if (!CANONICAL_BASE64URL.test(value)) return null;
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length !== TOKEN_BYTES) return null;
    return decoded;
}

function readTokenFile(file: string): ReadTokenConfig {
    let descriptor: number | null = null;
    try {
        descriptor = openSync(file, 'r');
        const stat = fstatSync(descriptor);
        if (!stat.isFile()) {
            return refusal('the Reader token file is not a regular file');
        }
        if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
            return refusal('the Reader token file permits group or world access');
        }
        if (stat.size < TOKEN_CHARACTERS || stat.size > MAX_TOKEN_FILE_BYTES) {
            return refusal('the Reader token file does not contain one canonical token');
        }

        // Read at most one byte beyond the largest accepted representation. This keeps a file
        // swapped or grown after fstat() from becoming an unbounded startup allocation.
        const storage = Buffer.alloc(MAX_TOKEN_FILE_BYTES + 1);
        let size = 0;
        while (size < storage.length) {
            const count = readSync(descriptor, storage, size, storage.length - size, null);
            if (count === 0) break;
            size += count;
        }
        const text = storage.subarray(0, size).toString('utf8');
        const token = text.endsWith('\r\n')
            ? text.slice(0, -2)
            : (text.endsWith('\n') ? text.slice(0, -1) : text);
        const decoded = decodeToken(token);
        if (size > MAX_TOKEN_FILE_BYTES || decoded === null
            || Buffer.byteLength(text, 'utf8') !== size) {
            return refusal('the Reader token file does not contain one canonical token');
        }
        return { ok: true, token: decoded };
    } catch {
        // Filesystem errors commonly carry the source path. Keep the startup refusal fixed so the
        // token source path cannot escape through diagnostics.
        return refusal('the Reader token file could not be read');
    } finally {
        if (descriptor !== null) {
            try {
                closeSync(descriptor);
            } catch {
                // A close failure cannot make an already-read secret safer to use. The descriptor
                // belongs to this process and will also be reclaimed on the startup refusal/exit.
            }
        }
    }
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
        const decoded = decodeToken(fromEnvironment as string);
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
    if (expected.byteLength !== TOKEN_BYTES) {
        throw new Error('the configured Reader token must decode to 32 bytes');
    }
    const expectedBytes = Buffer.from(expected);
    return ({ authorization }) => {
        if (authorization === null || !authorization.startsWith('Bearer ')) {
            return { kind: 'unauthenticated' };
        }
        const encoded = authorization.slice('Bearer '.length);
        const presented = decodeToken(encoded);
        if (presented === null || !timingSafeEqual(expectedBytes, presented)) {
            return { kind: 'unauthenticated' };
        }
        const authInfo: AuthInfo = {
            token: encoded,
            clientId: 'wyrd-reader',
            scopes: ['read']
        };
        return { kind: 'authenticated', authInfo };
    };
}
