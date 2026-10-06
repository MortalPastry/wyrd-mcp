import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { timingSafeEqual } from 'node:crypto';

const TOKEN_BYTES = 32;
const TOKEN_CHARACTERS = 43;
const MAX_TOKEN_FILE_BYTES = TOKEN_CHARACTERS + 2;
// Thirty-two bytes encode as 42 unconstrained base64url characters plus one character whose two
// padding bits are zero. Encoding the allowed final alphabet indices directly avoids comparing the
// presented secret as a string while still rejecting decoders' non-canonical aliases.
const CANONICAL_BASE64URL = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

export type TokenFileFailure = 'not-regular' | 'permissions' | 'invalid' | 'unreadable';
export type TokenFileResult =
    | { readonly ok: true; readonly token: Buffer }
    | { readonly ok: false; readonly reason: TokenFileFailure };

function failure(reason: TokenFileFailure): TokenFileResult {
    return { ok: false, reason };
}

export function decodeCanonicalToken(value: string): Buffer | null {
    if (!CANONICAL_BASE64URL.test(value)) return null;
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.length !== TOKEN_BYTES) return null;
    return decoded;
}

export function readCanonicalTokenFile(file: string): TokenFileResult {
    let descriptor: number | null = null;
    try {
        descriptor = openSync(file, 'r');
        const stat = fstatSync(descriptor);
        if (!stat.isFile()) {
            return failure('not-regular');
        }
        if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
            return failure('permissions');
        }
        if (stat.size < TOKEN_CHARACTERS || stat.size > MAX_TOKEN_FILE_BYTES) {
            return failure('invalid');
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
        const decoded = decodeCanonicalToken(token);
        if (size > MAX_TOKEN_FILE_BYTES || decoded === null
            || Buffer.byteLength(text, 'utf8') !== size) {
            return failure('invalid');
        }
        return { ok: true, token: decoded };
    } catch {
        // Filesystem errors commonly carry the source path. Return only a fixed reason.
        return failure('unreadable');
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

export function bearerTokenMatches(expected: Uint8Array, authorization: string | null): boolean {
    if (expected.byteLength !== TOKEN_BYTES) {
        throw new Error('the configured token must decode to 32 bytes');
    }
    if (authorization === null || !authorization.startsWith('Bearer ')) return false;
    const presented = decodeCanonicalToken(authorization.slice('Bearer '.length));
    return presented !== null && timingSafeEqual(Buffer.from(expected), presented);
}
