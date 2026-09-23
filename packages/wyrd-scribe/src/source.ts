/**
 * SOURCES — read and hashed THROUGH THE EXISTING GATE, with no fence change of any kind.
 *
 * ⚠⚠ D8 IS THE WHOLE REASON THIS MODULE EXISTS AT ALL, and the hole it closed is worth restating
 * because the shape is easy to rebuild by accident. The spec's first draft fenced only the path
 * being WRITTEN; the paths being CITED went straight to read-and-hash with no containment check.
 * That made `write_page` an arbitrary-file-read primitive — name any path the process can reach as
 * a "source", get back confirmation of its existence and its content hash, and because D4 stores
 * the QUOTED TEXT, get its bytes copied permanently into the ledger. Every read here goes through
 * `readFileInGrant`/`hashInGrant`, which are the identical code path the Reader uses.
 *
 * ⚠⚠ AND THE HASH IS NOT A FORMALITY — IT IS THE CHIMERA CHECK (D4). The window loop reads a
 * source in pieces; a source edited between the first window and the last yields a buffer that
 * existed at no instant, and span offsets over a chimera are SILENT MISLOCATION, which is the one
 * failure this whole lane is built against. So the bytes we hold are hashed ourselves and compared
 * against `hashInGrant`'s independent full read of the same path. A mismatch REFUSES.
 *
 * ⚠ THAT COMPARISON IS A DETECTOR, NOT A LOCK. Nothing here holds the file open across the two
 * reads — the gate opens and closes per call, deliberately, because a long-held handle is a
 * different hazard — so a source edited and edited BACK between them passes. The claim is
 * "detects the ordinary case", never "serialises against a concurrent writer".
 */

import { isRefusal } from 'wyrd-fence';
import type { FenceRefusal, FsGate, Slice } from 'wyrd-fence';

import { hashText } from './lineage.js';
import type { ScribeRefusal } from './refusal.js';
import { scribeRefuse } from './refusal.js';

/**
 * The window the source loop asks for. The gate clamps anything above its own `MAX_LIMIT` silently,
 * so asking for more than 1 MiB would be a request the gate quietly rewrites — a number that reads
 * as a decision and is not one.
 */
const SOURCE_WINDOW = 1 << 20;

export interface SourceBytes {
    /** The grant-relative path AS THE FENCE REPORTS IT, separators already folded to `/`. */
    readonly rel: string;
    readonly bytes: Buffer;
    readonly digest: string;
    readonly size: number;
}

/**
 * ⚠ SEPARATORS ARE FOLDED HERE AND NOWHERE ELSE. The fence builds `rel` with `path.relative`,
 * which yields BACKSLASHES on win32 — so a ledger written on this host and read on any other would
 * carry a path no POSIX consumer can resolve, and the two hosts would disagree about whether two
 * records name the same page. The ledger's path is a portable identity, so the fold happens at the
 * boundary where a fence value becomes a RECORD value.
 */
export function toLedgerPath(rel: string): string {
    return rel.split('\\').join('/');
}

/**
 * ⚠ THE FENCE'S OWN `isRefusal`, IMPORTED RATHER THAN RE-DECLARED — spec D8, and the same rule the
 * package manifest states about `createFsGate`. This file used to carry a byte-identical private
 * copy called `isRefusalLike`; so did `config.ts`. A local copy of a guard that decides whether a
 * fence result is a refusal is a second definition of the fence's own contract, free to drift from
 * it silently. ⚠ `stamp.ts` deliberately keeps a private one — read the note there before assuming
 * it was missed.
 */

/**
 * The per-process source cache the cost model requires (spec "Cost model": a stamp is
 * O(source bytes) once per source per process).
 *
 * ⚠⚠ THE KEY IS `path + size + digest`, WHICH MEANS A HIT STILL COSTS ONE FULL READ. That is not
 * an oversight and it is the honest version of the criterion. The cost model's original key was
 * `(path, size, mtime)`, but the gate exposes no mtime — and the only identity it DOES expose is
 * the digest, which cannot be known without reading. So what the cache buys is skipping the WINDOW
 * LOOP and the second buffer, not skipping I/O: `hashInGrant` streams in 64 KiB windows and
 * retains nothing, while the window loop materialises the whole source in memory. On a hit the
 * resident cost is one buffer instead of two and the traversal is one pass instead of two.
 *
 * ⚠ AC7's "reads that source's bytes once" is therefore NOT satisfied by this cache, and saying so
 * is the point of this paragraph. Satisfying it literally needs an mtime the gate does not expose;
 * claiming it while the digest key forces a read would be a cost claim the code cannot back.
 */
export class SourceCache {
    readonly #entries = new Map<string, SourceBytes>();

    #key(rel: string, size: number, digest: string): string {
        return `${rel}\u0000${size}\u0000${digest}`;
    }

    get(rel: string, size: number, digest: string): SourceBytes | undefined {
        return this.#entries.get(this.#key(rel, size, digest));
    }

    set(entry: SourceBytes): void {
        this.#entries.set(this.#key(entry.rel, entry.size, entry.digest), entry);
    }

    get size(): number {
        return this.#entries.size;
    }
}

/**
 * Read a source whole, through the gate, and prove the bytes we hold are the bytes on disk.
 *
 * Order matters: HASH FIRST. The hash gives the cache key, so a hit skips the window loop entirely;
 * hashing second would mean always paying for the loop before discovering the answer was cached.
 */
export async function readSource(
    gate: FsGate,
    request: string,
    cache: SourceCache
): Promise<SourceBytes | ScribeRefusal | FenceRefusal> {
    const hashed = await gate.hashInGrant(request);
    // ⚠ PASSED THROUGH UNDER THE FENCE'S OWN REASON — `ESCAPES`, `MISSING`, `DENIED`. The spec's
    // `SOURCE_MISSING` IS this `MISSING`; inventing a parallel word would make two vocabularies for
    // one outcome and force every consumer to learn both.
    if (isRefusal(hashed)) return hashed;

    const rel = toLedgerPath(hashed.rel);
    const cached = cache.get(rel, hashed.size, hashed.digest);
    if (cached) return cached;

    const chunks: Buffer[] = [];
    let held = 0;
    let offset = 0;
    for (;;) {
        const slice: Slice | FenceRefusal = await gate.readFileInGrant(request, offset, SOURCE_WINDOW);
        if (isRefusal(slice)) return slice;
        chunks.push(slice.bytes);
        held += slice.bytes.length;
        if (!slice.truncated) break;
        // ⚠⚠ A NON-ADVANCING WINDOW IS A REFUSAL, NEVER A RETRY. `nextOffset` can equal `offset`
        // only if the gate kept zero bytes while still reporting more to come; looping on that is
        // an unbounded spin inside a server, and treating it as "the source moved under us" is both
        // true and the outcome a caller can act on.
        if (slice.nextOffset <= offset) {
            return scribeRefuse(
                'SOURCE_CHANGED_DURING_READ',
                'a source stopped yielding bytes before the end it reported'
            );
        }
        offset = slice.nextOffset;
    }

    const bytes = Buffer.concat(chunks, held);
    const ours = hashText(bytes);

    /**
     * ⚠⚠ BOTH HALVES ARE COMPARED, AND THE SIZE HALF IS NOT REDUNDANT. A digest comparison alone
     * would pass if the loop somehow held a DIFFERENT number of bytes whose hash collided — which
     * is not the realistic case — but more usefully, comparing sizes catches the ordinary shape of
     * this failure (the file grew or shrank between the hash and the loop) with a check that cannot
     * itself be fooled by a truncated read reporting success.
     */
    if (bytes.length !== hashed.size || ours !== hashed.digest) {
        return scribeRefuse(
            'SOURCE_CHANGED_DURING_READ',
            'a source changed between being hashed and being read; span offsets over it would be silently wrong'
        );
    }

    const entry: SourceBytes = Object.freeze({ rel, bytes, digest: hashed.digest, size: hashed.size });
    cache.set(entry);
    return entry;
}
