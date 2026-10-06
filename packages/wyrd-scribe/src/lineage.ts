/**
 * THE LINEAGE LINE — `wyrd.lineage/v1`. One JSON object per line, LF-terminated, append-only (D3).
 *
 * ⚠⚠ EVERY IDENTITY CARRIES AN EXPLICIT DISCRIMINANT AND ITS VAULT, and both halves are rulings
 * rather than taste (2026-08-31 identity block).
 *
 *   · `kind` exists so no consumer ever type-sniffs a string. J35 shipped a POLYMORPHIC SCALAR —
 *     one field holding a capture id normally and a path for rows that can never have one — and
 *     the measured cost was that every consumer needed a sniff branch, with ~84 edges hanging on
 *     one of them being written correctly. Our format is JSONL. A structured format has no reason
 *     to make a reader guess. A page with no stable id is PERMANENTLY `kind: 'path'`; it is never
 *     `id: null`, and never a value with an explanatory suffix.
 *   · `vault_id` exists because `.wyrd/lineage.jsonl` scopes identity IMPLICITLY, and implicit
 *     scoping survives only while the record stays home. Records can travel between vaults,
 *     and the moment a record does, a bare path is ambiguous across two granted vaults —
 *     the same defect the ruling exists to prevent, one layer up. The identity block gave two
 *     acceptable answers and named picking neither as the failure. This is the first: the identity
 *     carries its vault explicitly.
 *
 * ⚠⚠ THE LIMITS BELOW ARE POLICY BOUNDS, NOT PROVEN ATOMICITY GUARANTEES. B4's argument is that a
 * single `write` of a complete line under `O_APPEND` does not interleave for writes below a
 * pipe/PIPE_BUF-class threshold. That threshold is a property of the platform and the filesystem,
 * it is not 65,536 anywhere in particular, and nothing in this repo has measured it. What these
 * numbers actually buy is that a line CANNOT grow without bound through a large quote or a long
 * `derived_from` list — so the atomicity argument is being made about a bounded object rather than
 * an unbounded one. Calling that a guarantee would be the "confident number with no regime" shape
 * this lane keeps catching in its own work.
 */

import { createHash } from 'node:crypto';

import type { ResolvedSpan } from './span.js';
import type { ScribeRefusal } from './refusal.js';
import { scribeRefuse } from './refusal.js';

export const LINEAGE_SCHEMA = 'wyrd.lineage/v1';

/** ≤ 1,024 UTF-8 bytes of quote text retained; the rest is dropped and `truncated` says so. */
export const QUOTE_BYTE_BUDGET = 1_024;
/** At most this many `derived_from` entries per line. */
export const MAX_SOURCES = 64;
/** At most this many spans per line, summed across all sources. */
export const MAX_SPANS = 256;
/** The serialised line INCLUDING its terminating LF. */
export const MAX_LINE_BYTES = 65_536;
/**
 * At most this many UTF-8 bytes in the page path, as the ledger spells it.
 *
 * ⚠⚠ IT EXISTS BECAUSE THE PAGE PATH WAS THE ONLY VARIABLE-WIDTH FIELD IN A BOUNDED LINE WITH NO
 * BOUND OF ITS OWN. Quotes have `QUOTE_BYTE_BUDGET`, sources have `MAX_SOURCES`, spans have
 * `MAX_SPANS`, the digest is fixed at 64 hex characters and the byte count is bounded by
 * `Number.MAX_SAFE_INTEGER` — so every other contributor to `MAX_LINE_BYTES` could be reasoned
 * about in advance, and one could not. A single 60,000-byte path was enough to consume the whole
 * budget and starve fields the caller had every right to expect would fit.
 *
 * ⚠ 4,096 IS THE FENCE'S `MAX_GRANT_LENGTH`, DELIBERATELY. That constant bounds the grant ROOT and
 * says nothing about the grant-RELATIVE path — measured 2026-09-03, an in-grant path was created
 * at 16,407 characters with no refusal — so this is not a restatement of an existing guarantee.
 * Reusing the number keeps one order of magnitude in the reader's head rather than two, and 4,096
 * bytes of path is far past any real vault while leaving 61,440 bytes for everything else.
 *
 * ⚠ WHAT THIS DOES NOT CLOSE. The bound is checked against the path the CALLER asked for, and the
 * ledger records the path the filesystem RESOLVED to; an in-grant junction can lengthen it after
 * the page is created. `stamp.ts` step 9 remains the last line of defence for that case and now
 * reports it honestly. Closing it properly needs a pre-write canonical path from the fence, which
 * is a change to the Fence's public API and remains outside this module's contract.
 */
export const MAX_PAGE_PATH_BYTES = 4_096;

export interface PageIdentity {
    readonly kind: 'path';
    readonly vault_id: string;
    readonly path: string;
}

export interface ContentHash {
    readonly algorithm: 'sha256';
    readonly digest: string;
    readonly bytes: number;
}

export interface StoredQuote {
    readonly text: string;
    readonly original_utf8_bytes: number;
    readonly stored_utf8_bytes: number;
    readonly sha256: string;
    readonly truncated: boolean;
}

export interface LineageSpan {
    readonly offset: number;
    readonly length: number;
    readonly quote: StoredQuote;
}

export interface LineageSource {
    readonly identity: PageIdentity;
    readonly content: ContentHash;
    readonly spans: readonly LineageSpan[];
}

export interface LineagePage {
    readonly identity: PageIdentity;
    readonly content: ContentHash;
}

export interface LineageWriter {
    readonly server: 'wyrd-scribe';
    readonly version: string;
    readonly tool: 'write_page' | 'overwrite_page';
}

export interface LineageRecord {
    readonly schema: typeof LINEAGE_SCHEMA;
    readonly event: 'page_written';
    /**
     * ⚠⚠ THE PER-WRITE IDENTIFIER, AND IT EXISTS BECAUSE `recorded_at` IS NOT ONE. Two distinct
     * writes can produce BYTE-IDENTICAL lines: write a page, delete it outside this server, write
     * the identical content again within the same millisecond, and every field of the record —
     * timestamp, page path, digest, sources — is the same. A ledger holding two identical lines
     * cannot say whether it recorded two events or duplicated one, and that is a question about the
     * permanent record that nothing else in the line can answer.
     *
     * ⚠ SERVER-MINTED, LIKE `recorded_at` AND FOR THE SAME REASON. A caller-supplied id would be an
     * unauthenticated assertion recorded as fact — the objection that keeps an `actor` field out of
     * this record entirely.
     *
     * ⚠ IT IS AN EVENT ID, NOT A CONTENT HASH. Identical content written twice is TWO events and
     * gets two ids; that is the distinction the field exists to draw, so deriving it from the
     * record's own bytes would defeat it exactly where it is needed.
     */
    readonly event_id: string;
    readonly recorded_at: string;
    readonly writer: LineageWriter;
    readonly vault: { readonly kind: 'uuid'; readonly id: string };
    readonly page: LineagePage;
    readonly sources: readonly LineageSource[];
}

/** A replacement records both the precondition that was met and the new page. */
export interface OverwriteRecord {
    readonly schema: typeof LINEAGE_SCHEMA;
    readonly event: 'page_overwritten';
    readonly event_id: string;
    readonly recorded_at: string;
    readonly writer: LineageWriter & { readonly tool: 'overwrite_page' };
    readonly vault: { readonly kind: 'uuid'; readonly id: string };
    readonly previous: LineagePage;
    readonly page: LineagePage;
    readonly sources: readonly LineageSource[];
}

export type AnyLineageRecord = LineageRecord | OverwriteRecord;

export function identity(vaultId: string, path: string): PageIdentity {
    return Object.freeze({ kind: 'path' as const, vault_id: vaultId, path });
}

export function contentHash(digest: string, bytes: number): ContentHash {
    return Object.freeze({ algorithm: 'sha256' as const, digest, bytes });
}

/**
 * Cut a quote to the byte budget ON A UTF-8 BOUNDARY, and hash the FULL text either way.
 *
 * ⚠⚠ THE HASH IS OVER THE WHOLE QUOTE EVEN WHEN THE TEXT IS CUT, and that is the entire value of
 * the truncation design. D4's repairability claim is that a stale stamp can be REPAIRED rather than
 * merely flagged — which needs an identity for the text that was actually cited. Hashing the stored
 * prefix instead would make a truncated span unverifiable against the source it came from: the
 * recorded hash would match nothing, and the record would look healthy while proving nothing.
 *
 * ⚠ THE CUT IS ON A CODEPOINT BOUNDARY, NOT A `slice(0, 1024)`. A byte cut through a multibyte
 * sequence yields text that does not re-encode to the bytes it came from, which is precisely the
 * identity-destroying move `span.ts` refuses on every other path. `Buffer.write` into a fixed
 * buffer does this natively: it never writes a partial character.
 */
export function storeQuote(text: string): StoredQuote {
    const full = Buffer.from(text, 'utf8');
    const sha256 = hashText(full);
    if (full.length <= QUOTE_BYTE_BUDGET) {
        return Object.freeze({
            text,
            original_utf8_bytes: full.length,
            stored_utf8_bytes: full.length,
            sha256,
            truncated: false
        });
    }
    // ⚠ `Buffer.write` STOPS AT THE LAST WHOLE CHARACTER THAT FITS, so `written` is a
    // codepoint-aligned length by construction. Doing the arithmetic by hand here would be a second
    // implementation of the boundary rule the fence already has one of.
    const held = Buffer.allocUnsafe(QUOTE_BYTE_BUDGET);
    const written = held.write(text, 0, QUOTE_BYTE_BUDGET, 'utf8');
    const stored = held.subarray(0, written);
    return Object.freeze({
        text: stored.toString('utf8'),
        original_utf8_bytes: full.length,
        stored_utf8_bytes: written,
        sha256,
        truncated: true
    });
}

/**
 * ⚠ THE SINGLE HOME OF THE SCRIBE'S CONTENT DIGEST, AND IT IS EXPORTED FOR THAT REASON RATHER THAN
 * BECAUSE THREE CALLERS WANTED A SHORTER LINE. `source.ts` hashes what it re-read to prove the
 * source did not move under it, `stamp.ts` hashes the page it is about to create, and this module
 * hashes the recorded text — and those three digests are COMPARED WITH EACH OTHER downstream. Three
 * inlined spellings of one algorithm can disagree the moment any one of them is edited, and the
 * failure would read as a source that changed rather than as a hash that drifted.
 *
 * ⚠ The fence's `hashInGrant` is NOT this and must not be folded in: it streams a file in windows
 * because a source is routinely a whole transcript, while this takes bytes already in hand.
 */
export function hashText(bytes: Buffer): string {
    return createHash('sha256').update(bytes).digest('hex');
}

export function lineageSpan(span: ResolvedSpan): LineageSpan {
    return Object.freeze({
        offset: span.offset,
        length: span.length,
        quote: storeQuote(span.quote)
    });
}

/**
 * ⚠ THE KEY ORDER HERE IS THE WIRE ORDER, because `JSON.stringify` emits own keys in insertion
 * order and a ledger line is a text artifact people will diff. Nothing depends on it semantically —
 * a consumer parses JSON — but a format whose byte layout drifts between versions makes every diff
 * of the ledger unreadable for no gain.
 */
export function serialiseRecord(record: AnyLineageRecord): Buffer {
    return Buffer.from(`${JSON.stringify(record)}\n`, 'utf8');
}

/**
 * The count bounds, checked BEFORE anything is serialised or written.
 *
 * ⚠ SPANS ARE COUNTED ACROSS ALL SOURCES, not per source. A per-source cap of 256 with 64 sources
 * admits 16,384 spans, which is the bound this is supposed to be — the whole reason the cap exists
 * is the serialised size of one line, and size is a property of the line rather than of a source.
 */
export function checkCounts(sources: readonly LineageSource[]): ScribeRefusal | null {
    let spans = 0;
    for (const source of sources) spans += source.spans.length;
    return checkRequestCounts(sources.length, spans);
}

/**
 * The same two bounds, over counts taken from the REQUEST rather than from resolved records.
 *
 * ⚠⚠ IT EXISTS SO A GUARANTEED REFUSAL CAN BE DECIDED BEFORE ANY SOURCE IS READ. Both caps are
 * knowable from the request's own shape — 65 `derived_from` entries is over the cap whether or not
 * a single one of those files exists — so checking them only after the source loop meant reading
 * every source to reach a conclusion that never depended on them, and leaking each one's existence
 * and timing on the way. `stamp.ts`'s step 3 carries the full argument.
 *
 * ⚠ ONE IMPLEMENTATION, TWO ENTRY POINTS. `checkCounts` now delegates here rather than repeating
 * the comparisons, so the pre-check and the post-resolution check can never disagree about a bound
 * or about the words a refusal uses.
 */
export function checkPagePath(pagePath: string): ScribeRefusal | null {
    const bytes = Buffer.byteLength(pagePath, 'utf8');
    if (bytes > MAX_PAGE_PATH_BYTES) {
        return scribeRefuse(
            'LINEAGE_LINE_TOO_LARGE',
            `the page path is ${bytes} bytes; the ceiling is ${MAX_PAGE_PATH_BYTES}`
        );
    }
    return null;
}

export function checkRequestCounts(sources: number, spans: number): ScribeRefusal | null {
    if (sources > MAX_SOURCES) {
        return scribeRefuse(
            'LINEAGE_LINE_TOO_LARGE',
            `a lineage line carries at most ${MAX_SOURCES} sources`
        );
    }
    if (spans > MAX_SPANS) {
        return scribeRefuse(
            'LINEAGE_LINE_TOO_LARGE',
            `a lineage line carries at most ${MAX_SPANS} spans`
        );
    }
    return null;
}

/**
 * The size bound, checked on the SERIALISED bytes.
 *
 * ⚠ NEVER SPLIT A LINE. B4's atomicity argument is about one `write` of one complete line; a line
 * split across two writes is exactly the interleaving the argument rules out, arriving through the
 * repair for the case it could not handle. So an over-size line REFUSES and nothing is appended.
 */
export function checkLineSize(line: Buffer): ScribeRefusal | null {
    if (line.length > MAX_LINE_BYTES) {
        return scribeRefuse(
            'LINEAGE_LINE_TOO_LARGE',
            `the serialised lineage line is ${line.length} bytes; the ceiling is ${MAX_LINE_BYTES}`
        );
    }
    return null;
}
