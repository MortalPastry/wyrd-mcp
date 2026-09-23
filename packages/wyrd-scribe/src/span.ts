/**
 * B1 — THE SPAN RESOLVER. Bytes in, a located span or a refusal out.
 *
 * Built to `designs/2026-08-31-span-resolver-plan.md`, which carries the reasoning and four rounds
 * of gate findings. The one rule everything here serves:
 *
 *   ⚠⚠ NO SILENT MISLOCATION. AMBIGUITY REFUSES; IT NEVER PICKS.
 *
 * ⚠ FENCE-FREE, AND THAT IS STRUCTURAL RATHER THAN POLITE. This module takes `(bytes, request)` and
 * no path. It never opens a file, never imports the fence, and has no way to reach the filesystem —
 * reading is the fence's job, and a resolver that opens files has become a second write path.
 *
 * ⚠ THE PROPERTY THIS MODULE PROTECTS: no substituted span resolution in a refusal, and no source
 * bytes in EITHER variant. It is NOT the fence's no-absolute-path rule — that belongs to
 * `wyrd-fence` (`packages/wyrd-fence/src/fsgate.ts`) and is asserted there. A reviewer briefed on
 * the fence's property is on the wrong axis here.
 *
 * ⚠⚠ AND THE PROPERTY IS NOT ENFORCED BY THESE TYPES. `SpanRefusal` and `ResolvedSpan` are
 * TypeScript-only shapes: the compiler forbids no extra property at runtime, and an unchecked
 * assignment can put a value anywhere. The enforcement is the own-key envelope in
 * `test/span.test.js`, applied to EVERY arm — refusal and success alike. This comment is not a
 * mechanism.
 *
 * ⚠ `Object.freeze` on every return is the runtime half OF THE EXTRA-KEY RULE ONLY. It says
 * nothing about what an ACCESSOR returns: freeze constrains the property, never the getter, so a
 * frozen own getter can serve a correct value to the first readers and the source buffer to the
 * next. Measured at code-gate round 2 — it passed all 29 arms. What closes that is the
 * data-property assertion in `envelope()`, not this line.
 */

export type SpanReason =
    | 'SPAN_INVALID_RANGE'
    | 'SPAN_INVALID_QUOTE'
    | 'SPAN_NOT_ALIGNED'
    | 'SPAN_NOT_FOUND'
    | 'SPAN_AMBIGUOUS'
    | 'SPAN_MISMATCH';

/**
 * The member at fault — **absence included**, which is the part the narrow wording missed.
 * `{ offset: 0 }` refuses `where: 'length'`, naming a member the caller never sent, because THERE
 * the fault IS the absence and naming it is the informative answer. That is not in tension with
 * the quote-only alignment path refusing `'request'`: there the fault is a property of a derived
 * span and the absent members are not at fault at all. So `where` names the member at fault,
 * supplied or absent — never "a supplied member."
 *
 * ⚠ ENUMERATED SO THE TYPE CANNOT CARRY A VALUE — and the type is not the enforcement. A frozen
 * own accessor named `where` can serve an enumerated value to the first readers and the whole
 * source afterwards; `envelope()`'s data-property assertion is what forbids it.
 */
export type SpanWhere = 'offset' | 'length' | 'quote' | 'request';

export interface ResolvedSpan {
    readonly ok: true;
    readonly offset: number;
    readonly length: number;
    readonly quote: string;
}

/**
 * ⚠ NO FREE-TEXT FIELD, AND NO SLOT FOR A RESOLUTION. There is no place in this shape for an
 * offset, a length, a quote, a candidate list or the source bytes. A `detail: string` was removed
 * at round 2 precisely because an unrestricted string can hold all of them.
 */
export interface SpanRefusal {
    readonly ok: false;
    readonly reason: SpanReason;
    readonly where: SpanWhere;
}

/**
 * Three shapes, all resolving to the same triple (D4 minus the hash, which is the fence's).
 * Any other shape — a lone `offset`, an unknown key, a non-object — refuses `SPAN_INVALID_RANGE`.
 */
export type SpanRequest =
    | { readonly offset: number; readonly length: number }
    | { readonly quote: string }
    | { readonly offset: number; readonly length: number; readonly quote: string };

/**
 * ⚠ AN UNKNOWN KEY REFUSES RATHER THAN BEING IGNORED, and the reason is a fail-open, not tidiness.
 * `{ offset, length, qoute }` read leniently is a valid OFFSETS-ONLY request: it succeeds, records
 * a quote the caller never asked to have verified, and silently drops the verification the caller
 * was asking for. That is mislocation arriving through a typo.
 */
const REQUEST_KEYS: ReadonlySet<string> = new Set(['offset', 'length', 'quote']);

function refuse(reason: SpanReason, where: SpanWhere): SpanRefusal {
    return Object.freeze({ ok: false as const, reason, where });
}

function resolved(offset: number, length: number, quote: string): ResolvedSpan {
    return Object.freeze({ ok: true as const, offset, length, quote });
}

/** A UTF-8 continuation byte — `10xxxxxx`. A span may not START on one, nor END just before one. */
function isContinuation(byte: number | undefined): boolean {
    return byte !== undefined && (byte & 0xc0) === 0x80;
}

/**
 * ⚠ BOTH ENDPOINTS, AND THE ARMS TEST THEM SEPARATELY. `é` is `c3 a9`: `{1,1}` cuts the START,
 * `{0,1}` cuts the END, and a check that validates one side passes half the rule while reading as
 * complete.
 *
 * Why a non-aligned span refuses at all: D4 stores the quoted TEXT over a source model the spec
 * declares UTF-8, and a lone `a9` has no lossless UTF-8 text representation. Decoding substitutes
 * `U+FFFD`, so the stored quote no longer re-encodes to the bytes it came from — the identity D4
 * exists to establish is destroyed at the moment of recording.
 */
function alignmentFault(bytes: Buffer, offset: number, length: number): 'offset' | 'length' | null {
    if (isContinuation(bytes[offset])) return 'offset';
    const end = offset + length;
    if (end < bytes.length && isContinuation(bytes[end])) return 'length';
    return null;
}

/**
 * ⚠ THE QUOTE IS VALIDATED FOR LOSSLESS UTF-8 ROUND-TRIP BEFORE ANY MATCHING. `"\uD800"` is a
 * well-formed JavaScript string and NOT well-formed Unicode text; encoding it substitutes
 * `U+FFFD`, so an unvalidated lone-surrogate quote would match GENUINE replacement-character bytes
 * in the source and return a quote that does not identify them.
 *
 * The empty quote refuses here too: against an empty source it would otherwise "uniquely match"
 * and mint a zero-length span, which the positive-length rule forbids on the offsets side.
 */
function quoteFault(quote: unknown): SpanRefusal | null {
    if (typeof quote !== 'string' || quote.length === 0) return refuse('SPAN_INVALID_QUOTE', 'quote');
    if (Buffer.from(quote, 'utf8').toString('utf8') !== quote) return refuse('SPAN_INVALID_QUOTE', 'quote');
    return null;
}

/**
 * Resolves a span request against the source bytes it was recorded over.
 *
 * ⚠ THE SOURCE IS A CALLER CONTRACT, NOT A REQUEST MEMBER. A non-Buffer source THROWS rather than
 * refusing: `where` names a member of the request, and there is no honest value for it here. A
 * refusal would have to lie about which member was at fault.
 */
/**
 * EVERY REFUSAL THIS MODULE CAN REACH WITHOUT THE SOURCE BYTES, AND NOTHING ELSE.
 *
 * ⚠⚠ IT EXISTS SO A GUARANTEED REFUSAL CAN BE DECIDED BEFORE A SOURCE IS READ. `stamp.ts` calls it
 * ahead of `loadConfig` and ahead of every read: a request carrying a malformed span is going to
 * refuse whatever the bytes turn out to be, so reading the source first buys nothing and COSTS the
 * existence-oracle property — an existing in-grant source and a missing one would otherwise produce
 * different reasons and different timings for a request that was always going to refuse. That is
 * the same argument the `Arc/` screen's ordering makes, applied to the other guaranteed refusal.
 *
 * ⚠⚠ IT IS `resolveSpan`'s OWN FIRST STEP, NOT A SECOND COPY OF THESE CHECKS. A parallel
 * implementation is a thing that drifts: the moment one side learns a rule the other has not, a
 * request refuses in one place and resolves in the other, and the pre-check stops being a
 * prediction of what the resolver will do. One function, two callers.
 *
 * ⚠ WHAT IT DELIBERATELY DOES NOT DECIDE: range-against-length, alignment, the lossy round-trip,
 * `SPAN_NOT_FOUND`, `SPAN_AMBIGUOUS` and `SPAN_MISMATCH`. Every one of those is a question about
 * the bytes, and answering it here would need the source — which is precisely what must not be read
 * yet. A `SpanMembers` from this function is NOT a prediction of success; it means only "nothing is
 * decided yet".
 *
 * ⚠⚠ IT RETURNS THE MEMBERS IT READ, AND THAT IS THE READ-ONCE RULE SURVIVING THE EXTRACTION. If
 * this function read the request's members and `resolveSpan` then read them AGAIN, a caller-supplied
 * accessor would fire twice and could serve one value to the shape check and another to the
 * resolver — which is precisely the defect `M1` pins, rebuilt by the refactor that was supposed to
 * be behaviour-preserving. Handing the values back means the request object is read exactly once on
 * every path, `stamp.ts`'s pre-check included.
 */
export interface SpanMembers {
    readonly hasOffset: boolean;
    readonly hasQuote: boolean;
    readonly offsetValue: unknown;
    readonly lengthValue: unknown;
    readonly quoteValue: unknown;
}

/** Narrows `spanShapeFault`'s result. A refusal carries `ok: false`; members never do. */
function isMembers(value: SpanRefusal | SpanMembers): value is SpanMembers {
    return (value as { ok?: unknown }).ok !== false;
}

export function spanShapeFault(request: SpanRequest): SpanRefusal | SpanMembers {
    const raw = request as unknown;
    if (typeof raw !== 'object' || raw === null) return refuse('SPAN_INVALID_RANGE', 'request');

    // ⚠ OWN KEYS, NOT `in`. `in` walks the prototype chain, so an inherited `offset` would be read
    // as a supplied one. Symbol keys are unknown keys and refuse with the rest.
    for (const key of Reflect.ownKeys(raw)) {
        if (typeof key !== 'string' || !REQUEST_KEYS.has(key)) return refuse('SPAN_INVALID_RANGE', 'request');
    }

    const own = (key: string): boolean => Object.prototype.hasOwnProperty.call(raw, key);
    const hasOffset = own('offset');
    const hasLength = own('length');
    const hasQuote = own('quote');

    // ⚠ THE SAME READ-ONCE, READ-ONLY-WHAT-WAS-SUPPLIED DISCIPLINE AS THE RESOLVER BELOW, and it
    // binds here for an additional reason: this function runs BEFORE any source is read, so an
    // inherited accessor fired here would run earlier than the one the resolver's rule is about.
    const view = raw as { offset?: unknown; length?: unknown; quote?: unknown };
    const offsetValue = hasOffset ? view.offset : undefined;
    const lengthValue = hasLength ? view.length : undefined;
    const quoteValue = hasQuote ? view.quote : undefined;

    if (!hasOffset && !hasLength && !hasQuote) return refuse('SPAN_INVALID_RANGE', 'request');

    // ⚠ `offset` and `length` are REQUIRED TOGETHER; `where` names the member that is missing.
    if (hasOffset !== hasLength) return refuse('SPAN_INVALID_RANGE', hasOffset ? 'length' : 'offset');

    if (hasOffset) {
        /**
         * ⚠⚠ RANGE VALIDATION RUNS FIRST AND COMPLETELY. Common byte-slice APIs coerce or clamp a
         * fractional, negative or oversized bound silently, producing a quote for a DIFFERENT
         * effective range while the record stores the offsets as supplied. That is silent
         * mislocation arriving through type coercion. An invalid range must never reach the
         * matcher, or the refusal describes the wrong failure.
         *
         * ⚠ THE `> bytes.length` HALF IS NOT HERE, and its absence is the boundary of this
         * function. Whether a well-formed range FITS is a question about the source.
         */
        if (!Number.isSafeInteger(offsetValue) || (offsetValue as number) < 0) {
            return refuse('SPAN_INVALID_RANGE', 'offset');
        }
        if (!Number.isSafeInteger(lengthValue) || (lengthValue as number) <= 0) {
            return refuse('SPAN_INVALID_RANGE', 'length');
        }
    }

    // ⚠ THE QUOTE'S OWN WELL-FORMEDNESS IS SOURCE-INDEPENDENT ON BOTH PATHS — a lone surrogate or
    // an empty string refuses against any source at all — so it is decided here for both, in the
    // order the resolver reaches it: after the range members on the offsets path, immediately on
    // the quote-only path.
    if (hasQuote) {
        const badQuote = quoteFault(quoteValue);
        if (badQuote) return badQuote;
    }

    return Object.freeze({ hasOffset, hasQuote, offsetValue, lengthValue, quoteValue });
}

export function resolveSpan(bytes: Buffer, request: SpanRequest): ResolvedSpan | SpanRefusal {
    if (!Buffer.isBuffer(bytes)) {
        throw new TypeError('resolveSpan(bytes, request): bytes must be a Buffer of source bytes');
    }

    /**
     * ⚠⚠ THE SOURCE-INDEPENDENT PREFIX, RUN AS ONE STEP, AND IT CARRIES THE READ-ONCE RULE WITH IT.
     * Every refusal it can reach is one this function reached itself before the extraction, in the
     * identical order — which is what makes `stamp.ts`'s pre-check a prediction of this resolver
     * rather than a second opinion about the same request. It also performs the ONLY read of the
     * request's members on this path and hands the values back: reading them again here would fire
     * a caller-supplied accessor twice, which is `M1`'s defect arriving through a refactor.
     */
    const shape = spanShapeFault(request);
    if (!isMembers(shape)) return shape;
    const { hasOffset, hasQuote, offsetValue, lengthValue, quoteValue } = shape;

    if (hasOffset) {
        const offset = offsetValue as number;
        const length = lengthValue as number;

        // ⚠ OVERFLOW-SAFE BY SUBTRACTION, NEVER `offset + length > bytes.length`. Both operands are
        // safe integers, so `bytes.length - offset` is exact and small; the sum is never compared.
        if (offset > bytes.length) return refuse('SPAN_INVALID_RANGE', 'offset');
        if (length > bytes.length - offset) return refuse('SPAN_INVALID_RANGE', 'length');

        const fault = alignmentFault(bytes, offset, length);
        if (fault) return refuse('SPAN_NOT_ALIGNED', fault);

        const slice = bytes.subarray(offset, offset + length);
        const text = slice.toString('utf8');
        /**
         * ⚠ ALIGNMENT IS NECESSARY AND NOT SUFFICIENT. `41 c3` is aligned at both endpoints and
         * still decodes lossily, because the sequence INSIDE the span is truncated. The round-trip
         * is the property alignment is a proxy for, so it is asserted directly rather than assumed
         * from the endpoints. `where` is `'request'`: with a well-formed source neither endpoint is
         * at fault, and naming one would be a guess.
         */
        if (!Buffer.from(text, 'utf8').equals(slice)) return refuse('SPAN_NOT_ALIGNED', 'request');

        if (!hasQuote) return resolved(offset, length, text);

        /**
         * ⚠⚠ MISMATCH PREFERS NEITHER SIDE, AND `where` IS `'request'`. Preferring the offsets
         * silently rewrites the caller's quote; preferring the quote silently relocates the
         * caller's offsets. Naming `'quote'` at fault IS preferring the offsets — the first of the
         * two failures the rule forbids. A whole-request inconsistency is `'request'`.
         *
         * String comparison is exact and safe here only because both sides are known to round-trip
         * losslessly: the source slice by the check above, the quote by `quoteFault`.
         */
        if ((quoteValue as string) !== text) return refuse('SPAN_MISMATCH', 'request');
        return resolved(offset, length, text);
    }

    // ⚠ THE QUOTE IS ALREADY KNOWN WELL-FORMED — `spanShapeFault` decided it, on both paths, before
    // any byte was looked at. The two `quoteFault` calls that used to sit here and in the offsets
    // branch are GONE rather than kept as belt-and-braces: a second call would re-run a decided
    // check against a value that can no longer change, and a guard nothing can trip is a guard
    // nobody is measuring.
    const needle = Buffer.from(quoteValue as string, 'utf8');

    /**
     * ⚠⚠ THE SCAN ADVANCES BY ONE BYTE, NEVER BY THE NEEDLE LENGTH. Bytes `"aaa"` with quote `"aa"`
     * match at offset 0 AND offset 1; a scan advancing by the needle length finds one match and
     * returns it, passing a naive occurs-twice arm while resolving an ambiguous span. Two matches
     * is all this needs to know, so it stops there.
     */
    let first = -1;
    let ambiguous = false;
    for (let from = 0; from <= bytes.length - needle.length; ) {
        const at = bytes.indexOf(needle, from);
        if (at === -1) break;
        if (first === -1) {
            first = at;
            from = at + 1;
            continue;
        }
        ambiguous = true;
        break;
    }

    if (first === -1) return refuse('SPAN_NOT_FOUND', 'quote');
    if (ambiguous) return refuse('SPAN_AMBIGUOUS', 'quote');

    /**
     * ⚠ ALIGNMENT IS A PROPERTY OF THE SPAN, SO IT IS CHECKED ON EVERY SHAPE THAT PRODUCES ONE.
     * In well-formed UTF-8 a located match is aligned by construction, since a valid encoded quote
     * never begins with a continuation byte. In a malformed source it need not be — `41 a9` with
     * quote `"A"` ends immediately before a continuation byte — and applying the rule only to the
     * shape that supplies offsets is the one-sided check this plan kept catching.
     */
    // ⚠ `where` is 'request', NOT the endpoint `alignmentFault` names. A quote-only request has no
    // `offset` and no `length` member, so naming either blames something the caller never sent —
    // the diagnostic would point at a value it derived itself. The offsets path above reaches the
    // same conclusion for a malformed source and says so in its own words: naming one endpoint
    // "would be a guess." Extending alignment to quote-only matches was right; inheriting the
    // offsets path's `where` with it was not. Both round-1 code-gate lenses, both judging the CODE
    // wrong and the SPEC right.
    if (alignmentFault(bytes, first, needle.length)) return refuse('SPAN_NOT_ALIGNED', 'request');

    return resolved(first, needle.length, quoteValue as string);
}
