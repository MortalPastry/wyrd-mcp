import assert from 'node:assert/strict';
import { test } from 'node:test';
import { types } from 'node:util';

import { resolveSpan } from '../dist/span.js';
import { declare as arm } from './manifest.mjs';

/**
 * B1 — THE SPAN RESOLVER'S ARMS.
 *
 * ⚠ SKIPS FAIL THE BUILD. Arms are declared in `test/arms.mjs` and reconciled by
 * `scripts/run-tests.mjs`, which requires the executed set to EQUAL the declared set and the
 * skipped count to be zero in both modes. Nothing here may skip, ever.
 *
 * ⚠⚠ THE PROPERTY UNDER TEST: no substituted span resolution in a refusal, and no source bytes in
 * EITHER variant. It is NOT the fence's no-absolute-path rule — `resolveSpan` takes no path and
 * this module is fence-free. An arm written against the fence's property would be checking the
 * wrong axis.
 *
 * ⚠ ARMS ARE PAIRED THROUGHOUT, because a resolver that always refuses passes every refusal arm
 * and one that never refuses passes every success arm.
 */

const REFUSAL_KEYS = ['ok', 'reason', 'where'];
const SUCCESS_KEYS = ['length', 'ok', 'offset', 'quote'];

/**
 * ⚠⚠ THE OWN-KEY ENVELOPE — this package's existing idiom (`packages/wyrd/test/fsgate.test.js`,
 * where `assert.deepEqual(Object.keys(made).sort(), ['bytes', 'ok', 'rel'])` enforces the sibling
 * shape ruling), widened from `Object.keys` to `Reflect.ownKeys` so a non-enumerable or symbol key
 * cannot hide.
 *
 * ⚠ NOT `JSON.parse(JSON.stringify(x))`, which was tried and removed. `JSON.stringify` silently
 * drops `undefined`-valued own keys, non-enumerable own properties, prototype getters and symbol
 * keys — and any `toJSON()` anywhere in the graph bypasses it completely, so the arm would test
 * the object's chosen self-description rather than the object.
 *
 * A property is worth what the check forbids, not what the declaration says: `!('quote' in x)`
 * tests the shape a compliant implementation already has, while an own-key comparison fails the
 * moment anything extra appears, whatever it is called and wherever it came from.
 */
function envelope(x, expectedKeys) {
    assert.ok(x !== null && typeof x === 'object', 'every result must be an object');
    // Checked before the sort, and not only for the message: the default sort comparator calls
    // ToString on every element, and ToString of a symbol THROWS — which would surface a
    // symbol-keyed leak as an unrelated TypeError instead of as the leak it is.
    assert.deepEqual(Object.getOwnPropertySymbols(x), [], 'a result may carry no symbol-keyed property');
    // ⚠ BOTH SIDES ARE SORTED, because the expectation is a SET and the plan's own written list is
    // not in `.sort()` order — it gives the success keys as `['length', 'ok', 'offset', 'quote']`,
    // and `'offset'` sorts BEFORE `'ok'`. Taken literally that arm could never pass, whatever the
    // implementation returned. Sorting the declaration keeps the comparison exact in both
    // directions while making it independent of how the list was written down.
    assert.deepEqual(Reflect.ownKeys(x).sort(), [...expectedKeys].sort());
    assert.equal(Object.getPrototypeOf(x), Object.prototype, 'a result is a plain object');
    assert.ok(Object.isFrozen(x), 'every returned object is frozen');

    // ⚠⚠ THE PROPERTY IS A CONJUNCTION, AND FIVE SUCCESSIVE REPAIRS EACH CLOSED ONE SIDE OF IT.
    //
    // Plan round 2 required a serialised check. Round 3 found that insufficient. Round 4 REMOVED
    // the JSON round-trip precisely because `toJSON` bypasses it, and put own-key checking in its
    // place. Code-gate round 1 then showed own-key checking has its own `toJSON` hole from the
    // opposite direction: a FROZEN PROXY can report exactly the expected own keys, prototype and
    // frozen state above, while its `get` trap serves a `toJSON()` returning
    // `{ ..., sourceBytes }` — every assertion passes and `JSON.stringify(result)` leaks the whole
    // source into a lineage line.
    //
    // Neither check subsumes the other, so BOTH run. That is the sentence nobody wrote for five
    // rounds: own-keys AND every own property a DATA property AND no reachable `toJSON` AND not a
    // proxy AND the serialised form agrees. FIVE terms, not four — round 2 measured the fourth
    // version of this sentence still being one-sided, which is the fifth time in a row.
    // ⚠⚠ THE FIFTH TERM, AND IT IS THE ONE FOUR ROUNDS MISSED: EVERY OWN PROPERTY MUST BE A DATA
    // PROPERTY. `Object.isFrozen` returns TRUE for a non-configurable ACCESSOR — freeze constrains
    // the property, never the getter's return value — and an own getter is invisible to
    // `types.isProxy`, reports the right key from `Reflect.ownKeys`, and defeats the round-trip
    // below because that builds its expected side from `x[k]`, so it compares one getter call
    // against another and agrees with itself. Measured at code-gate round 2: a frozen own `where`
    // accessor serving the enumerated value three times and the whole source buffer thereafter
    // passed all 29 arms. `where` is documented as "enumerated so it cannot carry a value"; under
    // that mutant it carried the source, to every reader after the third — and the real consumer,
    // the S6 lineage line, reads later than these tests do.
    for (const key of Reflect.ownKeys(x)) {
        const d = Object.getOwnPropertyDescriptor(x, key);
        assert.ok('value' in d, `own property ${String(key)} must be a DATA property — a getter is a dynamic-value channel freeze does not close`);
        assert.equal(d.writable, false, `own property ${String(key)} must not be writable`);
        assert.equal(d.configurable, false, `own property ${String(key)} must not be configurable`);
    }
    assert.ok(!types.isProxy(x), 'a result may not be a Proxy: a proxy satisfies every structural check above and can still serve a dynamic toJSON');
    assert.equal(x.toJSON, undefined, 'no toJSON may be reachable anywhere on the result or its chain');
    assert.deepEqual(
        JSON.parse(JSON.stringify(x)),
        Object.fromEntries([...expectedKeys].sort().map((k) => [k, x[k]])),
        'the SERIALISED form must carry exactly the envelope — this is what actually reaches a ledger line'
    );
}

/**
 * ⚠ THESE TWO ARE THE ONLY WAY AN ARM READS A RESULT, and that is structural rather than a
 * convention. Round 3 of the plan stated the envelope rule generally and then instantiated it on
 * exactly one of six refusal reasons and none of the success arms — a rule enforced on a subset.
 * Routing every assertion through one pair makes it impossible for an arm to pin values without
 * the key set, or the key set without values.
 */
function refusal(result, reason, where) {
    envelope(result, REFUSAL_KEYS);
    assert.equal(result.ok, false);
    assert.equal(result.reason, reason);
    assert.equal(result.where, where);
}

function success(result, offset, length, quote) {
    envelope(result, SUCCESS_KEYS);
    assert.equal(result.ok, true);
    assert.equal(result.offset, offset);
    assert.equal(result.length, length);
    assert.equal(result.quote, quote);
}

const HELLO = Buffer.from('hello world', 'utf8');

/**
 * ⚠⚠ EVERY NON-ASCII FIXTURE IN THIS FILE IS AN ESCAPE, NEVER A LITERAL, and the normalisation arm
 * is why. A literal e-acute is whatever composition this file happens to be saved in, so an
 * NFC-vs-NFD arm written with literals compares a string against itself and passes while testing
 * nothing — and every byte count the alignment arms assert would depend on an editor setting.
 */

/** U+00E9 is `c3 a9` — two bytes, one codepoint. The alignment arms live on it. */
const E_ACUTE = Buffer.from('\u00e9', 'utf8');
/** `caf` + U+00E9 + ` au lait`: the e-acute occupies bytes 3 and 4. */
const CAFE = Buffer.from('caf\u00e9 au lait', 'utf8');
/** A source genuinely containing U+FFFD — `78 ef bf bd 79`. The lone-surrogate pair depends on it. */
const REPLACEMENT = Buffer.from('x\ufffdy', 'utf8');
/** `a` + U+1F701 (four bytes) + `b`. The four-byte alignment cases live here. */
const EMOJI = Buffer.from('a\u{1F701}b', 'utf8');

test('B1-offsets-only — offsets are recorded as given and the quote is read from those bytes', () => {
    arm('B1-offsets-only');

    success(resolveSpan(HELLO, { offset: 6, length: 5 }), 6, 5, 'world');
    success(resolveSpan(HELLO, { offset: 0, length: 11 }), 0, 11, 'hello world');

    // Past the end, on each member. ⚠ A slice API would clamp both and return a quote for a
    // DIFFERENT effective range while the record stored the offsets as supplied.
    refusal(resolveSpan(HELLO, { offset: 7, length: 5 }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { offset: 12, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 11, length: 1 }), 'SPAN_INVALID_RANGE', 'length');
});

test('B1-quote-unique — a quote occurring once locates and computes byte offsets', () => {
    arm('B1-quote-unique');

    success(resolveSpan(HELLO, { quote: 'world' }), 6, 5, 'world');
    success(resolveSpan(HELLO, { quote: 'hello world' }), 0, 11, 'hello world');
    success(resolveSpan(HELLO, { quote: 'o w' }), 4, 3, 'o w');
});

test('B1-quote-ambiguous — a quote occurring twice REFUSES; it never picks', () => {
    arm('B1-quote-ambiguous');

    const bytes = Buffer.from('red fish blue fish', 'utf8');
    refusal(resolveSpan(bytes, { quote: 'fish' }), 'SPAN_AMBIGUOUS', 'quote');
    // ⚠ THE PAIR, IN THE SAME SOURCE: an ambiguity refusal is worth nothing without proof that the
    // resolver still resolves. `red` occurs once.
    success(resolveSpan(bytes, { quote: 'red' }), 0, 3, 'red');
});

test('B1-quote-overlapping — "aaa"/"aa" matches at 0 AND 1, and must refuse', () => {
    arm('B1-quote-overlapping');

    const bytes = Buffer.from('aaa', 'utf8');
    // ⚠ THIS IS THE ARM THAT KILLS A SCAN ADVANCING BY QUOTE LENGTH. Such a scan finds the match at
    // 0, resumes at 2, finds nothing, and returns a confidently wrong span — passing the plain
    // occurs-twice arm above.
    refusal(resolveSpan(bytes, { quote: 'aa' }), 'SPAN_AMBIGUOUS', 'quote');
    success(resolveSpan(bytes, { quote: 'aaa' }), 0, 3, 'aaa');
});

test('B1-quote-absent — a quote occurring zero times is SPAN_NOT_FOUND', () => {
    arm('B1-quote-absent');

    refusal(resolveSpan(HELLO, { quote: 'goodbye' }), 'SPAN_NOT_FOUND', 'quote');
    // A quote longer than the whole source takes the same path rather than throwing.
    refusal(resolveSpan(HELLO, { quote: 'hello world and then some' }), 'SPAN_NOT_FOUND', 'quote');
    success(resolveSpan(HELLO, { quote: 'hello' }), 0, 5, 'hello');
});

test('B1-both-match — offsets are authoritative and the quote must match what sits there', () => {
    arm('B1-both-match');

    success(resolveSpan(HELLO, { offset: 0, length: 5, quote: 'hello' }), 0, 5, 'hello');
    success(resolveSpan(HELLO, { offset: 6, length: 5, quote: 'world' }), 6, 5, 'world');
});

test('B1-both-mismatch — refuses SPAN_MISMATCH and prefers NEITHER side', () => {
    arm('B1-both-mismatch');

    // ⚠ `world` DOES occur in this source, at offset 6. A resolver preferring the quote would
    // relocate the caller's offsets to 6 and succeed; one preferring the offsets would rewrite the
    // caller's quote to `hello` and succeed. Both are refused by `ok === false`, and the envelope
    // forbids either value riding along in an extra key.
    refusal(resolveSpan(HELLO, { offset: 0, length: 5, quote: 'world' }), 'SPAN_MISMATCH', 'request');

    // ⚠ `where` IS `'request'`, NOT `'quote'`. `where` names the member at fault, and naming the
    // quote at fault IS preferring the offsets — the first of the two failures the rule forbids.
    // A quote that occurs nowhere at all takes the same disposition.
    refusal(resolveSpan(HELLO, { offset: 0, length: 5, quote: 'howdy' }), 'SPAN_MISMATCH', 'request');
    // Same start, wrong length: a prefix of the quote is still a mismatch.
    refusal(resolveSpan(HELLO, { offset: 0, length: 4, quote: 'hello' }), 'SPAN_MISMATCH', 'request');

    success(resolveSpan(HELLO, { offset: 0, length: 5, quote: 'hello' }), 0, 5, 'hello');
});

test('B1-range-fractional — a fractional bound refuses on either member', () => {
    arm('B1-range-fractional');

    refusal(resolveSpan(HELLO, { offset: 0.5, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 0, length: 1.5 }), 'SPAN_INVALID_RANGE', 'length');
    success(resolveSpan(HELLO, { offset: 0, length: 1 }), 0, 1, 'h');
});

test('B1-range-negative-offset — a negative offset refuses rather than counting from the end', () => {
    arm('B1-range-negative-offset');

    refusal(resolveSpan(HELLO, { offset: -1, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: -5, length: 5 }), 'SPAN_INVALID_RANGE', 'offset');
    success(resolveSpan(HELLO, { offset: 10, length: 1 }), 10, 1, 'd');
});

test('B1-range-negative-length — a negative length refuses rather than being clamped', () => {
    arm('B1-range-negative-length');

    refusal(resolveSpan(HELLO, { offset: 0, length: -1 }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { offset: 5, length: -5 }), 'SPAN_INVALID_RANGE', 'length');
    success(resolveSpan(HELLO, { offset: 5, length: 1 }), 5, 1, ' ');
});

test('B1-range-unsafe-integer — unsafe integers, NaN, Infinity and numeric strings refuse', () => {
    arm('B1-range-unsafe-integer');

    const unsafe = Number.MAX_SAFE_INTEGER + 1;
    refusal(resolveSpan(HELLO, { offset: unsafe, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 0, length: unsafe }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { offset: Number.NaN, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 0, length: Number.NaN }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { offset: Number.POSITIVE_INFINITY, length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 0, length: Number.POSITIVE_INFINITY }), 'SPAN_INVALID_RANGE', 'length');
    // ⚠ A NUMERIC STRING IS NOT A NUMBER, and it is the one that coerces perfectly in a slice API.
    refusal(resolveSpan(HELLO, { offset: '0', length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    refusal(resolveSpan(HELLO, { offset: 0, length: '1' }), 'SPAN_INVALID_RANGE', 'length');
    success(resolveSpan(HELLO, { offset: 0, length: 1 }), 0, 1, 'h');
});

test('B1-range-lone-offset — offset and length are required together, in both directions', () => {
    arm('B1-range-lone-offset');

    refusal(resolveSpan(HELLO, { offset: 0 }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { length: 1 }), 'SPAN_INVALID_RANGE', 'offset');
    // With a quote alongside, the missing member is still the fault — the request is not quote-only.
    refusal(resolveSpan(HELLO, { offset: 0, quote: 'hello' }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { length: 5, quote: 'hello' }), 'SPAN_INVALID_RANGE', 'offset');
    // ⚠ AN EXPLICIT `undefined` IS NOT AN ABSENT MEMBER — the key is present and its value is not a
    // safe integer, so it refuses on that member rather than being read as a quote-only request.
    refusal(resolveSpan(HELLO, { offset: 0, length: undefined }), 'SPAN_INVALID_RANGE', 'length');
    success(resolveSpan(HELLO, { offset: 0, length: 5, quote: 'hello' }), 0, 5, 'hello');
});

test('B1-range-zero-length — { offset: 1, length: 0 } refuses, distinct from a zero-length QUOTE', () => {
    arm('B1-range-zero-length');

    // ⚠ THE OFFSETS SIDE OF THE ZERO-LENGTH RULE, a separate code path from the empty quote in
    // `B1-quote-empty`. A mutant can pass one and succeed on the other.
    refusal(resolveSpan(HELLO, { offset: 1, length: 0 }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(HELLO, { offset: 0, length: 0 }), 'SPAN_INVALID_RANGE', 'length');
    refusal(resolveSpan(Buffer.alloc(0), { offset: 0, length: 0 }), 'SPAN_INVALID_RANGE', 'length');
    success(resolveSpan(HELLO, { offset: 1, length: 1 }), 1, 1, 'e');
});

test('B1-request-shape — anything but the three declared shapes refuses', () => {
    arm('B1-request-shape');

    for (const request of [null, undefined, 42, 'hello', true, Symbol('x'), () => 0]) {
        refusal(resolveSpan(HELLO, request), 'SPAN_INVALID_RANGE', 'request');
    }
    refusal(resolveSpan(HELLO, {}), 'SPAN_INVALID_RANGE', 'request');
    refusal(resolveSpan(HELLO, [1, 2]), 'SPAN_INVALID_RANGE', 'request');

    // ⚠ AN UNKNOWN KEY REFUSES RATHER THAN BEING IGNORED. `qoute` read leniently is a valid
    // offsets-only request: it succeeds and silently drops the verification the caller was asking
    // for, recording a quote nobody checked.
    refusal(resolveSpan(HELLO, { offset: 0, length: 5, qoute: 'hello' }), 'SPAN_INVALID_RANGE', 'request');
    refusal(resolveSpan(HELLO, { quote: 'hello', candidates: [0, 6] }), 'SPAN_INVALID_RANGE', 'request');
    refusal(resolveSpan(HELLO, { offset: 0, length: 5, [Symbol('extra')]: 1 }), 'SPAN_INVALID_RANGE', 'request');

    // ⚠ INHERITED KEYS ARE NOT SUPPLIED KEYS. `'offset' in request` would read this as a complete
    // offsets request carried on a prototype the caller never meant as data.
    refusal(resolveSpan(HELLO, Object.create({ offset: 0, length: 5 })), 'SPAN_INVALID_RANGE', 'request');

    // A null-prototype object carrying the right OWN keys is still a valid request.
    const bare = Object.assign(Object.create(null), { offset: 0, length: 5 });
    success(resolveSpan(HELLO, bare), 0, 5, 'hello');
});

test('B1-source-not-buffer — a non-Buffer source throws; it is a caller contract, not a refusal', () => {
    arm('B1-source-not-buffer');

    // ⚠ A REFUSAL WOULD HAVE TO LIE. `where` names a member of the REQUEST, and the source is not
    // one — so there is no honest value to put there.
    for (const source of ['hello world', null, undefined, 42, new Uint8Array([1, 2, 3]), [104, 105]]) {
        assert.throws(() => resolveSpan(source, { offset: 0, length: 1 }), TypeError);
        assert.throws(() => resolveSpan(source, { quote: 'h' }), TypeError);
    }
    success(resolveSpan(Buffer.from('hello world', 'utf8'), { offset: 0, length: 1 }), 0, 1, 'h');
});

test('B1-align-start — U+00E9 as { offset: 1, length: 1 } cuts the START and refuses', () => {
    arm('B1-align-start');

    assert.deepEqual([...E_ACUTE], [0xc3, 0xa9], 'the fixture must be the two-byte encoding of U+00E9');
    // ⚠ `a9` ALONE HAS NO LOSSLESS UTF-8 TEXT REPRESENTATION. Decoding substitutes U+FFFD, so the
    // stored quote would no longer re-encode to the bytes it came from.
    refusal(resolveSpan(E_ACUTE, { offset: 1, length: 1 }), 'SPAN_NOT_ALIGNED', 'offset');

    // The same cut inside a longer source, where the span is not the whole buffer.
    refusal(resolveSpan(CAFE, { offset: 4, length: 3 }), 'SPAN_NOT_ALIGNED', 'offset');
    success(resolveSpan(CAFE, { offset: 0, length: 5 }), 0, 5, 'caf\u00e9');
});

test('B1-align-end — U+00E9 as { offset: 0, length: 1 } cuts the END and refuses', () => {
    arm('B1-align-end');

    // ⚠ THE OTHER ENDPOINT, AND IT IS A SEPARATE ARM ON PURPOSE. A mutant checking only the start
    // passes `B1-align-start` while leaving half the rule unimplemented.
    refusal(resolveSpan(E_ACUTE, { offset: 0, length: 1 }), 'SPAN_NOT_ALIGNED', 'length');

    refusal(resolveSpan(CAFE, { offset: 0, length: 4 }), 'SPAN_NOT_ALIGNED', 'length');
    success(resolveSpan(CAFE, { offset: 6, length: 2 }), 6, 2, 'au');
});

test('B1-align-whole — an aligned span succeeds and its quote re-encodes to the exact bytes', () => {
    arm('B1-align-whole');

    const result = resolveSpan(E_ACUTE, { offset: 0, length: 2 });
    success(result, 0, 2, '\u00e9');
    // ⚠ THE ROUND-TRIP IS WHAT THE WHOLE ALIGNMENT RULE EXISTS FOR, so it is asserted rather than
    // implied by the equality above.
    assert.ok(Buffer.from(result.quote, 'utf8').equals(E_ACUTE), 'the stored quote must re-encode to the source bytes');

    const four = resolveSpan(EMOJI, { offset: 1, length: 4 });
    success(four, 1, 4, '\u{1F701}');
    assert.ok(Buffer.from(four.quote, 'utf8').equals(EMOJI.subarray(1, 5)));
    // Every interior cut of the four-byte sequence refuses, on one endpoint or the other.
    refusal(resolveSpan(EMOJI, { offset: 2, length: 3 }), 'SPAN_NOT_ALIGNED', 'offset');
    refusal(resolveSpan(EMOJI, { offset: 1, length: 2 }), 'SPAN_NOT_ALIGNED', 'length');
});

test('B1-source-lossy — an aligned span over a TRUNCATED sequence still refuses', () => {
    arm('B1-source-lossy');

    // ⚠ ALIGNMENT IS NECESSARY AND NOT SUFFICIENT, and this arm is the half a boundary-only check
    // misses: `41 c3` starts on a lead byte and ends at the buffer end — both endpoints aligned —
    // yet the sequence INSIDE the span is truncated, so the decode substitutes U+FFFD and the
    // stored quote would not identify the bytes it came from.
    const truncated = Buffer.from([0x41, 0xc3]);
    refusal(resolveSpan(truncated, { offset: 0, length: 2 }), 'SPAN_NOT_ALIGNED', 'request');
    // The same bytes with a `both` request refuse the same way rather than falling through to a
    // mismatch: the disposition belongs to the span, not to the request shape.
    refusal(resolveSpan(truncated, { offset: 0, length: 2, quote: 'A\ufffd' }), 'SPAN_NOT_ALIGNED', 'request');
    // The well-formed prefix of the same buffer still resolves.
    success(resolveSpan(truncated, { offset: 0, length: 1 }), 0, 1, 'A');
});

test('B1-quote-lone-surrogate — a lone-surrogate quote refuses BEFORE matching', () => {
    arm('B1-quote-lone-surrogate');

    // ⚠ `"\uD800"` IS A WELL-FORMED JAVASCRIPT STRING AND NOT WELL-FORMED UNICODE TEXT. Encoding it
    // substitutes U+FFFD, so an unvalidated lone-surrogate quote would match the genuine
    // replacement-character bytes this source carries — see the pair in `B1-quote-replacement`.
    refusal(resolveSpan(REPLACEMENT, { quote: '\uD800' }), 'SPAN_INVALID_QUOTE', 'quote');
    refusal(resolveSpan(REPLACEMENT, { quote: 'x\uDC00' }), 'SPAN_INVALID_QUOTE', 'quote');
    // The check runs before matching, so a `both` request with valid offsets refuses on the quote
    // rather than reaching the comparison.
    refusal(resolveSpan(REPLACEMENT, { offset: 1, length: 3, quote: '\uD800' }), 'SPAN_INVALID_QUOTE', 'quote');
    // A non-string quote is the same class of unusable input.
    refusal(resolveSpan(REPLACEMENT, { quote: 42 }), 'SPAN_INVALID_QUOTE', 'quote');
    refusal(resolveSpan(REPLACEMENT, { quote: null }), 'SPAN_INVALID_QUOTE', 'quote');
});

test('B1-quote-replacement — a source genuinely containing U+FFFD, which the surrogate must not match', () => {
    arm('B1-quote-replacement');

    assert.deepEqual([...REPLACEMENT], [0x78, 0xef, 0xbf, 0xbd, 0x79], 'the fixture must carry real U+FFFD bytes');
    // ⚠ THE PAIR THAT MAKES THE SURROGATE ARM MEAN SOMETHING: these bytes ARE matchable, by the
    // quote that honestly names them. So the refusal above is about the caller's string being
    // unrepresentable, not about this source being unsearchable.
    success(resolveSpan(REPLACEMENT, { quote: '\ufffd' }), 1, 3, '\ufffd');
    success(resolveSpan(REPLACEMENT, { offset: 1, length: 3 }), 1, 3, '\ufffd');
    success(resolveSpan(REPLACEMENT, { offset: 1, length: 3, quote: '\ufffd' }), 1, 3, '\ufffd');
});

test('B1-quote-empty — an empty quote refuses, including against an empty source', () => {
    arm('B1-quote-empty');

    refusal(resolveSpan(HELLO, { quote: '' }), 'SPAN_INVALID_QUOTE', 'quote');
    // ⚠ THE EMPTY SOURCE IS THE DANGEROUS HALF: `''` occurs exactly once in `''` by any ordinary
    // search, so a resolver without this check mints a zero-length span — which the offsets side
    // forbids outright.
    refusal(resolveSpan(Buffer.alloc(0), { quote: '' }), 'SPAN_INVALID_QUOTE', 'quote');
    refusal(resolveSpan(HELLO, { offset: 0, length: 5, quote: '' }), 'SPAN_INVALID_QUOTE', 'quote');
    // A non-empty quote against an empty source is simply absent.
    refusal(resolveSpan(Buffer.alloc(0), { quote: 'h' }), 'SPAN_NOT_FOUND', 'quote');
});

test('B1-quote-match-unaligned — a located match ending before a continuation byte refuses', () => {
    arm('B1-quote-match-unaligned');

    // ⚠ ALIGNMENT IS A PROPERTY OF THE SPAN, SO IT IS CHECKED ON EVERY SHAPE THAT PRODUCES ONE.
    // `41 a9` is a malformed source; `"A"` matches at 0 and the span ends immediately before a
    // continuation byte. Applying the rule only to requests that SUPPLY offsets is the one-sided
    // check this plan kept catching.
    // ⚠ `where` IS 'request', NOT 'length'. This arm pinned `'length'` until code-gate round 1:
    // a quote-only request has no `length` member, so the diagnostic was naming a value the
    // resolver derived itself rather than anything the caller sent. Both lenses judged the code
    // wrong and the spec right here.
    refusal(resolveSpan(Buffer.from([0x41, 0xa9]), { quote: 'A' }), 'SPAN_NOT_ALIGNED', 'request');
    success(resolveSpan(Buffer.from([0x41, 0x42]), { quote: 'A' }), 0, 1, 'A');
});

test('B1-request-inherited — an inherited accessor is never invoked for a member not supplied', () => {
    arm('B1-request-inherited');

    // ⚠⚠ THE OWN-KEY GUARANTEE MUST BIND THE READ, NOT ONLY THE DECISION. Before code-gate round 1
    // the resolver checked `hasOwnProperty` and then read all three members unconditionally, so a
    // prototype accessor for a member the caller never sent still fired. Two consequences, and the
    // second is the sharp one: the request throws instead of resolving, AND an arbitrary getter is
    // handed a chance to mutate the source buffer before any matching runs.
    let touched = false;
    const hostile = Object.create({
        get offset() { touched = true; throw new Error('an inherited accessor must never be read'); },
        get length() { touched = true; throw new Error('an inherited accessor must never be read'); }
    });
    hostile.quote = 'hello';

    success(resolveSpan(Buffer.from('hello', 'utf8'), hostile), 0, 5, 'hello');
    assert.equal(touched, false, 'no inherited accessor may be invoked');
});

test('B1-source-not-mutated — resolving never writes to the caller\'s buffer', () => {
    arm('B1-source-not-mutated');

    // ⚠ PINNED RATHER THAN ARGUED. The implementation has no write, but "appears read-only under
    // static reading" is not a measurement, and a mutant that wrote to the source after resolving
    // would have passed every other arm in this file.
    const bytes = Buffer.from('hello world', 'utf8');
    const before = Buffer.from(bytes);

    resolveSpan(bytes, { offset: 0, length: 5 });
    resolveSpan(bytes, { quote: 'world' });
    resolveSpan(bytes, { quote: 'nowhere' });
    resolveSpan(bytes, { offset: 0, length: 5, quote: 'wrong' });

    assert.ok(bytes.equals(before), 'the source buffer is unchanged by every request shape');
});

test('B1-source-subclass — a Buffer SUBCLASS is admitted, resolves identically, is left unmodified — and all THREE things a hostile one can still do', () => {
    arm('B1-source-subclass');

    /**
     * ⚠⚠ `Buffer.isBuffer` IS AN `instanceof` CHECK, so the source contract admits a subclass. This
     * arm pins that as the RULING rather than leaving it undecided — the argument for admitting it
     * rather than tightening the check is written out in `test/arms.mjs`, beside the inventory row.
     * The short form: the REQUEST crosses the trust boundary and the SOURCE does not, so a hostile
     * subclass presupposes a hostile caller, who can simply hand over different bytes.
     *
     * ⚠ THE ARM'S JOB IS TO MAKE THE ADMISSION FALSIFIABLE. A later session that tightens the check
     * to a prototype-identity test finds this red and has to rule on it deliberately, which is the
     * review event a comment could not produce.
     *
     * ⚠ A SUBCLASS IS BUILT BY RE-PROTOTYPING A REAL BUFFER, never by `new Sub(size)` — the Buffer
     * constructor is deprecated and would emit DEP0005 into the run.
     */
    const subclassOf = (Sub, from) => Object.setPrototypeOf(Buffer.from(from, 'utf8'), Sub.prototype);

    /* (1) THE ORDINARY CASE — a subclass that overrides nothing behaves exactly like its base. */
    class Plain extends Buffer {}
    const sub = subclassOf(Plain, 'hello world');
    assert.ok(sub instanceof Plain && Buffer.isBuffer(sub), 'the fixture must really be a Buffer subclass');

    // Every request shape, against the values the plain-Buffer arms above pin for the same source.
    success(resolveSpan(sub, { offset: 0, length: 5 }), 0, 5, 'hello');
    success(resolveSpan(sub, { quote: 'world' }), 6, 5, 'world');
    success(resolveSpan(sub, { offset: 6, length: 5, quote: 'world' }), 6, 5, 'world');
    refusal(resolveSpan(sub, { quote: 'nowhere' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(sub, { offset: 0, length: 5, quote: 'wrong' }), 'SPAN_MISMATCH', 'request');
    refusal(resolveSpan(sub, { offset: 0, length: 0 }), 'SPAN_INVALID_RANGE', 'length');

    /* (2) THE PURITY HALF, CARRIED ACROSS THE SUBCLASS GAP. `B1-source-not-mutated` asserts this
     * for a plain Buffer only, and a subclass is the shape that reaches different code paths in
     * `indexOf`/`subarray`/`toString`. */
    const before = Buffer.from(sub);
    resolveSpan(sub, { offset: 0, length: 5 });
    resolveSpan(sub, { quote: 'world' });
    resolveSpan(sub, { quote: 'nowhere' });
    resolveSpan(sub, { offset: 0, length: 5, quote: 'wrong' });
    assert.ok(before.equals(sub), 'the subclassed source buffer is unchanged by every request shape');

    /**
     * (3) WHAT THE RULING COSTS, MEASURED RATHER THAN REASONED ABOUT.
     *
     * ⚠⚠ THIS ASSERTION PINS A LIMIT, NOT A DESIRABLE BEHAVIOUR. An overriding subclass CAN mint a
     * span the source does not contain — `NO SILENT MISLOCATION` is a guarantee about a source the
     * module is HANDED, and it does not survive a source that lies about itself. It is asserted so
     * the cost of admitting subclasses cannot be quietly forgotten, and so that a product change
     * closing it cannot land silently either: this line is what goes red on the day someone
     * tightens the source contract, and that is the review event.
     */
    // ⚠ THE COUNTER IS A CLOSURE, NOT A PRIVATE FIELD. `Object.setPrototypeOf` re-homes an object
    // without running the constructor, so a `#field` is never installed and reading one THROWS.
    let indexOfCalls = 0;
    class Liar extends Buffer {
        indexOf() { indexOfCalls += 1; return indexOfCalls === 1 ? 3 : -1; }
    }
    const liar = subclassOf(Liar, 'hello world');
    const minted = resolveSpan(liar, { quote: 'zz' });
    success(minted, 3, 2, 'zz');
    assert.equal(liar.subarray(3, 5).toString('utf8'), 'lo',
        'the measurement: the source says "lo" at 3..5 and the resolver reported the quote "zz" there');

    /**
     * (4) THE SECOND MECHANISM, AND IT REACHES THE SHAPE (3) CANNOT.
     *
     * ⚠⚠ (3) OVERRIDES `indexOf`, WHICH ONLY THE QUOTE-ONLY PATH CALLS. The offsets-only path
     * never runs the scan, so a reader of (3) alone can conclude the offsets shape is safe — it is
     * not. `subarray` is on the offsets path, and offsets-WITHOUT-quote is the one request shape
     * with no cross-check at all: the quote is READ OUT of the slice rather than compared against
     * anything, so whatever `subarray` returns becomes the recorded quote verbatim.
     *
     * Measured, not reasoned: `{ offset: 0, length: 5 }` over a source whose real bytes 0..5 are
     * "hello" records the quote "XXXXX" — a span that names a range and quotes text that is not in
     * it. Every range check passed, because the range IS valid; the substitution happens after.
     */
    class SliceLiar extends Buffer {
        subarray() { return Buffer.from('XXXXX', 'utf8'); }
    }
    const sliceLiar = subclassOf(SliceLiar, 'hello world');
    success(resolveSpan(sliceLiar, { offset: 0, length: 5 }), 0, 5, 'XXXXX');
    assert.equal(Buffer.prototype.subarray.call(sliceLiar, 0, 5).toString('utf8'), 'hello',
        'the measurement: the source really says "hello" at 0..5 and the resolver recorded "XXXXX"');

    // ⚠ AND THE PAIRED HALF: supplying the quote DOES catch it, because the mismatch check compares
    // the caller's quote against the slice. So the exposure is precisely the unverified shape, and
    // a reader can see which half of the API is load-bearing here rather than inferring it.
    refusal(resolveSpan(sliceLiar, { offset: 0, length: 5, quote: 'hello' }), 'SPAN_MISMATCH', 'request');

    /**
     * (5) THE THIRD MECHANISM — SUPPRESSION RATHER THAN SUBSTITUTION, AND IT IS THE WORST-SHAPED
     * OF THE THREE.
     *
     * ⚠⚠ (3) AND (4) MINT A WRONG ANSWER; THIS ONE TURNS A REFUSAL INTO A SUCCESS. The module's
     * governing rule is `AMBIGUITY REFUSES; IT NEVER PICKS`, and the ambiguity scan is built out
     * of repeated `indexOf` calls — so a subclass that answers the FIRST call truthfully and the
     * second `-1` reports a genuinely ambiguous quote as uniquely located. Nothing here is
     * fabricated: offset 0 really does hold "aa". The span is a true statement that the resolver
     * was required to refuse to make, which is why an arm that only checks the returned values
     * cannot see it — the plain-Buffer control on the line above is what makes it visible.
     */
    class HideDuplicate extends Buffer {
        indexOf(needle, from) {
            return from === 0 ? Buffer.prototype.indexOf.call(this, needle, from) : -1;
        }
    }
    // The control first: the same source and quote through a plain Buffer must REFUSE.
    refusal(resolveSpan(Buffer.from('aa aa', 'utf8'), { quote: 'aa' }), 'SPAN_AMBIGUOUS', 'quote');
    success(resolveSpan(subclassOf(HideDuplicate, 'aa aa'), { quote: 'aa' }), 0, 2, 'aa');
});

test('B1-multibyte-offsets — byte offsets, never character offsets', () => {
    arm('B1-multibyte-offsets');

    // U+65E5 U+672C U+8A9E — three characters, three bytes each.
    const bytes = Buffer.from('\u65e5\u672c\u8a9e', 'utf8');
    assert.equal(bytes.length, 9, 'three characters, nine bytes');
    // ⚠ ASSERTED NUMERICALLY RATHER THAN BY ROUND-TRIP. A resolver treating offsets as CHARACTER
    // offsets answers 1 here and its quote still round-trips, so only the number catches it.
    success(resolveSpan(bytes, { quote: '\u672c' }), 3, 3, '\u672c');
    success(resolveSpan(bytes, { offset: 3, length: 3 }), 3, 3, '\u672c');
    success(resolveSpan(bytes, { quote: '\u8a9e' }), 6, 3, '\u8a9e');
    // A character-offset resolver would answer this one with the SECOND character.
    success(resolveSpan(bytes, { offset: 0, length: 3 }), 0, 3, '\u65e5');
});

test('B1-exact-whitespace — matching is exact over bytes; no whitespace normalisation', () => {
    arm('B1-exact-whitespace');

    const bytes = Buffer.from('a b', 'utf8');
    refusal(resolveSpan(bytes, { quote: 'a  b' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(bytes, { quote: 'a\tb' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(bytes, { quote: 'ab' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(bytes, { offset: 0, length: 3, quote: 'a  b' }), 'SPAN_MISMATCH', 'request');
    success(resolveSpan(bytes, { quote: 'a b' }), 0, 3, 'a b');
});

test('B1-exact-case — no case folding', () => {
    arm('B1-exact-case');

    const bytes = Buffer.from('Alpha', 'utf8');
    refusal(resolveSpan(bytes, { quote: 'alpha' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(bytes, { quote: 'ALPHA' }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(bytes, { offset: 0, length: 5, quote: 'alpha' }), 'SPAN_MISMATCH', 'request');
    success(resolveSpan(bytes, { quote: 'Alpha' }), 0, 5, 'Alpha');
});

test('B1-exact-normalisation — no Unicode normalisation, in either direction', () => {
    arm('B1-exact-normalisation');

    // NFC: `caf` + U+00E9, five bytes. NFD: `cafe` + U+0301, six bytes. They render alike and are
    // different texts, which is exactly the collapse this rule forbids.
    const NFC = 'caf\u00e9';
    const NFD = 'cafe\u0301';
    assert.notEqual(NFC, NFD, 'the two forms must be distinct strings, or this arm tests nothing');

    const nfcBytes = Buffer.from(NFC, 'utf8');
    assert.equal(nfcBytes.length, 5);
    refusal(resolveSpan(nfcBytes, { quote: NFD }), 'SPAN_NOT_FOUND', 'quote');
    refusal(resolveSpan(nfcBytes, { offset: 0, length: 5, quote: NFD }), 'SPAN_MISMATCH', 'request');
    success(resolveSpan(nfcBytes, { quote: NFC }), 0, 5, NFC);

    // ⚠ AND THE MIRROR, so the arm is not merely "NFD never matches anything".
    const nfdBytes = Buffer.from(NFD, 'utf8');
    assert.equal(nfdBytes.length, 6);
    refusal(resolveSpan(nfdBytes, { quote: NFC }), 'SPAN_NOT_FOUND', 'quote');
    success(resolveSpan(nfdBytes, { quote: NFD }), 0, 6, NFD);
});
