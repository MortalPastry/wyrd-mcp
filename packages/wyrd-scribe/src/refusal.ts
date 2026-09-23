/**
 * THE SCRIBE'S OWN REFUSAL SHAPE, and the one rule that binds every field in it.
 *
 * ⚠⚠ NEVER A RESOLVED ABSOLUTE PATH IN A `detail`. This is the fence's `META-no-outside-names`
 * property carried across the package boundary — the fence returns `rel` and never `actual`
 * precisely so a refusal cannot become a filesystem oracle, and a Scribe refusal that echoed a
 * caller-supplied path would hand that oracle back one layer up. So a Scribe `detail` names a
 * CONSTANT (`.wyrd/scribe.json`) or a BOUND (`65536 bytes`), never a request string.
 *
 * ⚠ THE CALLER'S OWN REQUEST STRING IS NOT SAFE TO ECHO EITHER, and that is the non-obvious half.
 * It looks harmless — the caller already knows what it sent — but the refusal travels to a MODEL
 * driving the server over stdio, and echoing `C:\Users\...\secrets\x.md` back into a transcript
 * puts an outside name in the one place the fence spent seven rounds keeping it out of. A refusal
 * says which RULE fired; it does not repeat the request.
 *
 * ⚠ FENCE REFUSALS PASS THROUGH UNCHANGED and are NOT re-wrapped in this shape. A parallel
 * vocabulary for `ESCAPES`/`MISSING`/`EXISTS` would be a second thing to get wrong, and D8's whole
 * argument is that there is one containment implementation and one set of words for its outcomes.
 * `SOURCE_MISSING` in the spec's prose IS the fence's `MISSING`; it is not a distinct reason.
 */

/**
 * The reasons the Scribe itself originates. `ARC_IMMUTABLE` is doctrine (D7) rather than a fence
 * outcome, so it lives here with the rest.
 */
export type ScribeReason =
    | 'BAD_INPUT'
    | 'DERIVED_FROM_INVALID'
    | 'ARC_IMMUTABLE'
    | 'SCRIBE_NOT_INITIALISED'
    | 'SCRIBE_CONFIG_INVALID'
    | 'SCRIBE_CONFIG_TOO_LARGE'
    | 'SOURCE_CHANGED_DURING_READ'
    | 'FRONTMATTER_INVALID'
    | 'FRONTMATTER_CONFLICT'
    | 'LINEAGE_LINE_TOO_LARGE'
    | 'PAGE_WRITTEN_LEDGER_FAILED';

/**
 * ⚠ NO `resolvedPath`, DELIBERATELY. The fence carries that field because a CONFIG refusal names
 * the grant the user themselves configured; a Scribe refusal has no such field to fill honestly,
 * and an empty-string placeholder would be a slot a later session fills with the wrong thing.
 */
export interface ScribeRefusal {
    readonly ok: false;
    readonly reason: ScribeReason;
    readonly detail: string;
}

export function scribeRefuse(reason: ScribeReason, detail: string): ScribeRefusal {
    return Object.freeze({ ok: false as const, reason, detail });
}
