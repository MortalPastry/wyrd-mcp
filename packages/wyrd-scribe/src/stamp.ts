/**
 * `writePage` — THE STAMP PATH, TIER A (create-only). The Scribe-side half of the spec's step list.
 *
 * ⚠⚠ THE ORDER IS THE SECURITY PROPERTY, NOT AN IMPLEMENTATION DETAIL. Read the numbered steps
 * below as a sequence of things that must not have happened yet:
 *
 *   · EVERY REFUSAL KNOWABLE FROM THE REQUEST'S OWN SHAPE IS DECIDED BEFORE ANY SOURCE IS READ —
 *     the `Arc/` screen, the count caps, and every span fault. If any of them ran after, a caller
 *     could send a request that was ALWAYS going to refuse — an `Arc/` target, 65 sources, a
 *     malformed span — with a `derived_from` naming any path on the machine, and read those
 *     sources' existence and hashes out of the refusal's timing and reason. That turns a check into
 *     an EXISTENCE ORACLE, which is D8's hole arriving through the back door after D8 closed the
 *     front one. ⚠ The rule was written for `Arc/` and enforced only there until 2026-09-02; the
 *     counts and the span shapes were being decided after the whole source loop had run.
 *
 *     ⚠⚠ THIS SAID "EVERY GUARANTEED REFUSAL" UNTIL 2026-09-08 AND THAT IS NO LONGER TRUE, so the
 *     claim is narrowed to what the order actually buys. The fence's `PARENT_ALIAS` is a guaranteed
 *     refusal — the page's parent is an alias, and no source read can change that — but it is
 *     knowable only from the vault's TOPOLOGY, not from the request's shape, and it fires at page
 *     creation in step 6, AFTER the source loop. ⚠ The oracle argument survives the narrowing: what
 *     a caller learns from a `PARENT_ALIAS` is a fact about a directory INSIDE the grant, which
 *     every read operation already discloses. The `.wyrd/` half is not affected at all — step 4's
 *     `loadConfig` refuses an aliased `.wyrd` before step 5 reads anything.
 *   · NO PAGE IS WRITTEN until every source has resolved and every limit KNOWABLE BEFORE THE PAGE
 *     EXISTS has passed. When a page IS created and the ledger step then REFUSES — the final size
 *     check at step 9, or the append after it — this invocation leaves that page with no ledger
 *     line: an ORPHAN, which the no-rollback ruling below leaves on disk and which the
 *     create-before-append clause two bullets down calls "detectable and repairable". That is what
 *     the draft size check at step 6 stands in front of.
 *
 *     ⚠ THE FIRST SENTENCE READ UNCONDITIONALLY UNTIL 2026-09-08 — "a page created before the
 *     ledger line is known to be serialisable is a page this invocation leaves with no ledger line"
 *     — WHICH IS WIDER THAN THE CODE. The ordinary path creates the page before the FINAL size
 *     check and then appends successfully; the orphan is what a REFUSAL at either ledger step
 *     leaves, not what the ordering leaves. The condition is now in the sentence.
 *
 *     ⚠ AND IT SAID "a page whose provenance can NEVER be recorded" BEFORE THAT, WHICH THE CODE
 *     ALSO DID NOT ESTABLISH. What this invocation leaves behind is a page with no ledger line.
 *     **`writePage` provides no pass that records one later, and re-invoking it on the same path
 *     refuses `EXISTS`** — so nothing in this package records one, which is narrower than the
 *     retired "a later pass can still record one" and is what the code actually says. Overclaiming
 *     in either direction is not a harmless flourish: the first makes the residual hole at step 9
 *     (`ST41`) sound impossible instead of merely narrow, the second promises a repair path this
 *     package does not contain.
 *
 *     ⚠⚠ "EVERY LIMIT" IS NOT WHAT THIS ORDERING BUYS AND THE CLAUSE SAID SO UNTIL 2026-09-08. One
 *     limit is decided AFTER the page exists: the final ledger-line size check at step 9, over the
 *     CANONICAL path the fence returns from the create. It is reachable — a fold-equal parent alias
 *     of different byte width makes `created.rel` wider than the request the draft was sized
 *     against (`ST41`) — and when it fires the page is already on disk with no ledger line. That
 *     ORPHAN is the outcome, asserted PRESENT on purpose by `ST38` and `ST41` so a green suite is
 *     never read as meaning it was closed. What the ordering buys is the narrower claim, which is
 *     still the one worth having: no page exists until every check that CAN be decided without one
 *     has passed.
 *
 *     ⚠⚠ THIS SAID "NOTHING IS WRITTEN" UNTIL 2026-09-08 AND THAT IS NO LONGER TRUE EITHER, so the
 *     subject is narrowed to the thing the ordering actually protects. Option C's part 3 hoists
 *     `loadConfig`'s exclusive create ahead of its read, so STEP 4 CAN CREATE `.wyrd/scribe.json`
 *     BEFORE ANY SOURCE IS READ. The distinction is worth the words: the config is this server's
 *     own bookkeeping, minted at a fixed path inside a directory the user created for it, and a
 *     vault that gains one has gained none of the caller's PAGE CONTENT (the `vault_id` it carries
 *     is whatever `newUuid` returned, and a caller supplying that option chose it). The PAGE is
 *     the first write of caller-supplied content, and it is still the write every check above
 *     stands in front of.
 *     Sources are read BETWEEN the two.
 *   · the page is created BEFORE the ledger line is appended, and that ORDER IS ALSO DELIBERATE.
 *     The reverse records provenance for a page that may never exist, which is a FALSE PROVENANCE
 *     CLAIM — D4 names that as the failure that matters, worse than breakage, because it looks
 *     healthy. A page with a missing ledger line is DETECTABLE — the page is on disk and the ledger
 *     has no line naming it, which a reader can see — and repairable BY SOMETHING OUTSIDE THIS
 *     PACKAGE; a ledger line with no page is a lie in the permanent record, and nothing detects it.
 *     ⚠ "repairable" ALONE READ AS A PROMISE THIS PACKAGE KEEPS, WHICH IT DOES NOT: `writePage` has
 *     no repair pass and refuses `EXISTS` on the orphan's own path. What the ordering buys is that
 *     the failure is the visible kind rather than the invisible kind.
 *
 * ⚠⚠ AND THERE IS NO ROLLBACK, WHICH IS A RULING RATHER THAN AN OMISSION. If the append fails after
 * the page was created, the page STAYS and the refusal says so (`PAGE_WRITTEN_LEDGER_FAILED`,
 * carrying the fence's `Created`). Two reasons, and the second is the load-bearing one: the fence
 * has no delete primitive at all in tier A, and deleting BY PATH would reopen the TOCTOU window the
 * fence's `wx` create exists to close — between the create and the delete, the name can become
 * something else. A caller told exactly what happened can decide; a caller handed a silent cleanup
 * that deleted the wrong object cannot.
 */

import { randomUUID } from 'node:crypto';

import type { Created, FenceRefusal, FsGate } from 'wyrd-fence';

import { loadConfig } from './config.js';
import { project, stamp as stampFrontmatter } from './frontmatter.js';
import {
    checkCounts,
    checkLineSize,
    checkPagePath,
    checkRequestCounts,
    contentHash,
    hashText,
    identity,
    lineageSpan,
    LINEAGE_SCHEMA,
    serialiseRecord
} from './lineage.js';
import type { LineageRecord, LineageSource } from './lineage.js';
import type { LedgerAppender } from './ledger.js';
import type { ScribeRefusal } from './refusal.js';
import { scribeRefuse } from './refusal.js';
import { readSource, SourceCache, toLedgerPath } from './source.js';
import { resolveSpan, spanShapeFault } from './span.js';
import type { SpanMembers, SpanRefusal, SpanRequest } from './span.js';

/** A `derived_from` entry: one source path and the spans cited from it. */
export interface DerivedFrom {
    readonly source: string;
    readonly spans: readonly SpanRequest[];
}

export interface WritePageRequest {
    readonly path: string;
    readonly content: string;
    readonly derivedFrom: readonly DerivedFrom[];
}

/**
 * ⚠⚠ THE OUTER SIDE-EFFECT SUMMARY, AND IT IS A DIFFERENT QUESTION FROM `retained`.
 *
 * `retained` is the FENCE's field and it is honest exactly as scoped: **it describes the ONE fence
 * call that produced the refusal it sits on** — whether that call may have left bytes at the target
 * IT was given. It says nothing about the invocation around it, and reading it as an
 * invocation-wide "nothing happened" is the mistake this field exists to ANSWER — the answer is
 * available beside it now, which is a different thing from the misreading being unavailable; a
 * caller can still read `retained` alone and reach the old wrong conclusion. Since
 * part 3 hoisted `loadConfig`'s exclusive create ahead of its read, a `writePage` that refuses at
 * step 4 or later may ALREADY have minted the vault's config — a real, persistent change to the
 * user's vault — while every `retained` in sight is `null` because the target that fence call was
 * given was never opened.
 *
 * ⚠ WHICH TARGET IT DESCRIBES IS GIVEN BY WHERE THE REFUSAL AROSE, AND THERE IS NO SHORTER RULE
 * THAN THAT. `retained`, where present, describes the fence call that produced the refusal it sits
 * on — which target that call was given is answered by reading where in `writePage` the refusal
 * came from, not by the refusal's shape. A pass-through from step 4 describes the CONFIG target
 * (`ST39`, `stamp.test.js` ~2280); one from step 8 describes the page; a source-read refusal may
 * carry no `retained` at all. On `LedgerFailed` the field lives at `cause.retained` and describes
 * whatever the failing call addressed — and where the cause is Scribe-originated, as `ST41`'s
 * `LINEAGE_LINE_TOO_LARGE` is, there is no `cause.retained` to read. The page's own outcome is
 * never in that field either way: it is the `created` beside it, which says the page exists.
 *
 * **`retained` describes the fence call that produced the refusal it sits on; `config_created` says
 * whether this invocation minted the vault config.** A caller repairing after a refusal needs both.
 *
 * ⚠ This field was added before the package's first public contract, so no earlier consumer shape
 * required compatibility.
 * It is on the ok shape AND on every POST-CONFIG Scribe-originated refusal shape for the same
 * reason: a field present only on success answers the question only when the answer is least
 * interesting. (A refusal decided at steps 1-3 carries no field; there is no answer yet.)
 *
 * ⚠⚠ AND THE RULE IS EXACTLY ONE SENTENCE WIDE, so read it before adding a return site. **Every
 * result `writePage` returns after `loadConfig` has run carries `config_created`, set from what
 * THIS invocation's `loadConfig` did — except a fence refusal passed through unchanged under D8,
 * which carries no field.** A refusal decided at steps 1-3, before `loadConfig` runs, carries no
 * field either, for the plainer reason that there is no answer yet.
 *
 * ⚠ ON A FENCE PASS-THROUGH THE CALLER IS SIMPLY NOT TOLD, and the residual is stated rather than
 * argued away: a fence refusal from step 6's create, or from the source loop, CAN follow a config
 * mint at step 4 and will not say so. **The absence of the field is not evidence the config was
 * untouched.** On a fence pass-through the caller is not told whether this invocation minted the
 * config, and **this package offers no observation that attributes it** — a later stat says the
 * file is there, not who put it there, and nothing here records the answer anywhere else. ⚠ THAT
 * CLAUSE READ "no later observation attributes it" UNTIL 2026-09-08, which speaks for observations
 * outside this package that it knows nothing about. Closing the gap properly means a discriminated
 * envelope around the pass-throughs, which is a wider change than this round is scoped to make.
 */
export interface ConfigCreated {
    /** True when THIS invocation minted `.wyrd/scribe.json`. */
    readonly config_created: boolean;
}

/**
 * ⚠ THE FAILED-LEDGER OUTCOME CARRIES THE `Created`, AND IT IS A REQUIRED FIELD. The caller's next
 * action depends entirely on knowing the page IS on disk and where — telling them only that
 * something failed leaves them unable to distinguish "nothing happened" from "a page exists with no
 * provenance", which are opposite situations demanding opposite repairs.
 */
export interface LedgerFailed extends ScribeRefusal, ConfigCreated {
    readonly reason: 'PAGE_WRITTEN_LEDGER_FAILED';
    readonly created: Created;
    /**
     * The fence or ledger refusal that actually fired, passed through rather than summarised.
     *
     * ⚠⚠ `ScribeRefusal` IS IN THIS UNION BECAUSE ITS ABSENCE WAS THE DEFECT. Every cause reaching
     * here used to be typed `FenceRefusal`, whose `reason` is the fence's closed `FenceReason`
     * union — so the one site that fires on a Scribe-side fault, the post-create line-size
     * re-check, had NOTHING HONEST IT COULD TYPECHECK and returned a fabricated `IO_ERROR`. The
     * caller was told a filesystem error lost their provenance when the truth was a request over a
     * documented bound. **A too-narrow cause type does not prevent the wrong cause; it compels
     * one.** Widening the union is what lets the site name `LINEAGE_LINE_TOO_LARGE`.
     */
    readonly cause: FenceRefusal | ScribeRefusal;
}

export interface Stamped extends ConfigCreated {
    readonly ok: true;
    readonly created: Created;
    readonly record: LineageRecord;
    readonly appended: number;
}

/**
 * A Scribe-originated refusal from the stamp path, carrying the outer summary.
 *
 * ⚠⚠ EVERY SCRIBE-ORIGINATED SHAPE RETURNED AFTER STEP 4 CARRIES THE FIELD, AND THE ONE EXCLUSION
 * IS THE FENCE PASS-THROUGH. The fence's refusals are returned unwrapped under D8 — a second
 * vocabulary for one containment implementation is what D8 exists to prevent — so they carry no
 * `config_created` and a caller reading one is NOT told whether this invocation minted the config.
 * That is the whole of the exclusion, and it is stated on the type at `WritePageResult` below.
 *
 * ⚠⚠ THE SPAN REFUSALS WERE IN THAT EXCLUSION UNTIL 2026-09-08 AND ARE NOT ANY MORE. The retired
 * argument was that `span.ts`'s envelope holds exactly `ok`, `reason` and `where`, that `ST20`
 * asserts that own-key set exactly, and that widening it here would be this module rewriting
 * another module's contract on its way past. What that reasoning missed is WHICH module's contract
 * the returned value belongs to: a `SPAN_*` refusal reaching a `writePage` caller is `writePage`'s
 * result, and the own-key envelope exists to stop UNDOCUMENTED keys reaching that caller rather
 * than to fix a cardinality. `config_created` is documented, on the type, in the same words on
 * every shape that carries it — so the envelope grows by exactly one documented key and `ST20`'s
 * assertion is widened to say so. `span.ts`'s own arms are untouched: the module still returns
 * three keys, and step 5 is what adds the fourth on its way out.
 *
 * ⚠ THE SHAPE-ONLY SPAN FAULTS AT STEP 3 STILL CARRY NOTHING, and that is the ordering rather than
 * an exception: they are decided BEFORE `loadConfig` runs, so there is no answer to report.
 */
export interface StampRefusal extends ScribeRefusal, ConfigCreated {}

/**
 * A `SPAN_*` refusal from step 5, carrying the outer summary. See `StampRefusal` for why the span
 * envelope grew by one key on 2026-09-08, and `span.ts` for why the module's own returns did not.
 */
export interface StampSpanRefusal extends SpanRefusal, ConfigCreated {}

export interface WritePageOptions {
    readonly gate: FsGate;
    readonly appender: LedgerAppender;
    readonly version: string;
    /** Injected so an arm can pin `recorded_at` and the minted vault id. Production uses the defaults. */
    readonly now?: () => Date;
    readonly newUuid?: () => string;
    /**
     * ⚠ A SEPARATE SEAM FROM `newUuid`, WHICH MINTS THE VAULT ID. They are both v4 UUIDs and both
     * default to `randomUUID`, and sharing one injection point would be convenient and wrong: an
     * arm pinning the vault id to a fixed value would pin every `event_id` to the SAME value, which
     * is precisely the collision `event_id` exists to make impossible. A suite that cannot pin one
     * without flattening the other cannot measure either.
     */
    readonly newEventId?: () => string;
    readonly cache?: SourceCache;
}

/**
 * ⚠⚠ THE ONE RULE THIS UNION EXISTS TO STATE, AND IT IS A RULE ABOUT `config_created`:
 *
 *   **Every result `writePage` returns after `loadConfig` has run carries `config_created`, set
 *   from what THIS invocation's `loadConfig` did — EXCEPT a fence refusal passed through unchanged
 *   under D8, which carries no field at all.**
 *
 * So the union is written to make that sentence checkable rather than merely asserted. `ScribeRefusal`
 * and `SpanRefusal` appear as `PreConfigRefusal`, a shape reachable ONLY from steps 1-3 — before
 * `loadConfig` runs, where there is nothing to report — and every Scribe-originated shape from step
 * 4 down carries the field. `FenceRefusal` is the documented exclusion: it is the ONE POST-CONFIG
 * member that does not carry the field. `PreConfigRefusal` lacks it too, which is the ordering
 * rather than an exclusion — it is decided before there is an answer.
 *
 * ⚠⚠ THE BARE `ScribeRefusal` MEMBER WAS THE DEFECT, NOT THE FIX. Until 2026-09-08 this union
 * listed `ScribeRefusal` and `SpanRefusal` outright, which made the type say "a Scribe refusal may
 * or may not carry the summary" — so a return site that dropped the field TYPECHECKED, and three
 * did. A type that admits both answers cannot catch the wrong one. If a later change makes
 * TypeScript reject a return site here, that site is an instance of the class, not a reason to
 * widen the union back.
 *
 * ⚠⚠ AND THE BRAND IS WHAT MAKES IT BIND, WHICH LISTING THE SHAPES SEPARATELY DID NOT. Measured
 * twice during this round, because the first attempt looked right and was not:
 *
 *   · With `PreConfigRefusal` declared as a bare `ScribeRefusal | SpanRefusal`, a post-config site
 *     returning the refusal unwrapped still COMPILED. The two shapes are structurally identical,
 *     so TypeScript matched the return against the pre-config member and had nothing to say. A
 *     union whose members are structurally interchangeable cannot encode WHERE a value came from.
 *   · With the brand declared OPTIONAL (`?: never`) it still compiled, for the plainer reason that
 *     an optional property is satisfied by its absence. An optional brand brands nothing.
 *
 * So the brand is REQUIRED. `PRE_CONFIG` is a `unique symbol` declared and never defined, so the
 * property exists only in the type system — no runtime value carries it, nothing can read it, and
 * it costs no bytes. What it buys is that an unbranded bare refusal returned from step 4 down
 * matches NO member of this union and is REJECTED, which is the whole point of writing the rule as
 * a type instead of as a sentence.
 */
declare const PRE_CONFIG: unique symbol;

/**
 * A refusal decided at steps 1-3, before `loadConfig` has run. It carries no `config_created` for
 * the plain reason that there is no answer yet, and the brand is what keeps it from standing in for
 * the post-config shapes — see the note above for the two measurements that forced it.
 */
export type PreConfigRefusal = (ScribeRefusal | SpanRefusal) & {
    readonly [PRE_CONFIG]: never;
};

/**
 * ⚠⚠ THE SNAPSHOT — THE VALIDATED REQUEST, HELD AS DATA THIS MODULE BUILT RATHER THAN AS THE
 * CALLER'S OBJECT.
 *
 * `preflight` used to return the caller's own object, narrowed. That is a different thing from
 * validating it: `writePage` then read `content`, `derivedFrom` and every span back off the SAME
 * object across two `await`s, so a getter, a Proxy, or a plain reassignment from an injected hook
 * could serve one value to the validation and another to the write. **The validated thing and the
 * used thing were different reads of a mutable object** — the 09-03 close-review's OWED row,
 * `issuelog.md`: *request members are re-read through accessors after validation*.
 *
 * So every member is COPIED OUT at validation time and this module's own code does not read the
 * caller's object again. `path` and `content` are strings, which are values; `derivedFrom` is rebuilt entry by entry into
 * frozen plain objects, and each SPAN is rebuilt from the members `spanShapeFault` already read —
 * see `snapshotSpan`. What holds the claim up is not this sentence: `ST42` counts the reads of
 * three caller-supplied getters and asserts each fired EXACTLY ONCE, and `M25`/`M26` are the
 * pass-through shapes it kills.
 *
 * ⚠ WHAT THE COPY DOES NOT REACH, stated because a snapshot invites the wider reading: `source` and
 * `quote` are strings and `offset`/`length` are numbers, all of them already type-checked, so there
 * is no object of the caller's left inside the snapshot for a later read to find. It says nothing
 * about the SOURCE BYTES, which arrive from the fence at step 5, or about the vault changing under
 * the invocation — three concurrent-writer races stay open and named in the fence. And it says
 * nothing about the OPTIONS: `now`, `newUuid`, `newEventId`, `gate`, `appender` and `cache` are the
 * caller's, run downstream, may close over the caller's request, and return what the caller chose.
 * The snapshot contains what THIS MODULE derives from the request; it does not contain the caller.
 *
 * ⚠⚠ A CLASS, NOT AN INTERFACE, AND THAT IS THE DISCRIMINATOR RATHER THAN A STYLE CHOICE. The old
 * split asked `isRefusalLike(checked)` — `value.ok === false` — which reads INHERITED properties, so
 * a request whose PROTOTYPE carried `{ ok: false }` was admitted as a refusal and handed back to the
 * caller as one. `instanceof` moves that question onto a prototype this module owns, does not
 * export, and never hands to a caller — so no value a caller supplies answers it.
 *
 * ⚠ THE TWO GUARDS ARE NOT INDEPENDENT, AND THAT WAS MEASURED. `M27` was first written as the
 * discrimination alone and SURVIVED: once the snapshot is in place, a `Validated` carries no `ok`
 * on itself or on its prototype, so the old `.ok === false` read cannot be made to answer true
 * either. The snapshot subsumes the forgery. What `instanceof` buys is the half that does not
 * depend on the snapshot staying deep — see the note in `test/arms.mjs`.
 *
 * ⚠ CONSTRUCTED ONLY INSIDE `preflight`. The class is not exported, so a `Validated` in hand is
 * proof that steps 1-3 ran — the same argument the `preConfigRefuse` local makes on the refusal
 * side, applied to the success side. ⚠ Unlike that one this is not a cast: no expression OUTSIDE
 * this module produces a `Validated`, because neither the class nor its prototype leaves it.
 * Inside the module `Object.create(Validated.prototype)` would, and nothing here does — so the
 * escape hatch the brand has is narrower here, not absent. (The class has no private nominal
 * member, so a structurally matching object can carry the static TYPE; it does not pass
 * `instanceof`, which is the check `writePage` actually asks.)
 */
class Validated {
    readonly path: string;
    readonly content: string;
    readonly derivedFrom: readonly DerivedFrom[];

    constructor(path: string, content: string, derivedFrom: readonly DerivedFrom[]) {
        this.path = path;
        this.content = content;
        this.derivedFrom = derivedFrom;
        Object.freeze(this);
    }
}

/**
 * One span, rebuilt from the members the shape check ALREADY READ.
 *
 * ⚠⚠ REBUILT RATHER THAN COPIED, AND THE DIFFERENCE IS THE WHOLE POINT. `spanShapeFault` returns
 * `SpanMembers` — the values it read, once, under `span.ts`'s read-once rule — precisely so a
 * caller-supplied accessor fires exactly one time. Passing the caller's span object on to
 * `resolveSpan` at step 5 threw that away: the resolver calls `spanShapeFault` again, so the
 * accessor fired a SECOND time, after an `await`, and could serve a different value to the resolver
 * than to the validation. Reconstructing the span from the members read here means step 5 re-reads a
 * plain frozen object of this module's own making.
 *
 * ⚠ THE SHAPE IS THE ONE `span.ts` DOCUMENTS, spelled from `hasOffset`/`hasQuote` rather than by
 * copying keys: `{ offset, length }`, `{ quote }`, or all three. Any other combination was already
 * refused by `spanShapeFault` before control reaches here, so there is no fourth case to spell.
 */
function snapshotSpan(members: SpanMembers): SpanRequest {
    if (members.hasOffset && members.hasQuote) {
        return Object.freeze({
            offset: members.offsetValue as number,
            length: members.lengthValue as number,
            quote: members.quoteValue as string
        });
    }
    if (members.hasOffset) {
        return Object.freeze({
            offset: members.offsetValue as number,
            length: members.lengthValue as number
        });
    }
    return Object.freeze({ quote: members.quoteValue as string });
}

export type WritePageResult =
    | Stamped
    | StampRefusal
    | StampSpanRefusal
    | PreConfigRefusal
    | LedgerFailed
    | FenceRefusal;

const REQUEST_KEYS: ReadonlySet<string> = new Set(['path', 'content', 'derivedFrom']);
const DERIVED_KEYS: ReadonlySet<string> = new Set(['source', 'spans']);

/**
 * ⚠ THIS ONE IS PRIVATE ON PURPOSE, AND IT IS NOT THE COPY THAT WAS REMOVED FROM `config.ts` AND
 * `source.ts`. Those two guarded values that really were `FenceRefusal`, so they now import the
 * fence's own `isRefusal` (spec D8: the fence is imported, never reimplemented). The body here is
 * byte-identical to it and the NARROWING IS NOT: this path guards unions that are only partly the
 * fence's — `ScribeRefusal | FenceRefusal` at the config and source steps, `FenceRefusal` at the
 * create and append steps — so it narrows to the structural `{ ok: false }` that all of them share
 * and each caller casts to the union it actually holds.
 *
 * ⚠ Those casts are the honest cost of it, and they are what to attack if this is ever revisited:
 * a guard that every call site has to correct is doing less work than its signature suggests. The
 * fix is a discriminated union over the refusal kinds, not folding this into the fence's guard —
 * that would narrow four call sites to a type two of them do not hold.
 */
function isRefusalLike(value: unknown): value is { ok: false } {
    return typeof value === 'object' && value !== null && (value as { ok?: unknown }).ok === false;
}

/**
 * ⚠⚠ WHICH SIDE A REFUSAL CAME FROM, DECIDED ON `resolvedPath` RATHER THAN ON THE `reason` WORD.
 * The two steps that can return either kind — the config load and the source loop — need the
 * answer to know whether to add `config_created`: a Scribe refusal gets it, a fence pass-through
 * is the documented D8 exclusion and gets nothing.
 *
 * ⚠ `resolvedPath` IS THE DISCRIMINATOR BECAUSE THE FENCE DECLARES IT ON EVERY REFUSAL — an empty
 * string where the refusal is not a config one, never absent — and `ScribeRefusal` has no such
 * field AT ALL, deliberately (`refusal.ts`: there is nothing it could fill honestly). Matching on
 * `reason` instead would mean this module holding a second copy of the fence's closed reason union,
 * which is the drift D8 forbids and which would silently misfile every reason added after today.
 */
function isScribeRefusal(value: { ok: false }): value is ScribeRefusal {
    return !('resolvedPath' in value);
}

/**
 * ⚠ OWN KEYS, MIRRORING `span.ts`, AND FOR THE SAME REASON RATHER THAN FOR CONSISTENCY. An unknown
 * key read leniently is a request the caller did not make succeeding as one they did: `derivedFrom`
 * misspelled is a page written with NO provenance at all, silently, which is the product's whole
 * value quietly absent. `in` would also walk the prototype chain and read an inherited key as a
 * supplied one.
 */
function ownKeysOnly(value: unknown, allowed: ReadonlySet<string>): boolean {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
    const own = Reflect.ownKeys(value);
    for (const key of own) {
        if (typeof key !== 'string' || !allowed.has(key)) return false;
    }
    // ⚠⚠ EXACTLY THE ALLOWED SET, NOT A SUBSET OF IT — and the subset version was a live defect
    // measured by `ST19`. Screening only for UNKNOWN own keys lets a MISSING one fall through to the
    // read below, which then walks the prototype chain and finds an INHERITED value: an object with
    // `path` and `content` of its own and `derivedFrom` on its prototype passed the screen, read the
    // inherited array, and wrote a page carrying provenance the caller never supplied. Requiring
    // every member to be an OWN key is what makes the own-key discipline bind the READ as well as
    // the decision — the same two-halves failure `span.ts` records at its own `view` read.
    for (const key of allowed) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) return false;
    }
    return true;
}

/**
 * ⚠⚠ THE `Arc/` SCREEN IS LEXICAL AND RUNS BEFORE THE FENCE RESOLVES ANYTHING, which is the only
 * ordering that keeps it from being an oracle — see the header. The cost of being lexical is real
 * and is stated rather than hidden: a path reaching `Arc/` THROUGH a link whose name is not `Arc`
 * is not caught here. That residual is bounded by the fence, which refuses anything resolving
 * outside the grant, and by the fact that `Arc/` immutability is doctrine about an agent's
 * behaviour rather than a containment boundary — the spec is explicit that it is doctrine (D7),
 * and the app itself is a neutral file tool.
 *
 * ⚠ CASE-INSENSITIVE, because this host's filesystem is. `arc/x.md` and `Arc/x.md` name the same
 * file on Windows, so a case-sensitive screen would be trivially bypassable by typing a lowercase
 * `a` — a rule that only stops the polite half of the callers.
 *
 * ⚠ SEPARATORS FOLDED FIRST. `Arc\x.md` is the same path to Windows and must not slip past a check
 * written against `/`.
 */
function targetsArc(request: string): boolean {
    const folded = request.split('\\').join('/').replace(/^\/+/, '');
    // ⚠ DOT SEGMENTS FOLDED TOO. `Mage/../Arc/x.md` and `./Arc/x.md` name `Arc/x.md` to the fence,
    // which normalises before it resolves — so a screen that reads the caller's spelling admits
    // exactly the spelling a caller who knows about the screen would choose. Found by the close-side
    // review on 2026-09-03, after the arms had only ever spelled the path straight.
    const segments: string[] = [];
    for (const part of folded.split('/')) {
        if (part === '' || part === '.') continue;
        if (part === '..') { segments.pop(); continue; }
        segments.push(part);
    }
    return /^arc$/i.test(segments[0] ?? '');
}

/**
 * ⚠⚠ STEPS 1-3, LIFTED OUT SO NO NAMED WAY TO BUILD THE PRE-CONFIG SHAPE EXISTS OUTSIDE HERE. Every
 * refusal knowable from the request's own shape is decided in here — the strict key screen, the
 * `Arc/` screen, the count caps, the page-path bound and every span SHAPE fault — and the function
 * returns either one of those refusals or a validated SNAPSHOT for the post-config half to use.
 *
 * ⚠ THIS READ "SO THE PRE-CONFIG SHAPE CANNOT BE BUILT ANYWHERE ELSE" UNTIL 2026-09-08, AND THE
 * CODE ESTABLISHES NO SUCH THING. `PRE_CONFIG` is erased at runtime and the brand is applied by a
 * cast, so `refusal as PreConfigRefusal` written anywhere in this module builds one — the same
 * escape hatch every branded type in TypeScript has. What scope buys is that no NAMED site offers
 * it: the honest reading of a post-config `preConfigRefuse(...)` is a compile error, and a
 * deliberate cast is a thing a reviewer can see. That is smaller than unbuildable and is worth
 * having; overclaiming it is what makes the next reader stop looking for the cast.
 *
 * ⚠⚠ THE SCOPE IS THE POINT, AND THE BRAND ALONE DID NOT BUY IT. `PRE_CONFIG` is erased at
 * runtime, so while `preConfigRefuse` was a module-level function a post-config site could still
 * CALL it: the value it returns carries no `config_created` at all, and the brand made TypeScript
 * accept the return anyway — a shape the type system blesses and the caller cannot use. Making the
 * helper a LOCAL of this function is what closes that, because a name out of scope is not a
 * discipline, it is a compile error.
 *
 * ⚠ MEASURED BOTH WAYS ON 2026-09-08, over the same one-line edit: the post-config
 * `if (counts) return stampRefuse(counts, configCreated);` at step 5 rewritten to call
 * `preConfigRefuse(counts)` instead.
 *
 *   · With a module-level copy of the helper hoisted back into scope, that call COMPILES CLEAN.
 *     `tsc --noEmit` says nothing. This is the defect the brand does not reach.
 *   · With the helper scoped here, the same call fails:
 *
 *       src/stamp.ts(591,24): error TS2304: Cannot find name 'preConfigRefuse'.
 *
 * The brand still earns its place — it is what rejects an UNBRANDED bare refusal returned from step
 * 4 down (see `WritePageResult`). Scope is what rejects a BRANDED one. Neither check subsumes the
 * other, which is why both are here.
 *
 * ⚠⚠ THE SUCCESS RETURN IS A SNAPSHOT, NOT THE CALLER'S OBJECT, AND THAT SENTENCE WAS FALSE OF THE
 * CODE UNTIL 2026-09-08. It read: "the validated request is the success return rather than `void`,
 * so the post-config half reads `path`, `content` and `derivedFrom` off a value TypeScript already
 * knows is well-formed." TypeScript knew the SHAPE; it did not know the value would still be that
 * shape after the next `await`, because the value returned WAS the caller's own object. `writePage`
 * then read `derivedFrom` and `content` back off it, and a getter or a Proxy could answer
 * differently the second time. See `Validated` for the copy that closes it.
 */
function preflight(request: WritePageRequest): PreConfigRefusal | Validated {
    /**
     * ⚠ THE ONLY NAMED WAY TO BUILD A `PreConfigRefusal`, AND IT IS A LOCAL WITH ONE JOB. The brand
     * has no runtime existence, so this adds nothing to the value; what it adds is a NAMED SITE that
     * EXISTS ONLY HERE. Every step 1-3 refusal routes through it, which makes "was this decided
     * before the config load?" a question answered by scope rather than by reading control flow —
     * and a post-config site that tries the same call does not fail review, it fails to compile.
     *
     * ⚠ IT SAID "THE ONLY WAY" UNTIL 2026-09-08. The body is a cast, so the shape it produces can be
     * produced by writing the same cast — see the note above the function for what scope does and
     * does not buy.
     */
    function preConfigRefuse<T extends ScribeRefusal | SpanRefusal>(refusal: T): PreConfigRefusal {
        return refusal as PreConfigRefusal;
    }

    /**
     * ---- 1. the request shape, strictly, AND EVERY MEMBER READ EXACTLY ONCE ------------------
     *
     * ⚠⚠ THE READ IS THE FIRST THING, AND THE VALIDATION RUNS OVER WHAT WAS READ. The previous
     * shape read `view.path` three times (the type check, the `Arc/` screen, the page-path bound)
     * and `view.derivedFrom` four, so even INSIDE this function a caller-supplied accessor could
     * answer differently each time: a `Mage/` path for the screen and an `Arc/` one for the bound.
     * Reading each member once into a local and validating the LOCAL is `span.ts`'s read-once rule
     * (`SpanMembers`, and the `M1` defect behind it) applied one level up. Every check below reads
     * a `const` this function owns; nothing reaches back through `request` after this block.
     */
    if (!ownKeysOnly(request, REQUEST_KEYS)) {
        return preConfigRefuse(scribeRefuse('BAD_INPUT', 'the request carries an unknown or missing key'));
    }
    const view = request as { path?: unknown; content?: unknown; derivedFrom?: unknown };
    const rawPath: unknown = view.path;
    const rawContent: unknown = view.content;
    const rawDerivedFrom: unknown = view.derivedFrom;
    if (typeof rawPath !== 'string' || rawPath.length === 0) {
        return preConfigRefuse(scribeRefuse('BAD_INPUT', 'path must be a non-empty string'));
    }
    if (typeof rawContent !== 'string') {
        return preConfigRefuse(scribeRefuse('BAD_INPUT', 'content must be a string'));
    }
    if (!Array.isArray(rawDerivedFrom)) {
        return preConfigRefuse(scribeRefuse('DERIVED_FROM_INVALID', 'derivedFrom must be an array'));
    }
    /**
     * ⚠ THE ENTRY LIST IS COPIED OFF THE ARRAY BEFORE ANYTHING IS VALIDATED, for the reason the
     * members are: an array is an object, and its indices can be accessors. `[...rawDerivedFrom]`
     * reads each index once; every loop below then iterates this module's own array.
     */
    const entries: readonly unknown[] = Object.freeze([...rawDerivedFrom]);
    /** The snapshot, filled entry by entry as each is validated. Frozen plain data, all of it. */
    const snapshot: DerivedFrom[] = [];
    let requestedSpans = 0;
    for (const entry of entries) {
        if (!ownKeysOnly(entry, DERIVED_KEYS)) {
            return preConfigRefuse(scribeRefuse('DERIVED_FROM_INVALID', 'a derived_from entry carries an unknown or missing key'));
        }
        const source = (entry as { source?: unknown }).source;
        const rawSpans = (entry as { spans?: unknown }).spans;
        if (typeof source !== 'string' || source.length === 0) {
            return preConfigRefuse(scribeRefuse('DERIVED_FROM_INVALID', 'a derived_from entry needs a non-empty source path'));
        }
        // ⚠ AN EMPTY `spans` ARRAY REFUSES. A source cited with no span is a provenance claim with
        // no evidence — it records "this page came from that file" while pointing at nothing inside
        // it, which is precisely the unfalsifiable claim D4's span identity exists to replace.
        if (!Array.isArray(rawSpans) || rawSpans.length === 0) {
            return preConfigRefuse(scribeRefuse('DERIVED_FROM_INVALID', 'a derived_from entry needs at least one span'));
        }
        // The same one-read-per-index rule as the entry list above, one level down.
        const spans: readonly unknown[] = Object.freeze([...rawSpans]);
        requestedSpans += spans.length;
        snapshot.push(Object.freeze({ source, spans: spans as readonly SpanRequest[] }));
    }

    // ---- 2. Arc/ — BEFORE any source is touched -----------------------------
    // ⚠⚠ THIS DETAIL WAS REWRITTEN TWICE ON 2026-09-08 AND THE OLD SENTENCES ARE NOT REPEATED HERE,
    // because a refusal detail is RETURNED API TEXT and each one claimed more than this server can
    // keep. The first asserted the negative universally and across every tier, speaking for tiers
    // that do not exist yet and for code this package does not contain. The second narrowed it to
    // "this server (tier A) does not write into it" — still CATEGORICAL, and still false of what
    // the code does: this screen is LEXICAL (see `targetsArc`), and the fence's `PARENT_ALIAS`
    // catches the statically resolvable aliases, while three concurrent-writer races stay open and
    // named in the fence. A path reaching `Arc/` through a race is not refused by anything here.
    //
    // ⚠ SO THE SENTENCE DESCRIBES THE ACT RATHER THAN THE OUTCOME: it refuses what is ADDRESSED
    // into `Arc/` — spelled, or statically aliased below the grant root — which is exactly what it
    // does, and it makes no claim about what cannot arrive there by other means. A refusal detail
    // is the hardest place to walk a guarantee back from, because the caller reads it as the
    // contract.
    if (targetsArc(rawPath)) {
        return preConfigRefuse(scribeRefuse(
            'ARC_IMMUTABLE',
            'Arc/ is the provenance layer; this server refuses writes addressed into it'
        ));
    }

    /**
     * ---- 3. EVERY REFUSAL THIS REQUEST HAS ALREADY EARNED, decided before a source is read ------
     *
     * ⚠⚠ THE SAME ORACLE ARGUMENT AS THE `Arc/` SCREEN ABOVE, AND IT WAS ONLY HALF-APPLIED. The
     * header says the doctrine check runs first so a guaranteed refusal cannot report a source's
     * existence through its timing and reason. Two other guaranteed refusals were running AFTER the
     * whole source loop:
     *
     *   · THE COUNT CAPS. `checkCounts` ran on the assembled `sources`, so a request with 65
     *     entries read all 65 — every existence probe, every hash, every window loop — and then
     *     refused for a reason knowable from `derivedFrom.length` alone. An existing in-grant
     *     source and a missing one produced different reasons and visibly different timings for a
     *     request that could never have succeeded.
     *   · A MALFORMED SPAN. `{ }` is refused by `resolveSpan` on shape alone, but the shape was not
     *     consulted until after that entry's source had been read.
     *
     * So both are decided here, before `loadConfig` and before any read. What CANNOT move is
     * everything that needs the bytes — whether a range fits, whether a quote is present, unique or
     * aligned — and `spanShapeFault` draws exactly that line, as `resolveSpan`'s own first step
     * rather than as a second opinion about it.
     *
     * ⚠ THE COUNTS ARE CHECKED OVER THE REQUEST, NOT OVER THE RESOLVED SOURCES, and the two agree
     * because the loop below pushes exactly one `LineageSource` per entry and one span per span.
     * `checkCounts` is re-run there over the real records, unchanged — it is cheap, it is the check
     * the limits are actually about, and a bound proved twice over the same numbers costs nothing.
     *
     * ⚠ `requestedSpans` AND THE ENTRY COUNT ARE BOTH TAKEN FROM THE SNAPSHOT, not from a second
     * walk of the caller's arrays. The old shape re-read `view.derivedFrom` twice more here, so a
     * request could present 2 entries to the cap and 65 to the loop.
     */
    const counted = checkRequestCounts(snapshot.length, requestedSpans);
    if (counted) return preConfigRefuse(counted);

    /**
     * ⚠ THE PAGE PATH IS BOUNDED HERE FOR THE REASON THE COUNTS ARE — it is knowable from the
     * request's own shape, so a guaranteed refusal is decided before any source is read, existence
     * probed or timing leaked. It is folded as the ledger will spell it, because that is the string
     * whose bytes land in the line; bounding the raw request would bound a different value than the
     * one that consumes the budget.
     */
    const pathSize = checkPagePath(toLedgerPath(rawPath));
    if (pathSize) return preConfigRefuse(pathSize);

    /**
     * ⚠⚠ THE SPAN SHAPE IS CHECKED AND THE SPAN IS REBUILT IN THE SAME PASS, which is what carries
     * `span.ts`'s read-once rule across the `await` that follows. `spanShapeFault` reads each
     * supplied member exactly once and HANDS THE VALUES BACK for precisely this reason; passing the
     * caller's span object on to step 5's `resolveSpan` made the resolver call `spanShapeFault`
     * again, so an accessor fired a second time — after the config load and after the source read —
     * and could serve the resolver a different value than the one validated here. `snapshotSpan`
     * rebuilds the span from the members already read, so step 5 re-reads plain frozen data.
     */
    for (let index = 0; index < snapshot.length; index += 1) {
        const entry = snapshot[index] as DerivedFrom;
        const spans: SpanRequest[] = [];
        for (const spanRequest of entry.spans) {
            const shape = spanShapeFault(spanRequest);
            // ⚠ THE `SPAN_*` REFUSAL IS RETURNED AS-IS HERE TOO, for the reason the source loop
            // gives below: `span.ts` made `reason` and `where` name the member at fault, and a
            // caller must not get a different diagnostic depending on WHEN the fault was noticed.
            if ((shape as { ok?: unknown }).ok === false) return preConfigRefuse(shape as SpanRefusal);
            spans.push(snapshotSpan(shape as SpanMembers));
        }
        snapshot[index] = Object.freeze({ source: entry.source, spans: Object.freeze(spans) });
    }

    return new Validated(rawPath, rawContent, Object.freeze(snapshot));
}

/**
 * ⚠⚠ THE OUTER HALF IS THE **ONLY** SCOPE IN WHICH THIS MODULE HOLDS THE CALLER'S REQUEST OBJECT,
 * and that is the containment rather than a tidy split. (The caller's own option hooks may close
 * over that object and run downstream; they are the caller's, and outside what the split
 * contains.) Steps 4-9 live in `stampValidated` below, which takes a
 * `Validated` snapshot and has NO `request` parameter — so a downstream read of the caller's object
 * is not a discipline anyone has to remember, it is `TS2304: Cannot find name 'request'`. The same
 * argument the `preConfigRefuse` local makes about building a pre-config refusal: a name out of
 * scope is a compile error.
 *
 * ⚠⚠ THE DISCRIMINATION IS `instanceof`, NOT `ok === false`, AND THE OLD TEST WAS A LIVE DEFECT.
 * `isRefusalLike(checked)` read `.ok` through the prototype chain, so a request whose PROTOTYPE
 * carried `{ ok: false }` came back from `preflight` validated, was read HERE as a refusal, and was
 * returned to the caller as one — a refusal the caller minted, wearing this module's name. Asking
 * `checked instanceof Validated` puts the answer on a prototype this module owns and never exports,
 * which a caller cannot supply through inheritance or any other means. `isRefusalLike` stays where
 * it belongs, guarding the fence and Scribe results below — values returned by the `gate` and the
 * `appender`, which are injected dependencies. Reading `.ok` off those is trust in the dependency
 * the caller chose to inject, not a defence against the request; it was never meant as one.
 */
export async function writePage(
    request: WritePageRequest,
    options: WritePageOptions
): Promise<WritePageResult> {
    // ---- 1-3. every refusal knowable from the request alone, before any source or config ----
    // ⚠ `preflight` OWNS THESE STEPS AND OWNS THE ONLY `preConfigRefuse` IN THE MODULE. See its
    // note for why the helper is a local of it rather than a module-level function.
    const checked = preflight(request);
    if (!(checked instanceof Validated)) return checked;
    return stampValidated(checked, options);
}

async function stampValidated(
    checked: Validated,
    options: WritePageOptions
): Promise<WritePageResult> {
    const { gate, appender, version } = options;
    const now = options.now ?? (() => new Date());
    const newUuid = options.newUuid ?? randomUUID;
    const newEventId = options.newEventId ?? randomUUID;
    const cache = options.cache ?? new SourceCache();

    // ---- 4. the vault's config. THE CONFIG MAY BE CREATED HERE. --------------
    // ⚠⚠ THIS STEP CAN WRITE, AND IT IS THE ONLY WRITE THAT PRECEDES THE SOURCE LOOP. Part 3 hoists
    // `loadConfig`'s exclusive create ahead of its read, so an uninitialised vault gains
    // `.wyrd/scribe.json` here — before a single source has been read. What it does NOT create is
    // anything of the caller's; see the header for why that distinction carries the ordering claim.
    // ⚠ A SCRIBE-SHAPED REFUSAL FROM THE LOAD ITSELF CARRIES `false`, AND THAT IS NOT AN ASSUMPTION:
    // `loadConfig` returns a Scribe refusal only where the create did not succeed — the `.wyrd/`
    // probe, or an existing config that is unreadable or fails validation. In every one of those the
    // create either never ran or refused, so nothing was minted.
    // ⚠⚠ AND THE SENTENCE ABOVE WAS FALSE OF THE CODE UNTIL 2026-09-08, WHICH IS THE FINDING. The
    // refusal was returned BARE here, so the `SCRIBE_NOT_INITIALISED` and `SCRIBE_CONFIG_*` shapes
    // reached the caller with no `config_created` at all while the documentation two screens up
    // promised one. A comment asserting a field the return site does not set is the class this round
    // closes: the fix is at the return, not in the sentence.
    const loaded = await loadConfig(gate, newUuid);
    if (isRefusalLike(loaded)) {
        // ⚠ THE FENCE'S OWN REFUSALS PASS THROUGH UNCHANGED (D8) and are the ONE documented
        // exclusion; a Scribe refusal is re-frozen with the flag. `isScribeRefusal` reads the
        // fence's `resolvedPath`, which a Scribe refusal never carries — see `refusal.ts`.
        if (isScribeRefusal(loaded)) return stampRefuse(loaded, false);
        return loaded as FenceRefusal;
    }
    const config = loaded.config;
    // ⚠ THE FLAG TRAVELS ON EVERY SCRIBE-SHAPED OUTCOME FROM HERE DOWN, REFUSALS INCLUDED. A caller
    // told only "refused" cannot tell whether their vault was left exactly as they found it.
    const configCreated = loaded.created;

    // ---- 5. every source and every span. No PAGE has been written yet. -------
    const sources: LineageSource[] = [];
    for (const entry of checked.derivedFrom) {
        const source = await readSource(gate, entry.source, cache);
        // ⚠ THE SAME SPLIT AS THE CONFIG LOAD ABOVE, AND `SOURCE_CHANGED_DURING_READ` IS WHY IT
        // MATTERS HERE. That refusal is the Scribe's own and it fires AFTER step 4 may have minted
        // the config, so returning it bare — which this site did until 2026-09-08 — told a caller
        // nothing about a real, persistent change to their vault. The fence's refusals in the same
        // position stay unwrapped under D8.
        if (isRefusalLike(source)) {
            if (isScribeRefusal(source)) return stampRefuse(source, configCreated);
            return source as FenceRefusal;
        }

        const spans = [];
        for (const spanRequest of entry.spans) {
            const resolved = resolveSpan(source.bytes, spanRequest);
            // ⚠ A `SPAN_*` REFUSAL KEEPS ITS OWN `reason` AND `where`, not translated. `span.ts`
            // spent four gate rounds making them say exactly which member is at fault; re-wrapping
            // them into one Scribe reason would discard the diagnostic that work produced.
            // ⚠⚠ IT GAINS `config_created` AND NOTHING ELSE, ADDED 2026-09-08. This refusal is
            // Scribe-originated and fires at step 5, after step 4 may have minted the config — so
            // the rule at `WritePageResult` binds it exactly as it binds every other own shape, and
            // the previous exemption (see `StampRefusal`) had the module boundary in the wrong place.
            if (!resolved.ok) return stampSpanRefuse(resolved, configCreated);
            spans.push(lineageSpan(resolved));
        }

        sources.push(Object.freeze({
            identity: identity(config.vault_id, source.rel),
            content: contentHash(source.digest, source.size),
            spans: Object.freeze(spans)
        }));
    }

    const counts = checkCounts(sources);
    if (counts) return stampRefuse(counts, configCreated);

    /**
     * ---- 6. build and size-check the record. STILL NO PAGE, and the config may exist. ---------
     *
     * ⚠⚠ THIS HEADING SAID "Still nothing written" UNTIL 2026-09-08 AND THAT WAS THE WRONG SUBJECT.
     * Step 4 above can have created `.wyrd/scribe.json` before control reaches here. What is still
     * true AT THIS LINE, and is the property the ordering buys, is that NO PAGE exists: not one byte
     * of caller-supplied content has been written yet. `config_created` is what tells the caller
     * about the other half.
     *
     * ⚠⚠ AND THE SENTENCE THAT FOLLOWED IT — "every refusal below this line leaves the caller's own
     * material untouched" — WAS FALSE, RETRACTED 2026-09-08. Two refusals below this line occur
     * AFTER step 8 has created the page: the final ledger-line size check at step 9, and the append
     * failure after it. Both return over a page that is already on disk (`PAGE_WRITTEN_LEDGER_FAILED`
     * carries the `Created` for exactly that reason), and neither is rolled back. The true scope is
     * this line down to step 8, not this line down to the end of the function.
     *
     * ⚠ THE TARGET'S LEDGER PATH IS THE REQUEST, FOLDED — NOT the fence's `rel`, because the fence
     * has not resolved it yet and will not until the create. That is a real difference: a request
     * reaching the target through an in-grant junction resolves to a canonical `rel` the record
     * would otherwise not carry. So the record is REBUILT from `created.rel` after step 8, and this
     * first build exists to prove the line SERIALISES within its bounds before anything is created,
     * and to fix the values the final record reuses (the frontmatter projection, the event id and
     * the time). Reusing it WHOLE would record the request's spelling as the identity.
     *
     * ⚠⚠ THE PLACEHOLDERS ARE THE WIDEST VALUES THEIR FIELDS CAN EVER HOLD, AND THE NARROW ONES
     * WERE A LIVE DEFECT. `bytes: 0` is one character where a real byte count can be sixteen, so a
     * draft landing within a few bytes of the ceiling PASSED this check, the page was CREATED, and
     * the final check then failed the line — returning `PAGE_WRITTEN_LEDGER_FAILED` with a
     * fabricated `IO_ERROR` cause for what was really `LINEAGE_LINE_TOO_LARGE`. A caller was told a
     * page had been written and its provenance lost to an I/O failure, when in fact the request was
     * over a documented bound and nothing should have been created at all.
     *
     * The digest is fixed-width at 64 hex characters, so `'0'.repeat(64)` is already exact. The
     * byte count is not, so it is `Number.MAX_SAFE_INTEGER` — the widest number `JSON.stringify`
     * can emit for this field, and wider than any file this process can hash. The canonical path is
     * the remaining variable-width member and it is handled by the re-check below, which stays.
     */
    const draft = buildRecord({
        version,
        eventId: newEventId(),
        recordedAt: now().toISOString(),
        vaultId: config.vault_id,
        pagePath: toLedgerPath(checked.path),
        pageContent: contentHash('0'.repeat(64), Number.MAX_SAFE_INTEGER),
        sources
    });
    const draftSize = checkLineSize(serialiseRecord(draft));
    if (draftSize) return stampRefuse(draftSize, configCreated);

    // ---- 7. compose the page bytes ------------------------------------------
    let pageText = checked.content;
    if (config.write_frontmatter) {
        const stamped = stampFrontmatter(checked.content, project(draft));
        if (typeof stamped !== 'string') return stampRefuse(stamped, configCreated);
        pageText = stamped;
    }
    const pageBytes = Buffer.from(pageText, 'utf8');
    const pageDigest = hashText(pageBytes);

    // ---- 8. create the page. THIS is the first write OF CALLER-SUPPLIED CONTENT. --------------
    // ⚠⚠ THIS SAID "THIS is the first write" UNTIL 2026-09-08 AND IT IS NO LONGER THE FIRST WRITE
    // OF ANYTHING. Step 4 can have created the vault's own `.wyrd/scribe.json` before any source
    // was read. It IS the first write of the caller's bytes, which is the claim the whole step
    // ordering above is built to protect, so the sentence is narrowed to it rather than dropped.
    const created = await gate.createFileInGrant(checked.path, pageBytes);
    // ⚠ `EXISTS` IS TIER A'S "PATH EXISTS" RULE ARRIVING FROM THE FENCE FOR FREE, and taking it
    // from there rather than pre-checking is the whole point: a pre-check is a TOCTOU window, while
    // the `wx` open refuses atomically against anything that appears in between.
    if (isRefusalLike(created)) return created as FenceRefusal;

    // ---- 9. the ledger line, over the CANONICAL path -------------------------
    // ⚠ THE SAME `event_id` AS THE DRAFT, AND THEREFORE THE SAME ONE THE PAGE CARRIES. Minting a
    // second here would give one write two event identities and break the only join between the
    // stamped page and its ledger line — the field would then be worse than absent, because it
    // would look like a key and match nothing.
    const record = buildRecord({
        version,
        eventId: draft.event_id,
        recordedAt: draft.recorded_at,
        vaultId: config.vault_id,
        pagePath: toLedgerPath(created.rel),
        pageContent: contentHash(pageDigest, pageBytes.length),
        sources
    });
    const line = serialiseRecord(record);
    /**
     * ⚠⚠ A LIVE CHECK THAT REALLY TRIPS, AND THIS NOTE CLAIMED THE OPPOSITE UNTIL 2026-09-08. The
     * retired wording called it "a defensive assertion that can no longer trip" and argued that
     * because the draft's placeholders are the WIDEST values their fields can hold, "a draft that
     * passed guarantees this line passes: only the canonical path can differ." **The last clause is
     * what fails.** The canonical path differing is not a null case — `created.rel` can be
     * materially WIDER in bytes than the request, because `_parentIsAliased` compares FOLDED and
     * `toLowerCase()` maps the Kelvin sign `K` (three UTF-8 bytes) to `k` (one). So two spellings
     * fold equal, are accepted as the same directory by design, and differ by two bytes per
     * character. `ST41` drives exactly that and reaches this branch deterministically.
     *
     * The placeholder widening is still worth having — it moved the ORDINARY over-size request to
     * the draft, where no page is created — but it bounds only the fields it replaced, and the
     * canonical path is not one of them. `MAX_PAGE_PATH_BYTES` bounds the REQUEST's spelling, which
     * is a different string from the one measured here.
     *
     * ⚠⚠ SO THE COST IS REAL AND IS NAMED RATHER THAN DESIGNED AWAY: by the time control reaches
     * here the page EXISTS, so a refusal at this line reports `PAGE_WRITTEN_LEDGER_FAILED` over a
     * page already on disk with no ledger line — an ORPHAN, which nothing rolls back (see the
     * header's no-rollback ruling). `ST41` asserts the orphan page PRESENT on purpose. The ordinary
     * `LINEAGE_LINE_TOO_LARGE` is still decided at the draft, before anything is created; this is
     * the residual the draft cannot reach.
     *
     * ⚠⚠ THE CAUSE IS THE SCRIBE'S OWN REFUSAL, NOT A FABRICATED `IO_ERROR`. This site used to
     * invent a fence-shaped `IO_ERROR` because `LedgerFailed.cause` was typed `FenceRefusal` and
     * nothing honest fit — so a caller over a documented bound was told a filesystem error had
     * lost their provenance, which is a different problem with a different repair. `checkLineSize`
     * already returns the exact refusal, carrying the measured byte count and the ceiling, so it
     * is passed through UNCHANGED. **The orphan page is not fixed by this and is not claimed to
     * be** — the page still exists with no lineage line. What changes is that the caller is told
     * why, and `MAX_PAGE_PATH_BYTES` below now bounds the field that can put them here.
     */
    const finalSize = checkLineSize(line);
    if (finalSize) return ledgerFailed(created, finalSize, configCreated);

    const appended = await appender.appendLine(line);
    if (isRefusalLike(appended)) return ledgerFailed(created, appended as FenceRefusal, configCreated);

    return Object.freeze({
        ok: true as const,
        created,
        record,
        appended: (appended as { bytes: number }).bytes,
        config_created: configCreated
    });
}

/**
 * A Scribe-originated refusal, re-frozen with the invocation's outer summary.
 *
 * ⚠ THE INPUT IS NOT MUTATED. `scribeRefuse` freezes what it returns, and the checkers upstream
 * (`checkCounts`, `checkLineSize`, the frontmatter stamp) hand back frozen values that other code
 * may hold; a copy is the only way to add the field without reaching into someone else's object.
 */
function stampRefuse(refusal: ScribeRefusal, configCreated: boolean): StampRefusal {
    return Object.freeze({
        ok: false as const,
        reason: refusal.reason,
        detail: refusal.detail,
        config_created: configCreated
    });
}

/**
 * A `SPAN_*` refusal from step 5, re-frozen with the outer summary.
 *
 * ⚠ THE INPUT IS NOT MUTATED, for the reason `stampRefuse` gives: `span.ts` freezes what it returns
 * and the resolver's value may be held elsewhere. ⚠ AND THE COPY IS MEMBER-BY-MEMBER RATHER THAN A
 * SPREAD, so this function can never widen the envelope by more than the one documented key — a
 * spread would carry through anything a future `span.ts` added, silently, which is the failure the
 * own-key assertions exist to catch.
 */
function stampSpanRefuse(refusal: SpanRefusal, configCreated: boolean): StampSpanRefusal {
    return Object.freeze({
        ok: false as const,
        reason: refusal.reason,
        where: refusal.where,
        config_created: configCreated
    });
}

function ledgerFailed(
    created: Created,
    cause: FenceRefusal | ScribeRefusal,
    configCreated: boolean
): LedgerFailed {
    return Object.freeze({
        ok: false as const,
        reason: 'PAGE_WRITTEN_LEDGER_FAILED' as const,
        detail: 'the page was created and its lineage line was NOT appended; the page is not removed',
        created,
        cause,
        config_created: configCreated
    });
}

function buildRecord(parts: {
    version: string;
    eventId: string;
    recordedAt: string;
    vaultId: string;
    pagePath: string;
    pageContent: LineageRecord['page']['content'];
    sources: readonly LineageSource[];
}): LineageRecord {
    return Object.freeze({
        schema: LINEAGE_SCHEMA,
        event: 'page_written' as const,
        // ⚠ SERVER-GENERATED, AND THERE IS NO CALLER-SUPPLIED ACTOR FIELD ANYWHERE IN THIS RECORD.
        // MCP over stdio supplies no authenticated caller, so an `actor` would be an unauthenticated
        // assertion written permanently into a provenance ledger as if it were fact — which is worse
        // than recording nothing, because a reader cannot tell the two apart. `event_id` is minted
        // under the same rule and for the same reason.
        event_id: parts.eventId,
        recorded_at: parts.recordedAt,
        writer: Object.freeze({
            server: 'wyrd-scribe' as const,
            version: parts.version,
            tool: 'write_page' as const
        }),
        vault: Object.freeze({ kind: 'uuid' as const, id: parts.vaultId }),
        page: Object.freeze({
            identity: identity(parts.vaultId, parts.pagePath),
            content: parts.pageContent
        }),
        sources: Object.freeze([...parts.sources])
    });
}
