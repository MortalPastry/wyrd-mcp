/**
 * B2 — THE OPT-IN FRONTMATTER STAMP. Line-based, and it REFUSES rather than merging.
 *
 * ⚠⚠ NO YAML PARSER AND NO AST MERGE, AND THAT IS A SECURITY DECISION RATHER THAN A DEPENDENCY ONE.
 * Parsing a stranger's frontmatter means running a YAML parser over untrusted text on the write
 * path — YAML's own history of anchor-expansion and tag-resolution defects is why that is not a
 * free operation — and then RE-EMITTING their document from an AST, which rewrites quoting,
 * ordering, comments and anchors in a file the user did not ask us to reformat. D3's justification
 * for writing into someone else's notes is that the act is benign and disclosed; silently
 * reserialising their frontmatter is neither.
 *
 * So this module does the smallest thing that can be correct: it finds the block's boundary LINES
 * and inserts ONE line. Anything it cannot do that way it REFUSES.
 *
 * ⚠⚠ THE PROJECTION CARRIES NO `page` KEY AT ALL, AND THE FULL REASON IS WORTH THE PARAGRAPH,
 * because the shape it replaces looked correct and was measurably wrong.
 *
 * It used to omit `page.content` and keep `page.identity`, on the argument that only the DIGEST is
 * self-referential: the frontmatter becomes part of the page bytes, so a projection containing the
 * page's own digest would have to be computed from bytes that do not exist until it is inserted.
 * That argument is sound and it does not go far enough — the IDENTITY is unrecordable here for a
 * different reason, and the two together leave nothing of `page` behind.
 *
 * The projection is built from the DRAFT record, whose page path is the CALLER'S SPELLING, because
 * the fence has not resolved the target yet and will not until the create. The ledger line is
 * rebuilt afterwards from the fence's canonical `created.rel`. So a write through an in-grant
 * junction — `Alias/answer.md` resolving to `Mage/answer.md` — put `Alias/answer.md` in the page
 * and `Mage/answer.md` in the ledger: TWO PROVENANCE RECORDS FOR ONE WRITE, DISAGREEING ABOUT WHICH
 * PAGE THIS IS. A reader with both cannot tell which is the page's identity, and the one embedded
 * in the bytes is the one that travels with the file.
 *
 * The fix is not to defer the projection until the canonical path is known — that would mean
 * composing the page bytes after creating the page, which inverts the ordering `stamp.ts`'s header
 * spends its length defending. It is that A PAGE DOES NOT NEED TO NAME ITSELF INSIDE ITSELF. The
 * projection's job is to carry the SOURCES — their identities, hashes and spans — plus the schema
 * and vault fields that make those readable. Page identity has exactly one home, the ledger, which
 * is where the canonical path is known and where a consumer already looks for it.
 *
 * ⚠ ONE KEY, `wyrd_lineage`, HOLDING SINGLE-LINE JSON. JSON is a subset of YAML 1.2, so a flow-style
 * value on one line parses under any conformant reader without this module emitting block scalars,
 * indentation or line folding — three things a hand-rolled emitter gets wrong and a diff makes
 * unreadable. It also keeps the insertion to exactly one line, which is what makes the "find the
 * closing fence and insert above it" rule sound.
 */

import type { AnyLineageRecord } from './lineage.js';
import type { ScribeRefusal } from './refusal.js';
import { scribeRefuse } from './refusal.js';

export const FRONTMATTER_KEY = 'wyrd_lineage';

/**
 * How far in we look for the closing `---`.
 *
 * ⚠ A BOUND, NOT A GUESS AT REAL DOCUMENTS. Without one, content that merely OPENS with `---` and
 * never closes makes this scan the whole file to decide it has no frontmatter — an unbounded read
 * of caller-supplied bytes on the write path, for a question about the document's first few lines.
 * A block longer than this refuses; it does not get treated as absent, because treating it as
 * absent would PREPEND a second block and produce a document with two.
 */
export const MAX_FRONTMATTER_LINES = 200;

/**
 * The record as it appears in the page: the SOURCES, and the fields that make them readable.
 *
 * ⚠ NO `page` MEMBER, AND ITS ABSENCE IS THE TYPE ENFORCING THE RULE ABOVE — a later session that
 * decides the page should name itself has to widen this interface deliberately rather than by
 * adding a line to `project`.
 */
export interface FrontmatterProjection {
    readonly schema: string;
    readonly event: string;
    readonly event_id: string;
    readonly recorded_at: string;
    readonly writer: AnyLineageRecord['writer'];
    readonly vault: AnyLineageRecord['vault'];
    readonly sources: AnyLineageRecord['sources'];
}

/**
 * ⚠ `event_id` IS CARRIED AND THE PAGE PATH IS NOT, WHICH IS THE ASYMMETRY WORTH NAMING. The id is
 * the one field that JOINS this projection to its ledger line — without it a reader holding a
 * stamped page and a ledger of many lines has only the timestamp to match on, and `ST29` exists
 * because a timestamp does not distinguish two writes. It is server-minted per write, so it says
 * nothing about the path and cannot disagree with the fence about anything.
 */
export function project(record: AnyLineageRecord): FrontmatterProjection {
    return {
        schema: record.schema,
        event: record.event,
        event_id: record.event_id,
        recorded_at: record.recorded_at,
        writer: record.writer,
        vault: record.vault,
        sources: record.sources
    };
}

/**
 * ⚠⚠ THE LINE SCAN IS OVER `\n` AND TOLERATES `\r`, because a document authored on Windows has
 * CRLF endings and a scan that only knows `\n` sees the closing fence as `"---\r"`, fails to match
 * it, and refuses `FRONTMATTER_INVALID` on a perfectly ordinary file. Trimming only the trailing
 * `\r` — never other whitespace — keeps the match exact in every other respect: ` ---` is NOT a
 * fence in YAML and must not be treated as one.
 */
function isFence(line: string): boolean {
    return (line.endsWith('\r') ? line.slice(0, -1) : line) === '---';
}

/**
 * The key a mapping line declares, or `null` if the line declares none AT THE TOP LEVEL.
 *
 * ⚠⚠ THE INDENTATION TEST IS THE ONLY THING SEPARATING A TOP-LEVEL KEY FROM A NESTED ONE, AND IT
 * HAD TO BE MADE SO. The first version sliced the key WITHOUT trimming, so an indented
 * `  wyrd_lineage:` yielded the string `"  wyrd_lineage"`, which never equalled the key anyway —
 * two guards where one was doing the work, and the mutation matrix measured exactly that: removing
 * the indentation test left the suite green (`M14`, a real survivor). The name is trimmed first now,
 * so the test is load-bearing and the mutant dies. A guard that is masked by an incidental
 * mismatch is a guard nothing is checking.
 */
function keyOf(line: string): string | null {
    const body = line.endsWith('\r') ? line.slice(0, -1) : line;
    // ⚠ Only a TOP-LEVEL key counts for the conflict check: an indented `wyrd_lineage:` is a member
    // of someone else's mapping and is not ours to collide with. A leading space disqualifies it.
    if (/^\s/.test(body)) return null;
    const colon = body.indexOf(':');
    if (colon <= 0) return null;
    return unquote(body.slice(0, colon).trim());
}

/**
 * ⚠⚠ `"wyrd_lineage"`, `'wyrd_lineage'` AND `wyrd_lineage` ARE ONE KEY IN YAML, AND UNTIL THIS
 * EXISTED THE CONFLICT CHECK SAW THREE. MEASURED 2026-09-03, not reasoned: stamping a page whose
 * frontmatter carried `"wyrd_lineage": {...}` did not refuse — it WROTE, leaving a document with
 * TWO top-level `wyrd_lineage` keys. That is invalid YAML, and the ordinary parser response is to
 * take one and silently drop the other, so the user's existing provenance record is destroyed
 * without a refusal, an error, or a visible mark. `FRONTMATTER_CONFLICT` exists for exactly that
 * case and was being routed around by a quote character.
 *
 * ⚠ IT STRIPS A MATCHED PAIR AND NOTHING MORE, AND THE NARROWNESS IS THE DESIGN. This module's
 * founding rule is that it does not run a YAML parser over a stranger's frontmatter on the write
 * path, so full scalar semantics — escape sequences, multi-line keys, flow keys — are deliberately
 * NOT handled here. What is handled is the spelling a stamp or a person actually produces.
 *
 * ⚠ THE FAILURE DIRECTION IS THE SAFE ONE EITHER WAY. An exotic spelling this does not recognise
 * falls back to today's behaviour, which is the bug and no worse than it. There is no spelling on
 * which this makes the module refuse a document it should have written: an unmatched or absent
 * quote returns the name unchanged.
 */
function unquote(name: string): string {
    if (name.length < 2) return name;
    const first = name[0];
    if ((first === '"' || first === "'") && name.endsWith(first)) {
        return name.slice(1, -1);
    }
    return name;
}

/**
 * ⚠⚠ A FIRST-LINE `---` IS NOT ENOUGH TO CALL SOMETHING FRONTMATTER, and the version that believed
 * it was mishandled ordinary documents in two directions.
 *
 * A Markdown document may legitimately OPEN with a horizontal rule. Under the old rule that first
 * line was an opening fence, so:
 *
 *   · a document opening with a rule and then prose was refused `FRONTMATTER_INVALID` — a
 *     perfectly ordinary file the user could never write through this server, with a message
 *     saying their frontmatter had no closing fence when they had written no frontmatter at all;
 *   · a document with a SECOND rule within the 200-line ceiling was worse, because it succeeded:
 *     the key was inserted between two horizontal rules, in the middle of the user's prose, as if
 *     the span between them had been a mapping.
 *
 * So the block between the fences must LOOK like YAML mapping lines. Every non-blank line is either
 * `key:`-shaped at column 0, a `#` comment, or an indented continuation of the line above. Prose
 * fails all three, and a document whose first line is a rule is then correctly treated as having no
 * frontmatter — it gets a block PREPENDED, which is the outcome the user wanted.
 *
 * ⚠ THIS IS A RECOGNISER, NOT A YAML PARSER, AND THE DISTINCTION IS THE MODULE'S WHOLE DESIGN. It
 * decides one question — does this look like a mapping block? — from line shapes alone, and it
 * still never parses, never builds an AST and never re-emits. The header's argument against running
 * a YAML parser over untrusted text on the write path is untouched.
 *
 * ⚠ IT ERRS TOWARD "NOT FRONTMATTER". A block this rejects is PREPENDED to rather than inserted
 * into, so the failure mode of a false negative is a document with a stamp block above a rule —
 * visible, correct YAML, and nothing of the user's rewritten. A false POSITIVE is the defect above:
 * a key spliced into prose.
 */
function looksLikeMapping(lines: readonly string[], from: number, to: number): boolean {
    for (let index = from; index < to; index += 1) {
        const raw = lines[index] as string;
        const body = raw.endsWith('\r') ? raw.slice(0, -1) : raw;
        if (body.trim().length === 0) continue;
        // An indented line continues whatever came before it — a nested mapping, a sequence member,
        // a folded scalar. Its own shape is not this recogniser's business.
        if (/^\s/.test(body)) continue;
        if (body.startsWith('#')) continue;
        // ⚠ A KEY AT COLUMN 0, WITH THE COLON REQUIRED. `keyOf` already encodes exactly this shape
        // for the conflict check, so it is reused rather than re-expressed — two spellings of "what
        // is a top-level key" would be two things to keep in step.
        if (keyOf(body) !== null) continue;
        return false;
    }
    return true;
}

/**
 * The document's line ending, decided from the OPENING FENCE rather than from a scan.
 *
 * ⚠ A CRLF DOCUMENT MUST GET A CRLF KEY LINE. Inserting a lone LF into a file whose every other
 * line ends CRLF produces a document with mixed endings — which git will report as a whole-file
 * change on the next normalisation, and which some Windows editors render as one run-on line. The
 * fence we are inserting above is the nearest evidence of what this document does, and it is the
 * line our insertion sits against.
 */
function endingOf(line: string): string {
    return line.endsWith('\r') ? '\r' : '';
}

/**
 * ⚠⚠ THE PREPENDED BLOCK'S ENDING, AND EVERY PREPEND EXIT GOES THROUGH HERE. Three call sites
 * used to build `` `---\n${keyLine}\n---\n${content}` `` inline, which put THREE lone LFs into a
 * CRLF document — measured 2026-09-03 on all three, against the compiled build. That is the
 * mixed-ending file `endingOf` exists to prevent, arrived at through the one path that had no
 * fence to read: a prepend happens precisely when the document has no frontmatter block.
 *
 * ⚠ THE BLOCK HAS THREE SEPARATORS AND ALL THREE MATTER — after the opening fence, after the key
 * line, and BETWEEN THE CLOSING FENCE AND THE USER'S FIRST LINE. A fix that changed only the ones
 * inside the block would still leave a lone LF at the seam, which is the byte that actually abuts
 * the user's text. That is why this returns the whole string rather than an ending to interpolate.
 *
 * ⚠ THE RULE IS THE FIRST PHYSICAL LINE'S ENDING, NOT A DOCUMENT-WIDE SURVEY, and the narrowness
 * is the design. Our block touches the document at exactly one seam — above its first line — so
 * that line is the only nearby evidence, and it is the same shape of rule the splice path already
 * follows (take the ending from the line you are inserting against). A majority or last-ending
 * heuristic would invent a global policy for a document that is already inconsistent, and would
 * disagree with the splice path on that document — one module with two rules.
 *
 * ⚠ AN ALREADY-MIXED DOCUMENT STAYS MIXED, DELIBERATELY. We did not cause it, and this module's
 * justification for writing into someone else's notes is that the act is minimal and disclosed;
 * normalising their line endings is neither. Not one byte of `content` is rewritten here.
 *
 * ⚠ NO BREAK AT ALL — an empty document, or a single unterminated line — HAS NO STYLE TO PRESERVE,
 * so it takes LF. Bare-CR (classic Mac) documents are out of scope and stay that way: `split('\n')`
 * does not see them as multi-line anywhere in this module.
 */
function prepended(keyLine: string, content: string): string {
    const firstBreak = content.indexOf('\n');
    const eol = firstBreak > 0 && content[firstBreak - 1] === '\r' ? '\r\n' : '\n';
    return `---${eol}${keyLine}${eol}---${eol}${content}`;
}

/**
 * Insert the stamp, or refuse.
 *
 * `content` is the caller's page text; the return carries the bytes to write.
 */
export function stamp(content: string, projection: FrontmatterProjection): string | ScribeRefusal {
    const value = JSON.stringify(projection);
    const keyLine = `${FRONTMATTER_KEY}: ${value}`;

    // ⚠ THE OPENING FENCE MUST BE THE FIRST LINE, with nothing before it — not even a blank line.
    // A `---` further down is a horizontal rule or a document separator in the body, and prepending
    // a block above it is correct; treating it as an opening fence would insert our key into the
    // middle of the user's prose.
    const lines = content.split('\n');
    const opens = lines.length > 0 && isFence(lines[0] as string);

    if (!opens) {
        return prepended(keyLine, content);
    }

    const ceiling = Math.min(lines.length, MAX_FRONTMATTER_LINES);
    for (let index = 1; index < ceiling; index += 1) {
        const line = lines[index] as string;
        if (isFence(line)) {
            /**
             * ⚠⚠ THE BLOCK IS RECOGNISED BEFORE IT IS WRITTEN INTO, AND A BLOCK THAT IS NOT A
             * MAPPING IS NOT FRONTMATTER AT ALL. A pair of fences around PROSE is two horizontal
             * rules, and splicing a key between them puts YAML into the middle of the user's
             * document — the defect this check exists for.
             *
             * ⚠ SO IT PREPENDS RATHER THAN REFUSING, and the choice is the whole point. Refusing
             * would leave an ordinary Markdown file — a rule, some prose, another rule —
             * permanently unwritable through this server, which is the OTHER half of the same
             * defect rather than an improvement on it. Treating the document as having no
             * frontmatter is both true and useful: it gets a block on top and not one byte of the
             * user's own text moves.
             *
             * ⚠ IT IS THE SAME ANSWER THE NO-CLOSING-FENCE PATH BELOW GIVES FOR THE SAME SHAPE,
             * deliberately. One question — is this a mapping block? — with one answer, rather than
             * two outcomes hanging on whether a second rule happened to fall inside the ceiling.
             */
            if (!looksLikeMapping(lines, 1, index)) {
                return prepended(keyLine, content);
            }
            // ⚠ THE KEY LINE MATCHES THE DOCUMENT'S OWN ENDING, taken from the closing fence it is
            // inserted above. A lone LF in a CRLF document is a mixed-ending file.
            const spliced = [...lines.slice(0, index), keyLine + endingOf(line), ...lines.slice(index)];
            return spliced.join('\n');
        }
        if (keyOf(line) === FRONTMATTER_KEY) {
            // ⚠ THE CONFLICT REFUSES; IT DOES NOT OVERWRITE. The existing value may be a previous
            // stamp or may be the user's own key — this module cannot tell, and replacing either
            // one destroys information the caller never offered up. Refusing is the only outcome
            // that is right in both readings.
            return scribeRefuse(
                'FRONTMATTER_CONFLICT',
                `the page already carries a top-level ${FRONTMATTER_KEY} key`
            );
        }
    }

    /**
     * No closing fence within the ceiling.
     *
     * ⚠⚠ AND THE MAPPING TEST DECIDES WHICH FAILURE THIS IS, which is the second half of the
     * horizontal-rule fix. If what follows the first line reads as a mapping, this really is an
     * unclosed frontmatter block and it REFUSES — prepending a second block would hand back a
     * document with two, which is why the ceiling refuses rather than falling through.
     *
     * If it does NOT read as a mapping, the first line was a horizontal rule and this document has
     * no frontmatter at all. It gets a block prepended, exactly as a document opening with prose
     * would. The old code refused here, which made an ordinary Markdown file — a rule, then prose —
     * permanently unwritable through this server, with a message about a closing fence the user had
     * no reason to think they owed.
     */
    if (!looksLikeMapping(lines, 1, ceiling)) {
        return prepended(keyLine, content);
    }

    return scribeRefuse(
        'FRONTMATTER_INVALID',
        `the page opens a frontmatter block with no closing --- within ${MAX_FRONTMATTER_LINES} lines`
    );
}

/** Replace only a line in the form this server generates; leave every other byte alone. */
export function stampOverwrite(content: string, projection: FrontmatterProjection): string | ScribeRefusal {
    const lines = content.split('\n');
    if (!isFence(lines[0] ?? '')) return stamp(content, projection);
    const ceiling = Math.min(lines.length, MAX_FRONTMATTER_LINES);
    let closing = -1;
    for (let index = 1; index < ceiling; index += 1) {
        if (isFence(lines[index] as string)) { closing = index; break; }
    }
    const matches: number[] = [];
    for (let index = 1; index < (closing < 0 ? ceiling : closing); index += 1) {
        const line = lines[index] as string;
        const body = line.endsWith('\r') ? line.slice(0, -1) : line;
        if (keyOf(line) === FRONTMATTER_KEY || /^wyrd_lineage(?:\s|$)/.test(body)) matches.push(index);
    }
    if (matches.length > 1) return scribeRefuse('FRONTMATTER_CONFLICT', 'the page carries duplicate top-level wyrd_lineage keys');
    if (closing < 0 || !looksLikeMapping(lines, 1, closing)) {
        if (matches.length > 0) return scribeRefuse('FRONTMATTER_INVALID', 'the existing wyrd_lineage block is malformed');
        return stamp(content, projection);
    }
    if (matches.length === 0) return stamp(content, projection);

    const index = matches[0] as number;
    const old = lines[index] as string;
    const body = old.endsWith('\r') ? old.slice(0, -1) : old;
    if (!body.startsWith(`${FRONTMATTER_KEY}: `)) {
        return scribeRefuse('FRONTMATTER_CONFLICT', 'the existing wyrd_lineage line is not in generated form');
    }
    let value: unknown;
    try { value = JSON.parse(body.slice(FRONTMATTER_KEY.length + 2)); }
    catch { return scribeRefuse('FRONTMATTER_INVALID', 'the existing wyrd_lineage value is malformed'); }
    const candidate = value as Partial<FrontmatterProjection> | null;
    const writer = candidate?.writer;
    const vault = candidate?.vault;
    if (typeof value !== 'object' || value === null || Array.isArray(value)
        || Object.keys(value).join(',') !== 'schema,event,event_id,recorded_at,writer,vault,sources'
        || candidate?.schema !== 'wyrd.lineage/v1'
        || (candidate.event !== 'page_written' && candidate.event !== 'page_overwritten')
        || typeof candidate.event_id !== 'string' || typeof candidate.recorded_at !== 'string'
        || typeof writer !== 'object' || writer === null
        || Object.keys(writer).join(',') !== 'server,version,tool'
        || writer.server !== 'wyrd-scribe' || typeof writer.version !== 'string'
        || (writer.tool !== 'write_page' && writer.tool !== 'overwrite_page')
        || typeof vault !== 'object' || vault === null
        || Object.keys(vault).join(',') !== 'kind,id'
        || vault.kind !== 'uuid' || typeof vault.id !== 'string'
        || !Array.isArray(candidate.sources)) {
        return scribeRefuse('FRONTMATTER_CONFLICT', 'the existing wyrd_lineage value is not in generated form');
    }
    lines[index] = `${FRONTMATTER_KEY}: ${JSON.stringify(projection)}${endingOf(old)}`;
    return lines.join('\n');
}
