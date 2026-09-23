/**
 * THE VAULT'S OWN CONFIG — `.wyrd/scribe.json`, read through the gate, never through `fs`.
 *
 * B2 rules frontmatter opt-in is PER-VAULT rather than per-call, so the answer to "does this vault
 * carry visible lineage?" is a fact about the vault. That makes this file the vault's, not the
 * server's, and the vault identity it carries is what the 2026-08-31 identity block requires on
 * every lineage identity so a record that travels between Mages stays unambiguous.
 *
 * ⚠⚠ `.wyrd/` MUST ALREADY EXIST, AND THE SCRIBE WILL NOT CREATE IT. The fence's
 * `createFileInGrant` requires an existing parent and the fence has no mkdir — deliberately, since
 * a directory-creating primitive is a second write shape to get right. The alternative to refusing
 * would be the Scribe mutating a stranger's vault merely by starting, which is the thing D7's
 * whole tier design exists to keep the user in charge of. So an absent `.wyrd/` refuses and NAMES
 * the directory to create.
 *
 * ⚠ NOTHING IS CACHED ACROSS CALLS. The config is one small read behind a gate that already
 * resolves the path; a cache would make "which vault am I writing to?" a question about process
 * history rather than about the vault, and the answer would go stale exactly when someone edits it.
 * The SOURCE cache in `source.ts` is a different trade — it exists because sources are transcripts.
 */

import { isRefusal } from 'wyrd-fence';
import type { FenceRefusal, FsGate, Slice } from 'wyrd-fence';

import type { ScribeRefusal } from './refusal.js';
import { scribeRefuse } from './refusal.js';

/** The directory the config lives in, grant-relative. Named in the refusal so the user can act. */
export const WYRD_DIR = '.wyrd';
export const CONFIG_PATH = '.wyrd/scribe.json';
export const LINEAGE_PATH = '.wyrd/lineage.jsonl';

export const CONFIG_SCHEMA = 'wyrd.scribe/v1';

/** The ceiling: a config LARGER than this many bytes refuses `SCRIBE_CONFIG_TOO_LARGE`. */
export const CONFIG_CEILING = 16_384;

/**
 * ⚠ ONE BYTE OVER THE CEILING, NOT AT IT. A read of exactly the ceiling cannot distinguish "the
 * file is exactly 16,384 bytes" from "the file is larger and this is the first window"; asking for
 * one more byte makes `truncated` the answer to that question rather than an inference.
 *
 * ⚠⚠ AND `truncated` ALONE DID NOT ENFORCE THE CEILING, WHICH A ROUND-5 LENS PROBED LIVE ON
 * 2026-09-08: a file of EXACTLY 16,385 bytes fits the window whole, so the gate reports
 * `truncated: false` and the file was accepted one byte past the documented ceiling. `readSlice`
 * therefore asks both questions — the gate's `truncated`, and `size > CONFIG_CEILING` — and `ST4`
 * pins both edges by exact byte count (`M28` deletes the size clause).
 */
export const CONFIG_READ_LIMIT = CONFIG_CEILING + 1;

export interface ScribeConfig {
    readonly schema: typeof CONFIG_SCHEMA;
    readonly vault_id: string;
    readonly write_frontmatter: boolean;
}

/** Exactly these three keys. An unknown key REFUSES rather than being ignored — see below. */
const CONFIG_KEYS: ReadonlySet<string> = new Set(['schema', 'vault_id', 'write_frontmatter']);

/**
 * ⚠ UUID v4, MATCHED STRICTLY. A loose match ("any 36-char string with dashes") would admit a
 * vault id minted by something other than this code path, and the identity block's whole point is
 * that a lineage record travelling between Mages is unambiguous. A shape that admits anything is
 * not an identity scheme.
 */
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/**
 * ⚠ THE FENCE'S OWN `isRefusal` IS IMPORTED ABOVE RATHER THAN RE-DECLARED HERE — spec D8, and the
 * same rule the package manifest states about `createFsGate`. A private copy of the guard that
 * decides whether a fence result is a refusal is a second definition of the fence's own contract,
 * free to drift from it silently. ⚠ `stamp.ts` deliberately keeps a private one; read the note
 * there before assuming it was missed.
 */

/**
 * ⚠ THE CONFIG IS PARSED WITH `Object.create(null)` SEMANTICS IN MIND — `JSON.parse` already
 * produces a plain object whose prototype is `Object.prototype`, so `__proto__` in the JSON text
 * lands as an ordinary own key and is caught by the unknown-key screen rather than mutating a
 * prototype. The screen therefore does double duty and is not merely tidiness.
 */
function validate(text: string): ScribeConfig | ScribeRefusal {
    let parsed: unknown;
    try {
        parsed = JSON.parse(text);
    } catch {
        return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} is not valid JSON`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} must be a JSON object`);
    }
    for (const key of Reflect.ownKeys(parsed)) {
        if (typeof key !== 'string' || !CONFIG_KEYS.has(key)) {
            return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} carries an unknown key`);
        }
    }
    const view = parsed as { schema?: unknown; vault_id?: unknown; write_frontmatter?: unknown };
    if (view.schema !== CONFIG_SCHEMA) {
        return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} must declare schema "${CONFIG_SCHEMA}"`);
    }
    if (typeof view.vault_id !== 'string' || !UUID_V4.test(view.vault_id)) {
        return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} must carry a v4 UUID vault_id`);
    }
    if (typeof view.write_frontmatter !== 'boolean') {
        return scribeRefuse('SCRIBE_CONFIG_INVALID', `${CONFIG_PATH} must carry a boolean write_frontmatter`);
    }
    return Object.freeze({
        schema: CONFIG_SCHEMA,
        vault_id: view.vault_id,
        write_frontmatter: view.write_frontmatter
    });
}

/**
 * The minted default. `write_frontmatter` is FALSE, matching D7's "defaulting to the safest":
 * stamping a stranger's page bytes is the more visible act, so it is the one they opt into.
 */
function mint(vaultId: string): ScribeConfig {
    return Object.freeze({ schema: CONFIG_SCHEMA, vault_id: vaultId, write_frontmatter: false });
}

/** The serialised form, with a trailing newline so the file is a well-formed text file. */
export function serialiseConfig(config: ScribeConfig): Buffer {
    return Buffer.from(
        `${JSON.stringify({ schema: config.schema, vault_id: config.vault_id, write_frontmatter: config.write_frontmatter }, null, 2)}\n`,
        'utf8'
    );
}

/**
 * What a load did, alongside what it loaded.
 *
 * ⚠⚠ AN ENVELOPE RATHER THAN A FOURTH KEY ON `ScribeConfig`, AND THE SEPARATION IS THE POINT.
 * `ScribeConfig` is the vault's own persisted document — exactly three keys, validated key-for-key
 * by `validate` above, and an unknown key REFUSES. `created` is a fact about THIS INVOCATION and
 * belongs to no vault, so putting it on the config value would make a per-call fact look like
 * persisted state and would collide with the very screen that keeps the document honest.
 */
export interface LoadedConfig {
    readonly config: ScribeConfig;
    /** True when THIS call minted `.wyrd/scribe.json`; false when it read one that already existed. */
    readonly created: boolean;
}

/**
 * Load the vault's config, minting it if `.wyrd/` exists and the file does not.
 *
 * ⚠ THE `.wyrd/` PROBE IS A LIST, NOT A STAT, because the gate exposes no stat and a list is the
 * operation whose refusal distinguishes the cases this needs: `MISSING` means the directory is
 * absent, `NOT_A_DIRECTORY` means something else owns the name. Both become
 * `SCRIBE_NOT_INITIALISED` naming the directory — the user's action is identical either way — but
 * every OTHER fence refusal (`ESCAPES`, `DENIED`, `ROOT_MOVED`) passes through UNCHANGED, because
 * translating those into "not initialised" would tell the user to create a directory that already
 * exists and hide the real reason.
 *
 * ⚠ THE LIST PROBE CANNOT SEE AN ALIASED `.wyrd/`, WHICH IS WHY THE CREATE MOVED ABOVE THE READ.
 * `listDirInGrant` resolves through an in-grant junction on purpose — `.wyrd -> Arc` canonicalises
 * to a directory inside the grant and lists happily. So does `readFileInGrant`. Only a WRITE path
 * asks whether the parent is where it was spelled.
 */
export async function loadConfig(
    gate: FsGate,
    newUuid: () => string
): Promise<LoadedConfig | ScribeRefusal | FenceRefusal> {
    const dir = await gate.listDirInGrant(WYRD_DIR);
    if (isRefusal(dir)) {
        if (dir.reason === 'MISSING' || dir.reason === 'NOT_A_DIRECTORY') {
            return scribeRefuse(
                'SCRIBE_NOT_INITIALISED',
                `this vault has no ${WYRD_DIR}/ directory; create ${WYRD_DIR}/ inside the vault and retry`
            );
        }
        return dir;
    }

    /**
     * ⚠⚠ THE CREATE IS ATTEMPTED FIRST, AHEAD OF THE READ, AND THE ORDER IS THE SECURITY PROPERTY.
     *
     * The fence's `resolveNew` compares the resolved parent against the spelled one BEFORE it
     * probes the leaf, so a `.wyrd -> Arc` junction is refused `PARENT_ALIAS` ahead of `EXISTS` —
     * ahead of any open, and ahead of any page write. Read-first cannot reach that: an existing
     * `Arc/scribe.json` answers the read successfully and the alias is never questioned, so the
     * page is created and only the LEDGER APPEND refuses, leaving an orphan page. That orphan is
     * the defect this ordering exists to close, and closing it needs no published API change.
     *
     * ⚠ `EXISTS` IS NOT AN ERROR HERE, AND THAT WAS ALREADY TRUE BEFORE THE HOIST. Two Scribe
     * processes granted the same vault reach this line together; the fence's `wx` open makes
     * exactly one of them the winner, and the loser must adopt the winner's id rather than refuse.
     * Minting a second id would give one vault two identities, which is the ambiguity the identity
     * block exists to prevent — arriving through a race instead of through a schema. What the hoist
     * changes is that `EXISTS` is now the ORDINARY path rather than the racing one.
     *
     * ⚠⚠ AND THIS CREATE IS NOW THE STAMP PATH'S FIRST WRITE, WHICH THE HEADER OF `stamp.ts` USED
     * TO DENY. Until 2026-09-08 that header said NOTHING was written until every source had
     * resolved and every limit had passed, and named the page as the first write. Both sentences
     * are narrowed there now, and the truth is stated here at the site that changed it: on an
     * uninitialised vault this line creates `.wyrd/scribe.json` BEFORE a single source has been
     * read. What the ordering still buys is the claim worth having — no PAGE, meaning no byte of
     * caller-supplied content, exists until every check that CAN be decided without one has passed.
     * This file is the server's own bookkeeping at a fixed path inside a directory the user made
     * for it, and `writePage` reports it back through `config_created` rather than leaving it to be
     * inferred.
     *
     * ⚠ THAT CLAUSE READ "until every check has passed" UNTIL 2026-09-08 AND IS NARROWED, because
     * one check runs after the page exists: the final ledger-line size re-check over the canonical
     * path (`stamp.ts` step 9), which leaves an ORPHAN page when it fires. Nothing about THIS file
     * changes — the config mint is still the first write and still reported — but a sentence here
     * that overstates the page guarantee is read as the guarantee, so it says what holds.
     *
     * ⚠⚠ THE MINTER RUNS ON EVERY LOAD, AND `loadConfig` RUNS ON EVERY STAMP THAT REACHES STEP 4
     * (`stamp.ts`; steps 1-3 can refuse before it), SO IT RUNS AT MOST ONCE PER WRITE. Two
     * consequences, both deliberate:
     *
     *   · One speculative `newUuid()` per stamp is discarded when the config already exists. That
     *     is `crypto.randomUUID` in production — no I/O, no syscall worth naming.
     *   · An INJECTED `newUuid` that THROWS now throws on a stamp against a VALID EXISTING config,
     *     where before it threw only when the config was missing. It is NOT caught here, and that
     *     is a ruling rather than an omission: there is no honest reason to convert it to.
     *     `SCRIBE_CONFIG_INVALID` would blame a config that is perfectly valid, and a fence reason
     *     would attribute a Scribe-side fault to the fence. Catching it behind a fallback to the
     *     read-first order would be worse still — a containment check that switches itself off when
     *     an injected function misbehaves is not a check. The default minter does not throw; a
     *     throwing one is a broken injection, and this path reports it as one.
     */
    const minted = mint(newUuid());
    const created = await gate.createFileInGrant(CONFIG_PATH, serialiseConfig(minted));
    // ⚠ `created: true` IS READ OFF THE ONE BRANCH THAT ACTUALLY CREATED, never inferred later from
    // the file's presence. By the time a caller could stat it, a concurrent process minting the same
    // vault's config makes "the file is there" true for both of them and true for neither's call.
    if (!isRefusal(created)) return Object.freeze({ config: minted, created: true });
    if (created.reason !== 'EXISTS') return created;

    const slice = await gate.readFileInGrant(CONFIG_PATH, 0, CONFIG_READ_LIMIT);
    if (isRefusal(slice)) return slice;
    // ⚠ NARROWED ON `ok`, NOT THROUGH THE FENCE'S `isRefusal`. That guard's predicate says
    // `FenceRefusal`, and what `readSlice` can return here is a SCRIBE refusal — borrowing the
    // fence's guard would typecheck by mislabelling the value's own union.
    const read = readSlice(slice);
    if ('ok' in read) return read;
    return Object.freeze({ config: read, created: false });
}

function readSlice(slice: Slice): ScribeConfig | ScribeRefusal {
    // ⚠ TWO QUESTIONS, BECAUSE EACH ALONE WAS WRONG IN ONE DIRECTION. `truncated` is the gate's
    // own answer to "is there more than the window holds", and it stays because the gate trims a
    // window back to a codepoint boundary, so a byte count compared against the WINDOW can disagree
    // with the gate about whether more remains. But a file that fits the window is not thereby
    // under the ceiling: the window is one byte wider than the ceiling on purpose (see
    // `CONFIG_READ_LIMIT`), so a file of exactly `CONFIG_CEILING + 1` bytes came back
    // `truncated: false` and was accepted until 2026-09-08. `slice.size` is the file's whole
    // length as the gate measured it, independent of any trimming, so comparing IT against the
    // ceiling is exact.
    if (slice.truncated || slice.size > CONFIG_CEILING) {
        return scribeRefuse(
            'SCRIBE_CONFIG_TOO_LARGE',
            `${CONFIG_PATH} is larger than ${CONFIG_CEILING} bytes`
        );
    }
    return validate(slice.bytes.toString('utf8'));
}
