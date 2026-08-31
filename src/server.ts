import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { isRefusal, type FsGate } from './fsgate.js';

export const SERVER_NAME = 'wyrd';
export const SERVER_VERSION = '0.0.0';

/** The default read window, in BYTES. D5a: every offset and size on this surface is a byte count. */
export const DEFAULT_WINDOW_BYTES = 32_768;
export const MAX_WINDOW_BYTES = 262_144;

export interface CreateServerOptions {
    readonly fsgate: FsGate;
    /**
     * Mage layer directories actually FOUND at the grant root, in canonical order. Detected by
     * `main()` before construction — never assumed. Empty for an ordinary folder, which is the
     * common case and must read as one.
     */
    readonly layers?: readonly string[];
    /**
     * True when the grant root could not be listed at startup, so `layers` is EMPTY BECAUSE
     * NOTHING WAS LOOKED AT rather than because nothing is there. Without this the two states
     * produce a byte-identical disclosure, and a full Mage vault whose listing hit a transient
     * EPERM under a sync provider reads exactly like a plain folder of ordinary notes.
     */
    readonly listingFailed?: boolean;
}

/**
 * The Mage layers worth warning about, and why each one earns a line.
 *
 * ⚠ D1: Mage structure is a DETECTED BONUS, not a requirement — this server works on any folder.
 * So the disclosure names only what is really there.
 */
const LAYER_NOTES: Record<string, string> = {
    Arc: 'immutable source — may hold private material',
    Mage: 'agent-curated structure',
    Forum: 'non-canonical staging, including pre-canon drafts'
};

export const KNOWN_LAYERS = Object.keys(LAYER_NOTES);

/**
 * Which known layers are present, given a listing of the grant root.
 *
 * ⚠⚠ A LAYER REACHED THROUGH A REPARSE POINT IS STILL THE LAYER, AND MISSING IT IS THE WORST
 * DIRECTION TO BE WRONG IN. `entryKind` tests `isSymbolicLink()` BEFORE `isDirectory()`, so a
 * junctioned or symlinked `Arc/` classifies as `link` and never reaches a directory filter —
 * verified on this machine by a review lens. Relocating a bulky immutable layer onto other storage
 * is exactly why someone junctions a directory, so the layer flagged as MOST sensitive is the one
 * whose real-world layout is most likely to defeat naive detection. The fence serves it either way;
 * only the warning went missing.
 *
 * `probeDir` resolves the ambiguity through the fence itself rather than by re-implementing link
 * resolution here: if the name lists as a directory within the grant, it is one.
 *
 * ⚠ The returned name is the ON-DISK spelling, not the canonical one. Matching is case-insensitive
 * because Windows is; printing `Arc/` for a directory actually named `arc` would hand the model a
 * path that does not exist on a case-sensitive volume.
 */
export async function detectLayers(
    entries: readonly { name: string; kind: string }[],
    probeDir?: (name: string) => Promise<boolean>
): Promise<string[]> {
    const found: string[] = [];
    for (const layer of KNOWN_LAYERS) {
        // ⚠ A CASE-INSENSITIVE COMPARE CAN MATCH MORE THAN ONE ENTRY, so this collects every
        // candidate rather than taking the first. On a case-sensitive filesystem a folder may hold
        // both `arc` and `Arc`; the old `.find()` took whichever the listing happened to yield
        // first, and if that was the FILE, the real directory beside it was never detected — the
        // disclosure then failed to name a layer that was actually there. Order of a directory
        // listing is not a guarantee, so the fix is to choose deliberately instead of positionally.
        const candidates = entries.filter(entry => entry.name.toLowerCase() === layer.toLowerCase());
        if (candidates.length === 0) continue;

        // A real directory wins outright — it cannot be shadowed by a same-named file.
        const directory = candidates.find(entry => entry.kind === 'directory');
        if (directory !== undefined) {
            found.push(directory.name);
            continue;
        }

        // No directory, so fall back to any link that resolves to one. Probing is the only way to
        // tell, and it costs a listing per candidate — bounded by how many entries share the name.
        if (probeDir === undefined) continue;
        for (const candidate of candidates) {
            if (candidate.kind !== 'link') continue;
            if (await probeDir(candidate.name)) {
                found.push(candidate.name);
                break;
            }
        }
    }
    return found;
}

/**
 * Tool descriptions are the product surface — the model's selection loop runs on them, and a
 * description that over-promises is the failure D5 exists to prevent. This one says what the
 * unit is, what happens at the boundary, and what a refusal means.
 */
const READ_DESCRIPTION = [
    'Read a byte-bounded slice of one file from the single folder this server was granted.',
    '',
    'Paths are relative to the granted folder, for example `Mage/projects/legend.md`. Absolute',
    'paths, Windows drive-relative paths such as `C:notes`, and any path that climbs out with',
    '`..` are refused.',
    '',
    'Reads are byte-oriented, never character-oriented. `offset` and `limit` are byte counts',
    "into the file's UTF-8 encoding. A returned slice may be up to 3 bytes shorter than `limit`",
    'so that it ends on a whole codepoint.',
    '',
    'If the file is longer than the slice, the response says `truncated: true` and gives',
    '`next_offset`. Call again with that offset to continue; following `next_offset` to',
    'exhaustion reconstructs the UTF-8 text byte for byte. This server never returns a silently',
    'shortened file — if content is missing, the response says so.',
    '',
    'Every path is validated against the granted folder before anything is opened, and a',
    'refusal names the rule that fired rather than pretending the file is absent.',
    '',
    'WHAT IS IN SCOPE, since the boundary is a folder and not a file type: EVERY file inside the',
    'granted folder can be requested, including hidden files and directories such as `.git`,',
    '`.env` and `.ssh`. There is no extension filter, no ignore-file support, and no cap on how',
    'much may be read in total. The granted folder is the whole of the restriction.',
    '',
    'What comes BACK is text. A requested slice that is not valid UTF-8 is refused with',
    '`NOT_TEXT` rather than returned with substituted characters — a file that comes back altered',
    'but looks complete is worse than one that is refused. Note this is a property of the BYTES,',
    'not the file extension: a `.bin` whose contents happen to be valid UTF-8 is returned, and a',
    '`.md` saved in Latin-1 is refused. Nothing here is a filter on what may be reached.',
    '',
    'KNOWN LIMITS of that restriction, stated because a containment claim without them would be',
    'false: a hard link created inside the folder can reach a file outside it; a folder or path',
    'component swapped after validation may be read instead of the one checked; and some',
    'filesystem reparse points are invisible to this runtime and are not detected at all — that',
    'last one needs no attacker and can occur in an ordinary cloud-synced folder. This list is',
    'what is known, not a proof that nothing else exists.'
].join('\n');

const READ_INPUT_SCHEMA = {
    type: 'object',
    properties: {
        path: {
            type: 'string',
            description: 'Path to the file, relative to the granted folder. Forward or back slashes both work.'
        },
        offset: {
            type: 'integer',
            minimum: 0,
            description: 'Byte offset to start at. Defaults to 0. Use the `next_offset` from a truncated response.'
        },
        limit: {
            type: 'integer',
            minimum: 1,
            maximum: MAX_WINDOW_BYTES,
            description: `Maximum bytes to return. Defaults to ${DEFAULT_WINDOW_BYTES}, capped at ${MAX_WINDOW_BYTES}.`
        }
    },
    required: ['path'],
    additionalProperties: false
} as const;

function refusalText(reason: string, detail: string): string {
    return `wyrd refused this read.\nreason: ${reason}\n${detail}`;
}

/**
 * The Wyrd MCP server.
 *
 * ⚠ ONE TOOL. `search` and `list` are specified (spec §3a) and deliberately absent: the fence
 * lands before any tool that widens the surface it fences.
 */
/**
 * The disclosure a driving model receives at connect time.
 *
 * ⚠⚠ THIS IS THE `initialize.instructions` FIELD, AND IT IS THE ONLY DISCLOSURE CHANNEL THE MODEL
 * EVER SEES. Measured 2026-08-28 by driving the built server with a real client: the startup line
 * on stderr (`wyrd: serving <path> (read-only)`) reaches a terminal, not a model — a client is free
 * to discard it, and most do. Before this existed, `instructions` was `null` and a model was told
 * nothing about what it had been granted.
 *
 * The privacy rule this server is built to: *disclosure AND an enforced scope fence* — say exactly
 * what happens regardless, and fence what it can reach. The fence half was built and proven first.
 * This is the other half, and it was missing for a while whilst the rule read as satisfied.
 *
 * ⚠ It states the CANONICAL root, not the name given, because the two can differ and the canonical
 * one is the boundary that is actually enforced.
 *
 * ⚠⚠ EVERY CLAIM HERE IS LOAD-BEARING AND EACH ONE WAS WRONG IN THE FIRST DRAFT — all three in the
 * SAME direction, more reassuring than the truth, which is the worst direction a security
 * disclosure can be wrong in. Two review lenses converged on exactly this. Before editing a word,
 * know what each survivor is standing on:
 *
 *   · "Only files inside that folder are served" — NOT "nothing above can be read, by any path,
 *     for any reason." That stronger sentence is refuted by this repo's own test:
 *     `A24-hardlink-limit` asserts wyrd SERVES an outside file through an in-grant hardlink, and
 *     calls it the documented limit. Hence the "Known limits" paragraph, which is not optional
 *     decoration — deleting it makes the first bullet false again.
 *   · "No tool here writes" — scoped to TOOLS on purpose. `WYRD_OBSERVE` makes the process itself
 *     write an observation log at exit (`observe.ts`), possibly outside the grant. An unqualified
 *     "nothing is written" is false whenever that variable is set.
 *   · "opens no network connection of its own" — NOT "nothing leaves this machine." A stdio server
 *     cannot promise that: the driving client forwards what it reads to a hosted model, which is
 *     the entire point of MCP. Saying otherwise tells a user their notes stay local when they do
 *     not, and that is the one sentence here that could actually hurt somebody.
 */
export function disclosure(
    root: string,
    layers: readonly string[] = [],
    listingFailed = false
): string {
    // ⚠ NAMED ONLY WHEN PRESENT, AND THAT IS A PRODUCT DECISION, NOT A TIDINESS ONE.
    // The old text asserted these layers unconditionally, behind "if this folder is a Mage vault" —
    // a conditional the reader was asked to evaluate about their own folder using a term they had
    // just met. It served neither reader: a stranger with plain notes got three directories they do
    // not have, inside a security disclosure where noise costs the most; a vault owner got the real
    // warning buried behind boilerplate. Detected, the term arrives attached to a directory the
    // reader can see in their own file manager, at the moment it means something.
    // ⚠ THREE STATES, NOT TWO. "No layers found" and "could not look" are different facts, and
    // collapsing them makes a vault that failed to list read as a plain folder — a silent
    // under-warning at the exact moment the warning matters.
    const vault = listingFailed
        ? [
              '',
              'This folder could not be listed at startup, so no structure warning appears below.',
              'That is not a statement that the folder has no sensitive layers — nothing was read.'
          ]
        : layers.length === 0
            ? []
            : [
                  '',
                  'This folder contains a Mage vault structure, detected at startup. Granting it',
                  'exposes:',
                  ...layers.map(layer => {
                      // Keyed case-insensitively so an on-disk `arc/` still finds its note.
                      const key = KNOWN_LAYERS.find(k => k.toLowerCase() === layer.toLowerCase());
                      return `  · ${layer}/ — ${key === undefined ? 'a Mage layer' : LAYER_NOTES[key]}`;
                  }),
                  'Grant a subfolder instead to expose only that subfolder.'
              ];

    return [
        `wyrd is serving exactly one folder, read-only: ${root}`,
        '',
        'What that means:',
        '  · Only files inside that folder are served. A path that resolves outside it is',
        '    refused, and the refusal names the rule that fired rather than pretending the',
        '    file is absent.',
        '  · No tool here writes, moves or deletes anything. There is none that can.',
        '  · This server opens no network connection of its own. That is NOT a promise your',
        '    content stays local: whatever you read through it goes to whichever model is',
        '    driving this conversation, under that provider\'s terms, not wyrd\'s.',
        '',
        '',
        'What is in scope: EVERY file inside that folder can be requested, including hidden files',
        'and directories such as .git, .env and .ssh. There is no extension filter, no ignore-file',
        'support, and no cap on how much may be read in total. The folder is the whole of the',
        'restriction — grant a subfolder containing only what you mean to share. (What comes back',
        'is text: bytes that are not valid UTF-8 are refused rather than altered, which limits what',
        'is READABLE, not what is REACHABLE.)',
        '',
        'Known limits, stated rather than buried, and each needs different conditions:',
        '  · A hard link created inside this folder can reach a file outside it, and a path',
        '    component swapped between validation and opening may be read instead of the one',
        '    checked. Both need write access to this folder.',
        '  · Some filesystem reparse points are invisible to this runtime. Those are not detected',
        '    at all — not partially — and this one NEEDS NO ATTACKER: an ordinary cloud-synced or',
        '    WSL-mounted folder can contain one in normal use.',
        '  · A refusal distinguishes "outside the grant" from "does not exist", which tells a',
        '    caller one bit about whether a file outside this folder exists.',
        'This list is what is known, not a proof that nothing else exists. The limits were measured',
        'on Windows; behaviour on macOS and Linux is reasoned but unmeasured.',
        ...vault
    ].join('\n');
}

export function createServer(options: CreateServerOptions): Server {
    const { fsgate, layers = [], listingFailed = false } = options;
    const server = new Server(
        { name: SERVER_NAME, version: SERVER_VERSION },
        {
            capabilities: { tools: {} },
            // ⚠ `listingFailed` MUST be forwarded. It was accepted here and dropped on the way to
            // `disclosure()`, which collapsed the model-facing third state back into "plain
            // folder" — so stderr warned that nothing could be listed while the model was told
            // nothing at all. Two lenses caught it independently. The whole point of the third
            // state is that "no layers" and "could not look" are different facts.
            instructions: disclosure(fsgate.disclosedRoot(), layers, listingFailed)
        }
    );

    server.setRequestHandler(ListToolsRequestSchema, () => ({
        tools: [
            {
                name: 'read',
                title: 'Read a file from the granted folder',
                description: READ_DESCRIPTION,
                inputSchema: READ_INPUT_SCHEMA,
                // ⚠ The read-only guarantee lived ONLY in prose until now — in the description and
                // in `initialize.instructions` — and a directory's automated review reads the
                // ANNOTATION, not the paragraph. `readOnlyHint` is the machine-readable form of a
                // claim this server already makes and already keeps: `read` reaches the disk through
                // `readFileInGrant` and no other path.
                //
                // ⚠ `openWorldHint` is deliberately NOT declared here. It is a defensible `false` —
                // the grant is one local folder — but "which annotations to assert" is a judgment
                // this slice did not take, and an annotation asserted casually is the same defect as
                // a prose claim nobody checked.
                annotations: { readOnlyHint: true }
            }
        ]
    }));

    server.setRequestHandler(CallToolRequestSchema, async request => {
        if (request.params.name !== 'read') {
            return {
                isError: true,
                content: [{ type: 'text' as const, text: `wyrd has no tool named ${request.params.name}.` }]
            };
        }

        const args = (request.params.arguments ?? {}) as Record<string, unknown>;
        const target = args['path'];
        if (typeof target !== 'string') {
            return {
                isError: true,
                content: [{ type: 'text' as const, text: refusalText('BAD_INPUT', '`path` must be a string.') }]
            };
        }
        const offset = typeof args['offset'] === 'number' ? args['offset'] : 0;
        const requested = typeof args['limit'] === 'number' ? args['limit'] : DEFAULT_WINDOW_BYTES;
        const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES);

        const slice = await fsgate.readFileInGrant(target, offset, limit);
        if (isRefusal(slice)) {
            return {
                isError: true,
                content: [{ type: 'text' as const, text: refusalText(slice.reason, slice.detail) }]
            };
        }

        // ⚠⚠ THE DECODE IS A CORRECTNESS GATE, NOT A FORMATTING STEP. `Buffer.toString('utf8')`
        // SILENTLY substitutes U+FFFD for every invalid byte — so a Latin-1 note, a PDF, an image
        // or a `.git` object came back altered, with `truncated: false`, no error, and a header
        // still reporting the original byte count. Measured: 4 bytes in, 8 bytes out, no signal.
        // The tool description promised the opposite in the same breath ("following next_offset to
        // exhaustion reconstructs the file byte for byte"), which made this the worst shape a
        // defect takes here — a claim and its refutation shipping together.
        //
        // A round-trip comparison is exact rather than heuristic: for well-formed UTF-8 the
        // re-encode is byte-identical by definition, and the fence already trims every slice to a
        // codepoint boundary (A27-utf8), so a mid-codepoint window cannot produce a false NOT_TEXT.
        // ⚠⚠ NO-PROGRESS GUARD, AND WITHOUT IT A CONFORMING CLIENT LOOPS FOREVER. The fence trims
        // a slice back to a codepoint boundary; when `limit` is smaller than the codepoint at
        // `offset`, that trim removes everything and returns an EMPTY slice whose `next_offset`
        // equals `offset`. An empty buffer round-trips perfectly, so the UTF-8 check below passes
        // it — and the description tells the model to "call again with that offset to continue".
        // It would do exactly that, forever. Found by two lenses independently.
        if (slice.bytes.length === 0 && slice.truncated && slice.nextOffset <= slice.offset) {
            return {
                isError: true,
                content: [
                    {
                        type: 'text' as const,
                        text: refusalText(
                            'LIMIT_TOO_SMALL',
                            `limit ${limit} is too small to return even one character at offset ` +
                                `${slice.offset}, so the read cannot advance. Retry with a larger ` +
                                `limit — a single character can need up to 4 bytes.`
                        )
                    }
                ]
            };
        }

        // ⚠ AN OFFSET INSIDE A CHARACTER IS A CALLER ERROR, NOT A CORRUPT FILE. A slice beginning
        // with a UTF-8 continuation byte (0b10xxxxxx) decodes to U+FFFD and would otherwise be
        // reported as NOT_TEXT — telling the user their perfectly good file is binary. Every
        // `next_offset` this server hands out lands on a boundary, so ordinary pagination never
        // reaches this; only a hand-picked offset does.
        const first = slice.bytes[0];
        if (first !== undefined && (first & 0xc0) === 0x80) {
            return {
                isError: true,
                content: [
                    {
                        type: 'text' as const,
                        text: refusalText(
                            'BAD_OFFSET',
                            `offset ${slice.offset} falls inside a multi-byte character, so the ` +
                                `slice cannot be decoded. Use the \`next_offset\` from a previous ` +
                                `response rather than choosing an offset directly.`
                        )
                    }
                ]
            };
        }

        const decoded = slice.bytes.toString('utf8');
        if (Buffer.compare(slice.bytes, Buffer.from(decoded, 'utf8')) !== 0) {
            return {
                isError: true,
                content: [
                    {
                        type: 'text' as const,
                        text: refusalText(
                            'NOT_TEXT',
                            `the requested slice of ${target} is not valid UTF-8, so it cannot be ` +
                                `returned without altering it. wyrd refuses rather than returning ` +
                                `content that looks complete and is not. This is a property of ` +
                                `the bytes, not the file name — the file is in scope, its ` +
                                `encoding is not something this tool can return faithfully.`
                        )
                    }
                ]
            };
        }

        const header =
            `wyrd read ${target} — bytes ${slice.offset}..${slice.nextOffset} of ${slice.size}` +
            ` · truncated: ${slice.truncated}` +
            (slice.truncated ? ` · next_offset: ${slice.nextOffset}` : '');

        return {
            content: [
                { type: 'text' as const, text: header },
                { type: 'text' as const, text: decoded }
            ]
        };
    });

    return server;
}
