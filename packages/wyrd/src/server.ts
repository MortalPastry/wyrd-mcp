import { Server, type Tool } from '@modelcontextprotocol/server';
import { channel } from 'node:diagnostics_channel';

import { isRefusal, type FenceRefusal, type FsGate, type Probe } from 'wyrd-fence';
import { SERVER_VERSION } from './version.js';
import { createSearchEngine, type SearchBackend, type SearchBackendDisclosure } from './search.js';

export { SERVER_VERSION } from './version.js';

export const SERVER_NAME = 'wyrd';

export type ServerTransport = 'stdio' | 'http';

/** The default read window, in BYTES. D5a: every offset and size on this surface is a byte count. */
export const DEFAULT_WINDOW_BYTES = 32_768;
export const MAX_WINDOW_BYTES = 262_144;

export interface CreateServerOptions {
    readonly searchBackend?: SearchBackend;
    readonly searchBackendDisclosure?: SearchBackendDisclosure;
    readonly fsgate: FsGate;
    readonly transport: ServerTransport;
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
 * Which known layers are present, using one fence-mediated probe for each known name.
 *
 * ⚠⚠ A LAYER REACHED THROUGH A REPARSE POINT IS STILL THE LAYER, AND MISSING IT IS THE WORST
 * DIRECTION TO BE WRONG IN. `entryKind` tests `isSymbolicLink()` BEFORE `isDirectory()`, so a
 * junctioned or symlinked `Arc/` classifies as `link` and never reaches a directory filter —
 * verified on this machine by a review lens. Relocating a bulky immutable layer onto other storage
 * is exactly why someone junctions a directory, so the layer flagged as MOST sensitive is the one
 * whose real-world layout is most likely to defeat naive detection. The fence serves it either way;
 * only the warning went missing.
 *
 * The probe resolves the ambiguity through the fence itself rather than by re-implementing link
 * resolution here. It returns kind only: no resolved pathname crosses the gate boundary.
 */
export interface LayerDetection {
    readonly layers: readonly string[];
    readonly listingFailed: boolean;
}

export async function detectLayers(
    probe: (name: string) => Promise<Probe | FenceRefusal>,
    listRoot?: () => Promise<import('wyrd-fence').Entry[] | FenceRefusal>
): Promise<LayerDetection> {
    let entries: import('wyrd-fence').Entry[] | undefined;
    if (listRoot !== undefined) {
        const listed = await listRoot();
        if (isRefusal(listed)) return Object.freeze({ layers: [], listingFailed: true });
        entries = listed;
    }
    const found: string[] = [];
    for (const layer of KNOWN_LAYERS) {
        const name = entries?.find(entry => entry.name.toLowerCase() === layer.toLowerCase())?.name ?? layer;
        const result = await probe(name);
        if (isRefusal(result)) {
            if (result.reason === 'MISSING') continue;
            return Object.freeze({ layers: [], listingFailed: true });
        }
        // `resolveInGrant` normally turns a junctioned directory into `directory`; retaining
        // `link` here is conservative for reparse kinds the runtime does not fully classify.
        if (result.kind === 'directory' || result.kind === 'link') found.push(name);
    }
    return Object.freeze({ layers: Object.freeze(found), listingFailed: false });
}

/**
 * Tool descriptions are the product surface — the model's selection loop runs on them, and a
 * description that over-promises is the failure D5 exists to prevent. This one says what the
 * unit is, what happens at the boundary, and what a refusal means.
 */
/**
 * ⚠⚠ THE FIRST LINE IS THE ONLY LINE A MODEL IS GUARANTEED TO SEE, AND IT IS CUT AT ABOUT 88
 * CHARACTERS. Measured in Claude Desktop on 2026-09-08 (`designs/2026-09-03-client-probe-results.md`):
 * the client drops the connect-time instructions entirely and lists this tool in a deferred index
 * as ONE truncated line — "Read a byte-bounded slice of one file from the single folder this
 * server was gr…" — until the model searches for it. So the scope warning that the rest of this
 * description states at length has to be IN the first line, inside that budget, or a model choosing
 * whether to call this tool never sees it. The line below is 84 characters. Ruled 2026-09-09 with
 * the 0.1.4 bump.
 */
const READ_DESCRIPTION = [
    'Read a byte slice of one file in the granted folder; ANY path in it, .env included.',
    '',
    'Paths are relative to the granted folder, for example `Mage/projects/legend.md`. Absolute',
    'paths, Windows drive-relative paths such as `C:notes`, and any path that climbs out with',
    '`..` are refused.',
    '',
    'A cloud placeholder is refused by default because reading it would download the file.',
    'Set `hydrate: true` on this call only to permit that download.',
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
    'WHAT IS IN SCOPE, since the boundary is a folder and not a file type: ANY PATH inside the',
    'granted folder can be requested, hidden entries included, such as `.env` and `.git/config`.',
    'There is no extension filter, no ignore-file support, and no cap on how much may be read in',
    'total. The granted folder is the whole of the restriction. The one narrowing on the request',
    'side is a handful of NAME SPELLINGS refused as input before anything is opened, so a file',
    'whose name takes one sits on the disk and cannot be requested through this tool: a name',
    'beginning with a drive letter and a colon, such as `C:notes`, on every host — including the',
    'hosts where that is an ordinary filename — and, on Windows, a component containing a colon',
    '(which names a data stream rather than a file) or a reserved device name such as `NUL.md` or',
    '`COM1`.',
    '',
    'What comes BACK is narrower than what can be requested. A DIRECTORY is refused with',
    '`NOT_A_FILE`, so `.git` and `.ssh` are refused as directories while the files inside them',
    'are readable. A requested slice that is not valid UTF-8 is refused with',
    '`NOT_TEXT` rather than returned with substituted characters — a file that comes back altered',
    'but looks complete is worse than one that is refused. Note this is a property of the BYTES,',
    'not the file extension: a `.bin` whose contents happen to be valid UTF-8 is returned, and a',
    '`.md` saved in Latin-1 is refused. Nothing here is a filter on what may be reached.',
    '',
    'KNOWN LIMITS of that restriction, stated because a containment claim without them would be',
    'false: a hard link created inside the folder makes an outside file readable and searchable;',
    'a folder or path component swapped after validation may be read instead of the one checked; and some',
    'filesystem reparse points cannot be classified by this runtime, where a path resolving',
    'through one is still checked against the folder but a refusal for a file outside it can',
    'distinguish missing from unreadable. That last one needs no attacker and can occur in an',
    'ordinary cloud-synced folder. This list is what is known, not a proof that nothing else',
    'exists.'
].join('\n');

const READ_INPUT_SCHEMA = {
    type: 'object',
    properties: {
        path: {
            type: 'string',
            /**
             * ⚠ THIS SAID "Forward or back slashes both work", UNQUALIFIED, AND THAT IS FALSE OFF
             * WINDOWS. On macOS and Linux a backslash is an ordinary filename character, and the
             * fence is currently of two minds about it — the depth guard splits on `/[\\/]/` on
             * every host while the `path.join` beside it folds only what the host folds. WHICH WAY
             * THAT RESOLVES IS AN OPEN DECISION AND NOT THIS STRING'S TO TAKE, so the wording is
             * chosen to stay true whichever way it is ruled: `/` works everywhere under both
             * candidate rulings, and the `\` claim is scoped to the host where it is settled.
             */
            description: 'Path to the file, relative to the granted folder. On Windows both `/` and `\\` separate directories; elsewhere use `/`.'
        },
        offset: {
            type: 'integer',
            minimum: 0,
            description: 'Byte offset to start at. Defaults to 0. Use the `next_offset` from a truncated response.'
        },
        hydrate: {
            type: 'boolean',
            description: 'Allow this call to download a cloud placeholder before reading it. Defaults to false.'
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

/*
 * ⚠ v2's `Tool.inputSchema` wants MUTABLE arrays, and `as const` above makes every array here
 * `readonly` — so passing the constant straight in is
 * `TS2322: readonly ["path"] is not assignable to string[]`.
 *
 * FOUND BY BUILDING against v2. No read-only review lane could have seen it: none of them could
 * install, so none of them could compile. Three lanes read this migration plan and approved it.
 *
 * The widening sits at the USE SITE rather than dropping `as const`, deliberately. The literal
 * types are load-bearing documentation of the schema this server publishes, and widening the
 * declaration to suit one consumer's signature would trade real precision for a type-checker's
 * convenience. The structural shape is identical — only the readonly modifiers differ — so this is
 * a variance cast, not a claim about the value.
 */
const READ_INPUT_SCHEMA_FOR_TOOL = READ_INPUT_SCHEMA as unknown as Tool['inputSchema'];

const SEARCH_DESCRIPTION = 'Search Markdown files in the granted folder. Returns up to 10 paths, byte sizes, Mage layer and canonicity, contextual excerpts with UTF-8 byte offsets, and a truncated flag. Cloud placeholders are excluded; detection and scope counts report when coverage is unavailable. Scope and placeholder counts describe the grant walk, searchable_files describes the backend scan, and revalidation_dropped_count counts candidates withheld during revalidation because they changed or became unreadable.';
const SEARCH_INPUT_SCHEMA = { type: 'object', properties: { query: { type: 'string', minLength: 1, maxLength: 256, description: 'Search terms, 1 to 256 characters.' } }, required: ['query'], additionalProperties: false } as unknown as Tool['inputSchema'];

function refusalText(reason: string, detail: string, tool: 'read' | 'search' = 'read'): string {
    return `wyrd refused this ${tool}.\nreason: ${reason}\n${detail}`;
}

/**
 * The Wyrd MCP server. Read and search share this handler for stdio and HTTP.
 */
/**
 * The disclosure a driving model receives at connect time.
 *
 * ⚠⚠ THIS IS THE MODEL-FACING INSTRUCTIONS FIELD: stdio delivers it through
 * `initialize.instructions`, and HTTP delivers it through `server/discover`'s
 * `result.instructions`. Measured 2026-08-28 by driving the built stdio server with a real client:
 * the startup line on stderr (`wyrd: serving <path> (read-only)`) reaches a terminal, not a model —
 * a client is free to discard it, and most do. Before this existed, `instructions` was `null` and
 * a model was told nothing about what it had been granted.
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
 *   · "Every request is CHECKED against that folder" — and never "only files inside that folder
 *     are served", which stood here until 2026-09-01 and was false in the same reassuring
 *     direction. It is refuted by this repo's own test: `A24-hardlink-limit` asserts wyrd SERVES
 *     an outside file through an in-grant hardlink, and calls it the documented limit. The claim
 *     is therefore about the CHECK, with the "Known limits" paragraph naming where the check does
 *     not hold — that paragraph is not optional decoration, and deleting it makes the bullet an
 *     over-promise again. `E5-disclosure` pins the old wording OUT.
 *   · "No tool here writes" — scoped to TOOLS on purpose. `WYRD_OBSERVE` makes the process itself
 *     ATTEMPT an observation log at exit (`observe.ts`), possibly outside the grant. An
 *     unqualified "nothing is written" is false whenever that variable is set — and an unqualified
 *     "it writes" is false too, because the write is tried at exit and its failure is swallowed.
 *   · The network claim is transport-qualified. In stdio mode the server opens no network
 *     connection of its own; in HTTP mode it is listening for connections but makes no outbound
 *     connection of its own. Neither claim means "nothing leaves this machine", nor does either
 *     mean "your content goes to a model provider". A client talking to a hosted model forwards
 *     what it reads, which is the ordinary case; a client driving a local model, or one that does
 *     not forward a particular result, sends nothing anywhere. The decision belongs to the client
 *     and not to wyrd, which is what README.md and PRIVACY.md both say. Saying otherwise tells a
 *     user their notes stay local when they do not, and that is the one sentence here that could
 *     actually hurt somebody.
 */
export function searchBackendParagraph(module?: SearchBackendDisclosure): string[] {
    return module === undefined ? [] : [
        '',
        `Search is answered by an additional search backend module the operator named, at ${module.path}.`,
        "That module runs inside this process with this process's permissions and is not confined to the granted folder.",
        'wyrd hands it only bounded reads of the granted folder but cannot prevent it opening other files or the network.',
        'What the module says about itself follows:',
        ...module.lines.map(line => `  Module: ${line}`)
    ];
}

export function disclosure(
    root: string,
    transport: ServerTransport,
    layers: readonly string[] = [],
    listingFailed = false,
    module?: SearchBackendDisclosure
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
              module ? 'Vault structure detection did not finish at startup, so no structure warning appears below.' : 'This folder could not be listed at startup, so no structure warning appears below.',
              module ? 'That is not a statement that the folder has no sensitive layers — detection was incomplete.' : 'That is not a statement that the folder has no sensitive layers — nothing was read.'
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

    const network = transport === 'stdio'
        ? ['  · In stdio mode, this server opens no network connection of its own. That is NOT a promise your']
        : [
              '  · In HTTP mode, this server is listening for connections and does not make outbound',
              '    connections of its own. That is NOT a promise your'
          ];

    const builtIn = module === undefined ? 'this server' : "wyrd's built-in server code";
    return [
        `wyrd is serving exactly one folder: ${root}`,
        module ? 'Its built-in read tool and search reads are read-only; the additional module has its own permissions.' : 'Its tools are `read` and `search`; both are read-only.',
        '',
        module ? "What wyrd's built-in reads mean:" : 'What that means:',
        module ? '  · Every read through wyrd is checked against that folder before a file is opened. A path that' : '  · Every request is checked against that folder before a file is opened. A path that',
        '    resolves outside it is refused, and the refusal names the rule that fired rather',
        '    than pretending the file is absent. The known limits below say where that check',
        '    does not hold.',
        module ? '  · The built-in read tool and search reads do not write, move or delete. The built-in code' : '  · No tool here writes, moves or deletes anything. There is none that can. The PROCESS',
        '    can write in exactly one case: with WYRD_OBSERVE set it ATTEMPTS, at exit, to log the',
        '    pathnames it touches, never file contents, to exactly the path that variable names,',
        '    which is not checked and may be a network share or a synchronised folder. The write',
        '    is attempted, not guaranteed — if it fails it fails silently.',
        ...network.map(line => module === undefined ? line : line.replace('this server', builtIn)),
        '    content stays local: what the client driving this conversation does with what it',
        '    reads is between you and that client, under its terms and not wyrd\'s. A client',
        '    talking to a hosted model will send your content there; one running a model locally,',
        '    or one that never forwards a particular result, will not. Wyrd cannot see which.',
        module ? "  · wyrd's built-in search backend builds a lazy in-memory cache of normalized terms and anchors; it holds no raw" : '  \u00b7 Search builds a lazy in-memory cache of normalized terms and anchors; it holds no raw',
        '    text and writes no search data to disk. The grant is fixed until restart.',
        '',
        '',
        'What is in scope: ANY PATH INSIDE that folder can be requested, hidden entries included,',
        'such as .env and .git/config. There is no extension filter, no ignore-file support, and no',
        module ? "cap on how much wyrd may read in total. The folder restricts wyrd's reads: grant a" : 'cap on how much may be read in total. The folder is the whole of the restriction: grant a',
        'subfolder containing only what you mean to share.',
        '',
        'A handful of NAME SPELLINGS are refused as input before anything is opened, so a file whose',
        'name takes one sits on the disk and cannot be requested: a name beginning with a drive',
        'letter and a colon, such as C:notes, on every host — including the hosts where that is an',
        'ordinary filename — and, on Windows, a component containing a colon (which names a data',
        'stream rather than a file) or a reserved device name such as NUL.md or COM1.',
        '',
        '(What comes back is narrower than what can be requested.',
        'A DIRECTORY is refused, so .git and .ssh are refused as directories',
        'while the files inside them are readable; and bytes that are not valid UTF-8 are refused',
        'rather than altered. Both limit what is READABLE, not what is REACHABLE.)',
        '',
        'Known limits, each needing different conditions:',
        '  · A hard link that already exists inside this folder makes the file it points at',
        '    readable and searchable, wherever on the disk that file lives, and ordinary folder inspection will',
        '    not show it as a link. Granting a folder the files were freshly COPIED into avoids',
        '    it, because copying makes new files rather than new links.',
        '  · A path component swapped between validation and opening may be read instead of the',
        '    one checked. That needs write access to this folder.',
        '  · Some filesystem reparse points cannot be classified by this runtime, and this one',
        '    NEEDS NO ATTACKER: an ordinary cloud-synced or WSL-mounted folder can contain one in',
        '    normal use. A path resolving through one is still checked against this folder, so it',
        '    cannot be used to read outside it; what remains is that a refusal for a file outside',
        '    this folder can distinguish missing from unreadable.',
        '  · A refusal distinguishes "outside the grant" from "does not exist", which tells a',
        '    caller one bit about whether a file outside this folder exists.',
        'This list is what is known, not a proof that nothing else exists. The limits were measured',
        'on Windows; behaviour on macOS and Linux is reasoned but unmeasured.',
        ...vault,
        ...searchBackendParagraph(module)
    ].join('\n');
}

export function createServer(options: CreateServerOptions): Server {
    const { fsgate, transport, layers = [], listingFailed = false } = options;
    const baseline = channel('wyrd.search.pre-engine');
    if (baseline.hasSubscribers) baseline.publish(process.memoryUsage().rss);
    const search = createSearchEngine(fsgate, options.searchBackend);
    const server = new Server(
        { name: SERVER_NAME, version: SERVER_VERSION },
        {
            capabilities: { tools: {} },
            // ⚠ `listingFailed` MUST be forwarded. It was accepted here and dropped on the way to
            // `disclosure()`, which collapsed the model-facing third state back into "plain
            // folder" — so stderr warned that nothing could be listed while the model was told
            // nothing at all. Two lenses caught it independently. The whole point of the third
            // state is that "no layers" and "could not look" are different facts.
            instructions: disclosure(fsgate.disclosedRoot(), transport, layers, listingFailed, options.searchBackendDisclosure)
        }
    );

    server.setRequestHandler('tools/list', () => ({
        tools: [
            {
                name: 'read',
                title: 'Read a file from the granted folder',
                description: READ_DESCRIPTION,
                inputSchema: READ_INPUT_SCHEMA_FOR_TOOL,
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
            },
            { name: 'search', title: 'Search Markdown in the granted folder', description: SEARCH_DESCRIPTION,
                inputSchema: SEARCH_INPUT_SCHEMA, annotations: { readOnlyHint: options.searchBackend === undefined } }
        ]
    }));

    server.setRequestHandler('tools/call', async request => {
        if (request.params.name === 'search') {
            const args = (request.params.arguments ?? {}) as Record<string, unknown>;
            const query = args['query'];
            if (typeof query !== 'string' || [...query].length < 1 || [...query].length > 256 ||
                Object.keys(args).some(key => key !== 'query')) {
                return { isError: true, content: [{ type: 'text' as const,
                    text: refusalText('BAD_INPUT', '`query` must be a string of 1 to 256 characters and the only argument.', 'search') }] };
            }
            try {
                const result = await search(query);
                const warnings = [
                    ...(result.placeholder_detection === 'unavailable' ? ['Cloud placeholder detection unavailable; exclusion coverage cannot be confirmed.'] : []),
                    ...(result.excluded_from_search !== null && result.excluded_from_search > 0 ? [`${result.excluded_from_search} cloud placeholder(s) excluded from search to avoid a download.`] : [])
                ];
                const payload = { ...result, warnings };
                return { structuredContent: payload, content: [{ type: 'text' as const, text: JSON.stringify(payload) }] };
            } catch {
                return { isError: true, content: [{ type: 'text' as const,
                    text: refusalText('IO_ERROR', 'the granted folder could not be searched.', 'search') }] };
            }
        }
        const summary = await fsgate.grantPlaceholderSummary();
        const status = () => summary.placeholder_detection === 'unavailable' ||
            fsgate.placeholderDetection() === 'unavailable'
            ? { placeholder_detection: 'unavailable' as const, placeholder_count: null,
                file_count: null, placeholder_fraction: null,
                ...(summary.warning ? { warning: summary.warning } : {}) }
            : summary;
        const readRefusal = (reason: string, detail: string) =>
            refusalText(reason, detail) + (summary.warning ? `\nwarning: ${summary.warning}` : '');
        if (request.params.name !== 'read') {
            return {
                isError: true,
                structuredContent: status(),
                content: [{ type: 'text' as const, text: `wyrd has no tool named ${request.params.name}.` }]
            };
        }

        const args = (request.params.arguments ?? {}) as Record<string, unknown>;
        const target = args['path'];
        if (typeof target !== 'string') {
            return {
                isError: true,
                structuredContent: status(),
                content: [{ type: 'text' as const, text: readRefusal('BAD_INPUT', '`path` must be a string.') }]
            };
        }
        const offset = typeof args['offset'] === 'number' ? args['offset'] : 0;
        const requested = typeof args['limit'] === 'number' ? args['limit'] : DEFAULT_WINDOW_BYTES;
        const limit = Math.min(Math.max(requested, 1), MAX_WINDOW_BYTES);

        const hydrate = args['hydrate'] === true;
        const slice = await fsgate.readFileInGrant(target, offset, limit, hydrate);
        if (isRefusal(slice)) {
            return {
                isError: true,
                structuredContent: { ...status(), ...(slice.reason === 'PLACEHOLDER' ? { dehydrated: true } : {}) },
                content: [{ type: 'text' as const, text: refusalText(slice.reason, slice.detail) +
                    (summary.warning ? `\nwarning: ${summary.warning}` : '') }]
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
                structuredContent: status(),
                content: [
                    {
                        type: 'text' as const,
                        text: readRefusal(
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
                structuredContent: status(),
                content: [
                    {
                        type: 'text' as const,
                        text: readRefusal(
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
                structuredContent: status(),
                content: [
                    {
                        type: 'text' as const,
                        text: readRefusal(
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
            (slice.truncated ? ` · next_offset: ${slice.nextOffset}` : '') +
            (summary.warning ? ` · warning: ${summary.warning}` : '');

        return {
            content: [
                { type: 'text' as const, text: header },
                { type: 'text' as const, text: decoded }
            ],
            structuredContent: { ...status(),
                ...(slice.dehydrated ? { dehydrated: true, warning: `${summary.warning ?? ''} This read downloaded a cloud placeholder.`.trim() } : {}) }
        };
    });

    return server;
}
