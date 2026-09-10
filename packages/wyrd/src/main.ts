import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createFsGate, isRefusal, type FsGate, type FenceRefusal } from 'wyrd-fence';
import { createServer, detectLayers, disclosure } from './server.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';

/**
 * The application seam. Every dependency that touches the world arrives as an argument, so a
 * startup arm exercises the real sequence rather than a stand-in for it.
 *
 * ⚠ Startup arms exercise THIS, not `createServer`. Injecting at `createServer` replaces the
 * fence, and a suite can go green having exercised a fake.
 */
export interface MainDeps {
    readonly argv: readonly string[];
    readonly env: Record<string, string | undefined>;
    readonly makeFsGate: (options: { rawGrant: string }) => FsGate | FenceRefusal;
    readonly stderr: (line: string) => void;
    readonly setExitCode: (code: number) => void;
    readonly connect?: ((server: Server) => Promise<void>) | undefined;
}

export interface MainResult {
    readonly started: boolean;
    readonly reason: string | null;
}

/**
 * The refusal printed when no folder has been granted.
 *
 * ⚠ STATIC, and that is the whole point. Nothing is known at refusal time and nothing may be
 * probed to find out — probing would breach the fence in order to write the fence's own error
 * message. The layer taxonomy below is fixed text, not detection.
 */
export const NO_GRANT_MESSAGE = [
    'wyrd: refusing to start — no folder has been granted.',
    '',
    'Grant one, either way:',
    '  --grant <absolute path>       on the command line (wins over the environment)',
    '  WYRD_GRANT=<absolute path>    in the environment',
    '',
    'Wyrd serves the folder you name. The only tool it registers is `read`; none writes, moves',
    'or deletes. Every request is checked against that folder before a file is opened, subject to',
    'the known limits below. ANY PATH INSIDE IT CAN BE REQUESTED, of any type, hidden entries',
    'included, such as .env and .git/config: there is no extension filter and no ignore-file',
    'support. What comes back is narrower than what can be requested, because a directory is',
    'refused and so are bytes that are not valid UTF-8; that limits what is READABLE, not what is',
    'REACHABLE. Grant a subfolder containing only what you mean to share.',
    '',
    'A handful of NAME SPELLINGS are refused as input before anything is opened, so a file whose',
    'name takes one sits on the disk and cannot be requested: a name beginning with a drive letter',
    'and a colon, such as C:notes, on every host — including the hosts where that is an ordinary',
    'filename — and, on Windows, a component containing a colon (which names a data stream rather',
    'than a file) or a reserved device name such as NUL.md or COM1.',
    '',
    'Known limits: a hard link that already exists inside the folder makes the file it points at',
    'readable wherever on the disk that file lives, and ordinary folder inspection will not show',
    'it as a link. A path component swapped between validation and opening may be read instead of',
    'the one checked; that one needs write access to the folder. Some filesystem reparse points',
    'cannot be classified by this runtime; a path resolving through one is still checked against',
    'the folder, so it cannot be used to read outside it, but if it leads to a file outside that is',
    'missing or unreadable the refusal distinguishes those two cases. That one needs no attacker',
    'and can occur in an ordinary cloud-synced folder. Measured on Windows; macOS and Linux are',
    'reasoned but unmeasured. This list is what is known, not a proof that nothing else exists.',
    '',
    'Setting WYRD_OBSERVE makes the process itself ATTEMPT, at exit, to write a diagnostic log of',
    'the PATHNAMES it touches, to exactly the path you supply, which is not checked and may be a',
    'network share. The write is attempted, not guaranteed — if it fails it fails silently.',
    '',
    'If that folder is a Mage vault, granting it exposes these layers:',
    '  Arc/     immutable source — may hold private material',
    '  Mage/    agent-curated structure',
    '  Forum/   non-canonical staging, including Forum/Antechamber/ pre-canon drafts',
    '',
    'Grant a subfolder instead to expose only that subfolder.',
    'No folder is inspected until one is granted.'
].join('\n');

/** `--grant <value>` and `--grant=<value>`. Nothing else is read from the command line. */
export function readGrantArg(argv: readonly string[]): string | null {
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index] as string;
        if (argument === '--grant') {
            const value = argv[index + 1];
            return value === undefined ? '' : value;
        }
        if (argument.startsWith('--grant=')) return argument.slice('--grant='.length);
    }
    return null;
}

export async function main(deps: MainDeps): Promise<MainResult> {
    // Step 2 — the command line wins over the environment; nothing else is read.
    const fromArgv = readGrantArg(deps.argv);
    const rawGrant = fromArgv !== null ? fromArgv : (deps.env['WYRD_GRANT'] ?? null);

    // Step 3 — absent. Static refusal, non-zero exit, nothing touched.
    if (rawGrant === null || rawGrant === '') {
        deps.stderr(NO_GRANT_MESSAGE);
        deps.setExitCode(2);
        return { started: false, reason: 'NO_GRANT' };
    }

    // Steps 4 to 6 — lexical validation, then the two primitives on the named root, inside the
    // factory so a direct caller cannot skip them.
    const gate = deps.makeFsGate({ rawGrant });
    if (isRefusal(gate)) {
        deps.stderr(`wyrd: refusing to start — ${gate.detail}`);
        if (gate.resolvedPath !== '' && !gate.detail.includes(gate.resolvedPath)) {
            deps.stderr(`wyrd: the path resolved to ${gate.resolvedPath}`);
        }
        deps.setExitCode(2);
        return { started: false, reason: gate.reason };
    }

    // Step 7 — detect which Mage layers are actually present, so the disclosure names what is
    // really there instead of asserting a structure the folder may not have (D1: Mage structure is
    // a detected bonus, not a requirement).
    //
    // ⚠ A FAILED LISTING IS NOT A REASON TO REFUSE TO START. The grant already passed the fence's
    // own startup checks; this read is for wording only, and a folder that cannot be listed still
    // gets an honest disclosure with no vault paragraph. Failing the whole server here would let a
    // cosmetic read veto a grant the fence accepted.
    const rootListing = await gate.listGrantRoot();
    const listingFailed = isRefusal(rootListing);
    const layers = listingFailed
        ? []
        : await detectLayers(rootListing, async name => !isRefusal(await gate.listDirInGrant(name)));

    // Construct, connect, and disclose the CANONICAL root, which is what the fence actually bounds
    // and may differ from the path the user named.
    const server = createServer({ fsgate: gate, layers, listingFailed });
    const connect = deps.connect ?? (async (target: Server) => {
        await target.connect(new StdioServerTransport());
    });
    await connect(server);

    // ⚠⚠ THE DISCLOSURE GOES TO THE HUMAN TOO, AND THIS IS THE ONLY CHANNEL WHOSE DELIVERY IS
    // CERTAIN. It previously went only into `initialize.instructions` — where the audience is the
    // MODEL, and where the fence plan's own §8 records that no client documents surfacing it at
    // all. So the person who owns the notes was told one word about what they had just exposed:
    // "(read-only)". The rule this server is built to is "say exactly what happens REGARDLESS",
    // and a channel that may reach nobody does not satisfy it.
    //
    // Convention, not invention: printing what you are operating on to stderr is ordinary CLI
    // practice and is what the reference filesystem MCP server does with its allowed directories.
    deps.stderr(disclosure(gate.disclosedRoot(), layers, listingFailed));
    return { started: true, reason: null };
}

/*
 * ⚠ `export { createFsGate };` STOOD HERE AND IS DELIBERATELY GONE, 2026-08-31. Do not restore it.
 *
 * It had no internal consumer — `index.ts` imports the fence itself, and every arm imports the
 * fence package directly — so its only effect was to make this package a SECOND public path to
 * `createFsGate`, alongside the deep import of `dist/fsgate.js` that `files: ["dist"]` allowed.
 * The fence now lives in `wyrd-fence`, which is where a consumer gets it; re-exporting it here
 * would put the extraction back where it started while looking like a convenience.
 */
