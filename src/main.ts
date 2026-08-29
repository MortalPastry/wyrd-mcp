import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createFsGate, isRefusal, type FsGate, type FenceRefusal } from './fsgate.js';
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
    'Wyrd serves the folder you name, read-only. It does not serve anything above it, subject to',
    'the limits below — and EVERY file inside it is readable, of any type, including hidden files',
    'and directories such as .git, .env and .ssh. There is no extension filter and no ignore-file',
    'support, so grant a subfolder containing only what you mean to share.',
    '',
    'Known limits, stated before you grant rather than after: a hard link created inside the',
    'folder can reach a file outside it, and a path component swapped between validation and',
    'opening may be read instead of the one checked — both need write access to that folder. Some',
    'filesystem reparse points are invisible to this runtime and are not detected at all; that one',
    'needs no attacker and can occur in an ordinary cloud-synced folder. Measured on Windows;',
    'macOS and Linux are reasoned but unmeasured.',
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

export { createFsGate };
