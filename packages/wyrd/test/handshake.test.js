import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

import { NO_GRANT_MESSAGE } from '../dist/main.js';
import * as server from '../dist/server.js';
import { preflightJunctionSupport, preflightSymlinkPrivilege } from '../scripts/preflight.mjs';
import { declare as arm, tier2 } from './manifest.mjs';
import { RawMcpClient } from './raw-stdio.mjs';

const temporaryBases = new Set();
process.once('exit', () => {
    for (const base of temporaryBases) fs.rmSync(base, { recursive: true, force: true });
});

function temporaryDirectory(prefix) {
    const base = fs.mkdtempSync(prefix);
    temporaryBases.add(base);
    return base;
}


const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entrypoint = path.join(repoRoot, 'dist', 'index.js');
const packageManifest = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));

/**
 * ⚠⚠ THIS FILE NO LONGER IMPORTS THE FENCE AT ALL, AND THAT IS THE POINT OF THE 2026-09-01 MOVE.
 *
 * `E4-export-inventory`, `E9-grant-injection` and `E12-declaration-inventory` lived here and
 * asserted the fence's SOURCE CONTRACT by calling `createFsGate` directly and by reading a sibling
 * package's build output. They now live in `wyrd-fence/test/surface.test.js`, where the subject and
 * the assertion are in the same package — see
 * `designs/2026-09-01-fence-test-relocation-plan.md`.
 *
 * What stayed is the integration coverage the plan asked for: `E3-read-and-refuse` serves and
 * refuses END TO END over the wire, and `E5-disclosure` asserts what the Reader RENDERS from the
 * canonical root the fence hands it. Both reach the fence through this package's normal server
 * paths and neither names it.
 *
 * ⚠ DO NOT RE-ADD A DIRECT `wyrd-fence` IMPORT HERE. A direct assertion added back would be a
 * fence arm living in a consumer's inventory — the exact coupling that took two slices to remove —
 * and the relocation contract would not catch it, because a NEW id is not one it locked.
 */

const TEST_TIMEOUT_MS = 20_000;

function makeVault() {
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-e2e-'));
    fs.mkdirSync(path.join(base, 'vault', 'subdir'), { recursive: true });
    fs.writeFileSync(path.join(base, 'vault', 'subdir', 'note.md'), 'E2E-NOTE-CANARY');
    fs.mkdirSync(path.join(base, 'outside'), { recursive: true });
    fs.writeFileSync(path.join(base, 'outside', 'secret.md'), 'E2E-OUTSIDE-CANARY');
    return { base, grant: path.join(base, 'vault') };
}

async function withClient(grant, assertions) {
    const client = new RawMcpClient({
        entrypoint,
        entrypointLabel: 'dist/index.js',
        env: { ...process.env, WYRD_GRANT: grant },
        clientInfo: { name: 'wyrd-test-client', version: '0.0.0' }
    });
    try {
        await client.connect();
        await assertions(client);
    } finally {
        await client.close();
    }
}

test('E1-handshake — the server starts on stdio and completes an initialize handshake', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E1-handshake');
    const vault = makeVault();
    try {
        await withClient(vault.grant, client => {
            assert.deepEqual(
                client.getServerVersion(),
                { name: 'wyrd', version: packageManifest.version }
            );
            assert.deepEqual(client.getServerCapabilities(), { tools: {} });
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E2-two-tools — the server declares read and search with real descriptions', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E2-two-tools');
    const vault = makeVault();
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            assert.equal(tools.length, 2);
            assert.deepEqual(tools.map(tool => tool.name), ['read', 'search']);
            assert.equal(tools[0].name, 'read');
            // The description is the product surface: it must state the unit and the
            // truncation contract, because the model's selection loop runs on it.
            assert.match(tools[0].description, /byte/i);
            assert.match(tools[0].description, /next_offset/);
            assert.match(tools[0].description, /truncated/);
            assert.match(tools[1].description, /Markdown/);
            assert.equal(tools[1].inputSchema.properties.query.maxLength, 256);
            assert.equal(tools[1].annotations.readOnlyHint, true);
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E13-read-description — the `read` description states the refusals and the limit, as the model receives it', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E13-read-description');
    // ⚠⚠ THIS SURFACE HAD NO ARM UNTIL 2026-09-01, AND IT IS WHAT THE MODEL IS TOLD THE TOOL DOES.
    // `E2-two-tools` checks `byte`, `next_offset` and `truncated` — the pagination contract — and
    // `E5-disclosure` reads `initialize.instructions`, a different string entirely. Reverting this
    // description to its pre-correction wording ("EVERY file inside the granted folder can be
    // requested" / "What comes BACK is text") passed the whole battery.
    //
    // ⚠ PINS CLAIMS, NOT PHRASING. Each match is a load-bearing fact the code actually keeps, so
    // an ordinary reword survives and a dropped or strengthened claim does not.
    const vault = makeVault();
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            const description = tools[0].description;

            // Reachable: the folder is the whole of the restriction.
            assert.match(description, /ANY PATH inside the\s+granted folder can be requested/i);
            assert.match(description, /no extension filter/i);

            // Readable is narrower, in exactly two ways, and both are refusals the handler makes.
            assert.match(description, /A DIRECTORY is refused with\s+`NOT_A_FILE`/);
            assert.match(description, /not valid UTF-8 is refused with\s+`NOT_TEXT`/);
            // ⚠ The UTF-8 refusal is over BYTES. Said as a file-type rule it becomes a guarantee
            // the code does not make — an ASCII-only `.pdf` slice is returned.
            assert.match(description, /property of the BYTES,\s+not the file extension/i);

            // The limit that reaches OUTSIDE the grant. Stopping at "a hard link can be followed"
            // would disclose nothing: the point is where the target may live.
            assert.match(description, /hard link created inside the folder makes an outside file readable and\s+searchable/i);

            // The refuted wordings, both false in the reassuring direction.
            // ⚠ `\s+` BETWEEN EVERY WORD — this string is hand-wrapped, and a negative pinned to
            // one wrapping stops matching when the break moves, passing for the wrong reason.
            assert.ok(
                !/EVERY\s+file\s+inside\s+the\s+granted\s+folder/i.test(description),
                'the refuted "every file is readable" scope claim must never come back'
            );
            assert.ok(
                !/What\s+comes\s+BACK\s+is\s+text/i.test(description),
                'the refuted single-refusal claim must never come back — a directory is refused too'
            );
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E11-read-only-hint — `read` declares readOnlyHint over the wire', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E11-read-only-hint');
    const vault = makeVault();
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            // ⚠ Asserted through a real client over stdio, never off the source object. The claim
            // is that the annotation ARRIVES — a field the server sets and the transport drops is
            // exactly the failure a source-side assertion cannot see.
            assert.ok(tools[0].annotations, '`read` must carry annotations');
            assert.equal(tools[0].annotations.readOnlyHint, true);
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E3-read-and-refuse — `read` serves an in-grant file and refuses an escape, end to end', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E3-read-and-refuse');
    const vault = makeVault();
    try {
        await withClient(vault.grant, async client => {
            const ok = await client.callTool({ name: 'read', arguments: { path: 'subdir/note.md' } });
            assert.notEqual(ok.isError, true);
            assert.ok(ok.content.some(block => block.text.includes('E2E-NOTE-CANARY')));

            const bad = await client.callTool({ name: 'read', arguments: { path: '../outside/secret.md' } });
            assert.equal(bad.isError, true);
            assert.match(bad.content[0].text, /ESCAPES/);
            assert.ok(!bad.content.some(block => block.text.includes('E2E-OUTSIDE-CANARY')));
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E5-disclosure — initialize.instructions discloses the canonical grant and names nothing outside it', { ...tier2('E5-disclosure'), timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E5-disclosure');
    // ⚠ REGRESSION ARM. Measured 2026-08-28 by driving the built server with a real client:
    // `instructions` was null, so the ONLY disclosure a model received was nothing. The startup
    // line on stderr reaches a terminal, not a model. Ruling 5 requires disclosure AND the fence;
    // the fence was built and proven while this half was absent and read as satisfied.
    const vault = makeVault();
    // The named root is a SYMLINK to the real one — the shape a synced vault actually has
    // (~/notes -> ~/Dropbox/vaults/notes). The disclosure must state the CANONICAL target,
    // because that is the boundary that is enforced; disclosing the alias would describe a
    // fence that is not the one running.
    const alias = path.join(vault.base, 'alias');
    fs.symlinkSync(vault.grant, alias, 'dir');
    try {
        await withClient(alias, client => {
            const instructions = client.getInstructions();
            assert.equal(typeof instructions, 'string', 'instructions must be sent, not omitted');
            assert.ok(instructions.length > 0, 'instructions must not be empty');

            const canonical = fs.realpathSync.native(vault.grant);
            assert.ok(
                instructions.includes(canonical),
                `instructions must name the canonical root ${canonical}; got: ${instructions}`
            );

            // It must not leak the outside sibling this vault deliberately holds, by any spelling.
            const outside = path.join(vault.base, 'outside');
            assert.ok(!instructions.includes(outside), 'instructions must name no path outside the grant');
            assert.ok(!instructions.includes('E2E-OUTSIDE-CANARY'), 'instructions must carry no outside content');

            // ⚠ THE ALIAS MUST NOT APPEAR AT ALL. Naming the path the user typed, alongside or
            // instead of the canonical one, describes a boundary that is not the one enforced.
            assert.ok(
                !instructions.includes(alias),
                `instructions must not name the alias ${alias}; got: ${instructions}`
            );

            // ⚠ NO ABSOLUTE PATH OTHER THAN THE CANONICAL ROOT. Asserting against one prepared
            // sibling lets any other outside path through; this pins the whole class.
            // ⚠ THREE SPELLINGS, NOT ONE. The first version matched only `C:\…`, and said in its
            // own comment that it "pins the whole class" — so a leaked UNC path or any POSIX path
            // passed silently, on a package that declares no `os` restriction. This repo already
            // made that exact mistake once in `volumeIdentity`, which was written against
            // drive-letter spelling and broke on UNC. A comment claiming completeness is what makes
            // an incomplete check a defect rather than a gap: it tells the next reader not to look.
            const absolutes = [
                ...(instructions.match(/[A-Za-z]:\\[^\s,;)]*/g) ?? []),
                ...(instructions.match(/\\\\[^\s,;)]+/g) ?? []),
                ...(instructions.match(/(?:^|\s)\/[^\s,;)]+/gm) ?? []).map(found => found.trim())
            ];
            for (const found of absolutes) {
                assert.ok(
                    canonical.startsWith(found) || found.startsWith(canonical),
                    `instructions names an unrelated absolute path: ${found}`
                );
            }

            // ⚠ EACH LOAD-BEARING CLAIM, AND EACH ONE'S QUALIFIER. The first draft of this text was
            // wrong on all three in the same direction — more reassuring than the truth. These arms
            // fail if a reword drops a claim OR strengthens one past what the code backs.
            // ⚠ "read-only" MUST CARRY ITS SCOPE. Unqualified it is false of the PROCESS, which
            // writes an observation log when WYRD_OBSERVE is set. The claim the code backs is
            // about the TOOL SURFACE, so the arm pins the scoping words beside the phrase rather
            // than the phrase alone.
            assert.match(instructions, /tools are `read` and `search`; both are read-only/i);
            assert.match(instructions, /No tool here writes/i);
            assert.match(
                instructions,
                /In stdio mode, this server opens no network connection of its own/i
            );
            assert.doesNotMatch(
                instructions,
                /(?:^|\n)\s*· This server opens no network connection of its own\./i,
                'the retired transport-neutral network claim must never come back'
            );
            assert.match(instructions, /names the rule that fired/i);

            // ⚠ THE CONTAINMENT CLAIM IS ABOUT THE CHECK, NOT ABOUT THE RESULT. "Only files inside
            // that folder are served" stood here until 2026-09-01 and is refuted by this repo's own
            // `A24-hardlink-limit`, which asserts an outside file IS served through an in-grant
            // hardlink. The arm now pins the weaker, true claim and its pointer to where it fails.
            assert.match(instructions, /Every request is checked against that folder before a file is\s+opened/i);
            assert.match(instructions, /known limits below say where that check\s+does not hold/i);
            assert.ok(
                !/only files inside that folder are served/i.test(instructions),
                'the refuted containment claim must never come back'
            );

            // ⚠ THE DIRECTORY AND UTF-8 REFUSALS ARE PART OF THE SCOPE SENTENCE. Saying "every file
            // can be read" while `read` refuses directories (NOT_A_FILE) and non-UTF-8 bytes
            // (NOT_TEXT) told a reader that `.git` and `.ssh` come back, when only the files inside
            // them do. Reachable and readable are different sets and the text must keep them apart.
            assert.match(instructions, /A DIRECTORY is refused/);
            // ⚠ PAIRED, BECAUSE THE PHRASE ALONE IS NOT A DETECTOR. The wording this arm replaced
            // ("What comes back is text: bytes that are not valid UTF-8 are refused rather than
            // altered, which limits what is READABLE, not what is REACHABLE") CONTAINED
            // `READABLE, not what is REACHABLE` verbatim. So matching it catches a deletion of the
            // clause and NOT the regression it looks like it guards — the old text passes it. The
            // negatives below are what the old text fails.
            assert.match(instructions, /READABLE, not what is REACHABLE/);
            // ⚠ `\s+` BETWEEN EVERY WORD, BECAUSE THIS TEXT IS HAND-WRAPPED. A negative whose words
            // are joined by literal spaces stops matching the moment the line break moves, and a
            // negative that has stopped matching is a guard that passes for the wrong reason.
            assert.ok(
                !/What\s+comes\s+back\s+is\s+text/i.test(instructions),
                'the refuted "what comes back is text" claim — which omitted the directory refusal — must never come back'
            );
            assert.ok(
                !/which\s+limits\s+what\s+is\s+READABLE/i.test(instructions),
                'the single-refusal wording must never come back: both refusals narrow the result, not just UTF-8'
            );

            // ⚠ THE PROCESS WRITE MUST BE DISCLOSED WHEREVER "read-only" IS. `observe.ts` accepts
            // ANY non-empty destination and writes to it unchecked, so a UNC or synced path is
            // accepted; the disclosure has to say the path is not checked, not merely that a log
            // exists.
            assert.match(instructions, /WYRD_OBSERVE/);
            assert.match(instructions, /pathnames it\s+touches, never file contents/i);
            assert.match(instructions, /which is not\s+checked/i);

            // The qualifiers are the half that makes the claims true. Losing one silently
            // re-introduces the exact over-promise two review lenses converged on.
            assert.match(instructions, /NOT a promise your\s+content stays local/i);
            // ⚠⚠ THE REACH-OUTSIDE CLAUSE IS THE WHOLE LIMIT, AND AN ARM THAT STOPS AT "readable"
            // MEASURES NOTHING. Without `wherever on the disk that file lives` the sentence says
            // only that an in-grant hard link makes its target readable — which is true of every
            // ordinary file and discloses no limit at all. The security fact is that the target
            // may sit OUTSIDE the grant, which is what `A24-hardlink-limit` (now the fence's)
            // proves the server actually does. A review lens supplied the passing mutation.
            assert.match(
                instructions,
                /hard link that already exists inside this folder makes the file it points at\s+readable and searchable[\s,]+wherever on the disk that file lives/i
            );
            assert.ok(
                !/nothing leaves this machine/i.test(instructions),
                'the refuted absolute claim must never come back'
            );
            assert.ok(
                !/by any path, for any reason/i.test(instructions),
                'the refuted absolute claim must never come back'
            );
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }
});

test('E8-not-text — a file that is not valid UTF-8 is refused NOT_TEXT, never returned altered', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E8-not-text');
    // ⚠ THE DEFECT THIS PINS WAS SILENT IN BOTH DIRECTIONS. `Buffer.toString('utf8')` substitutes
    // U+FFFD for invalid bytes, so a Latin-1 note came back ALTERED with `truncated: false`, no
    // error, and a header still reporting the original byte count — while the tool description
    // promised `next_offset` reconstruction "byte for byte" in the same breath.
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-nottext-'));
    try {
        fs.mkdirSync(path.join(base, 'vault'), { recursive: true });
        // 0xFF / 0xFE are invalid UTF-8 anywhere. Wrapped in ASCII so a naive "is it empty" check
        // could not pass this by accident.
        fs.writeFileSync(path.join(base, 'vault', 'latin1.md'), Buffer.from([0x48, 0xff, 0xfe, 0x49]));
        fs.writeFileSync(path.join(base, 'vault', 'clean.md'), 'ordinary text');
        // 'é' is C3 A9 — a two-byte codepoint at offset 0, for the boundary arms below.
        fs.writeFileSync(path.join(base, 'vault', 'accent.md'), Buffer.from([0xc3, 0xa9, 0x21]));
        fs.writeFileSync(path.join(base, 'vault', 'payload.bin'), 'PLAIN-ASCII-PAYLOAD');

        await withClient(path.join(base, 'vault'), async client => {
            const bad = await client.callTool({ name: 'read', arguments: { path: 'latin1.md' } });
            assert.equal(bad.isError, true, 'a non-UTF-8 file must be refused, not served');
            assert.match(bad.content[0].text, /NOT_TEXT/);
            // The altered bytes must not appear anywhere in the response.
            assert.ok(
                !bad.content.some(block => block.text.includes('\ufffd')),
                'a refusal must not carry the substituted characters it refused over'
            );

            // The control: the guard must not have made ordinary text unreadable.
            const good = await client.callTool({ name: 'read', arguments: { path: 'clean.md' } });
            assert.notEqual(good.isError, true);
            assert.ok(good.content.some(block => block.text.includes('ordinary text')));

            // ⚠ NO-PROGRESS. `limit: 1` on a file starting with a 2-byte character trims the slice
            // to nothing; an empty buffer round-trips perfectly, so the UTF-8 check passes it and
            // `next_offset` never advances. A client told to "call again with that offset" loops
            // forever. This must refuse, not return an empty success.
            const stuck = await client.callTool({ name: 'read', arguments: { path: 'accent.md', limit: 1 } });
            assert.equal(stuck.isError, true, 'a limit too small to advance must refuse, not loop');
            assert.match(stuck.content[0].text, /LIMIT_TOO_SMALL/);

            // ⚠ AN OFFSET INSIDE A CHARACTER IS A CALLER ERROR, NOT A CORRUPT FILE. Offset 1 of
            // 'é' starts on a continuation byte; reporting that as NOT_TEXT would tell the user
            // their perfectly good file is binary.
            const midpoint = await client.callTool({ name: 'read', arguments: { path: 'accent.md', offset: 1 } });
            assert.equal(midpoint.isError, true);
            assert.match(midpoint.content[0].text, /BAD_OFFSET/);
            assert.ok(
                !/NOT_TEXT/.test(midpoint.content[0].text),
                'a mid-character offset must not be misreported as a non-text file'
            );

            // ⚠ THE RULE IS ABOUT BYTES, NOT FILE NAMES. A `.bin` whose contents are valid UTF-8
            // is served — the claim surfaces now say so explicitly, and this pins that they stay
            // honest about it.
            const asciiBinary = await client.callTool({ name: 'read', arguments: { path: 'payload.bin' } });
            assert.notEqual(asciiBinary.isError, true, 'a .bin containing valid UTF-8 is in scope');
            assert.ok(asciiBinary.content.some(block => block.text.includes('PLAIN-ASCII-PAYLOAD')));
        });
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('E7-layers — Mage layers are named only when present, and a plain folder gets no vault paragraph', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E7-layers');
    // ⚠ THE NEGATIVE HALF IS THE POINT. The old text asserted Arc/Mage/Forum unconditionally, so a
    // stranger with ordinary notes met three directories they do not have and a term they do not
    // know, inside a security disclosure. Detection is what makes the sentence true for BOTH
    // readers; an arm that only checked the vault case would let the noise back in.
    const base = temporaryDirectory(path.join(os.tmpdir(), 'wyrd-layers-'));
    try {
        const plain = path.join(base, 'plain');
        fs.mkdirSync(path.join(plain, 'notes'), { recursive: true });
        fs.writeFileSync(path.join(plain, 'todo.md'), 'ordinary');

        await withClient(plain, client => {
            const text = client.getInstructions();
            assert.ok(!/Mage vault structure/.test(text), 'a plain folder must get no vault paragraph');
            for (const layer of ['Arc/', 'Mage/', 'Forum/']) {
                assert.ok(!text.includes(layer), `a plain folder's disclosure must not mention ${layer}`);
            }
            // The claims themselves must still be there — detection trims the vault note, nothing else.
            assert.match(text, /Every request is checked against that folder before a file is\s+opened/);
        });

        // A PARTIAL vault: Arc/ and Forum/ exist, Mage/ does not. Naming Mage/ here would be the
        // same defect as naming all three on a plain folder, one degree quieter.
        const vault = path.join(base, 'vault');
        fs.mkdirSync(path.join(vault, 'Arc'), { recursive: true });
        fs.mkdirSync(path.join(vault, 'Forum'), { recursive: true });
        fs.writeFileSync(path.join(vault, 'Mage'), 'a FILE named Mage, not a directory');

        await withClient(vault, client => {
            const text = client.getInstructions();
            assert.match(text, /Mage vault structure/);
            assert.match(text, /Arc\/ — immutable source/);
            assert.match(text, /Forum\/ — non-canonical staging/);
            // ⚠ A FILE named `Mage` is not the Mage layer. Detection keys on directories.
            assert.ok(!/Mage\/ — /.test(text), 'a file named Mage must not be reported as the Mage layer');
            assert.match(text, /Grant a subfolder instead/);
        });
    } finally {
        fs.rmSync(base, { recursive: true, force: true });
    }
});

test('E10-junction-preflight — the tier-1 preflight refuses when a junction cannot be created', () => {
    arm('E10-junction-preflight');
    // ⚠ THIS GUARD GATES PORTABLE MODE, SO IT NEEDS AN ARM OF ITS OWN. Portable mode's entire
    // premise is that junctions need no privilege. That premise cannot be measured on this machine
    // — Developer Mode is ON, so both link kinds succeed and the difference is invisible. What CAN
    // be measured is that the guard reports correctly when the capability is absent, which is the
    // half that runs on a stranger's machine. Injected, for the same reason the fence injects.
    const base = {
        mkdtempSync: () => 'C:\\probe',
        mkdirSync: () => {},
        rmSync: () => {},
        tmpdir: () => 'C:\\tmp'
    };

    assert.equal(
        preflightJunctionSupport({ ...base, symlinkSync: () => {} }),
        null,
        'a process that CAN create a junction must pass the tier-1 preflight'
    );

    for (const code of ['EPERM', 'EACCES', 'ENOTSUP', 'EINVAL']) {
        const denied = () => {
            const error = new Error(`denied ${code}`);
            error.code = code;
            throw error;
        };
        const result = preflightJunctionSupport({ ...base, symlinkSync: denied });
        assert.ok(result, `a ${code} junction failure must produce a diagnostic, not null`);
        assert.match(result, /junction/i, 'the diagnostic must name what could not be created');
        // ⚠ The same discipline the symlink preflight learned: say what was NOT run, so the reader
        // cannot mistake an environment refusal for a fence result.
        assert.match(result, /NOTHING WAS RUN/, 'the diagnostic must say nothing was run');
    }

    // A temp directory that cannot be made is a DIFFERENT cause and must not be reported as a
    // junction problem — the exact conflation the symlink preflight was corrected for on 2026-08-29.
    const noTmp = preflightJunctionSupport({
        ...base,
        mkdtempSync: () => {
            const error = new Error('denied');
            error.code = 'EACCES';
            throw error;
        }
    });
    assert.match(noTmp, /temp directory/, 'a temp-dir failure must be named as itself');
    assert.ok(!/cannot create a junction/.test(noTmp), 'a temp-dir failure must not be blamed on junctions');
});

test('E7-shadow — probe kinds and failures preserve the conservative layer warning', async () => {
    arm('E7-shadow');
    const kinds = { Arc: 'file', Mage: 'directory', Forum: 'link' };
    const detected = await server.detectLayers(async name => ({ ok: true, kind: kinds[name] }));
    assert.deepEqual(detected, { layers: ['Mage', 'Forum'], listingFailed: false });

    const denied = await server.detectLayers(async name => name === 'Arc'
        ? { ok: false, reason: 'DENIED', detail: 'denied', resolvedPath: '' }
        : { ok: true, kind: 'directory' });
    assert.deepEqual(denied, { layers: [], listingFailed: true });
});

test('E6-preflight — the suite preflight refuses on denied symlink privilege, and separates the probe stages', () => {
    arm('E6-preflight');
    // ⚠ THIS ARM EXISTS BECAUSE ITS ABSENCE WAS SHIPPED. NEXT.md claimed the preflight "has a
    // mutation test"; the mutation had been run by hand in one session and nothing in the suite
    // touched the guard, so deleting its EPERM branch would have landed green. A review lens caught
    // the claim before it landed. A hand-run mutation is evidence, not a regression test.
    const denied = code => () => {
        const error = new Error(`${code}: denied by the test`);
        error.code = code;
        throw error;
    };
    const base = { mkdtempSync: () => 'C:\\probe', writeFileSync: () => {}, rmSync: () => {}, tmpdir: () => 'C:\\tmp' };

    // The control: everything works, the guard stays out of the way.
    assert.equal(preflightSymlinkPrivilege({ ...base, symlinkSync: () => {} }), null);

    // Denied symlink privilege — the case the guard was built for. Both errnos Windows uses.
    for (const code of ['EPERM', 'EACCES']) {
        const result = preflightSymlinkPrivilege({ ...base, symlinkSync: denied(code) });
        assert.equal(typeof result, 'string', `${code} must refuse`);
        assert.match(result, /cannot create symlinks/);
        assert.match(result, /Developer Mode/);
        assert.match(result, /NOTHING WAS RUN/);
    }

    // ⚠ THE STAGES MUST NOT BE CONFLATED. An ACL that denies ordinary file creation must not be
    // diagnosed as a missing symlink privilege — symlinkSync is never reached in that case, and
    // telling the user to enable Developer Mode is a confident diagnosis of the wrong cause.
    const wrongStage = preflightSymlinkPrivilege({
        ...base,
        writeFileSync: denied('EPERM'),
        symlinkSync: () => assert.fail('symlinkSync must not be reached when the write stage fails')
    });
    assert.match(wrongStage, /NOT the symlink privilege/);
    assert.ok(!/Developer Mode/.test(wrongStage), 'the write-stage failure must not blame Developer Mode');

    // An unexpected errno is reported as itself, not folded into the privilege story.
    const odd = preflightSymlinkPrivilege({ ...base, symlinkSync: denied('ENOSPC') });
    assert.match(odd, /unexpected reason \(ENOSPC\)/);
    assert.ok(!/Developer Mode/.test(odd), 'an unrelated errno must not blame Developer Mode');
});

/* ===============================================================================================
 * THE SHARED CLAIM SET — one declaration, every disclosure surface, checked against each other.
 *
 * ⚠⚠ WHY THIS EXISTS. wyrd tells a user what it can reach and what it writes across several
 * artefacts: `README.md`, `PRIVACY.md`, `NO_GRANT_MESSAGE` in `src/main.ts`, `disclosure()` and the
 * `read` tool declaration in `src/server.ts`, the MCP registry manifest `server.json`, and the npm
 * manifest `package.json`. They disagreed with each other and with the code three separate times on
 * 2026-09-01, and each repair pinned one more string with one more arm: `S14-no-grant-claims` for
 * the refusal message, `E13-read-description` for the tool description, `E5-disclosure` for the
 * instructions. Every one of those validates a SURFACE AGAINST A REGEX. None of them compares the
 * surfaces to one another. So they could drift apart while every arm passed — a check that
 * validates one side is half a check.
 *
 * This is the other half. There is ONE table of claims below. Each claim names, for every surface,
 * either the pattern that surface must carry or the reason it is allowed to be silent. Adding a
 * surface, or changing a claim, is one edit in one place; and a claim that forgets to say anything
 * about a surface fails, so the table cannot go quietly incomplete.
 *
 * ⚠⚠ THE SURFACE LIST IS NOW DERIVED, BECAUSE THE HAND-WRITTEN ONE WAS WRONG FOUR TIMES: it read
 * 4, then 5, then 6, then 8, each correction made by a different reader, and the eighth reading was
 * still a count somebody had typed. A list that has to be maintained by hand in order to be a guard
 * against things drifting out of a list is the defect it was built to catch. So:
 *
 *   · THE SHIPPED DOCUMENTS come from `package.json`'s own `files` array — every `.md` entry in it.
 *     A document added to what npm publishes joins the claim table's obligations with no edit here,
 *     and one dropped from `files` disappears from the surfaces while every claim that names it
 *     fails loudly. This is a STRONGER derivation than the brief for this repair asked for, which
 *     expected the two Markdown files to stay an explicit list.
 *   · THE TOOL SURFACES come from `listTools()` OVER THE WIRE, one per tool, and each is EVERY
 *     STRING IN THAT TOOL OBJECT — name, title, description, and every string nested inside
 *     `inputSchema`, joined. Naming `description` alone is what left the input-schema property
 *     descriptions uncovered: `path`'s hint said "Forward or back slashes both work", which is
 *     false off Windows, and nothing here could see it. A second tool, a new property, or a new
 *     description on an existing property now joins the covered set with no edit, and a second tool
 *     makes every claim fail until the table accounts for it — which is the correct outcome, since
 *     `search` and `list` are specified and would widen what this server discloses.
 *   · THE MANIFESTS are walked for every string under a `description` key, `server.json` and
 *     `package.json` alike, by the same function and for the same reason.
 *
 * ⚠ WHAT CANNOT BE DERIVED, AND WHY, because an explicit list needs its reason written down:
 *
 *   · `NO_GRANT_MESSAGE` is a named export of `dist/main.js`. The alternative — treating EVERY
 *     exported string as a disclosure surface — would make an unrelated constant (a usage line, a
 *     version banner) a surface obliged to carry fourteen claims, and the exemptions written to
 *     silence it would be the exemption-farming this table's own notes warn about.
 *   · `initialize.instructions` is one named field of the initialize result. Walking that result's
 *     strings would add the protocol version and the server name, which disclose nothing.
 *
 * ⚠ AND `wyrd-fence`'s OWN `package.json` IS DELIBERATELY NOT A SURFACE HERE. It is a different
 * published product's registry page, addressed to a programmer choosing a library rather than to a
 * user granting a folder; most of this table (the tool surface, the observation log, retention,
 * the network) says nothing about it, so it would enter carrying a dozen written exemptions. Its
 * limits have their own home and their own design — `designs/2026-09-02-fence-published-limits.md`.
 *
 * ⚠ SILENCE IS PERMITTED, FALSEHOOD IS NOT. The surfaces are not obliged to say the same amount:
 * a 400-character registry manifest legitimately says less than the README. What `silent` means is
 * "this surface does not state this claim AND does not state anything that contradicts it" — and
 * the second half is what `RETIRED` below enforces, against every surface without exception.
 *
 * ⚠⚠ WHAT THIS ARM CANNOT CATCH, STATED PLAINLY BECAUSE THE TEMPTATION IS TO CLAIM MORE.
 *
 *   · IT IS REGEX OVER PROSE. It cannot detect a PARAPHRASE that keeps a false meaning in
 *     different words. "wyrd will not read past the folder" carries the retired containment claim
 *     and matches no pattern here; the arm goes green. `RETIRED` is a list of wordings KNOWN to
 *     have been wrong, not a semantic check, and it can only ever grow by someone noticing.
 *   · A SURFACE CAN SATISFY EVERY PATTERN AND STILL MISLEAD BY OMISSION — of something that is not
 *     in this table at all. The table is a floor on what must be said, never a ceiling on what the
 *     surface as a whole conveys.
 *   · THE `silent` REASONS ARE HUMAN JUDGEMENTS AND NOTHING MACHINE-CHECKS THEM. Marking a claim
 *     silent on a surface that ought to carry it makes this arm agree with the omission. That is
 *     the seam, and the only guard on it is that the reason must be written down and read.
 *   · ⚠⚠ IT MAKES THE SURFACES AGREE. IT CANNOT MAKE THEM TRUE. On 2026-09-02 this arm was found
 *     to be pinning THREE FALSE CLAIMS in place across the surfaces it covers, green throughout,
 *     because every surface said the same wrong thing. Consistency is the only property here.
 *     `E15-refusal-vocabulary` below closes one named slice of that gap by deriving one side of its
 *     comparison from the program rather than from prose; the rest is still found only by reading.
 *   · IT DOES NOT CHECK THE SURFACES AGAINST THE CODE. `E3-read-and-refuse`, `E8-not-text` and the
 *     fence's own arms do that. This one checks that the stories agree; a claim they all state and
 *     the code has stopped keeping would pass here and fail there.
 *
 * ⚠ THE SURFACES ARE LOADED AS THE READER RECEIVES THEM — the runtime strings over the wire
 * through a real client, the documents off disk, the manifests through `JSON.parse`. Never as
 * source text. That is deliberate: `src/server.ts` contains a comment quoting a retired wording in
 * order to warn against it, and a source-level scan would refuse on the warning.
 */

/** Asterisks stripped (Markdown emphasis splits a phrase), whitespace flattened (hand-wrapped). */
function flatten(text) {
    return text.replace(/\*/g, '').replace(/\s+/g, ' ').trim();
}

/**
 * The claim set. `carried` is what a surface MUST say; `silent` is why it need not.
 * ⚠ Every claim must name EVERY DERIVED SURFACE across the two, and the check below refuses
 * otherwise. No count is written here: the count is what kept going stale.
 */
/**
 * ⚠ ONE REASON, WRITTEN ONCE, FOR THE SURFACE THAT LEGITIMATELY CARRIES ALMOST NOTHING.
 *
 * `package.json`'s `description` is a single sentence rendered in npm search results. It cannot
 * carry this table and should not try. Seventeen separately-worded exemptions saying so would read
 * as seventeen judgements and be one — and a reader who scrolls past seventeen exemptions has
 * learnt that exemptions are cheap, which is the seam this table's own notes name.
 *
 * ⚠ SILENCE IS NOT LICENCE: this surface is still checked against every RETIRED wording, like every
 * other. If the blurb ever grows a real claim, this constant is the ONE place a reader has to
 * reconsider, instead of seventeen copies where sixteen would be missed.
 */
const NPM_BLURB = 'the npm registry description is one sentence shown in search results; it names the exposure and the fence and states no limit, refusal, retention or write claim for this to qualify. Still checked against every retired wording.';

const CLAIMS = [
    {
        id: 'DIRECTORY_REFUSED',
        says: 'a directory is refused rather than served',
        evidence: {
            grade: 'derived',
            limit: 'Deriving the refusal path does not prove every directory shape is refused on every supported filesystem.'
        },
        carried: {
            'README.md': [/A directory is refused \(`NOT_A_FILE`\)/i],
            'PRIVACY.md': [/a directory is refused, and so are bytes/i],
            'NO_GRANT_MESSAGE': [/because a directory is refused/i],
            'initialize.instructions': [/A DIRECTORY is refused, so \.git and \.ssh are refused as directories/],
            'tool:read':[/A DIRECTORY is refused with `NOT_A_FILE`/],
            'server.json': [/a directory is refused/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB
        }
    },
    {
        id: 'UTF8_REFUSED',
        says: 'bytes that are not valid UTF-8 are refused, never returned altered',
        evidence: {
            grade: 'derived',
            limit: 'Deriving the refusal path does not prove every invalid byte sequence is refused on every supported runtime.'
        },
        carried: {
            'README.md': [/Bytes that are not valid UTF-8 are refused \(`NOT_TEXT`\) rather than returned altered/i],
            'PRIVACY.md': [/bytes that are not valid UTF-8/i],
            'NO_GRANT_MESSAGE': [/so are bytes that are not valid UTF-8/i],
            'initialize.instructions': [/bytes that are not valid UTF-8 are refused rather than altered/i],
            'tool:read':[/not valid UTF-8 is refused with `NOT_TEXT` rather than returned with substituted characters/i],
            'server.json': [/so are bytes that are not valid UTF-8/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB
        }
    },
    {
        id: 'RULE_IS_BYTES_NOT_EXTENSION',
        says: 'the UTF-8 refusal is a property of the requested bytes, not of the file extension',
        evidence: {
            grade: 'observed',
            arms: ['E8-not-text'],
            limit: 'The exercised cases distinguish bytes from extensions only for sampled files, not every encoding or filename.'
        },
        carried: {
            'README.md': [/the bytes of the requested slice, never the file extension/i],
            'tool:read':[/property of the BYTES, not the file extension/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'PRIVACY.md': 'states the coarser reachable/readable split and routes the reader to the README for the fence\'s limits; it makes no file-type claim to qualify',
            'NO_GRANT_MESSAGE': 'a pre-grant refusal with no room for the byte/extension distinction; it says only that non-UTF-8 bytes are refused, which is true as far as it goes',
            'initialize.instructions': 'same — it states the refusal without characterising it as a type filter, so there is nothing to correct',
            'server.json': 'a short registry description; it states the refusal and claims nothing about extensions'
        }
    },
    {
        id: 'HARDLINK_REACHES_OUTSIDE',
        says: 'a hard link already inside the grant makes its target readable and searchable wherever on the disk that target lives',
        evidence: {
            grade: 'observed',
            arms: ['A24-hardlink-limit', 'SR28-hardlink-search-limit'],
            limit: 'The exercised hard-link case is one filesystem arrangement on one platform, not every disk, mount, or permission regime.'
        },
        carried: {
            'README.md': [/hard link inside the granted folder makes the file it points at readable and searchable, wherever on the disk that file lives/i],
            'PRIVACY.md': [/hard link that already exists inside the granted folder makes the file it points at readable and searchable, wherever that file lives/i],
            'NO_GRANT_MESSAGE': [/hard link that already exists inside the folder makes the file it points at readable and searchable wherever on the disk that file lives/i],
            'initialize.instructions': [/hard link that already exists inside this folder makes the file it points at readable and searchable, wherever on the disk that file lives/i],
            'tool:read':[/hard link created inside the folder makes an outside file readable and\s+searchable/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'server.json': 'the manifest states the scope of the grant and defers every fence limit to the README and to the running server\'s disclosure; it makes no containment promise for this to qualify'
        }
    },
    {
        id: 'HARDLINK_INVISIBLE_TO_INSPECTION',
        says: 'ordinary folder inspection will not show a hard link as a link',
        evidence: {
            grade: 'unverified',
            limit: 'No package mechanism observes file-manager presentation, which varies by file manager, platform, and configuration.'
        },
        carried: {
            'README.md': [/Ordinary folder inspection will not show it as a link/i],
            'PRIVACY.md': [/ordinary folder inspection will not show it as a link/i],
            'NO_GRANT_MESSAGE': [/ordinary folder inspection will not show it as a link/i],
            'initialize.instructions': [/ordinary folder inspection will not show it as a link/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'tool:read':'addressed to the MODEL, which does not inspect the folder in a file manager; it carries the reach, which is the half that bears on what the model may request',
            'server.json': 'as above — no containment promise, no limits section'
        }
    },
    {
        id: 'READ_ONLY_IS_TOOL_SCOPED',
        // ⚠ "outside the `cert` command" IS LOAD-BEARING AND WAS MISSING UNTIL 2026-09-15. The claim
        // said the process writes in exactly one case; `wyrd cert` writes a certificate and a key
        // (`src/index.ts:35`, `src/cert.ts:249`), so the table was false while `README.md:227`
        // carried the qualifier correctly — the shipped prose was more honest than the row
        // describing it. Found by a review lens reading the code rather than the table.
        says: 'read-only is a property of the TOOL surface; outside the explicit `cert` command the process itself writes in exactly one case',
        evidence: {
            grade: 'derived',
            limit: 'Program-to-surface comparison does not prove the process has no other write path, dependency effect, or side effect.'
        },
        carried: {
            'README.md': [
                /It registers `read` and `search`\. Neither tool writes, moves, renames or deletes/i,
                /The one thing that can persist on your disk is the optional observation log/i
            ],
            'PRIVACY.md': [
                /No tool writes, moves, renames or deletes\. The server registers `read` and `search`/i,
                /The process itself can write in exactly one case/i
            ],
            'NO_GRANT_MESSAGE': [
                /It registers `read` and `search`; neither writes, moves or deletes/i,
                /makes the process itself ATTEMPT, at exit, to write/
            ],
            'initialize.instructions': [
                /tools are `read` and `search`; both are read-only/i,
                /The PROCESS can write in exactly one case/
            ]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            // ⚠ NOT `NPM_BLURB` — this is the one claim the npm sentence brushes against, so it
            // gets its own judgement rather than the shared one. Same call as `server.json` below,
            // and the same discomfort with it.
            'package.json': 'the npm sentence calls the EXPOSURE read-only, which is true of every path wyrd serves, and never mentions the observation log. The same judgement call as server.json, made in fewer words and read by more people',
            'tool:read':'it describes the `read` tool and makes no read-only guarantee of its own; `E11-read-only-hint` asserts the machine-readable annotation beside it',
            'server.json': 'the manifest calls the EXPOSURE read-only, which is true of every path wyrd serves; the observation log is not part of the exposure and the manifest never mentions it. ⚠ THE ONE JUDGEMENT CALL IN THIS TABLE — an unqualified "read-only" in a registry blurb is the nearest thing here to a claim that says less and could be read as more'
        }
    },
    {
        id: 'OBSERVE_DESTINATION_UNCHECKED',
        says: 'the observation log is written to exactly the path supplied, and that path is not checked',
        evidence: {
            grade: 'derived',
            limit: 'Reading the write call shows no check between the supplied path and the write; it does not prove no check exists elsewhere, on every destination type or platform.'
        },
        carried: {
            'README.md': [/exactly the path you supply, and that path is not checked/i],
            'PRIVACY.md': [/exactly the path you supply, and that path is not checked/i],
            'NO_GRANT_MESSAGE': [/to exactly the path you supply, which is not checked and may be a network share/i],
            'initialize.instructions': [/to exactly the path that variable names, which is not checked and may be a network share/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'tool:read':'WYRD_OBSERVE is not a tool concern and the description never mentions it',
            'server.json': 'the manifest declares WYRD_GRANT only; it does not offer WYRD_OBSERVE as a configurable variable'
        }
    },
    {
        id: 'OBSERVE_WRITE_IS_ATTEMPTED',
        says: 'the log write is ATTEMPTED at exit and its failure is silent, so a missing log is not evidence',
        evidence: {
            grade: 'derived',
            limit: 'Reading the exit hook and its catch block does not prove the write is attempted under every termination mode, nor that failure is silent on every host.'
        },
        carried: {
            'README.md': [/The write is attempted at exit and a failure is silent/i],
            'PRIVACY.md': [/The write is attempted at exit and a failure is silent/i],
            'NO_GRANT_MESSAGE': [/The write is attempted, not guaranteed/, /if it fails it fails silently/i],
            'initialize.instructions': [/The write is attempted, not guaranteed/, /if it fails it fails silently/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'tool:read':'as above — not a tool concern',
            'server.json': 'as above — WYRD_OBSERVE is not declared there'
        }
    },
    {
        id: 'OBSERVE_RECORDS_PATHS_NOT_CONTENT',
        says: 'the observation log records pathnames, never file contents',
        evidence: {
            grade: 'unverified',
            limit: 'A 2026-09-02 measurement found no file contents in its sampled records, but that dated measurement is recorded only in a comment and is not re-run.'
        },
        carried: {
            'README.md': [/It records pathnames, not file contents/i],
            /**
             * ⚠ THIS PATTERN PINNED A FALSE SENTENCE UNTIL 2026-09-02: "Each record holds a
             * pathname and the name of the filesystem primitive that was called." MEASURED, by
             * arming the observer and reading one file through the running server: of 1,904 records
             * one was the `instrumentation-ready` marker (no call, no path) and 459 recorded a
             * DESCRIPTOR as `<fd N>` rather than a pathname. The per-record universal was wrong.
             * ⚠ The "no file contents" half was true and was measured in the same run — the file's
             * own text appeared in no record — so it is what this pattern now pins.
             */
            'PRIVACY.md': [/No record holds file contents/i],
            // ⚠ THE WEAKEST CARRIER, AND DELIBERATELY ACCEPTED AS ONE. The refusal message states
            // WHAT is logged and not what is excluded. That is less than the others say and it is
            // not false; requiring the full sentence here would be requiring the surface to grow.
            'NO_GRANT_MESSAGE': [/a diagnostic log of the PATHNAMES it touches/],
            'initialize.instructions': [/log the pathnames it touches, never file contents/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'tool:read':'as above — not a tool concern',
            'server.json': 'as above — WYRD_OBSERVE is not declared there'
        }
    },
    {
        id: 'ANY_PATH_REQUESTABLE',
        says: 'any path inside the granted folder can be requested, hidden entries included, apart from a handful of name spellings refused as input',
        evidence: {
            grade: 'derived',
            limit: 'Program-derived name and refusal rules do not prove every otherwise eligible path is requestable on every filesystem.'
        },
        /**
         * ⚠⚠ THE SECOND PATTERN IS NOT DECORATION AND IT IS NOT SEPARABLE FROM THE FIRST.
         *
         * Until 2026-09-02 this claim was the bare universal, carried word for word by six
         * surfaces, and it was FALSE — this arm was holding a falsehood in place across all of
         * them, which is what a consistency guard does when the thing it makes consistent is wrong.
         *
         * MEASURED on this Windows host on 2026-09-02, not reasoned: `NUL.md`, `CON`, `COM1` and
         * `nul` were CREATED inside a grant, appeared in `readdir`, and every one was refused
         * `RESERVED_NAME` by the fence. A drive-relative spelling (`C:notes`) is refused `BAD_INPUT`
         * by a screen with no platform gate at all, so on macOS and Linux — where `C:notes` is an
         * ordinary filename — a file that genuinely sits inside the grant is unreachable through
         * the tool. Two lexical screens, both correct and deliberate; only the prose overclaimed.
         *
         * The qualifier lives INSIDE this claim rather than as a claim of its own so that no
         * surface can be marked silent on the correction while still carrying the universal.
         */
        carried: {
            'README.md': [
                /any path inside the granted folder can be requested, `\.env` and `\.git\/config`/i,
                /name spellings refused as input/i
            ],
            'PRIVACY.md': [
                /Any path inside the granted folder can be requested, of any type, hidden entries included/i,
                /name spellings refused as input/i
            ],
            'NO_GRANT_MESSAGE': [
                /ANY PATH INSIDE IT CAN BE REQUESTED/,
                /NAME SPELLINGS are refused as input before anything is opened/
            ],
            'initialize.instructions': [
                /ANY PATH INSIDE that folder can be requested, hidden entries included/,
                /NAME SPELLINGS are refused as input before anything is opened/
            ],
            'tool:read':[
                /ANY PATH inside the granted folder can be requested, hidden entries included/,
                /NAME SPELLINGS refused as input before anything is opened/
            ],
            'server.json': [
                /Any path inside it can be requested, hidden entries included/i,
                /name spellings refused as input/i
            ]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB
        }
    },
    {
        id: 'NO_EXTENSION_FILTER',
        says: 'there is no extension filter and no ignore-file support',
        evidence: {
            grade: 'derived',
            limit: 'Program derivation does not prove that no indirect platform, runtime, or dependency filter can affect a request.'
        },
        carried: {
            'README.md': [/There is no extension filter and no ignore-file support/i],
            'PRIVACY.md': [/There is no extension filter and no ignore-file support/i],
            'NO_GRANT_MESSAGE': [/there is no extension filter and no ignore-file support/i],
            'initialize.instructions': [/There is no extension filter, no ignore-file support/i],
            'tool:read':[/There is no extension filter, no ignore-file support/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'server.json': 'it makes the same point positively — any path, hidden entries included, .env and .git/config named — which is the operative half in 400 characters'
        }
    },
    {
        id: 'READABLE_NARROWER_THAN_REACHABLE',
        says: 'the two refusals limit what is READABLE, not what is REACHABLE; the folder is the whole of the restriction',
        evidence: {
            grade: 'unverified',
            limit: 'No finite set of refusals and reachable samples can establish that the granted folder is the WHOLE of the restriction; this row records that this is a universal negative.'
        },
        carried: {
            'README.md': [/Both of those limit what is readable, not what is reachable/i],
            'PRIVACY.md': [/That limits what is readable, not what is reachable, so the folder is still the whole of the restriction/i],
            'NO_GRANT_MESSAGE': [/that limits what is READABLE, not what is REACHABLE/],
            'initialize.instructions': [/Both limit what is READABLE, not what is REACHABLE/],
            'tool:read':[/The granted folder is the whole of the restriction/, /Nothing here is a filter on what may be reached/],
            'server.json': [/That limits what is readable, not what is reachable/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB
        }
    },
    {
        id: 'SEARCH_TERM_CACHE_NO_DISK',
        says: 'search retains normalized terms and anchors in memory but no raw text and writes no search data to disk',
        evidence: {
            grade: 'derived',
            limit: 'Source inspection and the bounded cache arm cover this search engine, not arbitrary dependencies or future backends.'
        },
        carried: {
            'README.md': [/Search uses a lazy in-memory cache of normalized terms and anchors.*It holds no raw text/i],
            'PRIVACY.md': [/Search retains normalized terms and anchors in a lazy in-memory cache.*It retains no raw text/i],
            'initialize.instructions': [/Search builds a lazy in-memory cache of normalized terms and anchors; it holds no raw/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'NO_GRANT_MESSAGE': 'printed BEFORE anything is granted, when nothing has been read; it is about whether to grant, not about retention',
            'tool:read':'a per-call contract; retention is a property of the server, and the instructions carry it to the same model in the same session',
            'server.json': 'no room; the running server discloses it at startup to every client that connects'
        }
    },
    {
        id: 'LIMITS_NOT_EXHAUSTIVE',
        says: 'the list of known limits is what is known, not a proof that nothing else exists',
        evidence: {
            grade: 'unverified',
            limit: 'No finite check here can establish that a list contains every unknown limit; this row records that epistemic boundary.'
        },
        carried: {
            'README.md': [/This list is what is known, not a proof that nothing else exists/i],
            'NO_GRANT_MESSAGE': [/This list is what is known, not a proof that nothing else exists/i],
            'initialize.instructions': [/This list is what is known, not a proof that nothing else exists/i],
            'tool:read':[/This list is what is known, not a proof that nothing else exists/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'PRIVACY.md': 'it carries no list of its own to qualify — it names the sharpest limit and points at the README for the rest, which is where the completeness caveat sits',
            'server.json': 'no limits section, and no completeness claim to qualify'
        }
    },
    {
        // ⚠ THIS CLAIM WAS `REPARSE_POINTS_UNDETECTED` UNTIL 2026-09-02, AND IT WAS FALSE ON ALL
        // FOUR SURFACES AT ONCE. `resolveInGrant` arbitrates through `realpathNative` on EVERY
        // successful resolution (the gate that read `context.sawReparse ||` was deleted 2026-08-29),
        // so an unclassified tag is checked against the grant like any other component. What the
        // surfaces must now carry is BOTH halves: containment holds, and the refusal-class oracle
        // does not close for an unclassified INTERMEDIATE tag whose outside descendant is missing
        // or denied — that shape refuses inside `walk`, before the arbitration.
        id: 'REPARSE_TAGS_UNCLASSIFIED',
        says: 'some filesystem reparse points cannot be classified by this runtime; a path resolving through one is still checked against the granted folder, and what remains open is that a refusal can distinguish missing from unreadable for a file outside it',
        evidence: {
            grade: 'derived',
            limit: 'Derived from the arbitration control flow and its recorded reasoning; no arm exercises an unclassifiable tag, because none can be created on this runtime.'
        },
        carried: {
            'README.md': [/filesystem reparse points cannot be classified by this runtime/i, /still checked against the granted folder/i],
            'NO_GRANT_MESSAGE': [/Some filesystem reparse points cannot be classified by this runtime/i, /still checked against the folder/i],
            'initialize.instructions': [/Some filesystem reparse points cannot be classified by this runtime/i, /still checked against this folder/i],
            'tool:read':[/filesystem reparse points cannot be classified by this runtime/i, /still checked against the folder/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'PRIVACY.md': 'defers the limits list to the README, as above',
            'server.json': 'the manifest carries no known-limits section at all; the running server discloses every one of them to the client at startup'
        }
    },
    {
        id: 'TOCTOU_SWAP',
        says: 'a path component swapped between validation and opening may be read instead of the one checked',
        evidence: {
            // ⚠ `derived`, NOT `observed`, corrected 2026-09-15. `A35-root-moved` stages a swap and
            // asserts the refusal `ROOT_MOVED` — it proves the ROOT re-check fires, never that a
            // swapped COMPONENT is opened instead of the one checked, which is what this claim
            // says. The race window is read off the validate-then-open sequence in the fence's read
            // path. A staged swap that the fence CATCHES is not evidence for a swap it MISSES.
            grade: 'derived',
            limit: 'Read off the validate-then-open sequence in the fence read path; no arm opens a swapped component, and the window is not quantified on any platform.'
        },
        carried: {
            'README.md': [/A path component swapped between validation and opening may be read instead of the one that was checked/i],
            'NO_GRANT_MESSAGE': [/A path component swapped between validation and opening may be read instead of the one checked/i],
            'initialize.instructions': [/A path component swapped between validation and opening may be read instead of the one checked/i],
            'tool:read':[/path component swapped after validation may be read instead of the one checked/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'PRIVACY.md': 'defers the limits list to the README, as above',
            'server.json': 'the manifest carries no known-limits section at all; the running server discloses every one of them to the client at startup'
        }
    },
    {
        id: 'CLIENT_FORWARDING_NOT_WYRDS',
        says: 'in stdio mode wyrd opens no network connection of its own, and that is NOT a promise the content stays local',
        evidence: {
            grade: 'derived',
            limit: 'Derivation covers the selected stdio path, not dependency internals, client forwarding, or every runtime configuration.'
        },
        carried: {
            'README.md': [/In stdio mode it opens no network connection of its own/i, /What your AI client does with the content is between you and that client/i],
            'PRIVACY.md': [/In stdio mode, it opens no network connection of its own/i, /What happens next is between you and that client/i],
            'initialize.instructions': [/In stdio mode, this server opens no network connection of its own\. That is NOT a promise your content stays local/i]
        },
        silent: {
            'tool:search': 'search describes its own query and results; the shared instructions disclose server-wide limits and retention',
            'package.json': NPM_BLURB,
            'NO_GRANT_MESSAGE': 'printed before a grant exists and before any content can move; it makes no locality claim to qualify',
            'tool:read':'the model is the forwarding party, not a reader who could act on the warning; the instructions carry it in the same session',
            'server.json': 'the manifest makes no locality or network claim for this to qualify; the disclosure the client receives at startup carries it'
        }
    }
];

/**
 * ⚠⚠ THE NEGATIVES — wordings REFUTED on 2026-09-01, which must appear in NO surface.
 *
 * Every one was false in the reassuring direction, which is the worst one. They are checked against
 * EVERY surface without exception, including the surfaces a given claim lets stay silent: being
 * allowed to say less is never permission to say something false.
 */
const RETIRED = [
    {
        id: 'NOTHING_ABOVE',
        pattern: /\b(?:nothing|anything)\s+above\b/i,
        why: 'the retired containment claim ("it does not serve anything above it"). An in-grant hard link reaches outside the grant, so no surface may promise this.'
    },
    {
        id: 'EVERY_FILE_READABLE',
        pattern: /\bevery\s+file\b(?:\s+\S+){0,7}?\s+readable\b/i,
        why: 'the retired scope claim ("EVERY file inside it is readable"). A directory and non-UTF-8 bytes are refused, so readable is narrower than reachable.'
    },
    {
        id: 'ONLY_FILES_INSIDE',
        pattern: /\bonly\s+files\s+inside\b/i,
        why: 'the retired containment claim in its other wording. The fence CHECKS every request against the folder; it does not guarantee that only files inside it can be reached.'
    },
    {
        id: 'OF_MARKDOWN',
        pattern: /\bof\s+Markdown\b/i,
        why: 'the retired file-type claim. There is no extension filter; the UTF-8 rule is over bytes, and a folder of notes is not a folder of Markdown.'
    },
    {
        id: 'REPARSE_UNDETECTED',
        pattern: /reparse points are invisible to this runtime|not detected at all/i,
        why: 'the retired reparse claim. It errs in the SAFE direction, which is why it survived four surfaces and this arm: `resolveInGrant` arbitrates through `realpathNative` on every successful resolution, so an unclassified tag IS checked against the grant. Saying otherwise understates the fence and misdescribes what a consumer must guard against.'
    },
    {
        id: 'STAYS_ON_YOUR_DISK',
        pattern: /\bstays\s+on\s+your\s+disk\b/i,
        // ⚠ CONDITIONAL, NOT FORBIDDEN. The observation log genuinely stays on your disk ONLY IF
        // the path supplied is on your disk and unsynchronised, and both documents say exactly
        // that. What is refuted is the UNQUALIFIED promise, so the qualifier is what is checked —
        // and it is checked on the flattened text, because in both documents it falls on the
        // following line.
        qualifiedBy: /^ only if\b/,
        why: 'an UNCONDITIONAL "stays on your disk". WYRD_OBSERVE writes to an unchecked path that may be a UNC path, a network share or a cloud-synced folder.'
    }
];

/**
 * Every string the registry manifest ships under a `description` key, in document order.
 *
 * ⚠ WALKED, NOT NAMED. Listing `description`, `packageArguments[0].description` and
 * `environmentVariables[0].description` would be a claim that today's manifest is the whole shape,
 * and a claim added to a second package argument would leave this surface without an edit here
 * noticing. The walk is the derivation.
 */
function collectDescriptions(node, found = []) {
    if (Array.isArray(node)) {
        for (const item of node) collectDescriptions(item, found);
    } else if (node !== null && typeof node === 'object') {
        for (const [key, value] of Object.entries(node)) {
            if (key === 'description' && typeof value === 'string') found.push(value);
            else collectDescriptions(value, found);
        }
    }
    return found;
}

/**
 * EVERY string anywhere inside a parsed object, in document order.
 *
 * ⚠ USED FOR THE TOOL DECLARATIONS, AND WALKING IS THE WHOLE POINT. Reading `tool.description`
 * alone is a claim that the description is the only prose a tool ships to the model, and it is not:
 * `inputSchema.properties.<name>.description` is sent on every connection and is read by the model
 * before it composes an argument. One of those said "Forward or back slashes both work" — false off
 * Windows — for as long as this arm named a single field. Walking picks up `name`, `title`, every
 * property description, and anything a future schema adds, with no edit here.
 *
 * ⚠ SCHEMA KEYWORDS COME ALONG ("object", "string", "integer", "path") AND THAT IS ACCEPTED. They
 * are noise, not claims: no claim pattern and no retired wording can match on them, and excluding
 * them would mean naming which keys count, which is the hand-maintained list being removed.
 */
function collectStrings(node, found = []) {
    if (typeof node === 'string') found.push(node);
    else if (Array.isArray(node)) for (const item of node) collectStrings(item, found);
    else if (node !== null && typeof node === 'object') for (const value of Object.values(node)) collectStrings(value, found);
    return found;
}

/**
 * Load every disclosure surface AS THE READER RECEIVES IT, and derive which ones exist.
 *
 * ⚠⚠ THE RETURNED KEYS ARE THE SURFACE LIST. There is no `SURFACE_NAMES` array any more: the one
 * that used to sit here was hand-written, was wrong four times running (4 → 5 → 6 → 8), and was the
 * exact defect the claim table exists to prevent, sitting inside the claim table. The completeness
 * check below now runs against whatever this function found, so a surface that appears without the
 * table accounting for it fails every claim, and a claim naming a surface that no longer loads
 * fails too. Both directions, neither of them a number anyone types.
 *
 * ⚠ `client` MUST BE A LIVE CONNECTION. `instructions` and the tool declarations are asserted as
 * they ARRIVE, never off the source objects: a field the server sets and the transport drops is the
 * failure a source-side read cannot see, and `src/server.ts` carries a comment quoting a retired
 * wording as a warning, which a source scan would refuse on.
 */
function loadSurfaces(client, tools) {
    const surfaces = {};

    // ⚠ THE SHIPPED DOCUMENTS, FROM `files`. What npm publishes is the definition of a document
    // surface, and this reads it rather than restating it: add `SECURITY.md` to `files` and it
    // becomes a surface the table must account for, with no edit here.
    const npm = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
    for (const entry of npm.files ?? []) {
        if (!entry.toLowerCase().endsWith('.md')) continue;
        const full = path.join(repoRoot, entry);
        if (!fs.existsSync(full)) {
            // A document `files` promises and the tree does not hold is a defect in its own right;
            // it must not read as a surface that says nothing wrong.
            surfaces[entry] = '';
            continue;
        }
        surfaces[entry] = flatten(fs.readFileSync(full, 'utf8'));
    }

    // ⚠ NOT DERIVABLE, AND THE REASONS ARE IN THE HEADER ABOVE. Two named handles, both loaded the
    // way a reader meets them: the refusal message as `main()` prints it, the instructions as the
    // client receives them.
    surfaces['NO_GRANT_MESSAGE'] = flatten(NO_GRANT_MESSAGE);
    surfaces['initialize.instructions'] = flatten(client.getInstructions() ?? '');

    // ⚠ ONE SURFACE PER TOOL, EVERY STRING IN IT. A second tool arrives here on its own and makes
    // every claim fail until the table accounts for it — which is right: `search` and `list` are
    // specified, and either would widen what this server has to disclose.
    for (const tool of tools) surfaces[`tool:${tool.name}`] = flatten(collectStrings(tool).join(' | '));

    // ⚠ BOTH MANIFESTS, WALKED THE SAME WAY. Every string under a `description` key, joined — the
    // registry renders all of them, so a claim that moved between two has not left the surface.
    // `//`-prefixed keys are this repo's own comment convention and carry no `description`, so the
    // walk excludes them without needing a rule.
    surfaces['server.json'] = flatten(collectDescriptions(JSON.parse(fs.readFileSync(path.join(repoRoot, 'server.json'), 'utf8'))).join(' | '));
    surfaces['package.json'] = flatten(collectDescriptions(npm).join(' | '));

    return surfaces;
}

/** Every occurrence of a retired wording that is not rescued by its qualifier. */
function retiredHits(text, entry) {
    const scan = new RegExp(entry.pattern.source, `${entry.pattern.flags.replace('g', '')}g`);
    const hits = [];
    for (const match of text.matchAll(scan)) {
        const after = text.slice(match.index + match[0].length);
        if (entry.qualifiedBy && entry.qualifiedBy.test(after)) continue;
        hits.push(`${match[0]}${after.slice(0, 48)}`);
    }
    return hits;
}

test('E14-surface-claims — every disclosure surface carries one claim set, and none carries a retired wording', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E14-surface-claims');
    const vault = makeVault();
    let surfaces;
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            surfaces = loadSurfaces(client, tools);
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }

    const SURFACE_NAMES = Object.keys(surfaces);
    const problems = [];

    // ⚠ A SURFACE THAT FAILED TO LOAD MUST NOT READ AS A SURFACE THAT SAYS NOTHING WRONG.
    for (const name of SURFACE_NAMES) {
        if (typeof surfaces[name] !== 'string' || surfaces[name].length === 0) {
            problems.push(`SURFACE ${name} loaded empty — it was not read, and every claim below would fail for the wrong reason`);
        }
    }
    // ⚠ AND A DERIVATION THAT FOUND NOTHING IS NOT AN EMPTY WORLD. If `files` lost its documents
    // and `listTools` returned none, every loop below would iterate over nothing and the arm would
    // pass having checked no text at all — the shape this whole file exists to refuse.
    for (const kind of ['README.md', 'PRIVACY.md', 'NO_GRANT_MESSAGE', 'initialize.instructions', 'server.json', 'package.json']) {
        // ⚠ THE FLOOR, NOT THE LIST. These six are named because each has a DISTINCT derivation
        // that could silently yield nothing — a `files` array that lost an entry, an export that
        // stopped being loaded, a manifest that stopped parsing — and a derivation that yields
        // nothing must fail rather than shrink the world it checks. Nothing here caps the set:
        // the tool surfaces and any further shipped document arrive without being named.
        if (!(kind in surfaces)) problems.push(`SURFACE ${kind} was not derived at all — the derivation that finds it has stopped finding it, and every claim naming it would fail for the wrong reason`);
    }
    if (!SURFACE_NAMES.some(name => name.startsWith('tool:'))) {
        problems.push('no tool surface was derived — `listTools` returned nothing, so the strings the model actually receives went unchecked');
    }
    assert.ok(problems.length === 0, `\n${problems.join('\n')}\n`);

    for (const claim of CLAIMS) {
        const carried = Object.keys(claim.carried);
        const silent = Object.keys(claim.silent);

        // ⚠⚠ THE COMPLETENESS CHECK, AND IT IS THE WHOLE POINT OF THE TABLE. A claim must say
        // something about EVERY surface. Without this, a newly derived surface would silently be
        // exempt from EVERY claim in the table — the drift this arm exists to stop, reintroduced by
        // the very act of adding a surface. ⚠ No count is written here on purpose: an inlined one
        // goes stale the first time a claim is added, in a comment about a check against staleness.
        for (const name of SURFACE_NAMES) {
            const inCarried = carried.includes(name);
            const inSilent = silent.includes(name);
            if (inCarried && inSilent) {
                problems.push(`CLAIM ${claim.id} lists SURFACE ${name} as both carried and silent — one or the other`);
            } else if (!inCarried && !inSilent) {
                problems.push(`CLAIM ${claim.id} says nothing about SURFACE ${name} — every claim must give that surface a pattern or a written reason it may stay silent. (${claim.says})`);
            }
        }
        for (const name of [...carried, ...silent]) {
            if (!SURFACE_NAMES.includes(name)) problems.push(`CLAIM ${claim.id} names SURFACE ${name}, which does not exist`);
        }
        for (const [name, reason] of Object.entries(claim.silent)) {
            if (typeof reason !== 'string' || reason.trim().length < 20) {
                problems.push(`CLAIM ${claim.id} exempts SURFACE ${name} with no real reason — an exemption nobody had to justify is how a surface stops carrying a claim`);
            }
        }

        // The positives.
        for (const [name, patterns] of Object.entries(claim.carried)) {
            const text = surfaces[name];
            if (text === undefined) continue;
            for (const pattern of patterns) {
                if (!pattern.test(text)) {
                    problems.push(`CLAIM ${claim.id} is MISSING from SURFACE ${name}.\n    the claim: ${claim.says}\n    no match for: ${pattern}`);
                }
            }
        }
    }

    // The negatives, against every surface — silence is not licence to say something false.
    for (const entry of RETIRED) {
        for (const name of SURFACE_NAMES) {
            const text = surfaces[name];
            if (typeof text !== 'string') continue;
            for (const hit of retiredHits(text, entry)) {
                problems.push(`RETIRED WORDING ${entry.id} is back in SURFACE ${name}.\n    ${entry.why}\n    found: ...${hit}...`);
            }
        }
    }

    assert.ok(
        problems.length === 0,
        `\n${problems.length} claim-set problem(s) across the disclosure surfaces:\n\n${problems.join('\n')}\n`
    );
});

/* ===============================================================================================
 * E15 — THE REFUSAL VOCABULARY, DERIVED FROM THE PROGRAM AND ACCOUNTED FOR ON THE SURFACES.
 *
 * ⚠⚠ WHY THIS EXISTS, AND IT IS NOT COVERAGE. `E14` above makes the surfaces AGREE. It cannot make
 * them TRUE, and on 2026-09-02 it was found holding three false claims in place across every
 * surface it covers, green throughout, because all of them said the same wrong thing. One of the
 * three was found by noticing that `BAD_INPUT` is returned for a drive-relative request and that no
 * surface anywhere mentioned it. That is a shape a check can have: **one side derived from the
 * program, the other from the prose.**
 *
 * The rule: EVERY REFUSAL THE PROGRAM CAN HAND BACK IS EITHER STATED ON A SURFACE OR EXEMPTED IN
 * WRITING. A new refusal class then forces a documentation decision instead of silently widening
 * the gap between what the program refuses and what the documents say it refuses.
 *
 * ⚠ THE LEFT SIDE IS DERIVED, WHICH IS EXACTLY WHAT `SURFACE_NAMES` FAILED TO BE, and it comes from
 * two places because the refusals do:
 *
 *   · THE FENCE'S enumerated `RequestRefusalReason` and `ConfigRefusalReason` unions, read from the
 *     fence's DECLARED `types` entry point — the same public contract `src/server.ts` imports
 *     `isRefusal` and `FsGate` from.
 *   · THE READER'S OWN, scanned out of this package's built `dist/server.js`: the literal first
 *     argument of every `refusalText(...)` call. `LIMIT_TOO_SMALL` and `BAD_OFFSET` exist nowhere
 *     in the fence and are returned to the model by this file alone.
 *
 * ⚠⚠ AND THE RELOCATION RULE AT THE TOP OF THIS FILE STILL HOLDS. It forbids re-adding a DIRECT
 * `wyrd-fence` import because that would put a FENCE ARM in a consumer's inventory. This is not
 * one, and the distinguishing test is what the arm fails ON: if the fence adds a refusal class,
 * nothing here says the fence is wrong — it says WYRD'S DOCUMENTS have stopped accounting for what
 * wyrd can return. Every assertion below is about this package's prose. Nothing is imported: the
 * declaration file is read as data, through the fence's own `exports` map, and `wyrd-mcp` cannot
 * build or run without the fence resolving anyway.
 *
 * ⚠ WHAT IT CANNOT DO. It cannot tell whether the sentence that accounts for a reason is TRUE, only
 * that some surface says something matching. An exemption is a human judgement, as in `E14`; the
 * only guard is that it must be written down, and short ones are refused.
 */

/**
 * The two enumerated unions, off the fence's declared type surface.
 *
 * ⚠ THROUGH `types`, NOT BY PATH. Reading `dist/fsgate.d.ts` directly would leave this green while
 * a `types` swap handed every consumer a different file — the same reasoning `E12-declaration-
 * inventory` gives for the same indirection in the fence's own package.
 */
function fenceRefusalReasons() {
    const require_ = createRequire(import.meta.url);
    const manifestPath = require_.resolve('wyrd-fence/package.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    const declared = manifest.types ?? manifest.exports?.['.']?.types;
    assert.ok(declared, 'wyrd-fence must DECLARE a types entry — the refusal vocabulary is read from it');
    const raw = fs.readFileSync(path.resolve(path.dirname(manifestPath), declared), 'utf8');

    /**
     * ⚠ COMMENTS STRIPPED FIRST, AND THIS WAS MEASURED RATHER THAN ANTICIPATED. `tsc` keeps the
     * doc comments in the emitted `.d.ts`, and the members of `RequestRefusalReason` are documented
     * INLINE, between the union's own `|` arms. A semicolon inside one of those comments ended the
     * first version of this match early and it derived twelve of fifteen reasons — a check that
     * would have silently stopped requiring the three most recently added ones. It failed loudly
     * only because the table already accounted for all fifteen and the reverse direction caught it.
     */
    const dts = raw.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');

    const reasons = new Set();
    for (const union of ['RequestRefusalReason', 'ConfigRefusalReason']) {
        const match = dts.match(new RegExp(`export type ${union} =([^;]*);`));
        assert.ok(match, `wyrd-fence's declaration surface no longer carries \`${union}\` — the derivation this arm rests on has stopped deriving`);
        const members = [...match[1].matchAll(/'([A-Z0-9_]+)'/g)].map(hit => hit[1]);
        assert.ok(members.length > 0, `\`${union}\` parsed to no members — a union that reads as empty makes this arm pass having checked nothing`);
        for (const member of members) reasons.add(member);
    }
    return reasons;
}

/**
 * The refusals this package returns on its own, scanned out of its own build output.
 *
 * ⚠ THIS IS THE READER'S OWN ARTEFACT, NOT A SURFACE. The as-received rule governs what the claim
 * table READS AS PROSE; these are reason CODES in this package's compiled JavaScript, and there is
 * no over-the-wire way to enumerate a refusal that has not been provoked — provoking a chosen list
 * of them would be the hand-maintained list this whole repair removes.
 */
function readerRefusalReasons() {
    const built = fs.readFileSync(path.join(repoRoot, 'dist', 'server.js'), 'utf8');
    // ⚠ `assert.ok`, NOT `assert.match`. A failing `match` prints the whole 20KB haystack, and a
    // guard whose failure message is unreadable is a guard nobody diagnoses.
    assert.ok(/function refusalText\(/.test(built),
        'dist/server.js no longer defines `refusalText` — the scan below would find nothing and this arm would pass having derived an empty vocabulary');
    assert.ok(/refusalText\(\s*slice\.reason/.test(built),
        "dist/server.js no longer forwards the fence's own `slice.reason` to the caller — if the fence's refusals stop reaching the model, this arm's whole premise is gone");
    assert.ok(/const readRefusal[\s\S]*?refusalText\(reason, detail\)/.test(built),
        'the D6 warning wrapper must still forward literal Reader reasons through refusalText');
    const found = new Set([...built.matchAll(/(?:refusalText|readRefusal)\(\s*'([A-Z0-9_]+)'/g)].map(hit => hit[1]));
    assert.ok(found.size > 0, 'no literal refusal reason was found in dist/server.js — the scan has stopped matching');
    return found;
}

/**
 * ⚠ ONE REASON, WRITTEN ONCE, FOR THE CONFIG FAMILY. All ten `CONFIG_*`/`GRANT_*` refusals share an
 * audience and a moment: they are produced by `createFsGate` at startup, before any client has
 * connected, and `main()` prints them to STDERR for the person launching the server. `S2-missing`
 * and `S3-file-grant` assert that plumbing. They are not things a model can provoke and not limits
 * on what a granted folder exposes, which is what every surface in the claim table is about.
 *
 * ⚠ A NEW CONFIG REFUSAL STILL NEEDS A ROW. Sharing the sentence is not auto-exemption: the
 * derivation lists the member, the table must name it, and adding `CONFIG_FOO: { exempt: CONFIG }`
 * is a deliberate act somebody performs and a reviewer sees.
 */
const CONFIG_REFUSAL = 'a grant-configuration refusal, produced before any client connects and printed to stderr for the operator who launched the server; not reachable through the tool and not a limit on what a granted folder exposes. S2-missing and S3-file-grant assert that it surfaces.';

/**
 * ACCOUNTING. `surfaced` must match at least one loaded surface; `exempt` is a written reason.
 * ⚠ Exemptions under 20 characters are refused, as the claim table's already are.
 */
const REFUSALS = {
    /* --- reachable through the `read` tool, and stated --- */
    // ⚠ THE WIDEST CODE, and the one that started this arm: `BAD_INPUT` covers a non-string path, a
    // null byte, an absolute path and the DRIVE-RELATIVE spelling — and no surface mentioned that
    // last one until 2026-09-02, while six of them promised any path inside the grant could be
    // requested. That gap is what a derived left-hand side finds and a prose-to-prose check cannot.
    BAD_INPUT: { surfaced: /drive[- ]relative|drive letter and a colon|drive-letter-and-colon/i },
    ESCAPES: { surfaced: /resolves outside/i },
    MISSING: { surfaced: /does not exist/i },
    NOT_A_FILE: { surfaced: /NOT_A_FILE/ },
    NOT_TEXT: { surfaced: /NOT_TEXT/ },
    PLACEHOLDER: { surfaced: /cloud placeholder is refused by default/i },
    RESERVED_NAME: { surfaced: /reserved device name/i },
    // ⚠ `/data stream/`, NOT `/colon/`. The looser pattern was satisfied by the sentence about
    // DRIVE-RELATIVE names, which also contains the word "colon" — so this row would have read as
    // stated while no surface said anything about a stream. Measured while demonstrating the arm.
    STREAM_SYNTAX: { surfaced: /data stream/i },
    // `..` absorbed at the volume root. ⚠ The surfaces do not distinguish it from ESCAPES, and
    // deliberately do not: to a caller both mean "that path is not in the grant". The separate code
    // exists so the refusal names the rule rather than reading as "does not exist".
    CLAMPED: { surfaced: /climbs out with/ },

    /* --- reachable, and deliberately not stated --- */
    IS_ROOT: {
        exempt: 'asking for the granted folder itself. It resolves to a directory, which every surface already says is refused; the separate code exists so the refusal names the rule rather than reading as "does not exist".'
    },
    ELOOP: {
        exempt: 'a cycle of links, or too many hops, inside the grant. It discloses nothing about the boundary that the surfaces do not already state, and a user cannot act on it when deciding which folder to grant.'
    },
    DENIED: {
        exempt: "the operating system refused the open. That is a fact about the reader's own filesystem permissions, not about anything wyrd promises, withholds or can change."
    },
    NAME_TOO_LONG: {
        exempt: "a path longer than the platform's limit. A ceiling the operating system imposes, not a scope decision wyrd makes, and no surface carries a claim it could contradict."
    },
    IO_ERROR: {
        exempt: 'an unclassified filesystem error, surfaced rather than swallowed. It carries no containment or scope meaning and there is nothing a user could do differently on reading it.'
    },
    ROOT_MOVED: {
        exempt: '⚠ NO SURFACE MENTIONS IT, AND THAT IS A JUDGEMENT RATHER THAN AN OVERSIGHT. The canonical grant root changed under the running process; the fence rechecks it before each operation and refuses. It is not a decision a user makes when granting a folder, and the refusal names itself. Revisit the moment any surface starts describing what happens when the granted folder moves.'
    },

    /* --- not reachable through this server at all --- */
    NOT_A_DIRECTORY: {
        exempt: 'returned only by `listDirInGrant`. This server registers only read-only tools, so no request through them can produce this refusal; `E2-two-tools` pins that tool set.'
    },
    DIGEST_MISMATCH: { exempt: "returned only by the fence's `overwriteFileInGrant`, which the Reader never calls; its first caller is the Scribe's tier-B `overwrite_page`, whose own disclosure will state it." },
    EXISTS: {
        exempt: 'returned only by `createFileInGrant`. This server registers no tool that creates, so no request through it can produce this refusal; `E2-two-tools` is what keeps that true.'
    },
    // ⚠ THE EXEMPTION IS THE UNREACHABILITY, NOT THE OBSCURITY, AND THE DISTINCTION IS WHAT MAKES
    // IT REVISITABLE. `TARGET_CHANGED` is a genuinely interesting refusal — it says the file the
    // fence opened is not the file it looked at — and if this server ever registered a tool that
    // appended, it would need STATING rather than exempting, on the same footing as ESCAPES.
    TARGET_CHANGED: {
        exempt: 'returned only by `appendLineInGrant`. This server registers only read-only tools, so no request can reach the append path; `E2-two-tools` pins that tool set. ⚠ Revisit the moment this server gains a tool that writes: unlike the other unreachable codes, this one describes a containment observation a caller would want stated, not a fact about the local filesystem.'
    },
    // ⚠ SAME CLASS AS `EXISTS` AND `TARGET_CHANGED`, AND EXEMPTED ON THE SAME GROUND — the
    // unreachability, never the obscurity. `PARENT_ALIAS` is returned only by the two WRITE paths,
    // `createFileInGrant` and `appendLineInGrant`; this server registers two read-only tools, `read` and `search`,
    // so no request through it can produce this refusal.
    PARENT_ALIAS: {
        exempt: 'returned only by the fence\'s two write paths, `createFileInGrant` and `appendLineInGrant`, when a request\'s parent directory resolves somewhere other than where it was spelled. This server registers no tool that writes, so no request through it can produce this refusal; `E2-two-tools` is what keeps that true. ⚠ Revisit the moment this server gains a tool that writes: like `TARGET_CHANGED`, this one describes a containment observation a caller would want STATED rather than exempted — it says the write would have landed somewhere the caller did not name, which is a scope fact and not a fact about the local filesystem. The READ path resolves through in-grant aliases deliberately and is unaffected, so no surface claim changes while this server reads only.'
    },

    /* --- the Reader's own, returned by `src/server.ts` and by nothing in the fence --- */
    LIMIT_TOO_SMALL: {
        exempt: 'a per-call argument error whose own refusal text is the whole repair: it names the limit, names the offset and tells the caller to retry larger. It states no fact about scope, containment, retention or what is written.'
    },
    BAD_OFFSET: {
        exempt: 'as LIMIT_TOO_SMALL — a per-call argument error the refusal text repairs in place, telling the caller to use a `next_offset` the server handed out rather than choosing one.'
    },

    /* --- the config family, one shared reason; see CONFIG_REFUSAL above --- */
    CONFIG_EMPTY: { exempt: CONFIG_REFUSAL },
    CONFIG_NULL_BYTE: { exempt: CONFIG_REFUSAL },
    CONFIG_CONTROL_CHAR: { exempt: CONFIG_REFUSAL },
    CONFIG_TOO_LONG: { exempt: CONFIG_REFUSAL },
    CONFIG_RELATIVE: { exempt: CONFIG_REFUSAL },
    CONFIG_DRIVE_RELATIVE: { exempt: CONFIG_REFUSAL },
    CONFIG_NAMESPACED: { exempt: CONFIG_REFUSAL },
    CONFIG_MALFORMED: { exempt: CONFIG_REFUSAL },
    GRANT_MISSING: { exempt: CONFIG_REFUSAL },
    GRANT_NOT_A_DIRECTORY: { exempt: CONFIG_REFUSAL }
};

test('E15-refusal-vocabulary — every refusal the program can return is stated on a surface or exempted in writing', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E15-refusal-vocabulary');
    const vault = makeVault();
    let surfaces;
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            surfaces = loadSurfaces(client, tools);
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }

    const vocabulary = new Set([...fenceRefusalReasons(), ...readerRefusalReasons()]);
    const problems = [];

    for (const reason of [...vocabulary].sort()) {
        const row = REFUSALS[reason];
        if (row === undefined) {
            problems.push(
                `REFUSAL ${reason} can be returned to a caller and this table says nothing about it.\n` +
                '    State it on a surface and give it a `surfaced` pattern, or write down why it needs no surface.\n' +
                '    ⚠ Both are decisions. Neither is the default, which is the point of this arm.');
            continue;
        }
        // ⚠ EXACTLY ONE VERDICT PER REASON. A row carrying both would be read as STATED and its
        // written reason would go unread — the shape of defect this whole review round is about.
        if (row.surfaced !== undefined && row.exempt !== undefined) {
            problems.push(`REFUSAL ${reason} is declared both STATED and EXEMPT — one or the other, and the exempt text would never be read`);
            continue;
        }
        if (row.surfaced !== undefined) {
            const carriers = Object.keys(surfaces).filter(name => row.surfaced.test(surfaces[name]));
            if (carriers.length === 0) {
                problems.push(
                    `REFUSAL ${reason} is declared as STATED, and no surface states it.\n` +
                    `    no surface matched: ${row.surfaced}`);
            }
        } else if (typeof row.exempt !== 'string' || row.exempt.trim().length < 20) {
            problems.push(`REFUSAL ${reason} is exempted with no real reason — an exemption nobody had to justify is how a refusal stops being disclosed`);
        }
    }

    // ⚠ THE OTHER DIRECTION. A row for a reason the program can no longer return is a documentation
    // decision about nothing, and it is how this table would come to describe a program that no
    // longer exists.
    for (const reason of Object.keys(REFUSALS)) {
        if (!vocabulary.has(reason)) {
            problems.push(`REFUSAL ${reason} is accounted for here and the program can no longer return it — the row has outlived its subject`);
        }
    }

    assert.ok(
        problems.length === 0,
        `\n${problems.length} refusal-vocabulary problem(s):\n\n${problems.join('\n\n')}\n`
    );
});

/* ===============================================================================================
 * E16 — EVERY CLAIM DECLARES THE KIND AND LIMIT OF THE EVIDENCE BEHIND IT.
 *
 * `derived` — one side of the comparison comes from the PROGRAM rather than from another
 * sentence. Not proof.
 * `observed` — every named arm registered as executed in the gated root run.
 * Not proof. The row NAMES those arms in `evidence.arms`, and the root aggregation requires every
 * one of those registrations in the run being gated — see the stage-2 block below.
 * `unverified` — NO ARM IN THIS SUITE ASSERTS IT. That is the whole meaning: not an accusation of
 * falsehood, not a defect, and not a debt anyone owes. Three of the four current unverified
 * claims cannot be asserted by an arm: `READABLE_NARROWER_THAN_REACHABLE` and
 * `LIMITS_NOT_EXHAUSTIVE` are universal negatives, and `HARDLINK_INVISIBLE_TO_INSPECTION` is a
 * claim about file managers rather than about wyrd.
 * The bounded search-cache claim is derived from the engine and SR11's cache shape.
 *
 * This stage grades the table and keeps its denominator visible. It does not establish that any
 * claim is true.
 *
 * ⚠⚠ STAGE 2 — WHERE THE EXECUTION CHECK LIVES, AND WHY IT IS NOT HERE. An `observed` row names
 * its arms in `evidence.arms`, and this arm validates those names STATICALLY: non-empty, unique,
 * present on no other grade, and known to `relocation-contract.json`. What it CANNOT do is check
 * that they ran. `executed()` is process-local and `node --test` runs each of this package's five
 * test files in its OWN process with no ordering guarantee; more decisively, this arm cannot see
 * `A24-hardlink-limit`, which the fence owns. The Reader's runner sees only this package; the
 * fence's runner has no claim table. `scripts/aggregate.mjs` at the
 * repo root is the FIRST place holding every necessary fact, because it already unions both
 * packages' executed sets and already knows which package owns each arm. The check lives there,
 * and this arm hands it the mapping through `WYRD_CLAIM_EVIDENCE_OUT`.
 *
 * ⚠ THE ARM-NAME LOOKUP IS DATA, NOT AN IMPORT. `relocation-contract.json` is a file in this
 * package's own tree that happens to name every arm in BOTH packages. Nothing here reaches into
 * `wyrd-fence`, which the rule at the top of this file forbids.
 *
 * ⚠⚠ WHAT `observed` STILL DOES NOT ESTABLISH, and a comment here used to overclaim it. It said a
 * mutation deleting an arm's assertion "would then redden this one". THAT IS TOO STRONG, and both
 * independent designs for this stage said so unprompted: execution registration proves an arm
 * REACHED `arm(id)`, never that its body still asserts anything. An arm gutted to a no-op still
 * registers as executed. The limit is stated in full beside the root check.
 *
 * ⚠⚠ NO MUTATION ROW GRADES THIS ARM, AND STAGE 2 DOES NOT CHANGE THAT. The matrix mutates PRODUCT
 * files (`FILES`, scripts/mutate.mjs:77); this arm reads a table in a TEST file and the root
 * execution check is not reachable by a product mutation either. It stays in the position M90–M95
 * were written to end: asserted, green, named by no mutation row. ⚠ DO NOT FABRICATE ONE —
 * mutating a test file to make a test fail grades nothing about the product, which is the exact
 * defect those rows record. The grade on this arm is a measurement nobody has taken, and saying so
 * is worth more than a row that would measure the wrong thing.
 */
test('E16-claim-evidence — every claim declares an evidence grade and a substantive limit', () => {
    arm('E16-claim-evidence');
    const grades = ['derived', 'observed', 'unverified'];
    const problems = [];
    const seen = new Set();

    for (const claim of CLAIMS) {
        if (seen.has(claim.id)) {
            problems.push(`CLAIM ${claim.id} appears twice — ids are the handle stage 2 binds arms to, and two rows sharing one can hold contradictory grades while the pinned set still reads correctly`);
        }
        seen.add(claim.id);
        if (claim.evidence === null || typeof claim.evidence !== 'object' || Array.isArray(claim.evidence)) {
            problems.push(`CLAIM ${claim.id} has no evidence block`);
            continue;
        }
        if (!grades.includes(claim.evidence.grade)) {
            problems.push(`CLAIM ${claim.id} has unknown evidence grade ${JSON.stringify(claim.evidence.grade)}`);
        }
        if (typeof claim.evidence.limit !== 'string' || claim.evidence.limit.trim().length < 40) {
            problems.push(`CLAIM ${claim.id} has no substantive evidence limit — it must be at least 40 characters`);
        }
        // ⚠⚠ NO OWNER, NO REVIEW DATE, NO EXPIRY — and their removal on 2026-09-15 is the ruling
        // worth keeping. They were added to stop `unverified` rows becoming wallpaper, which
        // assumed every row is a debt someone must discharge. Most are not.
        //
        // `SEARCH_TERM_CACHE_NO_DISK` describes the term cache and lack of search disk writes.
        // Its grade is derived from code and the bounded cache arm, within the stated limit.
        // `READABLE_NARROWER_THAN_REACHABLE` and `LIMITS_NOT_EXHAUSTIVE` are universal
        // negatives; `HARDLINK_INVISIBLE_TO_INSPECTION` is about file managers, not about wyrd.
        // A review date on any of these schedules a meeting with a fact that will not have changed.
        //
        // Ruled 2026-09-15: unverified claims are not automatically debts to test.
        //
        // What `unverified` means here is therefore narrow and final: NO ARM ASSERTS THIS. It is
        // not a defect, not a debt, and not a promise that someone will come back to it.
    }

    assert.ok(
        problems.length === 0,
        `\n${problems.length} claim-evidence problem(s):\n\n${problems.join('\n')}\n`
    );

    /**
     * STAGE 2, STATIC HALF — the arm names an `observed` row declares must be real arms.
     *
     * ⚠ THE CONTRACT IS READ AS DATA AND ITS PARSE IS ASSERTED NON-EMPTY. A lookup set that comes
     * back empty would make every name below resolve to "unknown" — which fails loudly — but an
     * empty set built the other way round (matching everything) is the shape that passes having
     * checked nothing. The assertion is here so the failure is about the contract rather than
     * about the claims.
     */
    const contract = JSON.parse(
        fs.readFileSync(path.join(repoRoot, 'test', 'relocation-contract.json'), 'utf8'));
    const contractArms = new Map();
    for (const row of [...(contract.arms ?? []), ...(contract.armsAddedPostMove ?? [])]) {
        if (typeof row?.id === 'string') contractArms.set(row.id, row.destination);
    }
    assert.ok(contractArms.size > 0,
        'relocation-contract.json yielded no arms — the name check below would have nothing to resolve against');

    const observedMapping = [];
    for (const claim of CLAIMS) {
        const declared = claim.evidence.arms;
        if (claim.evidence.grade !== 'observed') {
            // ⚠ THE GRADES STAY DISJOINT. A `derived` or `unverified` row carrying arm names would
            // read as observation to anyone scanning the table, while nothing gates those names.
            if (declared !== undefined) {
                problems.push(`CLAIM ${claim.id} is graded ${claim.evidence.grade} and names arms — only an \`observed\` row may, and a name nothing gates is worse than no name`);
            }
            continue;
        }
        if (!Array.isArray(declared) || declared.length === 0) {
            problems.push(`CLAIM ${claim.id} is graded observed and names no arm — that grade requires execution registration, so it must say which arm`);
            continue;
        }
        if (new Set(declared).size !== declared.length) {
            problems.push(`CLAIM ${claim.id} names the same arm twice — a duplicate inflates how much execution evidence the row appears to name`);
        }
        for (const id of declared) {
            if (typeof id !== 'string' || id.trim().length === 0) {
                problems.push(`CLAIM ${claim.id} names an empty arm id`);
            } else if (!contractArms.has(id)) {
                problems.push(`CLAIM ${claim.id} names arm "${id}", which is not listed in the relocation contract — a renamed or deleted arm leaves execution evidence the contract cannot resolve`);
            }
        }
        observedMapping.push({ claim: claim.id, arms: [...declared] });
    }

    // ⚠ RE-ASSERTED BEFORE THE RECORD IS WRITTEN. Everything above appends to `problems`, and the
    // assertion that reads it sits further down — so without this, a run with a bad mapping would
    // still hand the root a record to gate. The record must never describe a table that failed.
    assert.ok(
        problems.length === 0,
        `\n${problems.length} claim-evidence problem(s):\n\n${problems.join('\n')}\n`
    );

    // Derived from the table directly, independent of the validation loop and its accumulator. This
    // is the denominator for the handoff: mapping code that drops a push, row or arm cannot pass.
    // ⚠ It binds the IN-MEMORY mapping. The record written below is that same array, unchanged; a
    // future transform between this comparison and the write would sit outside what it proves.
    const expectedObservedMapping = CLAIMS
        .filter(claim => claim.evidence.grade === 'observed')
        .map(claim => ({ claim: claim.id, arms: [...claim.evidence.arms] }))
        .sort((a, b) => a.claim.localeCompare(b.claim));
    const completeObservedMapping = [...observedMapping]
        .sort((a, b) => a.claim.localeCompare(b.claim));
    assert.deepEqual(
        completeObservedMapping,
        expectedObservedMapping,
        'the observed-claim handoff must exactly match the independently derived claim ids and arm lists'
    );

    const observedClaimCount = expectedObservedMapping.length;
    const namedArmCount = expectedObservedMapping
        .reduce((total, row) => total + row.arms.length, 0);

    /**
     * STAGE 2, HANDOFF — the mapping goes to whoever can actually check execution.
     *
     * ⚠ A SUPPLIED DESTINATION THAT CANNOT BE WRITTEN IS A FAILURE, NEVER A WARNING. The root sets
     * this variable precisely because it intends to gate on the result; swallowing the error would
     * turn its gate into a no-op at the exact moment something is wrong.
     */
    const evidenceOut = process.env['WYRD_CLAIM_EVIDENCE_OUT'];
    if (evidenceOut) {
        fs.mkdirSync(path.dirname(evidenceOut), { recursive: true });
        fs.writeFileSync(evidenceOut, JSON.stringify({
            source: 'E16-claim-evidence',
            observedClaimCount,
            namedArmCount,
            observed: completeObservedMapping
        }, null, 2));
    }

    const unverified = CLAIMS.filter(claim => claim.evidence.grade === 'unverified');
    const expectedUnverified = [
        'HARDLINK_INVISIBLE_TO_INSPECTION',
        'LIMITS_NOT_EXHAUSTIVE',
        'OBSERVE_RECORDS_PATHS_NOT_CONTENT',
        'READABLE_NARROWER_THAN_REACHABLE'
    ];
    // Assert ids, never a count: a count is what went stale four times in SURFACE_NAMES history.
    assert.deepEqual(
        unverified.map(claim => claim.id).sort(),
        expectedUnverified.sort(),
        'the unverified claim set changed — re-grading requires an explicit expected-id edit'
    );

    const counts = Object.fromEntries(
        grades.map(grade => [grade, CLAIMS.filter(claim => claim.evidence.grade === grade).length])
    );
    // ⚠ EVERY NUMBER HERE IS COMPUTED FROM THE TABLE, the row count included. A literal `17` stood
    // in the two explanatory lines below until 2026-09-15 and would have drifted the moment a claim
    // was added — the same defect this file's own `SURFACE_NAMES` history records four times over.
    console.log([
        `E16-claim-evidence — ${CLAIMS.length} claims, self-declared: ${counts.derived} derived, ${counts.observed} observed, ${counts.unverified} UNVERIFIED (${counts.unverified}/${CLAIMS.length}).`,
        '  UNVERIFIED — no arm in this suite asserts these. Three of them cannot be asserted by any',
        '  arm: two are universal negatives and one is about file managers rather than about wyrd.',
        ...unverified.map(claim => `    · ${claim.id} — ${claim.says}`),
        `  WHAT THIS ARM CHECKED: that each of the ${CLAIMS.length} rows declares a grade and a limit, that`,
        '  the ids are unique, that the unverified set is exactly the pinned one, and that every arm',
        `  named by the ${counts.observed} observed rows is listed in the relocation contract.`,
        '  WHAT IT DID NOT CHECK: whether any grade is CORRECT, whether any `derived` grade still',
        '  matches current behaviour, whether any limit text is adequate, or whether the',
        `  ${CLAIMS.length} rows are all the claims there are.`,
        // ⚠ THE DENOMINATOR OF THE EXECUTION CHECK, PRINTED EITHER WAY. A run that could not gate
        // execution must never read as one that did — and a run that DID gate it should say where,
        // because the check is in another file and nobody would otherwise know it happened.
        evidenceOut
            ? '  OBSERVED-ARM EXECUTION is gated by the root aggregation, which was handed this mapping.'
            : [
                '  ⚠ OBSERVED-ARM EXECUTION WAS NOT GATED. This run supplied no root sink, so nothing',
                '  here confirms the named arms ran: each test file is its own process and the fence is',
                '  another package entirely. The names were checked; the running was not.',
                '  Run the root `npm test` for the execution gate.'
            ].join('\n'),
        '  It did not establish that any claim is true.'
    ].join('\n'));
});

/* ===============================================================================================
 * E19 — EVERY PROGRAM TRANSPORT HAS ITS NETWORK BEHAVIOUR ACCOUNTED FOR ON A SURFACE.
 *
 * This checks the SET of transports against the disclosure accounting below. It does NOT establish
 * that any matching sentence is true; H23 and H32 exercise the HTTP disclosures, while the other
 * disclosure arms own their narrower claims.
 *
 * ⚠ READ THIS PACKAGE'S DECLARATION BY PATH. E15 is right to follow `wyrd-fence`'s declared `types`
 * entry because changing that entry changes the file handed to that package's consumers. That
 * indirection is wrong here: this package is a binary, deliberately declares `exports: {}`, and
 * has no type consumer to hand another file to. Adding `types` or reopening `exports` just to make
 * this arm resolve would reopen the deep-import class the empty map closes. The subject is therefore
 * this package's own built `dist/server.d.ts`, read directly as data.
 *
 * ⚠ COMMENTS ARE STRIPPED BEFORE THE UNION IS PARSED. E15 measured why: inline declaration comments
 * between union arms once made its parser derive only 12 of 15 members. A partial parse here could
 * silently drop a transport and therefore drop its disclosure obligation.
 */
function serverTransports() {
    const raw = fs.readFileSync(path.join(repoRoot, 'dist', 'server.d.ts'), 'utf8');
    const dts = raw.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
    const match = dts.match(/export type ServerTransport =([^;]*);/);
    assert.ok(match,
        '`dist/server.d.ts` no longer declares `ServerTransport` — the transport derivation has stopped deriving');

    const members = [...match[1].matchAll(/'([^']+)'/g)].map(hit => hit[1]);
    assert.ok(members.length > 0,
        '`ServerTransport` parsed to no members — an empty derivation would make the accounting loop assert nothing');

    const unexplained = match[1].replace(/'[^']+'/g, '').replace(/\|/g, '').trim();
    assert.equal(unexplained, '',
        '`ServerTransport` is no longer a plain union of string literals — update the derivation instead of silently skipping a member');

    return new Set(members);
}

/**
 * The transport literals the compiled runtime can assign at its selector.
 *
 * This is the independent defence against a partial declaration parse: if the parser found only
 * `stdio`, the `http` literal selected by `--http` in `dist/main.js` would be absent and the arm
 * would fail before treating the smaller set as complete.
 */
function runtimeSelectedTransports() {
    const built = fs.readFileSync(path.join(repoRoot, 'dist', 'main.js'), 'utf8');
    const selectors = [...built.matchAll(/\bconst transport\s*=\s*([^;]+);/g)];
    assert.equal(selectors.length, 1,
        '`dist/main.js` must contain exactly one literal transport selector — update the runtime cross-check if its shape changes');
    const selected = [...selectors[0][1].matchAll(/'([^']+)'/g)].map(hit => hit[1]);
    assert.ok(selected.length > 0,
        'the runtime transport selector yielded no literals — the declaration cross-check would assert nothing');
    return new Set(selected);
}

/** Each derived transport is stated somewhere, or carries a substantive written exemption. */
const TRANSPORT_NETWORK_BEHAVIOUR = {
    stdio: { surfaced: /In stdio mode(?:,)? (?:this server|it) opens no network connection of its own/i },
    http: { surfaced: /In HTTP or HTTPS mode it listens for connections that clients initiate\. In every mode it phones nothing home and initiates no outbound connection/i }
};

test('E19-transport-network-accounting — every derived transport has network behaviour stated or exempted', { timeout: TEST_TIMEOUT_MS }, async () => {
    arm('E19-transport-network-accounting');
    const vault = makeVault();
    let surfaces;
    try {
        await withClient(vault.grant, async client => {
            const { tools } = await client.listTools();
            surfaces = loadSurfaces(client, tools);
        });
    } finally {
        fs.rmSync(vault.base, { recursive: true, force: true });
    }

    assert.ok(Object.keys(surfaces).length > 0,
        'no disclosure surfaces were loaded — surfaced transport rows would have nothing to match');

    const transports = serverTransports();
    const runtimeTransports = runtimeSelectedTransports();
    const problems = [];

    for (const transport of [...runtimeTransports].sort()) {
        if (!transports.has(transport)) {
            problems.push(`RUNTIME transport ${transport} is selected by dist/main.js but missing from the derived ServerTransport union — the declaration parse is incomplete or the program contradicts its declared type`);
        }
    }

    for (const transport of [...transports].sort()) {
        const row = TRANSPORT_NETWORK_BEHAVIOUR[transport];
        if (row === undefined) {
            problems.push(
                `TRANSPORT ${transport} exists in ServerTransport and this table says nothing about its network behaviour.\n` +
                '    State that behaviour on a disclosure surface and give it a `surfaced` pattern, or write a substantive exemption.');
            continue;
        }

        const hasSurface = row.surfaced !== undefined;
        const hasExemption = row.exempt !== undefined;
        if (hasSurface === hasExemption) {
            problems.push(`TRANSPORT ${transport} must declare exactly one of \`surfaced\` or \`exempt\``);
        } else if (hasSurface) {
            if (!(row.surfaced instanceof RegExp)) {
                problems.push(`TRANSPORT ${transport} has a non-pattern \`surfaced\` value`);
                continue;
            }
            const carriers = Object.keys(surfaces).filter(name => row.surfaced.test(surfaces[name]));
            if (carriers.length === 0) {
                problems.push(
                    `TRANSPORT ${transport} is declared as STATED, and no loaded surface states its network behaviour.\n` +
                    `    no surface matched: ${row.surfaced}`);
            }
        } else if (typeof row.exempt !== 'string' || row.exempt.trim().length < 20) {
            problems.push(`TRANSPORT ${transport} is exempted with no substantive reason — exemptions must be at least 20 characters`);
        }
    }

    // The reverse direction: stale rows describe transports the program no longer declares.
    for (const transport of Object.keys(TRANSPORT_NETWORK_BEHAVIOUR)) {
        if (!transports.has(transport)) {
            problems.push(`TRANSPORT ${transport} is accounted for here but no longer exists in ServerTransport — the row has outlived its subject`);
        }
    }

    assert.ok(
        problems.length === 0,
        `\n${problems.length} transport-network-accounting problem(s):\n\n${problems.join('\n\n')}\n`
    );
});

function d6CallGate(summary, readFileInGrant, currentDetection = () => summary.placeholder_detection) {
    const fsgate = {
        disclosedRoot: () => 'test-grant',
        placeholderDetection: currentDetection,
        grantPlaceholderSummary: async () => summary,
        readFileInGrant
    };
    const instance = server.createServer({ fsgate, transport: 'stdio' });
    const handler = instance._getRequestHandler('tools/call');
    return args => handler({ method: 'tools/call', params: { name: 'read', arguments: args } },
        { mcpReq: { requestState: () => undefined } });
}

function d6Slice(text, dehydrated = false) {
    const bytes = Buffer.from(text);
    return { ok: true, bytes, offset: 0, nextOffset: bytes.length, truncated: false,
        size: bytes.length, dehydrated, placeholder_detection: 'available' };
}

test('SR1-placeholder-one-of-many — one known placeholder warns on an ordinary read', async () => {
    arm('SR1-placeholder-one-of-many');
    const summary = { placeholder_detection: 'available', placeholder_count: 1, file_count: 20,
        placeholder_fraction: 0.05, warning: '1 of 20 files in the grant are cloud placeholders (5.00%).' };
    const call = d6CallGate(summary, async () => d6Slice('ordinary'));
    const result = await call({ path: 'ordinary.md' });
    assert.equal(result.isError, undefined);
    assert.equal(result.content[1].text, 'ordinary');
    assert.match(result.content[0].text, /1 of 20 files.*5\.00%/);
    assert.deepEqual(result.structuredContent, summary);
});

test('SR3-read-opt-in — default refusal names the download and only true hydrates', async () => {
    arm('SR3-read-opt-in');
    const summary = { placeholder_detection: 'available', placeholder_count: 1, file_count: 2,
        placeholder_fraction: 0.5, warning: '1 of 2 files in the grant are cloud placeholders (50.00%).' };
    const seen = [];
    const call = d6CallGate(summary, async (_path, _offset, _limit, hydrate) => {
        seen.push(hydrate);
        return hydrate ? d6Slice('downloaded', true) : {
            ok: false, reason: 'PLACEHOLDER', resolvedPath: '',
            detail: 'reading cloud.md would download its cloud placeholder. Retry with hydrate: true.'
        };
    });
    const blocked = await call({ path: 'cloud.md' });
    assert.equal(blocked.isError, true);
    assert.match(blocked.content[0].text, /would download its cloud placeholder/);
    assert.match(blocked.content[0].text, /1 of 2 files.*50\.00%/);
    assert.equal(blocked.structuredContent.placeholder_count, 1);
    assert.equal(blocked.structuredContent.dehydrated, true);
    const allowed = await call({ path: 'cloud.md', hydrate: true });
    assert.equal(allowed.isError, undefined);
    assert.equal(allowed.content[1].text, 'downloaded');
    assert.equal(allowed.structuredContent.dehydrated, true);
    assert.deepEqual(seen, [false, true]);
});

test('SR4-unsupported-platform — unavailable is carried on passing and refusing reads', async () => {
    arm('SR4-unsupported-platform');
    const summary = { placeholder_detection: 'unavailable', placeholder_count: null,
        file_count: null, placeholder_fraction: null };
    const call = d6CallGate(summary, async path => path === 'missing.md'
        ? { ok: false, reason: 'MISSING', resolvedPath: '', detail: 'missing.md does not exist' }
        : { ...d6Slice('available'), dehydrated: null, placeholder_detection: 'unavailable' });
    const passing = await call({ path: 'normal.md' });
    const refusing = await call({ path: 'missing.md' });
    assert.equal(passing.content[1].text, 'available');
    assert.equal(refusing.isError, true);
    assert.equal(passing.structuredContent.placeholder_detection, 'unavailable');
    assert.equal(refusing.structuredContent.placeholder_detection, 'unavailable');
    assert.equal(passing.structuredContent.placeholder_count, null);
    assert.equal(refusing.structuredContent.placeholder_count, null);
    let detection = 'available';
    const lateFailure = d6CallGate({ placeholder_detection: 'available', placeholder_count: 0,
        file_count: 1, placeholder_fraction: 0 }, async () => {
        detection = 'unavailable';
        return { ...d6Slice('local'), dehydrated: null, placeholder_detection: 'unavailable' };
    }, () => detection);
    const afterFailure = await lateFailure({ path: 'normal.md' });
    assert.equal(afterFailure.structuredContent.placeholder_detection, 'unavailable');
    assert.equal(afterFailure.structuredContent.placeholder_count, null);
});
