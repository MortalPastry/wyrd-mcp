/**
 * THE FENCE'S PUBLISHED SECURITY ACCOUNT — `PC1`, `PC2`, `PC3`, `PC4`.
 *
 * ⚠⚠ WHAT THESE FOUR ARMS DO NOT DO, STATED FIRST BECAUSE THE TEMPTATION IS TO READ THEM AS MORE.
 * NONE OF THEM CHECKS A CLAIM AGAINST THE CODE. The fence's published limits were wrong three times
 * in one night, and of those three failures these arms would have caught EXACTLY ONE: the
 * `package.json` description that told a reader the README listed every known limit while the README
 * redirected to `src/fsgate.ts`, which is not in the published tarball. `PC1` reddens on that shape.
 *
 * The other two — the reparse bullet that described code deleted on 2026-08-29, and the
 * root-replacement bullet that understated a gap later reproduced — were prose that had been TRUE
 * and became false when the code moved underneath it. Nothing here can see that, and no mechanism
 * found in two days of looking addresses that class: a claim that was true when written fails
 * silently. ⚠ **The existence of this
 * file is not coverage of it.** These arms make the STRUCTURE honest — pointers land in the packed
 * artifact, retired falsehoods stay dead, the single home stays single. They do not make the
 * README's content true. That is read by a person, and it is still the only thing that reads it.
 *
 * ⚠ THIS IS NOT A SECOND CLAIM MATRIX. The Reader's `E14` asks "do N surfaces agree?"; the fence's
 * limits deliberately live in ONE place — the README is authoritative, the source header records how
 * they were measured and refuses to restate them, the description carries one concrete limit and a
 * pointer. With one home there is no cross-surface drift to guard, so a matrix here would be
 * machinery for a dissolved problem. See `designs/2026-09-02-fence-claim-guard.md`.
 *
 * ⚠ AND IT DELIBERATELY SHARES NO ENGINE WITH `E14`. A shared module would need a cross-package
 * relative import inside a file that ships, which is precisely what `importClosureProblems()`
 * refuses; the alternative — exporting test machinery from a security library's published surface —
 * is worse. `flatten` below is a four-line duplicate of the Reader's, on purpose. These are three
 * assertions, not an engine.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { declare as arm } from './manifest.mjs';

const pkgRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * THE PUBLISHED SET, DERIVED FROM npm'S OWN AUTHORITY RATHER THAN FROM `files`.
 *
 * ⚠⚠ `files` IS A DECLARATION; `npm pack` IS THE FACT, AND THEY DIFFER HERE. This package's `files`
 * is `["dist", "!dist/*.tsbuildinfo", "README.md", "LICENSE"]` and never mentions `package.json`,
 * which npm always includes anyway. A check that read `files` would therefore hold that the manifest
 * is unpublished — while it is the single most-read file on an npm page. Negation patterns,
 * `.npmignore` and npm's own defaults all move this set without touching `files`.
 *
 * ⚠ `--prefix` DOES NOT SELECT WHAT IS PACKED. npm packs the directory named as its ARGUMENT (or the
 * cwd); `--prefix` sets the config root, and passing it alone made npm read the directory ABOVE the
 * workspace and fail `ENOENT` on a package.json that does not exist there. The package directory is
 * passed positionally.
 *
 * ⚠⚠ AND npm IS REACHED THROUGH ITS OWN CLI SCRIPT, NEVER THROUGH `npm.cmd`. Node refuses to
 * `execFile` a `.cmd` without a shell — `spawnSync npm.cmd EINVAL`, the CVE-2024-27980 mitigation —
 * and the obvious repair, `shell: true`, would put this package's absolute path through cmd.exe's
 * parser, where `^` and `&` in a directory name become syntax. Running `npm-cli.js` on the Node
 * binary already executing this test spawns no shell at all and pins npm to this runtime.
 *
 * ⚠⚠ AND THAT SCRIPT IS NOT IN ONE PLACE, SO THREE LAYOUTS ARE TRIED IN ORDER. This file ships, so
 * it runs on a stranger's host, and a single hardcoded path reddens PC1 and PC2 as UNDETERMINED on
 * the majority of them.
 *   1. `process.env.npm_execpath` — npm sets it for every script it runs, so under `npm test` it is
 *      authoritative and layout-independent, and it is first for that reason. ⚠ IT NAMES THE PACKAGE
 *      MANAGER RUNNING THE SCRIPT, NOT NECESSARILY npm: under yarn it is `yarn.js` / `yarn-*.cjs`,
 *      under pnpm it is pnpm's own `.cjs`, and a JS-extension screen alone would hand that script
 *      npm's arguments (measured by a cold read 2026-09-02 — the first draft did exactly that). So it
 *      is accepted only when it is npm's OWN CLI script, `npm-cli.js`, and it exists. Anything else
 *      is SKIPPED, not fatal — the layout probes below still find the real npm beside this Node.
 *   2. `<dir of node>/node_modules/npm/bin/npm-cli.js` — Windows, nvm-windows, the zip distribution.
 *   3. `<dir of node>/../lib/node_modules/npm/bin/npm-cli.js` — the POSIX prefix layout: nvm, fnm,
 *      asdf, Homebrew, the official tarball, Fedora/Arch-style packages.
 *   4. `<dir of node>/../share/nodejs/npm/bin/npm-cli.js` — Debian and Ubuntu's split layout, where
 *      `/usr/bin/node` pairs with `/usr/share/nodejs/npm`.
 * None found is an unavailable oracle, and the throw names every path tried — a stranger debugging
 * an UNDETERMINED arm needs to see where it looked, not merely that it failed.
 * ⚠ Only branches 2–4 are measured, and only against constructed directory layouts on this host;
 * no branch has run on a genuine Linux or macOS install.
 *
 * ⚠⚠ AN UNAVAILABLE ORACLE IS NOT A CLEAN RESULT. If `npm pack` cannot run — no npm on PATH, a
 * read-only cache, a sandbox that denies it — this THROWS and the arm reddens as UNDETERMINED. It
 * must never quietly fall back to parsing `files` and report a pass: that would turn the one
 * mechanism that knows what ships into a mechanism that reports what was declared, which is the
 * defect it exists to catch.
 */
function resolveNpmCli() {
    const nodeDir = path.dirname(process.execPath);
    const tried = [];

    const fromEnv = process.env.npm_execpath;
    if (fromEnv) {
        // Accepted only when it is npm's own CLI script. A shim (npm.cmd, a shell wrapper) is not
        // runnable by `execFile` on the Node binary, and yarn's or pnpm's CLI is runnable but is not
        // npm — it would be handed npm's arguments. Either is skipped rather than fatal, because the
        // layout probes below can still find the real script.
        if (path.basename(fromEnv).toLowerCase() === 'npm-cli.js') {
            tried.push(`npm_execpath=${fromEnv}`);
            if (fs.existsSync(fromEnv)) return fromEnv;
        } else {
            tried.push(`npm_execpath=${fromEnv} (skipped — not npm-cli.js, so not npm)`);
        }
    } else {
        tried.push('npm_execpath (unset)');
    }

    for (const candidate of [
        path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
        path.join(nodeDir, '..', 'share', 'nodejs', 'npm', 'bin', 'npm-cli.js')
    ]) {
        tried.push(candidate);
        if (fs.existsSync(candidate)) return candidate;
    }

    throw new Error(`npm's CLI script was not found on any known layout (tried: ${tried.join(' | ')})`);
}

function packedFiles() {
    let raw;
    const cache = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-fence-npm-cache-'));
    try {
        const npmCli = resolveNpmCli();
        raw = execFileSync(
            process.execPath,
            [npmCli, 'pack', '--dry-run', '--json', '--ignore-scripts', pkgRoot],
            {
                cwd: pkgRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120_000,
                env: { ...process.env, npm_config_cache: cache }
            }
        );
    } catch (error) {
        throw new Error(
            'UNDETERMINED — `npm pack --dry-run --json` could not run, so what this package publishes ' +
            'is unknown. This arm refuses rather than falling back to the `files` field: `files` is a ' +
            `declaration and pack is the fact. Underlying failure: ${error?.message ?? error}`
        );
    } finally { fs.rmSync(cache, { recursive: true, force: true }); }
    let parsed;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new Error(`UNDETERMINED — \`npm pack --json\` emitted output this arm cannot parse: ${raw.slice(0, 400)}`);
    }
    const entry = Array.isArray(parsed) ? parsed[0] : parsed;
    const files = entry?.files;
    if (!Array.isArray(files) || files.length === 0) {
        throw new Error('UNDETERMINED — `npm pack --json` reported no file list, so the published set is unknown');
    }
    // npm reports POSIX-separated paths on every host; normalize so a comparison cannot turn on a slash.
    return new Set(files.map(file => String(file.path).replace(/\\/g, '/')));
}

/** Asterisks stripped (Markdown emphasis splits a phrase), whitespace flattened (hand-wrapped). */
function flatten(text) {
    return text.replace(/\*/g, '').replace(/\s+/g, ' ').trim();
}

const readme = fs.readFileSync(path.join(pkgRoot, 'README.md'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(pkgRoot, 'package.json'), 'utf8'));
const source = fs.readFileSync(path.join(pkgRoot, 'src', 'fsgate.ts'), 'utf8');

/** The one section every published surface routes a reader to for the security account. */
const LIMITS_HEADING = 'Security boundary and limits';

test('PC1-pointers-resolve — every published pointer resolves to a heading and a file a stranger actually receives', () => {
    arm('PC1-pointers-resolve');

    /**
     * ⚠ THIS IS THE ARM THAT WOULD HAVE CAUGHT THE REAL FAILURE. The description said the README
     * listed every known limit; the README said the limits were enumerated in `src/fsgate.ts`, which
     * `files` excludes. Both halves are checked here: the named heading must EXIST, and every local
     * file the README routes a reader to must be IN THE PACKED ARTIFACT.
     */
    const packed = packedFiles();
    assert.equal(packed.has('README.md'), true, 'the README must itself be published — every pointer below is worthless otherwise');

    /**
     * The heading, verbatim, as a Markdown heading rather than merely as a phrase somewhere.
     * ⚠ Asserted on a BOOLEAN rather than with `assert.match`, whose failure output prints the
     * entire subject — a 6KB README dumped into the runner buries the one line that says what broke.
     */
    const headingPattern = new RegExp(`^#{2,}\\s+${LIMITS_HEADING.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`, 'm');
    assert.equal(
        headingPattern.test(readme),
        true,
        `the README must carry a heading exactly "${LIMITS_HEADING}" — the description and the source header both send readers to it by that name. Headings found: ${[...readme.matchAll(/^#{1,6}\s+(.+)$/gm)].map(m => m[1]).join(' | ')}`
    );

    // The description names it, and the source header names the same one. Flattened, because the
    // header is hand-wrapped and a reflow must not silently stop the match.
    const flatDescription = flatten(manifest.description ?? '');
    assert.ok(
        flatDescription.includes(LIMITS_HEADING),
        `package.json's description must name the README section it points at; it reads: ${flatDescription}`
    );
    assert.ok(
        flatten(source).includes(`the account is README.md, "${LIMITS_HEADING}"`),
        'the source header must route to the same README section by name — that pointer is the single home'
    );

    /**
     * ⚠ EVERY LOCAL FILE THE README ROUTES A READER TO MUST SHIP. A backtick-quoted path with a
     * source-file extension is a route: this is what turned `src/fsgate.ts` into an instruction an
     * npm consumer could not follow. URLs and bare prose words are not routes and are not matched.
     */
    const routed = new Set(
        [...readme.matchAll(/`([A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:ts|js|mjs|cjs|json|md|d\.ts))`/g)].map(match => match[1])
    );
    const unpublished = [...routed].filter(file => !packed.has(file));
    assert.deepEqual(
        unpublished,
        [],
        `the README routes a reader to ${unpublished.join(', ')}, which the published tarball does not contain. ` +
        `A pointer into a file strangers cannot read is the defect this arm exists for. Packed: ${[...packed].sort().join(', ')}`
    );
});

/**
 * WORDINGS THAT WERE PUBLISHED, WERE FALSE, AND MAY NOT COME BACK.
 *
 * ⚠ ALL FOUR ERRED IN THE REASSURING DIRECTION OR SENT A READER SOMEWHERE THEY COULD NOT GO, which
 * is the direction that costs a consumer something. Each is pinned by the wording that actually
 * shipped rather than paraphrased.
 *
 * ⚠⚠ CHECKED AGAINST PUBLISHED ARTIFACTS ONLY, AND THAT EXCLUSION IS LOAD-BEARING RATHER THAN LAZY.
 * `src/fsgate.ts` QUOTES the retired reparse wording in order to warn the next editor against it —
 * so a source-level scan would redden on the warning, which is the same trap the Reader's table
 * names for `src/server.ts`. `src/` does not ship, so it is correctly out of scope here.
 *
 * ⚠ WHAT THIS CANNOT DO: it is regex over prose and cannot see a PARAPHRASE that keeps the false
 * meaning in different words. This list grows only when a person notices something.
 */
const RETIRED = [
    {
        id: 'ENUMERATED_IN_SOURCE',
        pattern: /\benumerated in\b(?:\s+\S+){0,4}?\s*src\/fsgate\.ts/i,
        why: 'the retired pointer into unshipped source ("The limits are enumerated in `src/fsgate.ts`"). `src/` is not in the published tarball, so an npm consumer cannot follow it. The README section is the account.'
    },
    {
        id: 'README_LISTS_EVERY_LIMIT',
        pattern: /\bREADME\b(?:\s+\S+){0,4}?\s*\blists every known limit\b/i,
        why: 'the retired description claim ("the README lists every known limit"). It was written while the README still redirected to unshipped source, and a promise of completeness is exactly what a consumer would rely on without checking.'
    },
    {
        id: 'REPARSE_NEVER_ARBITRATED',
        pattern: /realpathNative is consulted, and here it never is|WOULD DEFEAT THE ARBITRATION/i,
        why: 'the retired overstatement of the fence\'s own worst limit. `realpathNative` IS consulted on every successful resolution; the true residual is narrower (an unclassified INTERMEDIATE tag leading to a missing or denied outside descendant refuses before arbitration). Containment holds; the closed-oracle property does not, for that shape.'
    },
    {
        id: 'SAME_PATH_REPLACEMENT_NOT_CAUGHT',
        pattern: /A replacement at the same canonical path is not caught/i,
        why: 'the retired pre-F8 root-identity claim. The fence now re-checks the root object identity before every operation that touches the filesystem, so a different directory at the same canonical path refuses.'
    }
];

test('PC2-retired-wordings — a retired wording does not come back on any published fence artifact', async () => {
    arm('PC2-retired-wordings');

    const packed = packedFiles();
    /**
     * ⚠ THE SURFACES ARE THE PUBLISHED ONES, DERIVED FROM `pack` RATHER THAN LISTED. A hand-written
     * list of surfaces is the thing that goes stale when a file is added to `files`; deriving it
     * means a newly-published document is checked from the moment it ships.
     */
    const surfaces = {};
    for (const file of packed) {
        if (file === 'package.json') continue; // read below through JSON.parse, as a consumer receives it
        if (!/\.(md|txt)$/i.test(file) && file !== 'LICENSE') continue;
        surfaces[file] = flatten(fs.readFileSync(path.join(pkgRoot, file), 'utf8'));
    }
    surfaces['package.json:description'] = flatten(manifest.description ?? '');
    surfaces['package.json:keywords'] = flatten((manifest.keywords ?? []).join(' '));

    assert.ok(
        Object.keys(surfaces).some(name => name.endsWith('README.md')),
        'the README must be among the derived published surfaces — if it is not, this arm is checking nothing that matters'
    );

    const problems = [];
    for (const entry of RETIRED) {
        for (const [name, text] of Object.entries(surfaces)) {
            const hit = text.match(entry.pattern);
            if (hit) {
                problems.push(`RETIRED WORDING ${entry.id} is back on PUBLISHED SURFACE ${name}.\n    ${entry.why}\n    found: ...${hit[0]}...`);
            }
        }
    }
    assert.deepEqual(problems, [], problems.join('\n'));
});

test('PC3-limits-section-live — the limits section is substantive and the source header still points at it rather than restating it', () => {
    arm('PC3-limits-section-live');

    // 1 — it exists and is not a stub. The section runs to the next heading of the same or higher level.
    const start = readme.indexOf(`## ${LIMITS_HEADING}`);
    assert.notEqual(start, -1, `the README must carry the "${LIMITS_HEADING}" section`);
    const rest = readme.slice(start + LIMITS_HEADING.length + 3);
    const next = rest.search(/^##\s/m);
    const body = (next === -1 ? rest : rest.slice(0, next)).trim();

    assert.ok(
        body.length >= 800,
        `the limits section is ${body.length} characters, which is too thin to be an account of where containment does not hold. ` +
        'This arm is the floor under a section that a tidying edit could hollow out without deleting.'
    );
    const bullets = body.split('\n').filter(line => line.trimStart().startsWith('- ')).length;
    assert.ok(bullets >= 4, `the limits section carries ${bullets} bullet(s); the measured limits are several and an account that lists one or two has lost some`);

    /**
     * 2 — ⚠⚠ THE CLAUSE THAT DECAYS. The source header was reduced to a POINTER deliberately: it
     * carried a second copy of the limits until 2026-09-02, and the copy went wrong while the code
     * beside it stayed right. The easy future edit is to start explaining a limit in the header
     * again, which silently re-creates the two-copy problem this design removed. The header must
     * keep routing to the README, and must keep SAYING that it does not restate.
     */
    assert.ok(
        flatten(source).includes(`the account is README.md, "${LIMITS_HEADING}"`),
        'the source header must still point at the README section — a header that stops pointing has become a second home'
    );
    assert.match(
        source,
        /Do not restate the limits here/,
        'the source header must keep its standing instruction not to restate the limits; removing it is the first move of re-creating the second copy'
    );

    /**
     * ⚠ AND THE DESCRIPTION MUST STILL POINT RATHER THAN SUMMARIZE. It is allowed exactly one
     * concrete limit plus the pointer — a description that grows a list is a third home.
     */
    assert.ok(
        flatten(manifest.description ?? '').includes(`See the README section '${LIMITS_HEADING}'`),
        "package.json's description must keep routing to the README section by name"
    );
});

test('PC4-append-window-single-home — the exact append race account lives only in the README', () => {
    arm('PC4-append-window-single-home');

    const start = readme.indexOf(`## ${LIMITS_HEADING}`);
    const rest = readme.slice(start + LIMITS_HEADING.length + 3);
    const next = rest.search(/^##\s/m);
    const limits = next === -1 ? rest : rest.slice(0, next);
    const appendStart = source.indexOf('Append ONE already-serialised');
    const appendEnd = source.indexOf('appendLineInGrant(request:', appendStart);
    const appendComment = source.slice(appendStart, appendEnd);

    const flatLimits = flatten(limits);
    for (const required of [
        /once before it opens the leaf and once from the descriptor afterwards/i,
        /After the fence's last check[\s\S]*before the single write/i,
        /no share mode and no way to forbid `link\(\)` or `rename\(\)`/i,
        /single-named and inside the folder when it was opened/i,
        /bytes can end up under a name the other party chose/i
    ]) assert.match(flatLimits, required, 'the authoritative README lost part of the exact append-window account');

    assert.match(appendComment, /README\.md, "Security boundary and limits"/);
    assert.match(appendComment, /bytes under a name chosen by another writer/i);
    for (const distinctive of [
        /before the single write/i,
        /no share mode and no way to forbid `link\(\)` or `rename\(\)`/i,
        /single-named and inside the folder when it was opened/i
    ]) assert.doesNotMatch(appendComment, distinctive,
        'distinctive timing language appears in both the README and appendLineInGrant source comment');
});
