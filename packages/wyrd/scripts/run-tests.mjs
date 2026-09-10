#!/usr/bin/env node
/**
 * The suite runner.
 *
 * `node --test` alone is not enough for two reasons the plan cares about:
 *
 *   1. §5 requires `failed === 0 && skipped === 0` in the FULL suite, GLOBALLY. A per-file manifest
 *      test cannot see the other files, and `node --test` exits 0 on a fully skipped run.
 *      ⚠ Portable mode deliberately permits skips — exactly the declared tier-2 set, by identity,
 *      never merely by count. That is the one sanctioned exception and it is checked, not trusted.
 *   2. The executed arm set must equal the DECLARED set across every file, not within one.
 *
 * This runs the suite, streams its output unchanged, then asserts both.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_ARMS, SYMLINK_PRIVILEGE_ARMS, PORTABLE_ARMS } from '../test/arms.mjs';
import { preflightJunctionSupport, preflightSymlinkPrivilege } from './preflight.mjs';
import { loadContract, verifyArmInventory, refuse } from './verify-relocation-contract.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * ⚠⚠ THE RELOCATION CONTRACT, AND IT RUNS BEFORE EVERYTHING ELSE IN THIS FILE.
 *
 * `arms.mjs` is this package's own declaration, and the checks further down compare the suite
 * against it — which is a comparison of the tree with itself. That is exactly the check a move can
 * satisfy while losing arms: delete a test AND its row, and both sides agree about a smaller suite.
 * `test/relocation-contract.json` is the outside referent, written before anything moved. It has no
 * generator, so it cannot be brought into agreement with a shrunken suite by running a command.
 *
 * ⚠ FIRST, not merely before the spawn. Nothing else here gets to run against an inventory the
 * contract has already rejected — not the fence version gate, not the preflight, not one test.
 */
{
    const { contract, problems } = loadContract();
    if (problems.length) refuse(problems, 'the contract is not internally consistent');
    const armProblems = verifyArmInventory(contract, 'wyrd', ALL_ARMS);
    if (armProblems.length) refuse(armProblems, "this package's declared arm inventory does not match the pre-move contract");
    console.log(`· relocation contract: ${Object.keys(ALL_ARMS).length} arms declared here, of ${contract.totals.arms} locked pre-move`);
}

/**
 * ⚠ TWO TIERS, AND THE DEFAULT IS STILL THE WHOLE SUITE.
 *
 * Without `--portable` nothing below changes: the symlink preflight refuses, and a machine lacking
 * the privilege runs nothing. That is deliberate and is not a fallback — a green meaning "the arms
 * that could run, ran" is a defect, not a pass.
 *
 * `--portable` runs TIER 1 — the arms needing no symlink — and reports the denominator: how many
 * ran, how many were held back, and why. The principle is give a partial run DENOMINATORS rather
 * than generality: a partial run that cannot misstate what it skipped is honest; a full run that
 * silently shrinks is not.
 *
 * ⚠ No count is written in this comment ON PURPOSE. Both tier sizes are derived from `arms.mjs` at
 * run time and printed by the run itself; an inlined number here went stale within one commit the
 * first time it was written, and a stale count in a file about honest denominators is the worst
 * possible place for one.
 *
 * ⚠ The skipped set is asserted to equal `SYMLINK_PRIVILEGE_ARMS` EXACTLY. Skipping one arm more
 * than declared fails the run, and so does skipping one fewer. That equality is the whole reason
 * this mode is trustworthy, so do not relax it into a `>=`.
 */
const portable = process.argv.slice(2).includes('--portable');

/**
 * ⚠⚠ THE DECLARED FENCE VERSION AGAINST THE FENCE'S OWN, AND IT FAILS SILENTLY WITHOUT THIS.
 *
 * Every manifest in this workspace that depends on the fence names a version, and one file defines
 * it. npm links the local workspace package only while the local version SATISFIES the declared
 * spec; the moment they diverge it resolves the security module from the REGISTRY instead — no
 * error, no warning, and a suite that then measures a different build of the fence than the one in
 * this tree. That is the whole failure: not a crash, a green run against the wrong code.
 *
 * ⚠ It runs BEFORE the symlink preflight because it costs a handful of file reads and catches a
 * class the arms cannot see at all. And it is here rather than in an arm on purpose — an arm would
 * have to be declared in `arms.mjs`, and this is a property of the WORKSPACE, not of the fence.
 *
 * ⚠⚠ THE PACKAGE SET IS DERIVED FROM THE `workspaces` DECLARATION, NEVER LISTED. Until 2026-09-01
 * this named its sibling manifests as string literals and both halves of that were wrong. A
 * hand-written list is a claim that today's list is the whole set, and it goes stale the first time
 * a package is added — silently, because a shorter list still passes. And because THIS FILE SHIPS,
 * the literals also exported the name and dependency shape of a package that has never been
 * released; the export audit refused on exactly those two lines. The derivation closes both at
 * once: the set cannot go stale, and a checkout that does not contain a package does not enumerate
 * it either, so there is nothing to name and nothing to read. The public repo declares two
 * workspaces and this gate checks two there; the private one declares three and it checks three,
 * with no special case on either side.
 * ⚠ Do not "helpfully" re-add a constant naming the sibling packages. That is the bug, not the fix.
 *
 * ⚠ THE ONE NAME THAT STAYS IS THE FENCE'S, because it is the SUBJECT of the gate rather than a
 * member of the set — the module this suite resolves, and a package that publishes. It is found IN
 * the derived workspace map rather than assumed to sit at `packages/<its own name>`: a package's
 * directory need not be named after it, and in this very workspace one is not.
 *
 * ⚠⚠ WHAT A MISSING OR UNREADABLE MANIFEST DOES — DECIDED, NOT INHERITED.
 *
 *   · PRESENT BUT UNUSABLE (unreadable, unparseable, nameless) → REFUSE. This gate's claim is over
 *     a SET: *every* workspace package that declares the fence declares this exact version. A
 *     member it could not read makes that sentence unstatable, and carrying on would print a pass
 *     about a smaller set than the sentence describes — the silent shrink this whole file is
 *     written against, and the failure mode the portable tier exists to avoid.
 *   · NO MANIFEST AT ALL → NOT A MEMBER, and said out loud. A directory under a `dir/*` pattern
 *     with no `package.json` is not a workspace package to npm either, so refusing on it would
 *     make any stray or build-output directory break the suite. It is reported as a note rather
 *     than dropped quietly, so the denominator stays visible.
 *   · A PATTERN THIS CANNOT RESOLVE (negation, `**`, a star mid-segment) → REFUSE, because
 *     resolving a subset of the declaration is how a gate reports a pass about packages it never
 *     looked at.
 */
const FENCE = 'wyrd-fence';

/** A manifest read that distinguishes "absent" from "there but unusable". */
function readManifest(file) {
    let text;
    try {
        text = fs.readFileSync(file, 'utf8');
    } catch (error) {
        if (error.code === 'ENOENT') return { absent: true };
        return { unreadable: `could not be read — ${error.message}` };
    }
    try {
        return { manifest: JSON.parse(text) };
    } catch (error) {
        return { unreadable: `does not parse as JSON — ${error.message}` };
    }
}

/** The nearest ancestor declaring `workspaces`, and the patterns it declares. */
function findWorkspaceRoot(startDir) {
    let dir = path.resolve(startDir);
    for (;;) {
        const found = readManifest(path.join(dir, 'package.json'));
        if (found.unreadable) return { refuse: `${path.join(dir, 'package.json')} ${found.unreadable}` };
        const declared = found.manifest?.workspaces;
        const patterns = Array.isArray(declared) ? declared
            : (Array.isArray(declared?.packages) ? declared.packages : null);
        if (patterns) return { rootDir: dir, patterns };
        const parent = path.dirname(dir);
        if (parent === dir) return { refuse: `no ancestor of ${startDir} declares a "workspaces" array` };
        dir = parent;
    }
}

const DIRECTORY_GLOB = /^(.*?)\/?\*$/;

/** The directories a `workspaces` declaration names, or a refusal naming the pattern it could not resolve. */
function workspaceDirectories(rootDir, patterns) {
    const unresolvable = pattern =>
        ({ refuse: `workspace pattern ${JSON.stringify(pattern)} is not one this gate can resolve` });
    const directories = [];
    for (const pattern of patterns) {
        if (typeof pattern !== 'string' || pattern.includes('!') || pattern.includes('**')) {
            return unresolvable(pattern);
        }
        const glob = DIRECTORY_GLOB.exec(pattern);
        if (!glob) {
            if (pattern.includes('*')) return unresolvable(pattern);
            directories.push(path.join(rootDir, pattern));
            continue;
        }
        if (glob[1].includes('*')) return unresolvable(pattern);
        const parent = path.join(rootDir, glob[1]);
        let entries;
        try {
            entries = fs.readdirSync(parent, { withFileTypes: true });
        } catch (error) {
            return { refuse: `workspace pattern ${JSON.stringify(pattern)} points at ${parent}, which could not be read — ${error.message}` };
        }
        for (const entry of entries) if (entry.isDirectory()) directories.push(path.join(parent, entry.name));
    }
    return { directories };
}

function fenceVersionGate() {
    const problems = [];
    const notes = [];
    const checked = [];

    const root = findWorkspaceRoot(repo);
    if (root.refuse) return { problems: [root.refuse], notes, checked };
    const rel = target => path.relative(root.rootDir, target).replace(/\\/g, '/') || '.';

    const found = workspaceDirectories(root.rootDir, root.patterns);
    if (found.refuse) return { problems: [found.refuse], notes, checked };

    const workspace = [];
    for (const directory of found.directories) {
        const where = `${rel(directory)}/package.json`;
        const read = readManifest(path.join(directory, 'package.json'));
        if (read.absent) {
            notes.push(`${rel(directory)} matches a workspace pattern but has no package.json — not a workspace package`);
            continue;
        }
        if (read.unreadable) problems.push(`${where} ${read.unreadable}`);
        else if (typeof read.manifest?.name !== 'string') problems.push(`${where} declares no package name`);
        else workspace.push({ directory, where, manifest: read.manifest });
    }
    // ⚠ Refused here rather than after the loop below: the fence is FOUND among these entries, so a
    // set with a hole in it could fail to find it, and report the wrong reason for the same defect.
    if (problems.length) return { problems, notes, checked };

    const fence = workspace.find(entry => entry.manifest.name === FENCE);
    if (!fence) {
        return { problems: [`no workspace package is named "${FENCE}" — the suite's subject is not in this workspace`], notes, checked };
    }
    if (typeof fence.manifest.version !== 'string') {
        return { problems: [`${fence.where} declares no version, so there is nothing to check against`], notes, checked };
    }

    for (const entry of workspace) {
        const spec = entry.manifest.dependencies?.[FENCE];
        if (spec === undefined) continue;
        checked.push(entry.where);
        if (/^(workspace:|file:|link:)/.test(spec)) {
            problems.push(`${entry.where} declares "${spec}" — the packed manifest must carry an EXACT registry version`);
        } else if (spec !== fence.manifest.version) {
            problems.push(`${entry.where} declares ${FENCE}@${spec}, but the fence is ${fence.manifest.version}`);
        }
    }

    // ⚠⚠ THE GATE MUST NOT BE ABLE TO GO QUIET, and deriving the set is exactly what would let it:
    // a set that shrinks to nothing checks nothing and prints a tick. So two things are asserted
    // about the SET, not about its members —
    //   · this package is in it, and declares the fence. Its own suite imports the fence, so a
    //     manifest here that stopped declaring it is the original silent-resolution defect. This
    //     replaces the old literal row for this file's own package, with no name written down.
    //   · at least one package declares the fence. Otherwise the loop above ran zero times.
    const self = workspace.find(entry => path.resolve(entry.directory) === path.resolve(repo));
    if (!self) {
        problems.push(`the workspace declaration at ${rel(root.rootDir)}/package.json does not enumerate ${rel(repo)}, which is this package — the derived set is not this workspace's`);
    } else if (self.manifest.dependencies?.[FENCE] === undefined) {
        problems.push(`${self.where} declares no ${FENCE} dependency`);
    }
    if (!checked.length) {
        problems.push(`no workspace package declares a dependency on ${FENCE} — this gate would be asserting nothing`);
    }

    // The resolved module must be the LOCAL package, not a registry copy that happens to match.
    // ⚠ The separator is appended AFTER `realpathSync`, which strips a trailing one — comparing the
    // bare prefix would accept a sibling directory whose name merely starts with the fence's.
    try {
        const resolved = createRequire(import.meta.url).resolve(FENCE);
        const local = fs.realpathSync(fence.directory) + path.sep;
        if (!fs.realpathSync(resolved).startsWith(local)) {
            problems.push(`${FENCE} resolves to ${resolved}, which is not this workspace's package`);
        }
    } catch (error) {
        problems.push(`${FENCE} could not be resolved from this package — ${error.message}`);
    }
    // ⚠ Returned for the engines gate below, which must see the workspace ROOT's own manifest as
    // well as the packages — the root declares engines.node and is not a workspace package.
    const rootRead = readManifest(path.join(root.rootDir, 'package.json'));
    const rootEntry = rootRead.manifest
        ? { where: `${rel(root.rootDir)}/package.json`, manifest: rootRead.manifest }
        : null;

    return { problems, notes, checked, version: fence.manifest.version, workspace, rootEntry };
}

/**
 * ⚠ THE SECOND AGREEMENT GATE, OVER `engines.node`. Four manifests in this workspace declare a Node
 * floor and NOTHING held them together — found by a class sweep on 2026-09-02 looking for files that
 * declare a contract nobody checks. They agree today; that was luck, not control.
 *
 * The failure this prevents is quiet in the direction that costs most: a package published with a
 * LOWER floor than the code it ships needs installs for a stranger on that version and fails at
 * runtime, in their process, with no gate here having said a word.
 *
 * ⚠ THE SET IS DERIVED FROM THE WORKSPACE, exactly as the fence gate's is, and for the same reason —
 * a written list of the four is a second register that drifts from the real one. Which means it
 * carries the same hazard, so it carries the same guard: a derived set that shrinks to nothing
 * checks nothing and prints a tick, so `checked.length` is asserted below.
 *
 * ⚠ THE COMPARISON IS EXACT-STRING, DELIBERATELY. Two semantically equivalent spellings (`>=20` and
 * `>= 20.0.0`) are a drift signal here, not a passing case: this workspace publishes them verbatim
 * into package manifests, and a reader comparing two published packages sees the strings.
 */
function enginesAgreementGate(workspace, rootEntry) {
    const problems = [];
    const checked = [];
    let declared = null;

    // ⚠ THE WORKSPACE ROOT IS INCLUDED EXPLICITLY, and it is not one of the workspace PACKAGES.
    // The derived set above enumerates packages, so the root's own manifest falls outside it — and
    // the root declares engines.node too. Checking three of four declarations while printing a tick
    // is precisely the partial-coverage shape this gate exists to refuse, so the root is prepended
    // rather than left to be noticed by someone reading the denominator.
    for (const entry of [...(rootEntry ? [rootEntry] : []), ...workspace]) {
        const node = entry.manifest.engines?.node;
        if (node === undefined) continue;
        checked.push(entry.where);
        if (declared === null) declared = { spec: node, where: entry.where };
        else if (node !== declared.spec) {
            problems.push(`${entry.where} declares engines.node "${node}", but ${declared.where} declares "${declared.spec}"`);
        }
    }

    // ⚠⚠ THE ANTI-VACUITY ASSERTION REFUSES AT FEWER THAN TWO, NOT AT ZERO. A gate that only
    // refuses on an EMPTY set still passes vacuously with ONE declaration: there is nothing to
    // compare it against, so it prints a tick having asserted nothing. Agreement is a property of
    // a PAIR, so one is as empty as none for this gate's purpose. (It refused only at zero until a
    // review lens caught it — the same off-by-one the `[].every()` fail-open has taken three times
    // in this repo's publish path, arriving as a count instead of a predicate.)
    if (checked.length < 2) {
        problems.push(`${checked.length} manifest(s) declare engines.node — agreement needs at least two, so this gate would be asserting nothing`);
    }

    // ⚠⚠ AN UNREADABLE ROOT MANIFEST IS A REFUSAL, NEVER A SILENT DROP. `rootEntry` is null both
    // when the root genuinely declares no engines and when its manifest could not be read — and
    // those are different facts. Dropping it silently produces exactly the three-of-four coverage
    // this gate was written to refuse, which it did on its own first run.
    if (rootEntry === null) {
        problems.push('the workspace root manifest could not be read, so the root is absent from this set — a partial set cannot certify agreement');
    }
    return { problems, checked, spec: declared?.spec };
}

const gate = fenceVersionGate();
for (const note of gate.notes) console.log(`  · ${note}`);
if (gate.problems.length) {
    console.error(`\n⛔ SUITE GATE REFUSED — the workspace ${FENCE} version gate did not pass`);
    for (const problem of gate.problems) console.error(`   · ${problem}`);
    console.error('\n   NOTHING WAS RUN. A mismatch makes npm resolve the fence from the registry');
    console.error('   instead of linking the local one, and the suite would then measure other code.');
    process.exit(1);
}
// ⚠ THE DENOMINATOR, PRINTED. The set is derived, so the only way a reader can tell this gate
// covered what they think it covered is for it to say how many manifests it read and which.
console.log(`· ${FENCE}@${gate.version}: ${gate.checked.length} workspace manifest(s) declare it — ${gate.checked.join(', ')}`);

const engines = enginesAgreementGate(gate.workspace, gate.rootEntry);
if (engines.problems.length) {
    console.error('\n⛔ SUITE GATE REFUSED — the workspace engines.node declarations disagree');
    for (const problem of engines.problems) console.error(`   · ${problem}`);
    console.error('\n   NOTHING WAS RUN. These strings are published verbatim into package manifests,');
    console.error('   so a disagreement ships a floor that does not match the code behind it.');
    process.exit(1);
}
// ⚠ The denominator again, for the same reason: a derived set is only auditable if it says what it read.
console.log(`· engines.node ${engines.spec}: ${engines.checked.length} workspace manifest(s) declare it — ${engines.checked.join(', ')}`);

const preflight = portable ? preflightJunctionSupport() : preflightSymlinkPrivilege();
if (preflight) {
    console.error(`\n⛔ SUITE GATE REFUSED TO RUN${portable ? ' (portable tier)' : ''}`);
    console.error(`   · ${preflight}`);
    if (!portable) {
        console.error('\n   To run the arms that need NO symlink privilege:  npm run test:portable');
        console.error(`   That is ${PORTABLE_ARMS.length} of ${Object.keys(ALL_ARMS).length} arms, and it will say so.`);
    }
    process.exit(1);
}

/**
 * ⚠ THE FILE LIST IS HARD-CODED, AND THAT IS A DECISION RATHER THAN INERTIA. Auto-discovery is the
 * wrong trade here specifically: a rename or a move silently stops matching a glob, and this
 * suite's whole value is its denominator. Adding a test file costs two deliberate edits — this
 * list and `test/arms.mjs` — which is the point.
 *
 * ⚠ `test/fsgate.test.js` LEFT ON 2026-09-01 and is not coming back. Its 62 arms measure
 * `wyrd-fence`, which now measures itself; three grant-shape arms went with them out of
 * `startup.test.js` and three surface arms out of `handshake.test.js`. Re-adding a fence test file
 * here would put a fence arm back in a consumer's inventory.
 */
const FILES = ['test/handshake.test.js', 'test/manifest-schema.test.js', 'test/startup.test.js'];

/**
 * ⚠ THE LIST IS PREFLIGHTED, AND IT WAS NOT UNTIL 2026-09-01. `node --test` given a path that does
 * not exist is one of the ways a suite silently shrinks; the inventory below catches it afterwards,
 * but the message names twenty missing arms rather than one missing file. The Scribe's runner had
 * this check and this one did not, which the relocation plan called out by name.
 */
const absentFiles = FILES.filter(file => !fs.existsSync(path.join(repo, file)));
if (absentFiles.length || FILES.length === 0) {
    console.error('\n⛔ SUITE GATE REFUSED TO RUN');
    if (FILES.length === 0) console.error('   · the runner enumerates no test files at all');
    for (const file of absentFiles) console.error(`   · ${file} does not exist`);
    process.exit(1);
}

const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-arms-'));

const child = spawn(process.execPath, ['--test', ...FILES], {
    cwd: repo,
    env: {
        ...process.env,
        WYRD_ARM_LOG: logDir,
        ...(portable ? { WYRD_PORTABLE: '1' } : {}),
        // ⚠ COLOUR BREAKS THE SUMMARY PARSE, AND ONLY IN A REAL TERMINAL. `node --test` writes its
        // summary in ANSI colour when stdout is a TTY, so `ℹ fail 0` arrives wrapped in escape
        // sequences and the anchored match below finds nothing. Measured 2026-08-29: a run with
        // 71 passing arms reported "could not read the fail count" and refused — correct behaviour
        // for an unparseable summary, but the cause was the terminal, not the tests.
        //
        // ⚠ IT IS INVISIBLE TO A PIPED CALLER. CI and any tool that captures stdout get no colour
        // and parse fine, so this passes every automated check and fails for the person at the
        // keyboard — which is the population that matters most for a first run after `git clone`.
        NO_COLOR: '1',
        FORCE_COLOR: '0'
    },
    stdio: ['ignore', 'pipe', 'inherit']
});

let out = '';
child.stdout.on('data', chunk => {
    out += chunk;
    process.stdout.write(chunk);
});

child.on('close', code => {
    let failures = [];

    // ⚠ BELT AND BRACES WITH THE NO_COLOR ENV ABOVE, DELIBERATELY. Suppressing colour at the source
    // is the fix; stripping it here is the guard for the case where some future runner, reporter or
    // terminal emits it anyway. One mechanism can be defeated by a setting; the pair cannot, and the
    // failure this protects against is a green suite reported as an unreadable one.
    const plain = out.replace(/\[[0-9;]*m/g, '');
    const number = label => {
        const match = plain.match(new RegExp(`^\\u2139 ${label} (\\d+)$`, 'm'));
        return match ? Number(match[1]) : null;
    };
    // In portable mode exactly the tier-2 arms are expected to be skipped; everything else must
    // still be zero. The count is cross-checked against the arm-log equality below, so a wrong
    // number cannot pass by matching one assertion and not the other.
    const expectedSkips = portable ? SYMLINK_PRIVILEGE_ARMS.size : 0;
    for (const label of ['fail', 'skipped', 'cancelled', 'todo']) {
        const value = number(label);
        const allowed = label === 'skipped' ? expectedSkips : 0;
        if (value === null) failures.push(`could not read the "${label}" count from the runner output`);
        else if (value !== allowed) failures.push(`${label} = ${value}, must be ${allowed}`);
    }
    if (code !== 0) failures.push(`the test runner exited ${code}`);

    const executed = new Set();
    const skipped = new Set();
    try {
        for (const file of fs.readdirSync(logDir)) {
            const record = JSON.parse(fs.readFileSync(path.join(logDir, file), 'utf8'));
            for (const id of record.executed) executed.add(id);
            for (const id of record.skipped) skipped.add(id);
        }
    } catch (error) {
        failures.push(`could not read the arm logs: ${error.message}`);
    }
    fs.rmSync(logDir, { recursive: true, force: true });

    const total = Object.keys(ALL_ARMS).length;
    const expected = portable ? PORTABLE_ARMS : Object.keys(ALL_ARMS);
    const missing = expected.filter(id => !executed.has(id));
    const extra = [...executed].filter(id => !expected.includes(id));
    if (missing.length) failures.push(`expected but NOT EXECUTED: ${missing.join(', ')}`);
    // ⚠ In portable mode this catches the dangerous direction: a tier-2 arm that RAN means its
    // fixture was built after all, so the tier list is wrong and the skip set is a fiction.
    if (extra.length) failures.push(`executed but not expected in this tier: ${extra.join(', ')}`);

    // ⚠ THE SKIPPED SET BY IDENTITY, NOT BY COUNT. Until 2026-08-29 this compared only the number
    // node reported, and the comments claimed set equality the mechanism did not provide — a review
    // lens built the passing-but-wrong case: delete one tier-2 test, add an unrelated skipped one,
    // and the count still reads right. Identities come from `tier2()` at registration time, which
    // runs even though the skipped body does not.
    if (portable) {
        const held = [...SYMLINK_PRIVILEGE_ARMS];
        const notHeld = held.filter(id => !skipped.has(id));
        const unexpected = [...skipped].filter(id => !SYMLINK_PRIVILEGE_ARMS.has(id));
        if (notHeld.length) failures.push(`declared tier 2 but NOT skipped: ${notHeld.join(', ')}`);
        if (unexpected.length) failures.push(`skipped but not declared tier 2: ${unexpected.join(', ')}`);
    } else if (skipped.size > 0) {
        failures.push(`the full suite recorded skips: ${[...skipped].join(', ')}`);
    }

    /**
     * ⚠ THE MACHINE-READABLE RECORD, WRITTEN BEFORE THE PASS/FAIL DECISION IS ACTED ON. The root
     * aggregation unions this with the fence's and compares against the locked 88; if it were
     * written only on success, a failing package would contribute nothing and the union would then
     * report a DIFFERENT failure than the real one.
     *
     * ⚠ IT EXISTS BECAUSE A PER-PACKAGE INVENTORY IS A COMPARISON OF THE TREE WITH ITSELF. Each
     * runner can only assert that it ran what IT declares; nothing inside either package can see
     * that an arm fell out of both. That is what the root aggregation is for, and this file is how
     * it gets the numbers.
     */
    const emit = process.env['WYRD_EXECUTED_OUT'];
    if (emit) {
        try {
            fs.mkdirSync(path.dirname(emit), { recursive: true });
            fs.writeFileSync(emit, JSON.stringify({
                package: 'wyrd',
                tier: portable ? 'portable' : 'full',
                declared: Object.keys(ALL_ARMS),
                executed: [...executed],
                skipped: [...skipped],
                ok: failures.length === 0
            }, null, 2));
        } catch (error) {
            failures.push(`could not write the executed-arm record to ${emit}: ${error.message}`);
        }
    }

    if (failures.length) {
        console.error(`\n⛔ SUITE GATE FAILED${portable ? ' (portable tier)' : ''}`);
        for (const failure of failures) console.error(`   · ${failure}`);
        process.exit(1);
    }

    if (portable) {
        // ⚠ THE DENOMINATOR IS THE POINT, so it is stated before the pass line rather than after it.
        // A reader who stops at the tick must still have seen what did not run.
        const held = SYMLINK_PRIVILEGE_ARMS.size;
        console.log(`\n⚠ PARTIAL RUN — TIER 1 ONLY. ${expected.length} of ${total} arms ran.`);
        console.log(`   ${held} arm${held === 1 ? '' : 's'} ${held === 1 ? 'was' : 'were'} NOT run: ${held === 1 ? 'it needs' : 'they need'} the Windows symlink privilege.`);
        console.log(`   Held back: ${[...SYMLINK_PRIVILEGE_ARMS].join(', ')}`);
        // ⚠ THIS PARAGRAPH USED TO SAY THE HELD-BACK ARMS WERE "the fence's hardest cases" AND THAT
        // STOPPED BEING TRUE ON 2026-09-01. Every symlink-backed fence arm moved to `wyrd-fence`,
        // whose runner still says it; what is held back HERE is this package's own disclosure
        // coverage. A stale sentence in the one file about honest denominators is the worst
        // possible place for one.
        console.log('   This is the Reader\'s own coverage, not the fence\'s — the fence\'s tier-2');
        console.log('   arms are held back by `npm --workspace wyrd-fence run test:portable`, which');
        console.log('   states its own denominator. Neither partial run is a green fence.');
        console.log(`   For all ${total}: enable Developer Mode and run \`npm test\`.`);
        console.log(`\n✔ tier-1 gate: ${expected.length} arms all executed; 0 failed, 0 unexpected skips.`);
        return;
    }
    console.log(`\n✔ suite gate: ${total} declared arms all executed; 0 failed, 0 skipped, 0 cancelled.`);
});
