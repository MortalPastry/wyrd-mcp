#!/usr/bin/env node
/**
 * THE FENCE'S SUITE RUNNER.
 *
 * ⚠⚠ IT EXISTS BECAUSE THIS PACKAGE'S ADEQUACY WAS MEASURED BY ANOTHER PACKAGE'S SUITE. Until
 * 2026-09-01 `wyrd-fence` had a build script and nothing else: 62 arms and 66 mutation rows about
 * this code lived in `wyrd-mcp`, and a consumer's test suite was the only thing standing between
 * this fence and a regression. `designs/2026-09-01-fence-test-relocation-plan.md` is the move.
 *
 * `node --test` alone is not enough, for the two reasons the Reader's runner gives:
 *
 *   1. it exits 0 on a fully skipped run, and 0 on a run that enumerated nothing at all;
 *   2. the executed arm set must equal the DECLARED set across every file, and no per-file
 *      assertion can see across files.
 *
 * ⚠ HOW THIS DIFFERS FROM THE READER'S RUNNER, since the two are siblings and a reader will
 * compare them:
 *
 *   · THE FENCE VERSION GATE IS NARROWER, and had to be. See `fenceVersionGate()` below — reused
 *     verbatim it refuses falsely, because `self` IS the fence and no package declares a
 *     dependency on itself.
 *   · THE FILE LIST IS PREFLIGHTED. The plan asks for the Scribe-style check that refuses when the
 *     list is empty or names a file that is absent; the Reader's runner did not have one and now
 *     does too.
 *   · IT CAN EMIT ITS EXECUTED SET. `WYRD_EXECUTED_OUT` makes the run machine-readable so the root
 *     aggregation can union this package's arms with the Reader's and compare the union against
 *     the locked 88. Without that, a green fence with fewer arms would only have to satisfy its
 *     OWN inventory, which is a comparison of the tree with itself.
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ALL_ARMS, SYMLINK_PRIVILEGE_ARMS, PORTABLE_ARMS } from '../test/arms.mjs';
import { preflightJunctionSupport, preflightSymlinkPrivilege } from './preflight.mjs';
// ⚠⚠ THE VERIFIER IS THE READER'S, REACHED BY RELATIVE PATH ACROSS THE PACKAGE BOUNDARY.
// `test/relocation-contract.json` is ONE file — a permanent
// historical record of what the suite measured on 2026-09-01 — and duplicating it into this
// package would give the project two records that can be brought into agreement separately, which
// is the whole failure the no-generator rule is written against. So the contract stays where it
// was written and this harness reaches it. The public export preserves both package directories,
// and since 2026-09-09 the harness and its complete cross-package dependency closure all ship.
import { loadContract, verifyArmInventory, refuse } from '../../wyrd/scripts/verify-relocation-contract.mjs';
import { guardBattery, batteryLockFixture } from './battery-lock.mjs';

const pkg = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
guardBattery('fence suite');
batteryLockFixture();

/**
 * ⚠⚠ THE RELOCATION CONTRACT, AND IT RUNS FIRST — before the version gate, before the preflight,
 * before one test.
 *
 * `arms.mjs` is this package's own declaration and the checks further down compare the suite
 * against it, which is a comparison of the tree with itself. That is exactly the check a move can
 * satisfy while losing arms: delete a test AND its row, and both sides agree about a smaller
 * suite. The contract is the outside referent, written before anything moved, with no generator.
 */
{
    const { contract, problems } = loadContract();
    if (problems.length) refuse(problems, 'the contract is not internally consistent');
    const armProblems = verifyArmInventory(contract, 'wyrd-fence', ALL_ARMS);
    if (armProblems.length) refuse(armProblems, "wyrd-fence's declared arm inventory does not match the relocation contract");
    console.log(`· relocation contract: ${Object.keys(ALL_ARMS).length} arms declared here, of ${contract.totals.arms} locked pre-move plus ${contract.armsAddedPostMove.length} added since`);
}

/**
 * ⚠ TWO TIERS, AND THE DEFAULT IS STILL THE WHOLE SUITE. Without `--portable` the symlink
 * preflight refuses and a machine lacking the privilege runs nothing — a green meaning "the arms
 * that could run, ran" is a defect, not a pass. `--portable` runs TIER 1 and states its
 * denominator. No count is written in this comment on purpose; both tier sizes are derived from
 * `arms.mjs` at run time.
 */
const portable = process.argv.slice(2).includes('--portable');

/**
 * ⚠⚠ THE FENCE VERSION GATE, WITH A `self` EXEMPTION — AND REUSING THE READER'S VERBATIM WOULD
 * REFUSE FALSELY.
 *
 * The Reader's gate ends by asserting two things about the derived workspace SET, so that a set
 * which shrank to nothing cannot check nothing and print a tick:
 *
 *   · `self` is in the set, AND `self` declares a `wyrd-fence` dependency;
 *   · at least one package declares the fence.
 *
 * The second holds here. The first does not: `self` IS the fence, and no package declares a
 * dependency on itself, so `self.manifest.dependencies['wyrd-fence'] === undefined` is simply true
 * and the gate would refuse a perfectly healthy workspace. A sibling lane measured this on
 * 2026-09-01 and wrote it into the relocation contract as a merge note.
 *
 * ⚠ THE EXEMPTION IS NOT "SKIP THE ASSERTION WHEN IT IS INCONVENIENT". The claim the Reader's line
 * makes is *this suite resolves the local fence rather than a registry copy*. Here that claim is
 * stronger and cheaper: this suite imports `../dist/fsgate.js`, a path inside this package, so
 * there is no resolution to get wrong. What replaces the line is the assertion that `self` IS the
 * fence — that the derived set really is this workspace's and really does contain the package this
 * file lives in. A set that does not is not one whose version agreement means anything.
 *
 * ⚠ AND THE VERSION CHECK ITSELF IS KEPT IN FULL, because it is not about how this suite resolves
 * the fence. It is about every OTHER workspace manifest naming the exact version this package
 * publishes: the moment one diverges npm resolves that consumer's fence from the REGISTRY, with no
 * error and no warning. This package is the subject of that failure even though it is never the
 * victim, so the gate belongs here as much as in the Reader.
 *
 * The package set is DERIVED from the `workspaces` declaration, never listed — a hand-written list
 * is a claim that today's list is the whole set and it goes stale silently, and because a listed
 * name is a name written down it also discloses packages that have never been released.
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

    const root = findWorkspaceRoot(pkg);
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
    // Refused before the fence is looked for: a set with a hole in it could fail to find it and
    // then report the wrong reason for the same defect.
    if (problems.length) return { problems, notes, checked };

    // ⚠ THE FENCE IS FOUND IN THE DERIVED SET, NOT ASSUMED TO BE `self`. Reading `self` as the
    // fence because this file sits inside it would make the assertion below unfalsifiable.
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

    // ⚠⚠ THE `self` ASSERTION, AND THIS IS THE ONE LINE THAT DIFFERS FROM THE READER'S GATE.
    // There, `self` is a CONSUMER and the claim is that it declares the fence. Here `self` IS the
    // fence, so the claim that carries the same weight is that the derived set contains this
    // package AND that the package it found by name is this one.
    const self = workspace.find(entry =>
        fs.realpathSync.native(entry.directory) === fs.realpathSync.native(pkg));
    if (!self) {
        problems.push(`the workspace declaration at ${rel(root.rootDir)}/package.json does not enumerate ${rel(pkg)}, which is this package — the derived set is not this workspace's`);
    } else if (self.manifest.name !== FENCE) {
        problems.push(`this package declares the name ${JSON.stringify(self.manifest.name)}, but this suite is ${FENCE}'s — the gate would be checking a version against the wrong subject`);
    } else if (path.resolve(self.directory) !== path.resolve(fence.directory)) {
        problems.push(`two workspace packages answer to ${FENCE} — ${rel(self.directory)} and ${rel(fence.directory)}`);
    }
    if (!checked.length) {
        problems.push(`no workspace package declares a dependency on ${FENCE} — this gate would be asserting nothing`);
    }
    return { problems, notes, checked, version: fence.manifest.version };
}

const gate = fenceVersionGate();
for (const note of gate.notes) console.log(`  · ${note}`);
if (gate.problems.length) {
    console.error(`\n⛔ SUITE GATE REFUSED — the workspace ${FENCE} version gate did not pass`);
    for (const problem of gate.problems) console.error(`   · ${problem}`);
    console.error('\n   NOTHING WAS RUN. A mismatch makes npm resolve the fence from the registry');
    console.error('   instead of linking the local one, and a consumer would then run other code.');
    process.exit(1);
}
console.log(`· ${FENCE}@${gate.version}: ${gate.checked.length} workspace manifest(s) declare it — ${gate.checked.join(', ')}`);

/**
 * ⚠ THE FILE LIST IS HARD-CODED, AND THAT IS A DECISION RATHER THAN INERTIA. Auto-discovery is the
 * wrong trade here specifically: a rename or a move silently stops matching a glob, and this
 * suite's whole value is its denominator. Adding a test file costs two deliberate edits — this
 * list and `test/arms.mjs` — which is the point.
 *
 * ⚠ AND IT IS PREFLIGHTED. `node --test` given a path that does not exist is one of the ways a
 * suite silently shrinks; the inventory below would catch it afterwards, but the message would
 * name seventy missing arms rather than one missing file.
 */
const FILES = [
    'test/fsgate.test.js',
    'test/grant.test.js',
    'test/preflight.test.js',
    'test/published-claims.test.js',
    'test/surface.test.js'
];

const absent = FILES.filter(file => !fs.existsSync(path.join(pkg, file)));
if (absent.length || FILES.length === 0) {
    console.error('\n⛔ SUITE GATE REFUSED TO RUN');
    if (FILES.length === 0) console.error('   · the runner enumerates no test files at all');
    for (const file of absent) console.error(`   · ${file} does not exist`);
    process.exit(1);
}

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

const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-fence-arms-'));
process.once('exit', () => fs.rmSync(logDir, { recursive: true, force: true }));

const child = spawn(process.execPath, [fileURLToPath(new URL('./battery-lock.mjs', import.meta.url)),
    'exec', 'fence test subprocess', '--', process.execPath, '--test', ...FILES], {
    cwd: pkg,
    env: {
        ...process.env,
        WYRD_ARM_LOG: logDir,
        ...(portable ? { WYRD_PORTABLE: '1' } : {}),
        // ⚠ COLOUR BREAKS THE SUMMARY PARSE, AND ONLY IN A REAL TERMINAL. `node --test` writes its
        // summary in ANSI colour when stdout is a TTY, so `ℹ fail 0` arrives wrapped in escape
        // sequences and the anchored match below finds nothing — invisible to every piped caller
        // and to CI, and broken for the person at the keyboard.
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
    const failures = [];

    // Belt and braces with NO_COLOR above: suppressing colour at the source is the fix, stripping
    // it here is the guard for a future reporter that emits it anyway.
    const plain = out.replace(/\[[0-9;]*m/g, '');
    const number = label => {
        const match = plain.match(new RegExp(`^\\u2139 ${label} (\\d+)$`, 'm'));
        return match ? Number(match[1]) : null;
    };
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

    const declared = Object.keys(ALL_ARMS);
    const total = declared.length;
    // ⚠ ZERO IS A FAILURE ON BOTH SIDES. An empty inventory makes the equality below vacuously
    // true, which is the green-on-nothing this file exists to prevent.
    if (declared.length === 0) failures.push('the design inventory (test/arms.mjs) declares no arms');
    if (executed.size === 0) failures.push('no arm registered itself — the manifest was never reached');

    const expected = portable ? PORTABLE_ARMS : declared;
    const missing = expected.filter(id => !executed.has(id));
    const extra = [...executed].filter(id => !expected.includes(id));
    if (missing.length) failures.push(`expected but NOT EXECUTED: ${missing.join(', ')}`);
    // ⚠ In portable mode this catches the dangerous direction: a tier-2 arm that RAN means its
    // fixture was built after all, so the tier list is wrong and the skip set is a fiction.
    if (extra.length) failures.push(`executed but not expected in this tier: ${extra.join(', ')}`);

    // ⚠ THE SKIPPED SET BY IDENTITY, NOT BY COUNT. Comparing only the number node reports lets a
    // deleted tier-2 test be masked by an unrelated skipped one. Identities come from `tier2()` at
    // registration time, which runs even though the skipped body does not.
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
     * aggregation unions this with the Reader's and compares against the locked 88; if it were
     * written only on success, a failing package would contribute nothing and the union would then
     * report a DIFFERENT failure than the real one.
     */
    const emit = process.env['WYRD_EXECUTED_OUT'];
    if (emit) {
        try {
            fs.mkdirSync(path.dirname(emit), { recursive: true });
            fs.writeFileSync(emit, JSON.stringify({
                package: 'wyrd-fence',
                tier: portable ? 'portable' : 'full',
                declared,
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
        // ⚠ THE DENOMINATOR IS THE POINT, so it is stated before the pass line rather than after.
        console.log(`\n⚠ PARTIAL RUN — TIER 1 ONLY. ${expected.length} of ${total} fence arms ran.`);
        console.log(`   ${SYMLINK_PRIVILEGE_ARMS.size} arms were NOT run: they need the Windows symlink privilege.`);
        console.log(`   Held back: ${[...SYMLINK_PRIVILEGE_ARMS].join(', ')}`);
        console.log('   These cover symlink escapes, chains, cycles and the mirror shapes — this');
        console.log('   fence\'s hardest cases. A green here is NOT a green fence.');
        console.log(`   For all ${total}: enable Developer Mode and run \`npm test\`.`);
        console.log(`\n✔ fence tier-1 gate: ${expected.length} arms all executed; 0 failed, 0 unexpected skips.`);
        return;
    }
    console.log(`\n✔ fence suite gate: ${total} declared arms all executed; 0 failed, 0 skipped, 0 cancelled.`);
});
