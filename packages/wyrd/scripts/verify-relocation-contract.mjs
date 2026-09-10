#!/usr/bin/env node
/**
 * THE RELOCATION CONTRACT, CHECKED.
 *
 * `designs/2026-09-01-fence-test-relocation-plan.md` moves the fence's tests into the fence. The
 * whole value of this suite is its DENOMINATOR, and a move is the one operation that can shrink a
 * denominator while every gate stays green: an arm that fails to arrive in its new package simply
 * stops existing, and an inventory that no longer lists it agrees with itself.
 *
 * `test/relocation-contract.json` is the pre-move truth, written down BEFORE anything moved, while
 * the Reader still held all 88 arms and all 69 mutation rows. This file is what reads it.
 *
 * ⚠⚠ THERE IS NO GENERATOR AND THERE MUST NEVER BE ONE. No `--update`, no `--bless`, no script that
 * emits the contract. That absence IS the control: when this check fails, the only two moves
 * available are "put the arm back" and "edit a permanent historical record by hand", and the second
 * is a review event rather than a reflex. A regenerate command would collapse both into one
 * keystroke and the contract would then certify whatever the tree happened to contain — the exact
 * failure the fence's own `.d.ts` baseline is written against.
 *
 * ⚠ WHAT THIS DOES NOT STOP, STATED PLAINLY. Nothing here prevents someone editing the code and the
 * contract in the same change. The design document says the same thing about itself. The control is
 * social, resting on a structural absence, and it is the strongest one available.
 *
 * Used two ways:
 *
 *   · as a LIBRARY, by each package's `scripts/run-tests.mjs` before it spawns the suite and each
 *     `scripts/mutate.mjs` before it mutates anything — the fence's two reach across into this
 *     package for it, because there is one contract and there must only ever be one. Every caller
 *     hands it their LIVE inventory, so the check compares the contract against what the harness is
 *     actually about to run, never against a re-read of the same declaration.
 *     ⚠ AND THE INVENTORY IS HANDED OVER WHOLE. `verifyArmInventory` takes `ALL_ARMS` itself, not
 *     `Object.keys` of it; `verifyMutationRows` takes each row's `what` as well as its id and file.
 *     Every one of those call sites discarded the text until 2026-09-02, which left `asserts` and
 *     `mutates` — two fields of a permanent record — with no reader at all.
 *   · as a CLI, `node scripts/verify-relocation-contract.mjs`, which verifies the contract's own
 *     integrity and the Reader's arm inventory, and says out loud which half it cannot see.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/** The contract lives with the tests it describes, not with the script that reads it. */
export const CONTRACT_PATH = path.join(here, '..', 'test', 'relocation-contract.json');

/**
 * ⚠⚠ THE PRE-MOVE MUTATION MEASUREMENT, AND UNTIL 2026-09-02 IT WAS ASSERTED BY NOTHING.
 *
 * `mutation-baseline.json` is the matrix as it RAN before the fence's tests moved, captured at
 * commit `3b1ee5f` ("mutation baseline, captured BEFORE the fence moves"). It is the other half of
 * the same record `test/relocation-contract.json` is: the contract says what each row is CONTRACTED
 * to do, this says what each row was MEASURED doing on the day of the move.
 *
 * The only thing in this repo that named it was `scripts/release.mjs`'s intentionally-unshipped
 * inventory, which classifies it and never opens it — so it could be edited to say anything, in any
 * direction, and every gate in both packages would stay green. That is the same class as the
 * contract's `asserts` and `mutates` fields on the day before they got a reader, and the same class
 * as the `plan` references: a permanent record that reads like a control and is read by nothing.
 *
 * ⚠ IT IS CHECKED HERE RATHER THAN IN AN EXPORT OF ITS OWN, for the reason the `plan` check gives:
 * a separate function is a function a caller can forget to call, and a control nobody calls is the
 * precise failure being closed. Folded into `loadContract`, all six call sites get it.
 */
export const BASELINE_PATH = path.join(here, '..', 'mutation-baseline.json');

/**
 * ⚠ THE HISTORICAL NUMBERS, DUPLICATED ON PURPOSE — this is the one place in this lane where a
 * hard-coded count is correct. They are not "the current size of the suite"; they are the size the
 * suite HAD on 2026-09-01, before the move, and that is a fact which cannot go stale. The contract
 * declares them too. Two files must be edited in agreement to change either, which is the point:
 * a single-file edit that shrinks the denominator refuses here instead of passing.
 *
 * The plan states the split as a hard requirement: "the fence mutation set is not exactly 66 and
 * the Reader's not exactly 3" is a listed failure condition.
 */
export const LOCKED = Object.freeze({
    arms: 88,
    mutations: 69,
    fenceMutations: 66,
    readerMutations: 3
});

const FENCE = 'wyrd-fence';
const READER = 'wyrd';
const PACKAGES = [READER, FENCE];
const DESTINATIONS = [...PACKAGES, 'undecided'];

/**
 * ⚠ THE MUTATION HARNESS'S `FILES` KEY IS THE INDEPENDENT REFERENT for a row's destination. A row
 * that patches the fence's built output belongs to the fence; anything patching this package's
 * `dist` belongs here. That is derivable from the live row, so a contracted destination can be
 * cross-checked against something the contract did not author — the only destination field in this
 * whole file that has an oracle.
 *
 * ⚠ AN UNKNOWN KEY REFUSES. A `FILES` entry this map does not know is a new mutation target whose
 * ownership nobody has decided; treating it as a default would be an unknown key failing open,
 * which is how a control comes to be configured and to configure nothing.
 */
const FILE_OWNER = Object.freeze({
    fsgate: FENCE,
    preflight: FENCE,
    readme: FENCE,
    main: READER,
    index: READER,
    server: READER,
    /**
     * ⚠ TWO KEYS THAT ARE NOT BUILT OUTPUT, ADDED 2026-09-02 WITH `M94`/`M95`. The note above says
     * "anything patching this package's `dist`", and these two are the case that sentence did not
     * anticipate: `server.json` and `package.json` are PRODUCT files — the registry manifest and
     * the packed manifest — that ship and are not produced by `tsc`. `MF1-manifest-schema` and
     * `MF2-manifest-cross-reference` assert them, and until these keys existed no row could reach
     * either arm, which is the ungraded state `mutationsAddedPostMove` was added to end.
     *
     * ⚠ THE ORACLE IS UNWEAKENED. Both files live at THIS package's root, so the key still derives
     * the owner from where the mutated file is rather than from what the contract declares; the
     * fence has its own pair and would need its own keys.
     */
    serverjson: READER,
    pkgjson: READER
});

/**
 * ⚠⚠ AN ARM NAME WRITTEN INTO PROSE, AND WHETHER IT STILL NAMES ANYTHING.
 *
 * Every mutation row carries a `plan` — what the design's §5a table claimed would kill it — and
 * until 2026-09-02 nothing verified that the arms it names EXIST. That is the same class the
 * contract's `asserts` and `mutates` fields were in on the day before: a field that looks like a
 * control and is read by nothing. A `plan` naming an arm that was renamed or deleted points at
 * thin air, and the row still runs and still reports under it.
 *
 * ⚠ THE CHECK IS REFERENTIAL, NOT SUBSTANTIVE, AND THE DIFFERENCE IS THE WHOLE DESIGN. `plan` is
 * allowed — required, even — to be WRONG about which arm bites: the harness prints the §5a claim
 * beside what actually went red precisely so the divergence is visible, and `M10` claims six arms
 * that no longer redden. Making `plan` agree with the run would delete the finding. All this asks
 * is that the names resolve.
 *
 * ⚠ IT REFUSES ON AN AMBIGUOUS TOKEN RATHER THAN GUESSING. Nothing here can tell an arm citation
 * from an English word that happens to be shaped like one, so a token of arm shape that resolves
 * to no arm is a refusal, and the direction block tells the author to respell it. The bias is
 * deliberate: under-matching means a dangling reference passes, which is the state being left.
 *
 * ⚠ SHAPES, FROM THE LIVE INVENTORIES: bare-numbered (`A1`, `A17`), suffixed (`A14-M`,
 * `A55-same-path-replacement`), the two prefixed families (`META-…`, `SHAPE-…`), the Reader's and
 * fence's `S…`/`E…` rows, and the fence's `FP1`/`FP2`. A range spelled `A1-A6` matches as ONE
 * token and resolves to nothing — correctly, because nothing guarantees the numbers between two
 * endpoints are arms.
 */
const ARM_REFERENCE = /\b(?:META|SHAPE|FP\d+|PC\d+|[ASE]\d+)(?:-[A-Za-z0-9]+)*\b/g;

function armReferences(text) {
    return [...new Set(text.match(ARM_REFERENCE) ?? [])];
}

/**
 * ⚠⚠ ARMS WHOSE REDNESS CARRIES NO INFORMATION, EXEMPTED BY NAME FROM EVERY DECLARED RED SET.
 *
 * `verifyMutationResults` compares a declared `expectedRed` EXACTLY — as a set, not a minimum. An
 * arm that reddens on its own account would make that comparison a coin flip, and a gate that
 * flakes is a gate somebody switches off. This is the list of those arms, and it is ONE entry.
 *
 * ⚠⚠ AN ENTRY MUST CARRY ITS MEASUREMENT, AND THAT IS ASSERTED RATHER THAN ASKED FOR. A value that
 * is empty or blank refuses the run. Without it this list is the obvious place to quietly silence
 * a real failure: an arm that started reddening because a mutation genuinely reaches it now looks
 * exactly like an arm that reddens by itself, and only a measurement tells them apart.
 *
 * ⚠ WHAT THAT CANNOT DO, SAID PLAINLY — the same limit the contract states about itself. Nothing
 * here can check that a measurement is TRUE, only that one was written down and had to survive a
 * review. The control is social, resting on a structural requirement, and it is the strongest one
 * available.
 *
 * ⚠ IT LIVES IN CODE AND NOT IN THE CONTRACT ON PURPOSE. A session adding a row to the contract is
 * already editing the contract, so an exemption list living there could be widened in the same
 * keystroke as the row it silences. Here, softening the gate means editing the CHECKER — the one
 * file in this lane whose entire identity is that its edits are review events.
 */
/**
 * ⚠⚠ EMPTY SINCE 2026-09-04, AND THE ONE ENTRY IT HELD WAS RETIRED ON MEASUREMENT RATHER THAN
 * TIDIED AWAY. `A35-root-moved` was exempted on 2026-09-02 with an honest measurement: it went red
 * INTERMITTENTLY under mutants that did not target it, and 2,500 standalone iterations reproduced
 * it ZERO times, so the cause read as mechanism-shaped rather than rate-shaped. That was the right
 * call on the evidence then available.
 *
 * ⚠ WHAT CHANGED IS THE CODE UNDERNEATH IT, NOT THE STANDARD. The F8 ruling (2026-09-03) made the
 * granted root's identity re-check UNCONDITIONAL on every operation. `A35-root-moved` swaps the
 * root and asserts the swap is caught — a WRITE-path assertion running through `asWriteRefusal` —
 * so a write-refusal mutant now reaches the root-identity arms through a path that did not exist
 * when the exemption was written the day before.
 *
 * ⚠ RE-MEASURED 2026-09-03, 28 runs, ZERO intermittency anywhere:
 *     unmutated control                          A35 red 0/8
 *     M12, skip realpath arbitration (READ path) A35 red 0/8  (reddens A14-M / A36 / A38)
 *     M65, drop `retained` (WRITE path)          A35 red 6/6, byte-identical red set each run
 *     M66, populate `retained` (WRITE path)      A35 red 6/6, byte-identical red set each run
 * Every reddening is deterministic and traceable to the write path. Nothing supports the
 * "intermittent under non-targeting mutants" premise any more.
 *
 * ⚠⚠ AND THE COST OF KEEPING IT HAD INVERTED, WHICH IS WHAT DECIDED IT. `exempt()` filters exempt
 * ids out of `actual` BEFORE the comparison, in BOTH directions — so a row that legitimately
 * reddens `A35` could not DECLARE it, and an attempt to widen `M89`'s `expectedRed` was refused on
 * exactly that ground. A list built to tolerate noise had become a way to absorb a real regression
 * in the root-identity arms, which are the safety-critical ones.
 *
 * ⚠ THE RETURN PATH, SO NOBODY RE-DERIVES IT: 28 runs on one machine is a reading, not a proof of
 * absence. **If the flake reappears, add a NARROW entry naming the read-path rows it actually
 * affects — never the blanket form**, which is what created the hazard above. The mechanism below
 * is kept intact for exactly that case; only the entry went.
 */
const RED_SET_NOISE_EXEMPT = Object.freeze({});

/** The exemption list's own integrity, checked on every run that could be softened by it. */
function noiseExemptionProblems(contractedArmIds) {
    const problems = [];
    for (const [id, measurement] of Object.entries(RED_SET_NOISE_EXEMPT)) {
        if (typeof measurement !== 'string' || measurement.trim() === '') {
            problems.push(`the red-set noise exemption for "${id}" states no measurement — an exemption asserted rather than measured is how this list becomes a way to silence a real failure`);
        }
        if (!contractedArmIds.has(id)) {
            problems.push(`the red-set noise exemption names "${id}", which is not an arm the contract knows — an exemption for an arm that does not exist silences nothing and hides that it silences nothing`);
        }
    }
    return problems;
}

function tally(entries, field) {
    const counts = {};
    for (const entry of entries) counts[entry[field]] = (counts[entry[field]] ?? 0) + 1;
    return counts;
}

function compareTally(label, actual, declared, problems) {
    if (declared === null || typeof declared !== 'object') {
        problems.push(`the contract declares no ${label} tally`);
        return;
    }
    const keys = [...new Set([...Object.keys(actual), ...Object.keys(declared)])].sort();
    for (const key of keys) {
        const got = actual[key] ?? 0;
        const want = declared[key] ?? 0;
        if (got !== want) {
            problems.push(`${label}: the rows say ${key} = ${got}, the declared tally says ${want}`);
        }
    }
}

function duplicates(ids) {
    const seen = new Set();
    return [...new Set(ids.filter(id => (seen.has(id) ? true : (seen.add(id), false))))];
}

/**
 * The package an entry lives in RIGHT NOW.
 *
 * ⚠ `moved` is how the later slices of the relocation walk this contract forward. It started false
 * for every row and flipping one is a deliberate, reviewable edit to a permanent record. It cannot
 * be flipped to buy silence: the id must then turn up in the DESTINATION package's inventory, and
 * an id that is in neither package's inventory fails there instead of here.
 *
 * ⚠ THE ORDERING CONSTRAINT THAT MADE THAT TRUE, KEPT BECAUSE IT STILL GOVERNS ANY FUTURE MOVE.
 * "Fails there instead of here" needs a THERE. Until the destination package had a runner of its
 * own AND the root aggregation of the plan's step 4 existed, flipping `moved` would have dropped an
 * arm from the Reader with nothing on the other side to catch it — which is why every row was false
 * while that was the state of the tree, and why the plan put step 4 in the same change as step 3.
 *
 * ⚠ BOTH LANDED ON 2026-09-01, so the constraint is satisfied rather than retired:
 * `packages/wyrd-fence/scripts/run-tests.mjs` is the fence's own runner and `scripts/aggregate.mjs`
 * is the root aggregation, and 68 of the 88 locked rows now read `moved: true`. The rule survives
 * the landing: a move whose destination has no runner still has no there, and the next relocation
 * has to build one before it flips a single row.
 */
function currentHome(entry) {
    return entry.moved === true ? entry.destination : entry.currentPackage;
}

/**
 * ⚠⚠ THE BASELINE AGAINST THE CONTRACT'S LOCKED ROWS, AND THE COMPARISON IS SET EQUALITY.
 *
 * Both files describe THE SAME 69 ROWS of the same pre-move matrix, so anything weaker than "the
 * same ids, exactly" leaves a hole in the direction that matters. A subset check would let a row be
 * dropped from the baseline; a superset check would let one be dropped from the contract's locked
 * array — which `LOCKED.mutations` already catches, but only by count, and a swap keeps the count.
 *
 * ⚠ THE COMPOSITE IDS ARE NOT AN EXCEPTION, AND THAT WAS MEASURED RATHER THAN ASSUMED. `M4+M2` and
 * the `M20-*` family look like they might be baseline-only combinations, and they are not: the two
 * id sets are equal today, all 69 of them, with nothing on either side the other lacks. So this
 * states the strong rule instead of pre-weakening it around a case that does not exist. If a future
 * baseline row genuinely has no contract row, the right answer is a contract row or a stated
 * exemption — not a comparison quietly relaxed to let it through.
 *
 * ⚠ AND ONLY THE LOCKED 69, NEVER `mutationsAddedPostMove`. The baseline is a measurement of the
 * matrix as it stood BEFORE the move; a row added after it was captured cannot appear in it, and
 * requiring one to would make the additions array unusable — the exact "stop adding rows" lesson
 * `allContractedMutations` exists to avoid teaching.
 *
 * ⚠ WHAT THIS CANNOT DO, SAID PLAINLY, as everywhere else in this file: it makes the two records
 * AGREE. It cannot make either TRUE. A row whose measured disposition was mis-transcribed into both
 * files on the day of capture passes here. What it stops is the two drifting apart afterwards,
 * which is the only failure a checker on two files can reach.
 */
function baselineProblems(lockedMutations) {
    let baseline;
    try {
        baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
    } catch (error) {
        return [`${BASELINE_PATH} could not be read as JSON — ${error.message}. It is the pre-move mutation measurement and the contract's locked rows are checked against it; a missing or unparseable baseline is a deleted record, not an absent option`];
    }
    if (!Array.isArray(baseline)) {
        return [`the mutation baseline is ${JSON.stringify(typeof baseline)} rather than an array of measured rows — a shape this check cannot read is a record it cannot hold the contract to`];
    }

    const problems = [];
    const dupes = duplicates(baseline.map(row => row?.id));
    if (dupes.length) {
        problems.push(`the mutation baseline lists the same id twice — ${dupes.join(', ')}`);
    }

    const locked = new Map(lockedMutations.map(row => [row.id, row]));
    const measured = new Map();
    for (const [index, row] of baseline.entries()) {
        if (typeof row?.id !== 'string' || row.id === '') {
            problems.push(`mutation baseline row [${index}] has no id`);
            continue;
        }
        measured.set(row.id, row);
        if (!locked.has(row.id)) {
            problems.push(`the mutation baseline measures "${row.id}", which is not one of the contract's locked pre-move rows — both files describe the same 69-row matrix, so a row in one and not the other means one of them lost a row`);
        }
    }
    for (const row of lockedMutations) {
        if (!measured.has(row.id)) {
            problems.push(`the contract locks "${row.id}" and the mutation baseline never measured it — both files describe the same 69-row matrix, so a row in one and not the other means one of them lost a row`);
        }
    }

    /**
     * ⚠ THE DISPOSITION, WHICH IS THE FIELD WITH TEETH. `status` is what the row DID on the day of
     * capture and `expectedDisposition` is what the contract requires it to keep doing; a matrix
     * run grades against the contract, so a baseline `status` edited to agree with a weakened
     * contract row erases the only independent record that the row ever behaved differently.
     */
    for (const [id, row] of measured) {
        const contracted = locked.get(id);
        if (!contracted) continue; // already reported above
        if (row.status !== contracted.expectedDisposition) {
            problems.push(
                `mutation "${id}" was MEASURED ${JSON.stringify(row.status)} before the move and the contract expects ${JSON.stringify(contracted.expectedDisposition)}.\n` +
                `       measured, in ${path.relative(path.join(here, '..', '..', '..'), BASELINE_PATH).split(path.sep).join('/')}: ${JSON.stringify(row.status)}\n` +
                `       contracted, in ${path.relative(path.join(here, '..', '..', '..'), CONTRACT_PATH).split(path.sep).join('/')}: ${JSON.stringify(contracted.expectedDisposition)}`);
        }
    }
    if (problems.length) problems.push(BASELINE_DIRECTION);
    return problems;
}

/**
 * ⚠⚠ THE FOURTH DIRECTION BLOCK, IN THE SHAPE OF THE THREE ABOVE AND DELIBERATELY NOT A NEW STYLE —
 * see `ARM_TEXT_DIRECTION` for the argument about gradients, which is not repeated here.
 *
 * ⚠ WHAT DIFFERS IS THAT NEITHER HALF IS PROSE. `asserts` and `mutates` are two descriptions of one
 * thing and the artefact decides between them. Here both halves are the SAME FACT recorded twice —
 * what the row did — so there is nothing to read that settles it except the run itself, and the run
 * that produced the baseline is on the other side of the move and cannot be repeated.
 *
 * ⚠ NOTHING HERE RECORDS AN ANSWER — no flag, no prompt, no attestation field — for the reason
 * given on the arm block.
 */
const BASELINE_DIRECTION = [
    'DIRECTION: THE BASELINE IS A MEASUREMENT OF A RUN THAT CANNOT BE REPEATED.',
    '`mutation-baseline.json` was captured at commit `3b1ee5f`, BEFORE the fence\'s tests moved, and',
    'the tree that produced it no longer exists. So unlike an `asserts` or a `mutates` mismatch,',
    'there is no artefact to go and read that settles which half is right.',
    'Editing the baseline is the smaller edit every time, and it is almost never the right one: it',
    'rewrites what was observed, which is the one thing a record of a past run is for. A row whose',
    'CONTRACTED disposition genuinely changed wants the contract edited and the change reviewed —',
    'and `verifyMutationResults` grades against the contract, so the current matrix already says',
    'what the row does TODAY. The baseline says what it did THEN, and those are different questions.',
    'A row present in one file and absent from the other is a lost row, not a disagreement. Put it',
    'back rather than deleting its twin.'
].join('\n       ');

/** Reads and structurally verifies the contract. Never writes, and there is nothing here that could. */
export function loadContract() {
    const problems = [];
    let contract;
    try {
        contract = JSON.parse(fs.readFileSync(CONTRACT_PATH, 'utf8'));
    } catch (error) {
        return { contract: null, problems: [`${CONTRACT_PATH} could not be read as JSON — ${error.message}`] };
    }

    const arms = Array.isArray(contract.arms) ? contract.arms : null;
    const mutations = Array.isArray(contract.mutations) ? contract.mutations : null;
    /**
     * ⚠⚠ ARMS ADDED AFTER THE MOVE, AND THEY ARE A SEPARATE ARRAY BECAUSE THE 88 IS A HISTORICAL
     * MEASUREMENT. `LOCKED.arms` is asserted against `arms.length` from code below, so appending a
     * new arm to `arms` refuses — correctly: a session that could grow the pre-move total could
     * make a shrunken suite balance by adding arms that were never part of the thing being
     * measured. New arms are still CONTRACTED (deleting one refuses) and still ROUTED (an id in no
     * package's inventory refuses); they simply do not count toward a number about the past.
     *
     * ⚠ ABSENT IS LEGAL AND MEANS "NONE", but a present-and-wrong value REFUSES. A contract whose
     * `armsAddedPostMove` is a string or an object would otherwise read as zero additions and let
     * an inventory that declares one pass as though it declared none.
     */
    const added = contract.armsAddedPostMove === undefined ? []
        : (Array.isArray(contract.armsAddedPostMove) ? contract.armsAddedPostMove : null);
    /**
     * ⚠⚠ THE SAME ARRAY FOR MUTATION ROWS, AND IT ARRIVED LATE ENOUGH THAT TWO ARMS WERE ALREADY
     * OUTSIDE THE MATRIX. `LOCKED.mutations` is asserted against `mutations.length` from code
     * exactly as `LOCKED.arms` is, which was correct and had one consequence nobody chose: with no
     * additions array beside it, an arm added after the move could never receive a mutation row at
     * all. `A54-writeall-loop` and `A55-same-path-replacement` were each graded by a measurement
     * written into a source comment, and a comment is not re-run. `A55` is the arm pinning open
     * fork F8, so the thing with no reader was the detector for a security gap.
     *
     * ⚠ WHAT THIS ARRAY MUST NOT REACH IS THE PRE-MOVE DENOMINATOR, and the split is mechanical
     * rather than promised: every number about the past — `LOCKED.mutations`, the 66/3 split,
     * `totals.mutations`, `mutationsByDestination` — is still computed from `mutations` ALONE, so
     * an addition cannot move one. What additions DO join is the live half, all of which reads
     * `allContractedMutations`: routing, the `mutates` text comparison, the every-row-produced-a-
     * result check, and the contracted-KILL check.
     *
     * ⚠ ABSENT IS LEGAL AND MEANS "NONE", present-and-wrong REFUSES — the same rule and the same
     * reason as `armsAddedPostMove` above.
     */
    const mutationsAdded = contract.mutationsAddedPostMove === undefined ? []
        : (Array.isArray(contract.mutationsAddedPostMove) ? contract.mutationsAddedPostMove : null);
    if (!arms) problems.push('the contract declares no `arms` array');
    if (!mutations) problems.push('the contract declares no `mutations` array');
    if (added === null) problems.push('the contract declares `armsAddedPostMove` and it is not an array');
    if (mutationsAdded === null) problems.push('the contract declares `mutationsAddedPostMove` and it is not an array');
    if (!arms || !mutations || added === null || mutationsAdded === null) return { contract: null, problems };

    const check = (entries, label, extra = () => {}) => {
        for (const [index, entry] of entries.entries()) {
            const where = `${label}[${index}]${typeof entry?.id === 'string' ? ` (${entry.id})` : ''}`;
            if (typeof entry?.id !== 'string' || entry.id === '') problems.push(`${where} has no id`);
            if (!PACKAGES.includes(entry?.currentPackage)) {
                problems.push(`${where} declares currentPackage ${JSON.stringify(entry?.currentPackage)}, which is not one of ${PACKAGES.join(', ')}`);
            }
            if (!DESTINATIONS.includes(entry?.destination)) {
                problems.push(`${where} declares destination ${JSON.stringify(entry?.destination)}, which is not one of ${DESTINATIONS.join(', ')}`);
            }
            if (typeof entry?.why !== 'string' || entry.why.trim() === '') {
                problems.push(`${where} carries no \`why\` — a destination with no stated reason is a guess that later reads as settled`);
            }
            if (entry?.moved === true && entry.destination === 'undecided') {
                problems.push(`${where} is marked moved but its destination is still undecided`);
            }
            extra(entry, where);
        }
        const dupes = duplicates(entries.map(entry => entry.id));
        if (dupes.length) problems.push(`${label}: duplicate id(s) — ${dupes.join(', ')}`);
    };

    /**
     * ⚠⚠ `asserts` AND `mutates` BECAME REQUIRED ON 2026-09-02, WHICH IS THE DAY THEY FIRST GOT A
     * READER. Both were written into every row when the contract was authored, and for a day
     * nothing compared either to anything: `verifyArmInventory` was handed `Object.keys(ALL_ARMS)`
     * and `verifyMutationRows` a `{ id, file }` projection, so the live text was discarded at the
     * call site before the check could see it. Two arms drifted from their locked wording inside
     * that window while this file printed `✔ contract integrity`.
     *
     * Requiring the field is the second half of closing that. A row that simply omitted it would
     * restore the identical hole one row at a time — nothing to compare against, so nothing said —
     * and an absent field failing open is how a control comes to be configured and to configure
     * nothing.
     */
    const requireText = (field, why) => (entry, where) => {
        if (typeof entry?.[field] !== 'string' || entry[field].trim() === '') {
            problems.push(`${where} carries no \`${field}\` — ${why}`);
        }
    };
    const requireAsserts = requireText('asserts', 'the locked wording of what the arm claims is what the live inventory is now checked against, and a row carrying none is a row that check skips in silence');

    check(arms, 'arms', requireAsserts);
    check(added, 'armsAddedPostMove', (entry, where) => {
        if (typeof entry?.addedOn !== 'string' || entry.addedOn.trim() === '') {
            problems.push(`${where} carries no \`addedOn\` — an addition with no date cannot be told from a locked row that lost its place`);
        }
        requireAsserts(entry, where);
    });
    // ⚠ AND THE ONE THING THE SEPARATE ARRAY MUST NOT BECOME: a place to re-home a locked arm. An
    // id appearing in both would be routed by whichever list was consulted last, and the pre-move
    // total would then be satisfiable by a row nobody counts.
    {
        const locked = new Set(arms.map(arm => arm.id));
        for (const entry of added) {
            if (locked.has(entry?.id)) {
                problems.push(`armsAddedPostMove declares "${entry.id}", which is one of the locked pre-move arms — an addition may not shadow a locked row`);
            }
        }
    }
    /**
     * Every arm id this contract knows — the locked 88 plus the additions — as the referent for the
     * mutation rows' `expectedRed`. Built here rather than from `allContractedArms`, which reads the
     * normalised contract this function has not finished producing.
     */
    const armIds = new Set([...arms, ...added].map(arm => arm?.id));

    /**
     * ⚠ ONE SET OF MUTATION-ROW RULES, APPLIED TO BOTH ARRAYS. A rule that held only for the locked
     * 69 would be a rule with a loophole exactly where new rows are written, and new rows are the
     * ones nobody has read yet.
     */
    const mutationRow = (entry, where) => {
        requireText('mutates', 'the locked wording of the transformation is what the live matrix is now checked against, and a row carrying none is a row that check skips in silence')(entry, where);
        /**
         * ⚠ AND THE DISPOSITION, WHICH NOTHING REQUIRED UNTIL THE MATRIX COULD GROW. All 69 locked
         * rows carry `KILLED` or `SURVIVED`, so this closes a hole rather than raising a bar — but
         * it is the additions that made the hole reachable: `verifyMutationResults` grades a row by
         * branching on this field, so a row carrying neither value runs, produces a result, and is
         * then walked past by both the adequacy check and the stale-row note. Silently ungraded is
         * the one state a row added to buy grading must not be able to reach.
         */
        if (entry?.expectedDisposition !== 'KILLED' && entry?.expectedDisposition !== 'SURVIVED') {
            problems.push(`${where} declares expectedDisposition ${JSON.stringify(entry?.expectedDisposition)} — a row is graded as KILLED or SURVIVED and nothing else, and a row carrying neither is one the results check walks past in silence`);
        }
        /**
         * ⚠⚠ THE EXACT RED SET, OPT-IN PER ROW — AND ABSENT MEANS UNGATED, NOT EMPTY.
         *
         * That is the one place this field's absence rule INVERTS the one every other array in this
         * contract follows, so it is stated here rather than assumed. `armsAddedPostMove` absent
         * means "no additions"; `expectedRed` absent means "this row makes no claim about which arms
         * redden, and the run will not check". `expectedRed: []` is a real and much stronger claim —
         * NOTHING may go red — and a row is entitled to make it.
         *
         * ⚠ WHY OPT-IN AT ALL, WHEN THE PUBLISH GATE REQUIRES A SET ON EVERY ROW.
         * `run-publish-gate-tests.mjs` can demand one because every arm it grades is deterministic.
         * This matrix has `A35-root-moved`, whose redness is measured noise, and a blanket-exact rule
         * here would flake and be switched off. Blanket-diagnostic was the state until 2026-09-02, and
         * it cannot ATTRIBUTE: `M71-root-identity-unconditional` reddens `A55-same-path-replacement`
         * and `META-no-outside-names` together, so KILLED never proved which arm caught it — and that
         * row exists to make `A55`'s pin permanent. Opt-in keeps the strong property everywhere it is
         * available and is honest about the one place it is not.
         *
         * ⚠ AND PRESENT-AND-WRONG REFUSES, as everywhere else here. A string, an object, or a list
         * carrying a blank would otherwise read as a declaration and gate on nothing.
         */
        if (entry?.expectedRed !== undefined) {
            if (!Array.isArray(entry.expectedRed) || entry.expectedRed.some(id => typeof id !== 'string' || id.trim() === '')) {
                problems.push(`${where} declares expectedRed ${JSON.stringify(entry.expectedRed)} — it is a list of arm ids or it is absent, and absent means UNGATED rather than empty`);
            } else {
                for (const id of entry.expectedRed) {
                    if (!armIds.has(id)) {
                        problems.push(`${where} declares expectedRed "${id}", which is not an arm this contract knows — a red set naming an arm that does not exist can never be satisfied`);
                    }
                    // ⚠ A DECLARED ARM THAT IS ALSO EXEMPT IS A DECLARATION THAT DOES NOTHING. The
                    // comparison drops exempt arms from both sides, so this would read as a pin and
                    // pin nothing — configured, and configuring nothing.
                    if (Object.hasOwn(RED_SET_NOISE_EXEMPT, id)) {
                        problems.push(`${where} declares expectedRed "${id}", which is on the measured noise-exemption list — the comparison ignores it in both directions, so declaring it claims a pin that does not exist`);
                    }
                }
            }
        }
        const owner = FILE_OWNER[entry?.file];
        if (owner === undefined) {
            problems.push(`${where} names mutation file key ${JSON.stringify(entry?.file)}, which this checker does not know — a new mutation target's ownership has to be decided, not defaulted`);
        } else if (entry.destination !== owner) {
            problems.push(`${where} patches \`${entry.file}\`, which belongs to ${owner}, but the contract routes it to ${entry.destination}`);
        }
    };

    check(mutations, 'mutations', mutationRow);
    check(mutationsAdded, 'mutationsAddedPostMove', (entry, where) => {
        if (typeof entry?.addedOn !== 'string' || entry.addedOn.trim() === '') {
            problems.push(`${where} carries no \`addedOn\` — an addition with no date cannot be told from a locked row that lost its place`);
        }
        mutationRow(entry, where);
    });
    // ⚠ THE SAME PROHIBITION THE ARMS HAVE, FOR THE SAME REASON: an id in both arrays would be
    // routed by whichever list was consulted last, and the locked 69 would then be satisfiable by
    // a row nobody counts.
    {
        const locked = new Set(mutations.map(row => row.id));
        for (const entry of mutationsAdded) {
            if (locked.has(entry?.id)) {
                problems.push(`mutationsAddedPostMove declares "${entry.id}", which is one of the locked pre-move mutation rows — an addition may not shadow a locked row`);
            }
        }
    }

    // The declared totals, against the rows themselves.
    const totals = contract.totals ?? {};
    if (arms.length !== totals.arms) problems.push(`the contract lists ${arms.length} arms but declares totals.arms = ${totals.arms}`);
    if (mutations.length !== totals.mutations) problems.push(`the contract lists ${mutations.length} mutation rows but declares totals.mutations = ${totals.mutations}`);
    compareTally('arms by destination', tally(arms, 'destination'), totals.armsByDestination, problems);
    compareTally('arms by current package', tally(arms, 'currentPackage'), totals.armsByCurrentPackage, problems);
    compareTally('mutations by destination', tally(mutations, 'destination'), totals.mutationsByDestination, problems);

    // ⚠ AND THE SAME NUMBERS AGAIN, FROM CODE RATHER THAN FROM THE CONTRACT. The tallies above only
    // prove the contract agrees with itself; a single edit that changed a row AND its tally would
    // pass them. These do not live in the contract, so that edit has to reach two files.
    //
    // ⚠⚠ EVERY LINE BELOW READS `arms` AND `mutations`, NEVER THE ADDITIONS, AND THAT IS WHAT KEEPS
    // BOTH LOCKED FIGURES LOCKED. The 88 and the 69 are measurements of a suite that existed on
    // 2026-09-01; a checker that counted the union would let a session restore a shrunken
    // denominator by appending rows to the array that has no ceiling. Adding an addition can never
    // turn a failure here into a pass — the only way to satisfy these is to put the missing thing
    // back, or to edit a permanent record by hand and have the edit reviewed.
    if (arms.length !== LOCKED.arms) problems.push(`the contract lists ${arms.length} arms; the pre-move suite had exactly ${LOCKED.arms}`);
    if (mutations.length !== LOCKED.mutations) problems.push(`the contract lists ${mutations.length} mutation rows; the pre-move matrix had exactly ${LOCKED.mutations}`);
    const mutationSplit = tally(mutations, 'destination');
    if ((mutationSplit[FENCE] ?? 0) !== LOCKED.fenceMutations) {
        problems.push(`the fence mutation set must be exactly ${LOCKED.fenceMutations}; the contract routes ${mutationSplit[FENCE] ?? 0} rows there`);
    }
    if ((mutationSplit[READER] ?? 0) !== LOCKED.readerMutations) {
        problems.push(`the Reader mutation set must be exactly ${LOCKED.readerMutations}; the contract routes ${mutationSplit[READER] ?? 0} rows there`);
    }

    // ⚠ AND THE MEASUREMENT THE LOCKED ROWS WERE WRITTEN FROM, which had no reader at all until
    // 2026-09-02. See `BASELINE_PATH` and `baselineProblems` above for why it lives here.
    for (const problem of baselineProblems(mutations)) problems.push(problem);

    // The normalised addition lists, so every consumer below reads one shape whether the keys were
    // present or not.
    contract.armsAddedPostMove = added;
    contract.mutationsAddedPostMove = mutationsAdded;

    return { contract: problems.length ? null : contract, problems };
}

/**
 * Every arm the contract knows about — the locked pre-move 88 plus anything added since.
 *
 * ⚠ THE ROOT AGGREGATION COMPARES AGAINST THIS, NOT AGAINST `arms`. A union that had to equal 88
 * exactly would fail the moment either package legitimately grew an arm, and the lesson that
 * teaches is "stop adding arms" — which is the opposite of what this contract is for.
 */
export function allContractedArms(contract) {
    return [...contract.arms, ...contract.armsAddedPostMove];
}

/**
 * Every mutation row the contract knows about — the locked pre-move 69 plus anything added since.
 *
 * ⚠ THE LIVE CHECKS READ THIS; THE HISTORICAL NUMBERS READ `contract.mutations`. A matrix required
 * to equal 69 exactly is a matrix that cannot grade an arm added after the move, which is how
 * `A54-writeall-loop` and `A55-same-path-replacement` came to be graded by a comment. The lesson a
 * union-that-must-equal-69 teaches is "stop adding arms", and that is the opposite of the point.
 */
export function allContractedMutations(contract) {
    return [...contract.mutations, ...contract.mutationsAddedPostMove];
}

/** Where an arm lives right now, exported so the root aggregation can partition the union. */
export function armHome(contract, id) {
    const entry = allContractedArms(contract).find(arm => arm.id === id);
    return entry ? currentHome(entry) : null;
}

/** Shared set comparison. `live` is what the harness is about to run; `expected` is the contract's. */
function compareSets(kind, pkg, live, expected, contracted, homeOf) {
    const problems = [];
    const dupes = duplicates(live);
    if (dupes.length) problems.push(`${pkg}'s ${kind} inventory lists the same id twice — ${dupes.join(', ')}`);

    const present = new Set(live);
    const missing = expected.filter(id => !present.has(id));
    if (missing.length) {
        problems.push(`${kind} contracted to ${pkg} but ABSENT from its inventory: ${missing.join(', ')}`);
    }
    for (const id of new Set(live)) {
        if (!contracted.has(id)) {
            problems.push(`${pkg} declares ${kind.slice(0, -1)} "${id}", which the relocation contract does not list — an undeclared extra during the move is how a swap hides a drop`);
        } else if (homeOf(id) !== pkg) {
            problems.push(`${kind.slice(0, -1)} "${id}" is contracted to live in ${homeOf(id)}, but ${pkg}'s inventory declares it`);
        }
    }
    return problems;
}

/**
 * Where an arm's BODY lives, derived from the registration call rather than read off a register.
 *
 * ⚠ THE CONTRACT DOES NOT RECORD A PATH FOR AN ARM, AND IT SHOULD NOT START. A recorded path is a
 * fourth register to keep in step with the other three, and it would go stale in exactly the way
 * `asserts` did. This derives from the one fact about an arm that cannot drift without the suite
 * failing somewhere else: an arm registers itself by id, as `arm('<id>')`, in the file that runs it.
 *
 * ⚠ SCANNED ONLY WHEN SOMETHING HAS ALREADY DRIFTED, so the green path does no filesystem work, and
 * it must never turn a text mismatch into a crash. A renamed helper, a moved directory or an
 * unreadable file yields `null`, and the refusal then names the search instead of the file.
 */
function armSourceFile(pkg, id) {
    const dir = path.join(here, '..', '..', pkg, 'test');
    let names;
    try {
        names = fs.readdirSync(dir).filter(name => name.endsWith('.test.js')).sort();
    } catch {
        return null;
    }
    for (const name of names) {
        try {
            if (fs.readFileSync(path.join(dir, name), 'utf8').includes(`arm('${id}')`)) {
                return `packages/${pkg}/test/${name}`;
            }
        } catch { /* an unreadable file is not an answer, and it is not this check's failure */ }
    }
    return null;
}

/**
 * ⚠⚠ SAID ONCE PER REFUSAL, NOT ONCE PER ARM, AND THAT IS THE WHOLE DESIGN OF THIS TEXT. What it
 * has to close is a GRADIENT, not an ambiguity: when this reddens, two edits turn it green, editing
 * the contract is always the smaller one, and the smaller one launders drift into a permanent record
 * with a passing suite behind it. Naming the fork is not enough, because the fork is already visible
 * and the cheap side of it still wins.
 *
 * ⚠ AND IT IS DELIBERATELY NOT LOUDER THAN THIS. A refusal that repeats a paragraph per drifted arm
 * is one a reconciler learns to scroll past, and this file cannot afford a refusal anyone skims: it
 * is the only reader the contract's `asserts` field has. So the per-arm lines stay short and carry
 * the facts that differ (the two texts, and where the body is), and the direction is stated once.
 *
 * ⚠ NOTHING HERE RECORDS AN ANSWER. No flag, no prompt, no attestation field. A prompt nobody
 * answers is a blocked suite and a self-attestation flag is a box that gets ticked; either would
 * replace reading the arm with satisfying the tool, which is the failure this text exists to avoid.
 */
const ARM_TEXT_DIRECTION = [
    'DIRECTION for every arm above: TWO EDITS TURN THIS GREEN AND ONLY ONE OF THEM IS RIGHT.',
    'Reword the live inventory, or reword the contract. Nothing in this tooling can tell which',
    'half is wrong, because both halves are prose about the same arm — THE ARM BODY DECIDES, and',
    'reading it is the work this refusal is asking for.',
    'Editing the contract is the smaller edit every time, and it is the right one ONLY when the arm',
    'has genuinely changed what it measures. When the contract still describes the arm correctly,',
    'that edit writes the drift into a permanent record and the build goes green over it — worse',
    'than the drift this check was built to catch, because nothing is red afterwards.',
    'Both reconciliations before this one were settled by reading the body, and the contract was',
    'the true half both times.'
].join('\n       ');

/**
 * The live arm inventory of one package against the contract.
 *
 * `arms` is `ALL_ARMS` ITSELF as the runner sees it — the whole map, not `Object.keys` of it, and
 * not a re-read of the same file by this script, which would only prove the file parses twice.
 *
 * ⚠⚠ THE MAP, NOT ITS KEYS, AND THAT DISTINCTION IS THE WHOLE OF THE 2026-09-02 REPAIR. Every one
 * of this function's three call sites used to hand it `Object.keys(ALL_ARMS)`, which threw away the
 * values — and the values are the arm text. So the contract's `asserts` field, in a locked,
 * generator-less, permanent record, had no reader at all: two arms had already been reworded away
 * from their locked descriptions while this check reported the inventory matched "exactly". It did:
 * the ids matched exactly, and the ids were all it could see.
 *
 * ⚠ A LIST REFUSES RATHER THAN DEGRADING. Handed an array, this could quietly fall back to checking
 * ids alone and go green — which is precisely the behaviour being removed, and it would be removed
 * in a way that lets any future call site re-introduce it by writing the shorter expression. The
 * refusal is what makes the repair hold.
 */
export function verifyArmInventory(contract, pkg, arms) {
    if (arms === null || typeof arms !== 'object' || Array.isArray(arms)) {
        return [`${pkg} handed this check ${Array.isArray(arms) ? 'a list of ids' : JSON.stringify(arms)} instead of its live arm map — the contract's \`asserts\` text can only be compared against the map's VALUES, and a call site that drops them is how that field went unread from the day it was written`];
    }
    const all = allContractedArms(contract);
    const home = new Map(all.map(arm => [arm.id, currentHome(arm)]));
    const expected = all.filter(arm => currentHome(arm) === pkg).map(arm => arm.id);
    const ids = Object.keys(arms);
    const problems = compareSets('arms', pkg, ids, expected, new Set(home.keys()), id => home.get(id));

    /**
     * ⚠ THE TEXT, AGAINST THE LOCKED TEXT. An id that survives a move while its description quietly
     * changes subject is an arm that still counts toward the denominator and no longer measures the
     * thing the contract says it measures — a shrunken suite that balances.
     *
     * ⚠ AND WHAT THIS CANNOT DO, SAID PLAINLY: it makes the two registers AGREE. It cannot make
     * either one TRUE. An arm whose body was corrected while both its inventory row and its contract
     * row stayed as they were passes here, because they agree with each other — and one such pair
     * was found by hand on the same day this check was written. Reading the arm is still the only
     * thing that finds those.
     */
    const contracted = new Map(all.map(arm => [arm.id, arm]));
    let drifted = 0;
    for (const id of ids) {
        const record = contracted.get(id);
        if (!record) continue; // already reported above as an undeclared extra
        if (record.asserts !== arms[id]) {
            drifted += 1;
            const source = armSourceFile(pkg, id);
            problems.push(
                `arm "${id}" no longer says what the contract locked it as.\n` +
                `       live, in packages/${pkg}/test/arms.mjs: ${JSON.stringify(arms[id])}\n` +
                `       locked, in ${path.relative(path.join(here, '..', '..', '..'), CONTRACT_PATH).split(path.sep).join('/')}: ${JSON.stringify(record.asserts)}\n` +
                `       the arm's body, which is what settles it: ${source ?? `NOT FOUND — search packages/${pkg}/test for \`arm('${id}')\``}`);
        }
    }
    // ⚠ ONE DIRECTION BLOCK, AFTER THE ARMS, WHETHER ONE DRIFTED OR TWENTY. See its own note above
    // for why it is not repeated per arm and why it records nothing.
    if (drifted > 0) problems.push(ARM_TEXT_DIRECTION);
    return problems;
}

/**
 * ⚠⚠ THE MUTATION SIDE OF THE SAME GRADIENT, WORDED ONCE PER REFUSAL — see `ARM_TEXT_DIRECTION`
 * above for the argument, which is identical and is not repeated here. Two edits turn a `mutates`
 * mismatch green, editing the contract is the smaller one, and the smaller one launders drift into
 * a permanent record behind a passing suite.
 *
 * ⚠ WHAT DIFFERS FROM THE ARM SIDE IS WHERE THE DECIDING ARTEFACT LIVES, AND IT NEEDED NO
 * DERIVATION. An arm's text is in `arms.mjs` while its body is in some `.test.js` the checker has
 * to go and find; a mutation row's text and its `from`/`to` are two fields of ONE object in
 * `packages/<pkg>/scripts/mutate.mjs`, by construction. So the home is named from `pkg` rather than
 * scanned for, and the reader is sent to the same row rather than to another file.
 *
 * ⚠ AND THE LAST LINE IS NOT THE ARM SIDE'S. That one cites two reconciliations already settled by
 * reading the body. No `mutates` mismatch has ever been reconciled — all 69 rows agreed on the day
 * the field first got a reader — so this says what is true instead of borrowing a precedent.
 *
 * ⚠ NOTHING HERE RECORDS AN ANSWER: no flag, no prompt, no attestation field, for the reason given
 * on the arm block.
 */
const MUTATION_TEXT_DIRECTION = [
    'DIRECTION for every mutation above: TWO EDITS TURN THIS GREEN AND ONLY ONE OF THEM IS RIGHT.',
    'Reword the live row, or reword the contract. Nothing in this tooling can tell which half is',
    'wrong, because both halves are prose about the same transformation — THE ROW\'S OWN `from`/`to`',
    'DECIDES, and reading it is the work this refusal is asking for.',
    'Editing the contract is the smaller edit every time, and it is the right one ONLY when the row',
    'genuinely patches something else now. When the contract still describes the transformation',
    'correctly, that edit writes the drift into a permanent record and the build goes green over it',
    '— worse than the drift this check was built to catch, because nothing is red afterwards.',
    'A drifted mutation row is worse than a drifted arm in one specific way: it still RUNS. It kills',
    'something, and the matrix reports a kill under the name of a mutation nobody made.',
    'No `mutates` mismatch has been reconciled before this one — all 69 locked rows agreed on the',
    'day the field first got a reader, so there is no precedent here to lean on.'
].join('\n       ');

/**
 * ⚠⚠ THE `plan` SIDE, AND IT IS A DIFFERENT FORK FROM THE TWO ABOVE — see `ARM_REFERENCE` for the
 * argument, which is not repeated here. Those two blocks close a gradient between two prose
 * registers that disagree. This one closes a reference that resolves to nothing, where there is no
 * second register at all: the arm inventory is the real thing and the `plan` is prose about it.
 *
 * ⚠ SO THE INSTRUCTION IS THE OPPOSITE OF "MAKE THEM AGREE". The claim in `plan` may be wrong and
 * the run prints it beside what actually reddened for exactly that reason. Only the NAME is being
 * reconciled.
 *
 * ⚠ NOTHING HERE RECORDS AN ANSWER — no flag, no prompt, no attestation field — for the reason
 * given on the arm block.
 */
const PLAN_REFERENCE_DIRECTION = [
    'DIRECTION for every mutation above: THE ARM INVENTORY IS THE REAL THING; `plan` IS PROSE ABOUT IT.',
    '`plan` records what the design\'s §5a table claimed would kill the row, and it is ALLOWED TO BE',
    'WRONG about that — the harness prints it beside what actually went red so the divergence shows.',
    'What it may not be is a name that resolves to NOTHING: a renamed or deleted arm leaves the row',
    'pointing at thin air while it still runs and still reports.',
    'So reconcile the REFERENCE and leave the CLAIM alone. Spell a family or a range as its live',
    'members, restore a suffix the row dropped, follow a genuine rename — but never edit `plan` to',
    'match what actually reddened this run. That edit deletes the only thing the field is for.',
    'If a token above was never meant as an arm citation, respell it so it cannot be read as one.',
    'This check cannot tell a citation from a coincidence and refuses rather than guessing.'
].join('\n       ');

/**
 * The live mutation matrix of one package against the contract.
 *
 * `rows` is the harness's own `ROWS`, reduced to `{ id, file, mutates }`. The `file` is checked as
 * well as the id: a row that quietly changed which built file it patches has changed which package
 * it measures, and its destination with it.
 *
 * ⚠⚠ `mutates` IS THE LIVE ROW'S `what`, AND IT WAS NOT PASSED UNTIL 2026-09-02. Both `mutate.mjs`
 * files projected `{ id, file }` and dropped it, so the contract's `mutates` text had exactly the
 * same non-reader as its `asserts` text — the same defect, in the other half of the contract, found
 * while repairing the first. Unlike the arms, all 69 rows agreed on the day it was closed.
 *
 * ⚠ THE UNION, NOT THE LOCKED 69. A row added after the move is contracted and routed like any
 * other; only the historical totals hold to `contract.mutations` alone.
 *
 * ⚠⚠ AND SINCE 2026-09-02 IT ALSO TAKES THE LIVE ROW'S `plan`, WHICH IS WHY THE PLAN CHECK LIVES
 * HERE RATHER THAN IN AN EXPORT OF ITS OWN. A separate function is a function a matrix can forget
 * to call — and a control nobody calls is the precise failure this whole repair is closing, three
 * times over now (`asserts`, `mutates`, and `plan` itself). Folded in, a call site cannot obtain
 * the row check without also obtaining the reference check.
 */
export function verifyMutationRows(contract, pkg, rows) {
    const all = allContractedMutations(contract);
    const home = new Map(all.map(row => [row.id, currentHome(row)]));
    const expected = all.filter(row => currentHome(row) === pkg).map(row => row.id);
    const problems = compareSets('mutations', pkg, rows.map(row => row.id), expected, new Set(home.keys()), id => home.get(id));

    const armIds = new Set(allContractedArms(contract).map(arm => arm.id));
    const contracted = new Map(all.map(row => [row.id, row]));
    let drifted = 0;
    let dangling = 0;
    for (const row of rows) {
        const record = contracted.get(row.id);
        if (!record) continue;
        // ⚠ ABSENT REFUSES, IT DOES NOT SKIP — the `mutates` rule below, for the same reason. Every
        // live row carries a `plan`; `undefined` here means the CALL SITE dropped it, and skipping
        // on absence restores the hole for any caller that writes the shorter projection.
        if (row.plan === undefined) {
            problems.push(`mutation "${row.id}" reached this check with no \`plan\` — the harness's live §5a claim was dropped at the call site, and the arms it names are then checked against nothing`);
        } else if (typeof row.plan !== 'string' || row.plan.trim() === '') {
            problems.push(`mutation "${row.id}" carries no \`plan\` text — the row would print "§5a claims:" with nothing after it, which reads as a claim rather than as an absence`);
        } else {
            const unresolved = armReferences(row.plan).filter(id => !armIds.has(id));
            if (unresolved.length) {
                dangling += 1;
                problems.push(
                    `mutation "${row.id}" names ${unresolved.length === 1 ? 'an arm' : 'arms'} in its \`plan\` that no inventory declares: ${unresolved.join(', ')}\n` +
                    `       the plan text, in packages/${pkg}/scripts/mutate.mjs: ${JSON.stringify(row.plan)}`);
            }
        }
        if (record.file !== row.file) {
            problems.push(`mutation "${row.id}" now patches \`${row.file}\`; the contract recorded it patching \`${record.file}\` — the row has changed which package it measures`);
        }
        // ⚠ ABSENT REFUSES, IT DOES NOT SKIP. `undefined` here means the CALL SITE dropped the
        // field, not that the row has no transformation — every live row carries a `what`. Skipping
        // on absence would restore the pre-2026-09-02 hole for any caller that writes the shorter
        // projection, which is the one thing this repair is for.
        //
        // ⚠ AND IT IS NOT COUNTED AS DRIFT. A dropped field is a broken CALL SITE; the direction
        // block below is about two prose registers disagreeing, and printing it here would send a
        // reader to reconcile texts when one of them never arrived.
        if (row.mutates === undefined) {
            problems.push(`mutation "${row.id}" reached this check with no \`mutates\` text — the harness's live \`what\` was dropped at the call site, and the contract's recorded transformation is then compared against nothing`);
        } else if (record.mutates !== row.mutates) {
            drifted += 1;
            problems.push(
                `mutation "${row.id}" no longer says what the contract locked it as.\n` +
                `       live, in packages/${pkg}/scripts/mutate.mjs: ${JSON.stringify(row.mutates)}\n` +
                `       locked, in ${path.relative(path.join(here, '..', '..', '..'), CONTRACT_PATH).split(path.sep).join('/')}: ${JSON.stringify(record.mutates)}\n` +
                `       the row's own \`from\`/\`to\`, in that same file, is what settles it`);
        }
    }
    // ⚠ ONE DIRECTION BLOCK, AFTER THE ROWS, WHETHER ONE DRIFTED OR TWENTY — the arm side's rule,
    // deliberately not a second style. See its own note above.
    if (drifted > 0) problems.push(MUTATION_TEXT_DIRECTION);
    if (dangling > 0) problems.push(PLAN_REFERENCE_DIRECTION);
    return problems;
}

/**
 * ⚠⚠ THE RED-SET SIDE OF THE SAME GRADIENT — the third block in this file, in the shape of the two
 * above and deliberately not a fourth style. Two edits turn a red-set violation green, widening the
 * declared set is the smaller one, and the smaller one erases the attribution the declaration is
 * for while leaving a passing suite behind it.
 *
 * ⚠ WHAT DIFFERS FROM THE TEXT BLOCKS IS WHICH DIRECTION IS THE DANGEROUS ONE. A drifted `asserts`
 * or `mutates` is one register lying about another. Here the two halves are a claim and a
 * MEASUREMENT, so the reader is not being sent to decide which prose is true — they are being told
 * which half of the diff is the alarming one, and it is the arm that went green.
 *
 * ⚠ NOTHING HERE RECORDS AN ANSWER, for the reason given on the arm block.
 */
const RED_SET_DIRECTION = [
    'DIRECTION for every mutation above: TWO EDITS TURN THIS GREEN AND ONLY ONE OF THEM IS RIGHT.',
    'Repair what the mutation or the arm now does, or widen the declared set to match the run.',
    'Widening is the smaller edit every time, and it is right ONLY when the new reach was reasoned',
    'about and found correct — a declared set exists because a DISPOSITION cannot attribute.',
    '`M71-root-identity-unconditional` reddens `A55-same-path-replacement` AND `META-no-outside-names`,',
    'so KILLED alone never proved which arm caught it, and that row exists to make `A55`\'s pin',
    'permanent. Editing the set to whatever the run produced restores exactly that blindness.',
    '⚠ AN ARM THE SET DECLARES THAT CAME BACK GREEN IS THE SERIOUS HALF. It means the row no longer',
    'reaches the arm it was written to pin: the detector is disarmed, and the row still reports',
    'KILLED off whatever else it happens to break.',
    'A row that declares no set is UNGATED here and always has been. Adding one is opt-in, and it is',
    'a claim you must have MEASURED — do not declare a set for a row you have not run.'
].join('\n       ');

/**
 * The mutation harness's RESULTS against the contract.
 *
 * ⚠⚠ DISPOSITIONS ALWAYS; EXACT RED SETS WHERE A ROW DECLARES ONE. Until 2026-09-02 this was
 * dispositions and nothing else, because `A35-root-moved` has a measured noise floor and a
 * blanket-exact rule would have gated the matrix on a coin flip. What that cost was then measured:
 * `M71-root-identity-unconditional` reddens `A55-same-path-replacement` and `META-no-outside-names`
 * together — correctly, since an unconditional identity comparison adds an `lstat` to every request
 * — so `M71` coming back KILLED did not prove `A55` was the detector, and `M71` exists precisely to
 * make `A55`'s pin permanent.
 *
 * ⚠ SO IT IS OPT-IN PER ROW, EXACT WHERE DECLARED, WITH THE NOISE SOURCE EXEMPTED BY NAME. A row
 * carrying no `expectedRed` behaves exactly as every row did before — diagnostic, ungated — so no
 * existing row changed meaning when this landed. `RED_SET_NOISE_EXEMPT` is the by-name half, one
 * entry, and an entry there must state its measurement or the run refuses.
 *
 * ⚠ THE COMPARISON IS SKIPPED WHERE IT WOULD ONLY ECHO. A row that never applied, or one contracted
 * KILLED that came back SURVIVED, has already failed above with the reason that matters; adding
 * "and nothing went red" underneath it is noise in a refusal this file cannot afford to have skimmed.
 *
 * ⚠⚠ AND THE READER'S THREE ROWS CANNOT DECLARE A SET AT ALL TODAY — measured 2026-09-02, and it is
 * the sharpest argument there is for opt-in over blanket-exact. A harness reads its red set out of
 * the runner's `✖ <title>` lines, and only the FENCE titles its tests `<arm id> — …`. Every test in
 * `packages/wyrd/test/startup.test.js` and `handshake.test.js` is titled in prose, so `M25` reports
 * `actually red: startup` and there is no arm name to compare. A set declared for one of those rows
 * would be unsatisfiable, and this check would refuse it every run. Closing that means retitling the
 * Reader's suite, which is a slice and not a side effect of this one.
 *
 * ⚠ THE ASYMMETRY IS DELIBERATE. A contracted SURVIVOR that gets KILLED is good news — an arm grew
 * teeth — and failing on it would teach the next person to weaken the arm to get green. It is
 * reported loudly as a stale contract row instead, which is the review event the contract exists to
 * force.
 *
 * ⚠ THE UNION AGAIN, AND THIS IS THE HALF THAT MAKES AN ADDITION WORTH ADDING. A row appended to
 * `mutationsAddedPostMove` is held to the identical two rules as a locked one: with `full`, it must
 * have PRODUCED a result, and a `KILLED` disposition that comes back `SURVIVED` fails the run.
 * `ANCHOR-NOT-FOUND` fails it for added rows exactly as for locked ones — an added row whose anchor
 * a refactor moved is a disarmed detector, which is the state the additions exist to prevent.
 */
export function verifyMutationResults(contract, pkg, results, { full, restored }) {
    const problems = [];
    const notes = [];
    const expected = allContractedMutations(contract).filter(row => currentHome(row) === pkg);
    const byId = new Map(results.map(result => [result.id, result]));

    if (restored === false) {
        problems.push('the harness did not restore the built files byte-for-byte — the tree is now carrying a mutant');
    }

    if (full) {
        const missing = expected.filter(row => !byId.has(row.id));
        if (missing.length) {
            problems.push(`the harness produced no result for ${missing.length} contracted row(s): ${missing.map(row => row.id).join(', ')}`);
        }
        if (results.length !== expected.length) {
            problems.push(`the harness produced ${results.length} results for ${expected.length} contracted rows`);
        }
    }

    // The exemption list can only ever WEAKEN what follows, so its own integrity is checked on
    // every run that it could weaken — not once, somewhere else, by somebody.
    for (const problem of noiseExemptionProblems(new Set(allContractedArms(contract).map(arm => arm.id)))) {
        problems.push(problem);
    }

    const exempt = id => Object.hasOwn(RED_SET_NOISE_EXEMPT, id);
    let violated = 0;
    for (const row of expected) {
        const result = byId.get(row.id);
        if (!result) continue;
        let graded = true;
        if (result.status === 'ANCHOR-NOT-FOUND') {
            problems.push(`mutation "${row.id}" never applied — its anchor is gone, so it measured nothing. Repair the row's \`from\`, never delete the row.`);
            graded = false;
        } else if (row.expectedDisposition === 'KILLED' && result.status !== 'KILLED') {
            problems.push(`mutation "${row.id}" is contracted KILLED and came back ${result.status} — ${row.why}`);
            graded = false;
        } else if (row.expectedDisposition === 'SURVIVED' && result.status === 'KILLED') {
            notes.push(`"${row.id}" is contracted SURVIVED and was KILLED. That is an arm getting stronger, not a failure — but the contract row is now stale and wants a deliberate edit.`);
        }

        if (!Array.isArray(row.expectedRed) || !graded) continue;
        // ⚠ ABSENT REFUSES HERE TOO. A declared set compared against a `red` the call site never
        // passed would report "nothing went red" for every row and read as a matrix-wide regression.
        if (result.red === undefined) {
            problems.push(`mutation "${row.id}" declares an exact red set and reached this check with no \`red\` list — the harness's record of which arms failed was dropped at the call site, and the declaration is then compared against nothing`);
            continue;
        }
        const actual = [...new Set(result.red)].filter(id => !exempt(id)).sort();
        const declared = [...new Set(row.expectedRed)].sort();
        const green = declared.filter(id => !actual.includes(id));
        const extra = actual.filter(id => !declared.includes(id));
        if (green.length || extra.length) {
            violated += 1;
            problems.push(
                `mutation "${row.id}" declares an exact red set and this run did not produce it.\n` +
                `       declared, in ${path.relative(path.join(here, '..', '..', '..'), CONTRACT_PATH).split(path.sep).join('/')}: ${declared.join(', ') || '(nothing may go red)'}\n` +
                `       actually red this run: ${actual.join(', ') || '(nothing)'}\n` +
                (green.length ? `       ⚠ DECLARED AND GREEN — the row no longer reaches ${green.length === 1 ? 'this arm' : 'these arms'}: ${green.join(', ')}\n` : '') +
                (extra.length ? `       red and not declared: ${extra.join(', ')}\n` : '') +
                `       ignored in both directions, by measured exemption: ${Object.keys(RED_SET_NOISE_EXEMPT).join(', ')}`);
        }
    }
    // ⚠ ONE DIRECTION BLOCK, AFTER THE ROWS — the rule the two text checks follow, and for the same
    // reason: a paragraph repeated per row is a refusal a reconciler learns to scroll past.
    if (violated > 0) problems.push(RED_SET_DIRECTION);
    return { problems, notes };
}

/** Prints and exits. Every caller refuses the same way, so the banner is written once. */
export function refuse(problems, what) {
    console.error(`\n⛔ RELOCATION CONTRACT REFUSED — ${what}`);
    for (const problem of problems) console.error(`   · ${problem}`);
    console.error(`\n   NOTHING WAS RUN. ${CONTRACT_PATH} is the pre-move record of what this`);
    console.error('   suite measured. It has no generator on purpose: put the missing thing back,');
    console.error('   or edit the contract by hand and have the edit reviewed.');
    process.exit(1);
}

// ---------------------------------------------------------------------------------------------
// CLI

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
    const { contract, problems } = loadContract();
    if (problems.length) refuse(problems, 'the contract is not internally consistent');

    const { ALL_ARMS } = await import('../test/arms.mjs');
    const armProblems = verifyArmInventory(contract, READER, ALL_ARMS);
    if (armProblems.length) refuse(armProblems, `${READER}'s declared arm inventory does not match the contract`);

    console.log(`✔ contract integrity: ${contract.arms.length} locked pre-move arms + ${contract.armsAddedPostMove.length} added since, ${contract.mutations.length} locked pre-move mutation rows + ${contract.mutationsAddedPostMove.length} added since, no duplicates, every destination stated.`);
    console.log(`✔ ${READER}'s arm inventory matches the contract exactly.`);
    const where = tally(allContractedArms(contract), 'destination');
    console.log(`  routing: ${Object.entries(where).map(([pkg, n]) => `${pkg} ${n}`).join(' · ')}`);
    console.log('\n⚠ NOT CHECKED HERE, and it is half the contract: the mutation matrix. `scripts/mutate.mjs`');
    console.log('  builds its rows at module scope and running it is the whole harness, so this CLI cannot');
    console.log('  import them. That half is checked inside `npm run mutate`, before it mutates anything.');
}
