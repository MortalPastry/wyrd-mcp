/**
 * THE FENCE'S OWN SUITE PREFLIGHT — `FP1`, `FP2`.
 *
 * ⚠⚠ NEW IDS, AND THE NEW IDS ARE THE RULING. The relocation contract recorded `E6-preflight` and
 * `E10-junction-preflight` as `undecided` and stated the prohibition that decided them: ONE ID
 * CANNOT LIVE IN TWO INVENTORIES. Their subject is `scripts/preflight.mjs` — suite infrastructure,
 * neither product nor fence source — and BOTH packages need a preflight after the move, because
 * the fence cannot import a module out of the Reader and still be a package that publishes.
 *
 * So the module is duplicated and the SECOND COPY GETS ITS OWN IDS. `E6` and `E10` keep their ids
 * and stay with the Reader, grading the Reader's copy. `FP1` and `FP2` grade this one. They are
 * recorded in the contract's `armsAddedPostMove` array — outside the locked 88, so that adding
 * arms cannot inflate a pre-move denominator, and inside the contract, so that deleting one still
 * refuses.
 *
 * ⚠ THE DUPLICATION IS REAL AND IS NOT PRETENDED AWAY. Two copies of a guard drift. What stops
 * this pair drifting silently is that each copy has an arm of its own asserting the same
 * behaviours, so a change to one that the other does not get shows up as a failing arm in exactly
 * one package rather than as a quiet divergence in neither.
 *
 * ⚠ WHY THE FENCE NEEDS A PREFLIGHT AT ALL: 20 of its 70 arms build symlink fixtures. Without the
 * privilege the run does not produce 20 independent failures — it produces ONE environmental fact
 * reported 20 times as a stack trace, with the cause named nowhere.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { preflightJunctionSupport, preflightSymlinkPrivilege } from '../scripts/preflight.mjs';
import { declare as arm } from './manifest.mjs';

test('FP1-preflight — the fence suite preflight refuses on denied symlink privilege, and separates the probe stages', () => {
    arm('FP1-preflight');
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

test('FP2-junction-preflight — the fence tier-1 preflight refuses when a junction cannot be created', () => {
    arm('FP2-junction-preflight');
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
