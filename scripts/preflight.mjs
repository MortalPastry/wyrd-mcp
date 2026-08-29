/**
 * THE SUITE'S OWN PREFLIGHT — can this process create a symlink at all?
 *
 * ⚠ WHY THIS IS ITS OWN MODULE. It lived inside `run-tests.mjs`, where nothing could import it, so
 * it had no regression test — and the session that wrote it recorded in NEXT.md that it "has a
 * mutation test." It did not. A mutation run BY HAND in one session is evidence; it is not a test,
 * and a later change deleting the EPERM branch would have landed green. A review lens caught the
 * claim. This module exists so the guard is reachable by the suite that depends on it.
 *
 * The tier-2 arms of this suite build symlink fixtures. Without the privilege the run does not
 * produce N independent failures — it produces ONE environmental fact reported N times as a stack
 * trace, with the cause named nowhere. Measured 2026-08-28: a session read that output as a broken
 * fence.
 *
 * ⚠ IT REFUSES; IT DOES NOT SKIP. A suite that quietly drops its link arms when the privilege is
 * absent reports a green meaning "the arms that could run, ran" — the exact defect this lane keeps
 * finding elsewhere: a check that cannot say what it did not check.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const DEV_MODE_HINT = [
    '',
    '   On Windows, symlink creation requires either Developer Mode or an elevated shell.',
    '   Fix: Settings -> System -> For developers -> Developer Mode = On.',
    '   (Leave the Device Portal and remote-debugging sub-toggles OFF; they are unrelated.)',
    '   Verify: reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModelUnlock"',
    '           AllowDevelopmentWithoutDevLicense must read 0x1.',
    '',
    '   NOTHING WAS RUN. This is not a fence failure and says nothing about src/fsgate.ts.'
].join('\n');

/**
 * THE TIER-1 PREFLIGHT — can this process create a JUNCTION?
 *
 * ⚠ WHY THIS EXISTS AT ALL, since junctions are supposed to need no privilege. That "supposed to"
 * is the problem. Portable mode rests entirely on the claim that a junction is a mount point and is
 * therefore ungated — which is true of documented Windows behaviour and is ALSO exactly the shape
 * of claim this lane has been wrong about before. It cannot be measured on the dev machine, because
 * Developer Mode being ON there makes both link kinds succeed and hides any difference.
 *
 * So the claim is not asserted; it is CHECKED, on the machine where it matters, at the moment it
 * matters. If a junction cannot be created, tier 1 refuses with its own named reason instead of
 * producing a page of identical failures whose real cause is stated nowhere — the same defect the symlink
 * preflight was built to prevent, one tier down.
 *
 * @returns {string | null} null when a junction can be created; otherwise the diagnostic.
 */
export function preflightJunctionSupport(primitives = {}) {
    const {
        mkdtempSync = fs.mkdtempSync,
        mkdirSync = fs.mkdirSync,
        symlinkSync = fs.symlinkSync,
        rmSync = fs.rmSync,
        tmpdir = os.tmpdir
    } = primitives;

    let probe;
    try {
        probe = mkdtempSync(path.join(tmpdir(), 'wyrd-junction-'));
    } catch (error) {
        return `could not create a temp directory to probe with (${error.code}): ${error.message}`;
    }

    try {
        const target = path.join(probe, 'target');
        mkdirSync(target, { recursive: true });
        symlinkSync(target, path.join(probe, 'link'), 'junction');
        return null;
    } catch (error) {
        return (
            `this process cannot create a junction (${error.code}): ${error.message}\n` +
            '   Portable mode assumes junctions need no privilege. On this machine they do, or the\n' +
            '   filesystem does not support reparse points (a non-NTFS volume for the temp dir will\n' +
            '   do it). NOTHING WAS RUN, and this says nothing about src/fsgate.ts.'
        );
    } finally {
        try {
            rmSync(probe, { recursive: true, force: true });
        } catch {
            /* a leaked temp probe dir is not worth failing the suite over */
        }
    }
}

/**
 * @returns {string | null} null when a symlink can be created; otherwise the diagnostic.
 *
 * Primitives are injectable at this seam so the suite can exercise every branch without needing a
 * machine in the failing state — the same reason the fence itself injects rather than faking.
 */
export function preflightSymlinkPrivilege(primitives = {}) {
    const {
        mkdtempSync = fs.mkdtempSync,
        writeFileSync = fs.writeFileSync,
        symlinkSync = fs.symlinkSync,
        rmSync = fs.rmSync,
        tmpdir = os.tmpdir
    } = primitives;

    let probe;
    try {
        probe = mkdtempSync(path.join(tmpdir(), 'wyrd-preflight-'));
    } catch (error) {
        return `could not create a temp directory to probe with (${error.code}): ${error.message}`;
    }

    try {
        // ⚠ THE TWO STAGES ARE REPORTED SEPARATELY, AND THAT IS THE POINT. Catching both under one
        // message told a user to enable Developer Mode when an ACL or endpoint-security policy had
        // denied ordinary file creation and `symlinkSync` was never reached — a confident
        // diagnosis of the wrong cause. Found by a review lens, 2026-08-29.
        try {
            writeFileSync(path.join(probe, 'target'), 'probe');
        } catch (error) {
            return (
                `cannot create an ordinary file in the temp directory (${error.code}): ` +
                `${error.message}\n   This is NOT the symlink privilege — a symlink was never ` +
                `attempted. Something is denying ordinary writes to ${probe}.`
            );
        }

        try {
            symlinkSync(path.join(probe, 'target'), path.join(probe, 'link'));
        } catch (error) {
            if (error.code !== 'EPERM' && error.code !== 'EACCES') {
                return `symlink creation failed for an unexpected reason (${error.code}): ${error.message}`;
            }
            // ⚠ "nearly every arm" until 2026-08-29, which stopped being true when the battery was
            // tiered — the symlink-needing arms are a minority now. The exact split is derived and
            // printed by the runner, so it is deliberately not restated here.
            return `this process cannot create symlinks, and the tier-2 arms of this suite need to.${DEV_MODE_HINT}`;
        }

        return null;
    } finally {
        try {
            rmSync(probe, { recursive: true, force: true });
        } catch {
            /* a leaked temp probe dir is not worth failing the suite over */
        }
    }
}
