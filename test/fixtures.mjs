import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { PORTABLE } from './manifest.mjs';

/**
 * Fixture trees for the fence arms.
 *
 * ⚠ Fixtures are built in the OS temp directory, never inside the repository or the workspace.
 * ⚠ Teardown unlinks every reparse point AS A LINK before any recursive delete, so nothing is
 *   ever deleted THROUGH a junction into its target.
 * ⚠ Nothing here skips. A fixture that cannot be created throws, and the arm depending on it
 *   FAILS — a skipped arm that exits green is the failure this suite exists to catch.
 *
 * ⚠ THE ONE EXCEPTION, AND IT IS GATED FROM BOTH ENDS: under `PORTABLE` the `fs.symlinkSync` calls
 * are omitted, because on a machine without the Windows symlink privilege they throw EPERM and the
 * whole tree dies before any arm runs — including every arm that needs no symlink at all. Only
 * the symlink calls are omitted; junctions and hard links are NOT privileged and are always built.
 * Every arm that reads an omitted fixture is skipped in the same mode, and the runner asserts the
 * skipped set equals `SYMLINK_PRIVILEGE_ARMS` exactly — so an omission here cannot silently shrink
 * what is tested. **Adding a symlink fixture outside a `PORTABLE` guard re-breaks portable mode**;
 * adding one inside a guard without adding its arm to that set fails the runner's equality check.
 */

/** `fs.symlinkSync` for privileged link types, omitted under PORTABLE. Junctions never come here. */
function symlink(target, linkPath, type) {
    if (PORTABLE) return;
    fs.symlinkSync(target, linkPath, type);
}

export const CANARY = {
    outsideSecret: 'OUTSIDE-SECRET-CANARY-9f3a2b',
    outsideExists: 'OUTSIDE-EXISTS-CANARY',
    siblingPrefix: 'SIBLING-PREFIX-CANARY',
    inGrantNote: 'IN-GRANT-NOTE-CANARY-4c8e1d',
    inGrantSecret: 'IN-GRANT-SECRET-CANARY',
    plainNotes: 'PLAIN-NOTES-CANARY',
    viaJunctionPlain: 'VIA-JUNCTION-PLAIN-CANARY',
    /** A14-M: the answer the substituted (directory-symlink) reading would reach. In-grant. */
    mirrorDecoy: 'MIRROR-SUBSTITUTED-DECOY',
    /** A14-T: the answer the traversal (junction) reading reaches. In-grant, and the OS serves it. */
    twinTraversal: 'TWIN-TRAVERSAL-INGRANT-CANARY',
    /** A14-T: the answer the substituted reading would reach. OUTSIDE the grant. */
    twinDecoy: 'TWIN-SUBSTITUTED-OUTSIDE-DECOY',
    /** A38: both readings in-grant and DIFFERENT — the cell nothing else covers. */
    bcTraversal: 'BC-TRAVERSAL-READING-ANSWER',
    bcSubstituted: 'BC-SUBSTITUTED-READING-ANSWER',
    bc2Only: 'BC2-SUBSTITUTED-ONLY-ANSWER',
    bc3InGrant: 'BC3-SUBSTITUTED-INGRANT-ANSWER'
};

function junction(target, link) {
    // Measured identical to `mklink /J`: reparse tag 0xa0000003, same readlink, same
    // traversal-relative resolution. Needs no privilege.
    fs.symlinkSync(target, link, 'junction');
}

/**
 * Build the tree every fence arm runs against.
 *
 * The grant is named `vault` and a sibling `vault-secrets` exists, so `path.relative`'s
 * sibling-prefix trap (A9) is exercised against a directory that really is there.
 */
export function buildFixture() {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'wyrd-fence-'));
    const grant = path.join(base, 'vault');
    const outside = path.join(base, 'outside');

    fs.mkdirSync(path.join(base, 'vault-secrets'), { recursive: true });
    fs.writeFileSync(path.join(base, 'vault-secrets', 'x.md'), CANARY.siblingPrefix);

    fs.mkdirSync(outside, { recursive: true });
    fs.writeFileSync(path.join(outside, 'secret.md'), CANARY.outsideSecret);
    fs.writeFileSync(path.join(outside, 'exists.md'), CANARY.outsideExists);

    // A14-T's substituted answer lives OUTSIDE the grant, so the twin discriminates.
    fs.mkdirSync(path.join(base, 'inside'), { recursive: true });
    fs.writeFileSync(path.join(base, 'inside', 'note.md'), CANARY.twinDecoy);

    fs.mkdirSync(path.join(grant, 'subdir'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'subdir', 'note.md'), CANARY.inGrantNote);
    fs.mkdirSync(path.join(grant, 'secrets'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'secrets', 'x.md'), CANARY.inGrantSecret);
    fs.writeFileSync(path.join(grant, 'notes'), CANARY.plainNotes);
    fs.mkdirSync(path.join(grant, 'inside'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'inside', 'note.md'), CANARY.twinTraversal);

    // Pagination fixtures (D5 / D5a).
    const big = Buffer.alloc(70_000, 0x61);
    fs.writeFileSync(path.join(grant, 'big.md'), big);
    // A 3-byte codepoint straddling byte 8: 'aaaaaaa' + U+2014 + more.
    fs.writeFileSync(path.join(grant, 'utf8.md'), Buffer.from('aaaaaaa—bbbbbbbb', 'utf8'));

    // ---- the mirror (A14-M) -------------------------------------------------
    // alias is a JUNCTION, so the OS resolves `esc`'s relative target against the TRAVERSAL
    // spelling `vault\alias`, reaching base\outside\secret.md — outside the grant.
    // A fence resolving against the substituted path would reach the in-grant decoy instead.
    fs.mkdirSync(path.join(grant, 'a', 'b', 'c', 'd'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'a', 'b', 'outside'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'a', 'b', 'outside', 'secret.md'), CANARY.mirrorDecoy);
    fs.writeFileSync(path.join(grant, 'a', 'b', 'c', 'd', 'plain.md'), CANARY.viaJunctionPlain);
    symlink('..\\..\\outside\\secret.md', path.join(grant, 'a', 'b', 'c', 'd', 'esc'), 'file');
    junction(path.join(grant, 'a', 'b', 'c', 'd'), path.join(grant, 'alias'));

    // Same shape, but the alias is a DIRECTORY SYMLINK. Measured 2026-08-28: the operating
    // system then uses the SUBSTITUTED spelling and serves the in-grant decoy. Node cannot
    // tell this alias from the junction above.
    symlink(path.join(grant, 'a', 'b', 'c', 'd'), path.join(grant, 'dsalias'), 'dir');

    // ---- the twin (A14-T) ---------------------------------------------------
    fs.mkdirSync(path.join(grant, 'x'), { recursive: true });
    fs.mkdirSync(path.join(grant, 'd2'), { recursive: true });
    symlink('..\\..\\inside\\note.md', path.join(grant, 'd2', 'escape'), 'file');
    junction(path.join(grant, 'd2'), path.join(grant, 'x', 'alias'));

    // ---- junctions ----------------------------------------------------------
    junction(path.join(grant, 'subdir'), path.join(grant, 'j_in'));
    junction(outside, path.join(grant, 'j_out'));
    junction(path.join(grant, 'j_out'), path.join(grant, 'j_chain'));
    junction(path.join(grant, 'j_in'), path.join(grant, 'j_chain_in'));
    junction(grant, path.join(grant, 'j_self'));
    junction(path.join(grant, 'cycb'), path.join(grant, 'cyca'));
    junction(path.join(grant, 'cyca'), path.join(grant, 'cycb'));
    junction(path.join(outside, 'nodir'), path.join(grant, 'j_dangle_out'));
    junction(path.join(grant, 'nodir'), path.join(grant, 'j_dangle_in'));

    // ---- symlinks -----------------------------------------------------------
    symlink(path.join(outside, 'secret.md'), path.join(grant, 's_out'), 'file');
    symlink(path.join(grant, 'subdir', 'note.md'), path.join(grant, 's_in'), 'file');
    symlink('..\\outside\\secret.md', path.join(grant, 's_rel_out'), 'file');
    symlink('subdir\\note.md', path.join(grant, 's_rel_in'), 'file');
    // A multi-hop chain whose every target is RELATIVE, and a cycle of the same kind. Both
    // exist so the visited set's key is exercised on the relative branch, not only the
    // absolute one: a set keyed on the original request refuses the chain and looks correct.
    symlink('rc_b', path.join(grant, 'rc_a'), 'file');
    symlink('subdir\\note.md', path.join(grant, 'rc_b'), 'file');
    symlink('rcyc_b', path.join(grant, 'rcyc_a'), 'file');
    symlink('rcyc_a', path.join(grant, 'rcyc_b'), 'file');
    symlink(path.join(grant, 'sc_b'), path.join(grant, 'sc_a'), 'file');
    symlink(path.join(outside, 'secret.md'), path.join(grant, 'sc_b'), 'file');
    symlink(path.join(grant, 'sc_in_b'), path.join(grant, 'sc_in_a'), 'file');
    symlink(path.join(grant, 'subdir', 'note.md'), path.join(grant, 'sc_in_b'), 'file');
    symlink(outside, path.join(grant, 'ds_out'), 'dir');
    // A UNC-target symlink. `path.relative` returns the UNC path unchanged, so it is neither
    // `..` nor `..`-prefixed: the ONLY containment clause that refuses it is `!isAbsolute(rel)`.
    // Without this fixture that clause has no killing arm on a machine with one volume.
    symlink('\\\\wyrd-no-such-server\\share\\x.md', path.join(grant, 'unc_out'), 'file');
    symlink(path.join(grant, 'scyc_b'), path.join(grant, 'scyc_a'), 'file');
    symlink(path.join(grant, 'scyc_a'), path.join(grant, 'scyc_b'), 'file');
    // Self-descending directory symlink: `sd -> sd\sub`.
    symlink(path.join(grant, 'sd', 'sub'), path.join(grant, 'sd'), 'dir');

    // ---- a reparse point HIDDEN INSIDE another link's target -----------------
    // `hop`'s target is lexically in-grant, but reaching it traverses `hidden`, which is not.
    // `lstat` does not follow a path's FINAL component but does traverse its intermediates, so
    // lstatting the target as one opaque string lands outside and the errno then reports
    // whether the outside file exists. Both requests below must refuse identically.
    fs.mkdirSync(path.join(outside, 'subdir'), { recursive: true });
    fs.writeFileSync(path.join(outside, 'subdir', 'exists.md'), CANARY.outsideExists);
    fs.mkdirSync(path.join(grant, 'path'), { recursive: true });
    junction(outside, path.join(grant, 'path', 'hidden'));
    junction(path.join(grant, 'path', 'hidden', 'subdir'), path.join(grant, 'hop'));

    // ---- finite ACYCLIC chains, above and below the hop bound ----------------
    // A cycle is refused by the OS before the walk's own bounds are reached, so the hop limit
    // needs a chain that terminates. 70 links exceed MAX_HOPS; 20 do not.
    for (let index = 0; index < 70; index += 1) {
        const target = index === 69 ? 'subdir\\note.md' : `hop70_${index + 1}`;
        symlink(target, path.join(grant, `hop70_${index}`), 'file');
    }
    for (let index = 0; index < 20; index += 1) {
        const target = index === 19 ? 'subdir\\note.md' : `hop20_${index + 1}`;
        symlink(target, path.join(grant, `hop20_${index}`), 'file');
    }

    // ---- a directory holding one file, for the list arms ---------------------
    fs.mkdirSync(path.join(grant, 'listing'), { recursive: true });
    fs.writeFileSync(path.join(grant, 'listing', 'a.md'), 'AAAA');
    fs.mkdirSync(path.join(grant, 'listing', 'nested'), { recursive: true });
    symlink('a.md', path.join(grant, 'listing', 'a_link'), 'file');

    // ---- BOTH READINGS IN-GRANT AND DIFFERENT (A38) --------------------------
    // The alias is absolute-target, so the two readings of `L2`'s relative target differ only
    // in their PARENT: traversal `<grant>\\bcN\\<alias>\\..` versus substituted
    // `<grant>\\bcN\\d0\\d1\\d2\\..`. Both land in-grant. Which one the OS uses depends on the
    // alias's reparse tag, and `lstat` reports both aliases identically.
    for (const cell of ['bc', 'bc2', 'bc3', 'bc4']) {
        fs.mkdirSync(path.join(grant, cell, 'd0', 'd1', 'd2'), { recursive: true });
        symlink('..\\target.md', path.join(grant, cell, 'd0', 'd1', 'd2', 'L2'), 'file');
        symlink(path.join(grant, cell, 'd0', 'd1', 'd2'), path.join(grant, cell, 'Lsym'), 'dir');
    }
    // bc: both readings EXIST and name different files. A wrong choice serves the wrong file.
    fs.writeFileSync(path.join(grant, 'bc', 'target.md'), CANARY.bcTraversal);
    fs.writeFileSync(path.join(grant, 'bc', 'd0', 'd1', 'target.md'), CANARY.bcSubstituted);
    junction(path.join(grant, 'bc', 'd0', 'd1', 'd2'), path.join(grant, 'bc', 'Ljunc'));
    // bc2: the traversal reading does NOT exist. A wrong choice refuses MISSING.
    fs.writeFileSync(path.join(grant, 'bc2', 'd0', 'd1', 'target.md'), CANARY.bc2Only);
    // bc3: the traversal reading is itself a link pointing OUTSIDE. A wrong choice refuses
    // ESCAPES — the server accusing in-grant content of leaving the grant.
    symlink(path.join(outside, 'secret.md'), path.join(grant, 'bc3', 'target.md'), 'file');
    fs.writeFileSync(path.join(grant, 'bc3', 'd0', 'd1', 'target.md'), CANARY.bc3InGrant);
    // bc4: the pairing. The reading the OS actually uses leads OUTSIDE, so it must refuse.
    fs.writeFileSync(path.join(grant, 'bc4', 'target.md'), 'BC4-TRAVERSAL-INGRANT-DECOY');
    symlink(path.join(outside, 'secret.md'), path.join(grant, 'bc4', 'd0', 'd1', 'target.md'), 'file');

    // ---- the hardlink, which no path-based fence can see ---------------------
    fs.linkSync(path.join(outside, 'secret.md'), path.join(grant, 'h_out.md'));

    return { base, grant, outside, teardown: () => teardown(base) };
}

/** Every reparse point is unlinked AS A LINK first. Nothing is deleted through one. */
export function teardown(base) {
    const links = [];
    (function scan(dir) {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            return;
        }
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (entry.isSymbolicLink()) {
                links.push(full);
                continue;
            }
            if (entry.isDirectory()) scan(full);
        }
    })(base);
    for (const link of links.reverse()) {
        try {
            fs.unlinkSync(link);
        } catch {
            try {
                fs.rmdirSync(link);
            } catch {
                /* reported by the existence check below, not swallowed silently */
            }
        }
    }
    fs.rmSync(base, { recursive: true, force: true });
    return { unlinked: links.length, removed: !fs.existsSync(base) };
}
