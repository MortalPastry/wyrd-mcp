/**
 * THE LEDGER SEAM — a TYPE, the production appender over the fence, and a refusing one for the arms.
 *
 * ⚠⚠ THE APPEND IS THE FENCE'S, NEVER THIS FILE'S. B4 rules the append is one `O_APPEND` write of
 * one fully-serialised line, and `FsGate.appendLineInGrant` is that write — landed 2026-09-02 with
 * its own containment argument, its own name screens and its own identity re-proof. Everything
 * `gateAppender` below does is name the path and hand the bytes over. Reaching around the gate with
 * `fs.appendFileSync` would put a second, unfenced write path in the very package whose D8 argument
 * is that there is exactly one — and it is worth saying plainly that the temptation is real, since
 * an append to a known relative path looks like the most harmless call in the file.
 *
 * ⚠ THIS FILE USED TO SAY THE PRIMITIVE DID NOT EXIST, AND THE ARM IT NAMED AS OWED IS NOW PAID.
 * `ST22`–`ST25` append real lines to a real `.wyrd/lineage.jsonl` over a real grant: one line
 * landing, three accumulating in order, a parent deleted underneath the write refusing after the
 * page was created, and eight concurrent writers producing eight intact lines. The `ST-OWED`
 * inventory row is gone rather than annotated, because an inventory that describes a debt already
 * settled is worse than no row at all.
 *
 * ⚠ INJECTED, NOT IMPORTED, at the composition root. `writePage` takes the appender as a parameter
 * so the arms can supply a spy or a refuser without the production path acquiring a mode flag. A
 * module that knows whether it is under test is a module whose test proves less than it looks like.
 */

import type { FenceRefusal, FsGate } from 'wyrd-fence';

import { LINEAGE_PATH } from './config.js';

/** What an append reports on success. `bytes` is the line INCLUDING its terminating LF. */
export interface Appended {
    readonly ok: true;
    readonly bytes: number;
}

/**
 * ⚠ THE PARAMETER IS A FULLY-SERIALISED BUFFER, AND THE TYPE IS THE RULE. B4's atomicity argument
 * holds for ONE write of ONE complete line; an implementation handed a record and left to serialise
 * it could emit in pieces. Handing over bytes makes "never split a line" a property of the
 * signature rather than of a comment inside whoever implements it.
 */
export interface LedgerAppender {
    appendLine(line: Buffer): Promise<Appended | FenceRefusal>;
}

/**
 * THE PRODUCTION APPENDER. One line, through the gate, to the vault's own lineage log.
 *
 * ⚠⚠ THE FENCE'S RESULT IS PASSED THROUGH UNCHANGED, NOT REPACKAGED, and that is a decision rather
 * than laziness. The fence's `Appended` carries `rel` alongside `ok` and `bytes`, so it already
 * satisfies this module's narrower `Appended`; its `WriteRefusal` is a `FenceRefusal` carrying
 * `retained`, which is the field that tells a caller whether a failed append may have left a
 * partial line behind. Narrowing either one to this file's shape would DISCARD exactly the
 * diagnostics the fence spent its slice producing — and `stamp.ts` hands the refusal straight to
 * the caller inside `PAGE_WRITTEN_LEDGER_FAILED`, where the retention answer is the whole point.
 *
 * ⚠ THE PATH IS A CONSTANT AND THE CALLER CANNOT CHOOSE IT. A lineage log the caller can redirect
 * is a provenance record that can be written somewhere nobody reads — so the only path this
 * appender will ever name is `config.ts`'s `LINEAGE_PATH`, and the constant is shared with the
 * config loader so the ledger and the config can never disagree about which directory is the
 * vault's.
 *
 * ⚠ NO RETRY, ANYWHERE ABOVE THE FENCE EITHER. The fence refuses to retry under `O_APPEND` because
 * a second attempt re-selects the end of file and splices this record through whatever another
 * appender landed in between; a retry loop added HERE would manufacture precisely that, one level
 * up, where the fence's comment explaining why cannot be seen.
 */
export function gateAppender(gate: FsGate): LedgerAppender {
    return Object.freeze({
        appendLine: (line: Buffer) => gate.appendLineInGrant(LINEAGE_PATH, line)
    });
}

/**
 * The appender the arms use to exercise the failure branch.
 *
 * ⚠ IT REFUSES RATHER THAN NO-OPS, deliberately. A no-op appender would make every arm above it
 * green while the ledger silently recorded nothing — the exact "green on a path that does nothing"
 * shape the suite runner exists to make impossible. It is no longer what the package ships with:
 * `createScribe` now defaults to `gateAppender`, and the argument for that change is in `index.ts`.
 */
export function refusingAppender(detail = 'the ledger append was refused'): LedgerAppender {
    return Object.freeze({
        appendLine: async (): Promise<FenceRefusal> =>
            Object.freeze({ ok: false as const, reason: 'IO_ERROR' as const, detail, resolvedPath: '' })
    });
}
