import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/** The window `hashInGrant` streams a source through. Never slurp a source: they are transcripts. */
const HASH_WINDOW = 64 * 1024;

/**
 * The scope fence.
 *
 * Everything that touches the filesystem on behalf of a request goes through this module,
 * and the primitives it uses are module-private. The exported operations take an UNTRUSTED
 * REQUEST STRING and fence it themselves; nothing exported accepts an already-resolved path.
 *
 * Read `designs/2026-08-27-s2-fence-plan.md` §4 before changing the predicate, and
 * `designs/2026-08-28-windows-link-measurements.md` §9 before changing anything about links.
 *
 * ⚠ The one non-obvious platform fact this module is built on, measured 2026-08-28:
 * a relative symlink target resolves against the path used to TRAVERSE to the link when the
 * earlier reparse point was a JUNCTION, and against the SUBSTITUTED path when it was a
 * DIRECTORY SYMLINK. Node exposes no reparse tag, so the two are indistinguishable from here.
 * `resolveInGrant` therefore screens link targets itself and defers the ambiguous cases to
 * `realpathSync.native`, which tracked the operating system on every shape measured.
 */

/**
 * ⛔ NOT COVERED — the account is README.md, "Security boundary and limits", and that section is
 * AUTHORITATIVE. Do not restate the limits here: this file's header carried a second copy until
 * 2026-09-02, and the copy went wrong while the code beside it stayed right (it claimed
 * `realpathNative` "never is" consulted for unclassified reparse tags; it is consulted
 * unconditionally on every successful resolution, a few hundred lines below).
 *
 * What stays here is measurement, because it is a fact about this codebase and not about the
 * boundary a consumer reasons over:
 *
 * - TOCTOU and the root-swap window cannot be closed on this platform. Node on Windows has no
 *   `openat`; measurement found no `*at` family in the binding at all.
 * - Hard links are invisible to every canonicalization API, measured rather than assumed.
 * - Unclassified reparse tags (WSL `LX_SYMLINK`, Windows Container `WCI`, `APPEXECLINK`, cloud
 *   provider tags) are UNTESTED here rather than tested-and-passing: creating one needs privileged
 *   or platform-specific tooling. ⚠ Do not read the differential fuzz results as covering them —
 *   every shape in those is one `isSymbolicLink()` reports.
 */

/**
 * The walk's own bound.
 *
 * ⚠ 64 is a chosen number, not a measured one. Measurements §5 mentions a depth-64 OS backstop
 * for one junction cycle; §9.5 measured Windows returning `ELOOP` IMMEDIATELY at every tested
 * depth (1, 2, 5, 20, 40, 64, 100). Do not restate this as "matches Windows" — nothing here
 * depends on the two agreeing, because this bound has to terminate walks the OS never sees.
 */
const MAX_HOPS = 64;

/** Disclosure-size policy, not a filesystem limit. See `validateGrantLexically`. */
const MAX_GRANT_LENGTH = 4096;

/**
 * Windows drive-relative input: `C:notes`. `path.isAbsolute` returns FALSE for these.
 *
 * ⚠ UNCONDITIONAL ON EVERY PLATFORM, DELIBERATELY, AND BOTH 2026-08-31 REVIEW LENSES FLAGGED IT AS
 * THE SIBLING OF THE TWO SCREENS THAT JUST BECAME WIN32-ONLY. They are right that it is the same
 * shape: `C:notes` is a legal POSIX filename and is refused here on every host.
 *
 * It stays unconditional, and the distinction is COVERAGE — not motive.
 *
 * ⚠ THE FIRST VERSION OF THIS PARAGRAPH GOT THAT WRONG IN A WAY WORTH KEEPING VISIBLE. It said the
 * name screens "RESTORED access to files that exist" while conditioning this one would "ADMIT a
 * request form", and concluded **"this module does not widen on reasoning."** That describes the
 * two changes' MOTIVES, not their effects: both widen the accepted grammar on a host this suite
 * cannot exercise. As written, the rule licensed the very change it sat beside while claiming to
 * forbid it — and it is this module's own written test for whether a future conditioning is
 * allowed, so a later maintainer applying it literally would get the wrong answer. Found by the
 * cross-vendor escalation lens, 2026-08-31.
 *
 * **The real distinction is what else covers the request form.** A colon-bearing READ is covered
 * downstream: every successful walk arbitrates through `realpathNative`, measured returning the
 * `:stream` suffix intact, so an escaping stream refuses at the containment check with the screen
 * off. Nothing downstream covers `C:notes`, the `\`-separator split, or the grant validator's
 * Win32 namespace/UNC rules — those are the only thing standing between those spellings and a
 * resolution nobody here has measured. **Condition a guard only where something else still covers
 * the case; never on the ground that relaxing it would be convenient.**
 *
 * ⚠ SO THE HONEST STATEMENT OF THE CURRENT GUARANTEE: **wyrd accepts a WIN32-SHAPED REQUEST GRAMMAR
 * on every host, EXCEPT that the two name screens are host-conditional — the device screen on both
 * paths, the stream screen on the read path only.** The unqualified version of this sentence stood
 * here briefly and overclaimed a uniformity the same commit had just removed. Revisiting the
 * remainder wants a POSIX host rather than another review round.
 *
 * ⚠ THIS PARAGRAPH USED TO CLAIM THE RESTRICTION WAS RECORDED IN THIS REPO'S ISSUE LOG, AND IT WAS
 * NOT. A review pass checked and found nothing — a claim that a record exists is not a record, and
 * the claim is exactly what stops the next reader checking. This repo's issue entries are written
 * at session close, so code cannot truthfully assert one mid-session. Nothing is asserted here now.
 */
const DRIVE_RELATIVE = /^[A-Za-z]:(?![\\/])/;

/**
 * Characters that must never reach a rendered disclosure.
 *
 * ⚠⚠ THIS IS AN INJECTION GUARD, NOT A TIDINESS RULE. The grant path is interpolated into
 * `initialize.instructions` -- the highest-trust text this server emits into a model's context --
 * and into the operator's stderr. A character that starts a new visual line lets a directory name
 * forge disclosure text, including a counterfeit "Known limits" paragraph claiming there are none.
 *
 * C0 and DEL were the first version and were NOT enough. Each range below is here for a reason:
 *   \u0000-\u001F  C0 controls, including newline and carriage return
 *   \u007F         DEL
 *   \u0080-\u009F  C1 controls, including NEL (\u0085), which terminates a line in some renderers
 *   \u200B-\u200F  zero-width space/joiners and LRM/RLM -- invisible, and they alter rendering
 *   \u2028\u2029   LINE SEPARATOR and PARAGRAPH SEPARATOR -- a real newline to many renderers
 *   \u202A-\u202E  bidirectional embedding and OVERRIDE -- reorders displayed text
 *   \u2066-\u2069  bidirectional isolates -- same class, added in Unicode 6.3
 *   \uFEFF         zero-width no-break space / BOM appearing mid-string
 *
 * ⚠ Rejecting these makes a small number of legal POSIX filenames ungrantable. That is a
 * deliberate trade: such a name cannot be rendered honestly in a security disclosure, and a
 * disclosure that cannot be trusted is worth less than a folder that cannot be granted.
 */
const UNSAFE_IN_DISCLOSURE =
    /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u2028\u2029\u202A-\u202E\u2066-\u2069\uFEFF]/;

/** The Win32 device and UNC-device namespaces. A grant root spelled this way refuses its own children. */
const NAMESPACED = /^[\\/][\\/][.?][\\/]/;

export type RequestRefusalReason =
    | 'BAD_INPUT'
    | 'CLAMPED'
    | 'IS_ROOT'
    | 'ESCAPES'
    | 'ELOOP'
    | 'MISSING'
    | 'NOT_A_DIRECTORY'
    | 'NOT_A_FILE'
    | 'DENIED'
    | 'NAME_TOO_LONG'
    | 'ROOT_MOVED'
    | 'IO_ERROR'
    /**
     * A component carries a `:`. On Windows that is ALTERNATE DATA STREAM syntax, not part of the
     * filename — `note.md::$DATA` addresses the primary stream of `note.md`, and `link:s` addresses
     * a stream on whatever `link` resolves to. Measured 2026-08-29: `resolveNewInGrant('s_out:wyrd')`
     * against a symlink leaf resolved successfully and a write through it landed on the file
     * OUTSIDE the grant. Refused lexically because no containment check downstream can see it.
     *
     * ⚠ SCREENED ON WIN32 ONLY — REVERSED 2026-08-31, AND THE PARAGRAPH THIS REPLACES ARGUED THE
     * OPPOSITE. It said the screen ran on every platform and called the cost a deliberate trade for
     * cross-machine consistency. That was wrong in the direction that matters: a colon is an
     * ordinary filename character on macOS and Linux and is a device stream nowhere but Windows, so
     * the screen was refusing files that genuinely exist inside the grant on hosts where nothing
     * hazardous was ever present. `2026-08-29 10:30 standup.md` is a legal POSIX note, `0.1.1` reads
     * it, and an unconditional screen breaks that for every POSIX reader already running.
     *
     * The consistency argument does not survive contact with the Reader's one job, which is to read
     * what is in the grant. A vault that syncs to Windows has a real portability problem; refusing
     * to read the file on Linux does not fix it and is not this module's call to make.
     */
    | 'STREAM_SYNTAX'
    /**
     * A component is a reserved DOS device name — `CON`, `NUL`, `COM1` and friends.
     *
     * ⚠ THIS IS A PORTABILITY SCREEN, NOT A CONTAINMENT ONE, AND THE FIRST VERSION OF THIS COMMENT
     * CLAIMED OTHERWISE. It asserted that Windows resolves these to DEVICES so `lstat` reports
     * ENOENT and the containment checks pass on a name that is not a file. **Measured on this
     * runtime, that is false**: `NUL`, `NUL.`, `nul.md`, `CON`, `COM1` and the superscript variants
     * all create, `lstat` and list as ordinary files inside the grant. Trailing dots and spaces
     * also survive, which is the signature of libuv issuing extended-length `\\?\` paths — those
     * bypass Win32 device translation entirely.
     *
     * ⚠ AND ITS "ONE BEHAVIOUR ACROSS MACHINES" RATIONALE DIED ON 2026-08-31, when the screen
     * became WIN32-ONLY alongside its sibling. That paragraph argued the screen bought uniform
     * behaviour wherever the fence runs; it now does the opposite by construction, and keeping the
     * claim would have left this file arguing for a property its own code had just given up.
     *
     * What it buys NOW, which is narrower and true: on Windows, where these names have historically
     * been resolved as devices by some path forms and as files by others, a request naming one is
     * refused rather than resolved down a path whose behaviour depends on which form libuv chose.
     * The cost is a handful of unusable names, on Windows only. **This remains a PORTABILITY screen
     * and is not load-bearing for containment** — the measurement above is what settles that, and it
     * is why making it conditional is a different-sized decision from touching the walk.
     */
    | 'RESERVED_NAME'
    /** The target already exists, on a path that may only create. */
    | 'EXISTS'
    /**
     * The leaf is not the object the append path observed.
     *
     * Between the leaf probe and the pre-write verification, the append path re-reads the target
     * three ways — `fstat` on the descriptor it actually holds, a second `lstat` of the name, and
     * `realpathNative` of the name — and requires them to agree with each other and with what the
     * probe saw. This reason covers every disagreement: the leaf appeared where the probe found
     * nothing, vanished where the probe found a file, changed `dev`/`ino`, stopped being a regular
     * non-link file, or the filesystem supplied an identity too weak to prove it unchanged
     * (`ino === 0`, which is what a network share reports).
     *
     * ⚠ IT IS NOT A CLAIM THAT AN ATTACK HAPPENED, and it must not be read as one. An ordinary
     * concurrent writer replacing a log file mid-rotation produces exactly this. The append path
     * refuses rather than deciding which of the two objects the caller meant.
     *
     * ⚠ NOT REACHABLE THROUGH `createFileInGrant`, whose analogous window closes as `EXISTS` at
     * the exclusive open. The two are separate reasons because they answer different questions:
     * `EXISTS` says the name was already taken, `TARGET_CHANGED` says the object under the name
     * is not the one this call observed.
     */
    | 'TARGET_CHANGED'
    /**
     * A write's PARENT DIRECTORY resolves to somewhere other than where it was spelled — the
     * spelling names one directory and the filesystem hands back another.
     *
     * ⚠⚠ THIS IS A CONTAINMENT REASON THAT `ESCAPES` CANNOT EXPRESS, and that is why it is its own
     * code. `Notes` as an in-grant junction to `Arc` resolves to a path that IS inside the grant,
     * so every containment predicate passes and a write through it lands in `Arc/` — the user's
     * immutable provenance layer. Measured 2026-09-04: `writePage({path:'Notes/planted.md'})`
     * returned `ok: true` with the file at `vault/Arc/planted.md`. `ESCAPES` would be a false
     * statement (nothing left the grant), `DENIED` names an OS permission failure, and `BAD_INPUT`
     * would blame a valid spelling.
     *
     * ⚠ THE COMPARISON IS CASE-FOLDED, AND THAT IS A MEASUREMENT RATHER THAN A PREFERENCE. Asking
     * for `vault\mage` where the directory on disk is `Mage` returns the canonical `vault\Mage`, so
     * an exact comparison refuses an ORDINARY user spelling — the same false-positive class
     * `rootStillCanonical` records above, where exact comparison was revision 2 of 3 and had to be
     * replaced. Case folding still catches the real alias, because `Notes` and `Arc` differ folded.
     * Measured 2026-09-04, 8 names, 8/8 agreeing: wherever Windows RESOLVES a differently-cased
     * spelling (ASCII, Greek `ΣΟΦΙΑ`, Cyrillic, accented `Café`), `toLowerCase()` folds them equal
     * too; wherever JavaScript would MIS-fold (`Straße`, `Meſſe`, `ΟΔΟΣ`, `İstanbul`) Windows
     * returns ENOENT, so there is no alias to catch.
     *
     * ⚠ THE ACCEPTED COST, STATED: on a case-SENSITIVE filesystem a genuine `mage -> Mage` alias
     * folds equal and is ALLOWED. That is the price of avoiding the measured Windows false
     * positive, and it is a deliberate trade rather than an oversight.
     *
     * ⚠ WRITE PATHS ONLY. The read path resolves through aliases on purpose — reading an in-grant
     * directory through a junction discloses nothing the grant does not already cover — so this
     * reason is reachable through `createFileInGrant` and `appendLineInGrant` and through nothing
     * else. ⚠ THE SENTENCE NAMED `Arc/` UNTIL 2026-09-08 AND THE SUBSTITUTION IS NOT COSMETIC: the
     * fence holds no rule about any particular directory, and a rule sentence naming one would
     * read as a guarantee this module cannot make. The consumer's protected subtree appears here
     * only as the RATIONALE above, where it is a measured incident rather than a rule.
     */
    | 'PARENT_ALIAS';

export type ConfigRefusalReason =
    | 'CONFIG_EMPTY'
    | 'CONFIG_NULL_BYTE'
    | 'CONFIG_CONTROL_CHAR'
    | 'CONFIG_TOO_LONG'
    | 'CONFIG_RELATIVE'
    | 'CONFIG_DRIVE_RELATIVE'
    | 'CONFIG_NAMESPACED'
    | 'CONFIG_MALFORMED'
    | 'GRANT_MISSING'
    | 'GRANT_NOT_A_DIRECTORY';

export type FenceReason = RequestRefusalReason | ConfigRefusalReason;

export interface FenceRefusal {
    readonly ok: false;
    readonly reason: FenceReason;
    /** Human-readable, and for config refusals it carries the path the user actually named. */
    readonly detail: string;
    /** The lexically normalized grant path, on config refusals only. Empty string otherwise. */
    readonly resolvedPath: string;
}

export interface Slice {
    readonly ok: true;
    readonly bytes: Buffer;
    readonly offset: number;
    readonly nextOffset: number;
    readonly truncated: boolean;
    readonly size: number;
}

export interface Entry {
    readonly name: string;
    readonly kind: 'file' | 'directory' | 'link' | 'other';
    readonly size: number | null;
}

/**
 * The result of asking the gate about one existing name. It deliberately carries no path: the
 * caller supplied the name, and the gate keeps the resolved spelling private while performing the
 * filesystem operation itself.
 */
export interface Probe {
    readonly ok: true;
    readonly kind: Entry['kind'];
}

/**
 * The outcome of a gate-mediated write. **It carries no absolute path**, deliberately: `rel` is
 * grant-relative and safe to disclose, and there is nothing here a caller could re-open.
 */
export interface Created {
    readonly ok: true;
    readonly rel: string;
    readonly bytes: number;
}

/**
 * The outcome of a gate-mediated append. Same rule as `Created`: `rel` is grant-relative and
 * `bytes` is the exact length of the line that was written — never a reduced count, because a
 * short append is a refusal here exactly as a short create is.
 */
export interface Appended {
    readonly ok: true;
    readonly rel: string;
    readonly bytes: number;
}

/**
 * What a failed write MAY have left behind. A `Retained` value is only ever
 * `state: 'indeterminate'`, and the indeterminacy covers EXISTENCE as well as content: the target
 * may or may not have been created, and if it was, its content may be absent, partial, or
 * complete-but-unflushed. The fence cannot narrow that further without reading back what it just
 * failed to write.
 *
 * ⚠ THIS DOC SAID "THE FILE EXISTS" UNTIL 2026-08-31, AND THAT WAS A PROMISE THE CODE DOES NOT
 * KEEP. Both code-review lenses caught it independently. `retained` is returned for every
 * non-`EEXIST` `openExclusive` failure, and an ordinary `wx` open can fail with `EACCES` having
 * created nothing at all. Returning non-null there is the right CONSERVATIVE choice — the caller
 * must treat the path as possibly-dirty — but stating it as existence overstates what was
 * observed, and a caller that trusted the stronger claim would clean up a file that is not there.
 */
export interface Retained {
    readonly rel: string;
    /**
     * The target MAY exist; if it does, its content may be absent, partial, or
     * complete-but-unflushed. Never a claim that the file is present.
     */
    readonly state: 'indeterminate';
}

/**
 * A refusal from the write path. `retained` is REQUIRED, never optional.
 *
 * ⚠ AN OPTIONAL FIELD WOULD BE A HAND-MAINTAINED LIST OF THE SITES THAT REMEMBERED IT. Making it
 * required means the compiler enumerates the refusal sites, not a reviewer — so a new refusal
 * added to `createFileInGrant` cannot ship without stating what it left on disk.
 *
 * `null` means the target was not created BY THIS INVOCATION. It is half the value of the type:
 * a caller that cannot tell *nothing was created* from *something was left* has to treat every
 * refusal as possibly-dirty.
 */
export interface WriteRefusal extends FenceRefusal {
    readonly retained: Retained | null;
}

/** The outcome of a gate-mediated hash. Same rule: `rel` only, never an absolute path. */
export interface Hashed {
    readonly ok: true;
    readonly rel: string;
    readonly algorithm: 'sha256';
    readonly digest: string;
    readonly size: number;
}

export interface FsGate {
    readFileInGrant(request: string, offset: number, limit: number): Promise<Slice | FenceRefusal>;
    listDirInGrant(request: string): Promise<Entry[] | FenceRefusal>;
    listGrantRoot(): Promise<Entry[] | FenceRefusal>;
    probeInGrant(request: string): Promise<Probe | FenceRefusal>;
    disclosedRoot(): string;

    /* ---------------------------------------------------------------- *
     * THE SHARED CONTAINMENT SEAM — scribe spec D8                      *
     *                                                                   *
     * ⚠⚠ THE SEAM IS GATE-MEDIATED: THE CALLER NAMES A PATH AND THE     *
     * GATE PERFORMS THE OPERATION. NO RESOLVED PATH IS EVER RETURNED.   *
     *                                                                   *
     * This shape was ruled 2026-08-29 AFTER a first attempt returned    *
     * resolved pathnames to the caller. That attempt failed its review  *
     * round with five HIGHs, of which two were REPRODUCED as live       *
     * escapes: an alternate-data-stream leaf wrote onto a file outside  *
     * the grant, and a hardlink leaf overwrote one. All five were one   *
     * class — **a path-based check cannot establish what object a name  *
     * will resolve to at open time** — and a returned string also left  *
     * an unbounded window between the check and the caller's use of it. *
     *                                                                   *
     * Handing back a path means the fence's guarantee ends at the       *
     * `return`. Performing the operation means it ends at the syscall,  *
     * which is where it has to end.                                     *
     * ---------------------------------------------------------------- */

    /**
     * Create a NEW file and write it, in one gate-mediated operation.
     *
     * ⚠ Opened `wx` — create-exclusive. If anything already exists at that name the open fails
     * and nothing is written, which is what closes the existing-object classes structurally
     * rather than by inspection: a symlink, a hardlink, a junction or a reparse point the runtime
     * cannot classify all refuse `EXISTS` — but the refusal comes from the LEAF PROBE in
     * `resolveNew`, not from this flag. What `wx` adds is the narrower guarantee that an ORDINARY
     * object appearing between that probe and this open is refused rather than overwritten.
     *
     * ⚠ It does NOT refuse a DANGLING reparse name inserted in that same window: `CREATE_NEW`
     * follows one and creates at the substituted path. That residual is the documented TOCTOU
     * limit, and this comment claimed to close it until 2026-08-29.
     *
     * ⚠⚠ A FAILED WRITE DOES NOT CLEAN UP AFTER ITSELF. It REPORTS what it left, in `retained`,
     * and the caller decides. Deleting the leftover was considered and ruled out: deleting by
     * PATH reopens the TOCTOU this fence exists to close, and deleting by HANDLE has no pure-Node
     * form, because success must retain the file so `FILE_FLAG_DELETE_ON_CLOSE` cannot serve.
     *
     * Three cases, and they are genuinely different:
     *
     *   1. PRE-OPEN refusals — `BAD_INPUT`, every `resolveNew` refusal, and an `EEXIST` from the
     *      exclusive open — carry `retained: null`. Nothing was created by this invocation.
     *      (`EEXIST` means something else already owns the name; that object is not ours.)
     *   2. A NON-`EEXIST` failure of the exclusive open carries an indeterminate `retained`. The
     *      open is an injectable primitive whose contract makes no promise that a throwing
     *      implementation materialised nothing, so the fence must not claim one.
     *   3. POST-CREATION write and close failures carry an indeterminate `retained`. A close
     *      failure is a refusal, not a footnote: the bytes may never have reached the disk, so a
     *      success reported before the descriptor closed would be a success the fence cannot back.
     */
    createFileInGrant(request: string, bytes: Buffer): Promise<Created | WriteRefusal>;

    /**
     * Append ONE already-serialised, LF-terminated line to a file under the grant, creating the
     * file if the name is free. The parent directory must already exist: this never makes one, so
     * a caller whose `.wyrd/` is missing gets a refusal rather than a directory it did not ask for.
     *
     * ⚠⚠ WHAT `O_APPEND` BUYS, STATED HONESTLY, BECAUSE THE STRONGER WORDING IS FALSE AND BOTH
     * COLD REDESIGN LANES FALSIFIED IT INDEPENDENTLY. `O_APPEND` makes offset selection and the
     * write one operation with respect to competing appenders — two processes appending whole
     * lines cannot interleave their bytes or overwrite each other's. It does **NOT** make the
     * write all-or-nothing. A disk-full condition, a device error or an interrupted syscall can
     * leave a PARTIAL line on disk, and no flag available on this runtime prevents that.
     *
     * ⚠ THIS COMMENT IS THE SINGLE HOME OF THE ATOMICITY CONTRACT. README.md carries the
     * consumer-facing consequence — a reader must survive a trailing fragment — and points here
     * for the reasoning rather than restating it. ⚠ It points at `dist/fsgate.d.ts`, NOT at this
     * file: `src/` is not in the published tarball, and `PC1-pointers-resolve` refuses a pointer
     * strangers cannot follow. This comment reaches them through the emitted declaration.
     * The README used to restate the contract, in different words, which
     * is the drift pair: two hand-maintained encodings of one contract, either free to go stale
     * without the other looking wrong. If this promise changes, the README bullet needs checking
     * for whether its one consequence still holds; it does not need rewording in parallel.
     *
     * So the promise is exactly this, and no more:
     *   · ONE write call, never retried. A retry under `O_APPEND` re-selects the end of file, so a
     *     second attempt after a partial write appends the tail AFTER whatever another appender
     *     landed in between — manufacturing the interleaving the flag exists to prevent.
     *   · No interleaving caused BY THIS FENCE.
     *   · A refusal that names what may have been retained, never a silent truncation.
     * It is NOT a promise that a partial line can never exist. A reader of the resulting file must
     * be able to survive a trailing fragment.
     *
     * ⚠ A multi-named leaf refuses, but residual link and rename races can still leave appended
     * bytes under a name chosen by another writer. The exact timing, consequences, and platform
     * limit have one authoritative account: README.md, "Security boundary and limits".
     *
     * ⚠ THE CREATE BRANCH INHERITS `createFileInGrant`'s DOCUMENTED `CREATE_NEW` WINDOW, UNCHANGED
     * AND NOT WIDENED. `ax` is the same `CreateFileW(CREATE_NEW)` the create path uses, so a
     * DANGLING reparse leaf inserted after this path's `ENOENT` probe takes `STATUS_REPARSE` and
     * the create is retried at the substituted path — materialising the outside target. The
     * post-open binding then refuses before `appendOnce` runs, so NO BYTE OF THE CALLER'S LINE IS
     * WRITTEN and this opens no new byte-write window; what it leaves behind is an empty outside
     * file. It is the SAME accepted window, reached through a second entry point, and closing it
     * needs an atomic no-follow create that this runtime does not offer in pure Node. See the
     * probe comment in `resolveNew` for the measurements, and README.md's limits section.
     *
     * Retention follows `createFileInGrant`'s three cases, with one addition: a `TARGET_CHANGED`
     * raised BEFORE the open carries `retained: null` (nothing was opened), and one raised after
     * it carries an indeterminate `retained` — nothing was written, but `openAppend` is an
     * injectable primitive and its contract promises nothing about what a call materialised.
     */
    appendLineInGrant(request: string, line: Buffer): Promise<Appended | WriteRefusal>;

    /**
     * Hash a file in the grant, for the Scribe's `derived_from` provenance (spec D4/D8).
     *
     * ⚠ This exists so the Scribe never needs a path to a source. Without it, citing a source
     * means asking the fence where the source is and then reading it — which is the returned-path
     * shape again, arriving through the read side instead of the write side.
     */
    hashInGrant(request: string): Promise<Hashed | FenceRefusal>;
}

/**
 * The primitives the fence is allowed to reach the filesystem through. Injectable at the
 * BOOTSTRAP SEAM only, so a test exercises a real gate with instrumented primitives rather
 * than a fake gate.
 *
 * ⚠ `realpathNative` must be `fs.realpathSync.native`. Bare `fs.realpathSync` is banned:
 * it walks 14 ancestors from `C:\` per call (syscall-observations §2) and it disagrees with
 * the operating system in both directions on relative symlink targets (link-measurements §9).
 */
export interface Primitives {
    open(target: string, flags: string): number;
    close(fd: number): void;
    read(fd: number, buffer: Uint8Array, offset: number, length: number, position: number): number;
    fstat(fd: number): fs.Stats;
    lstat(target: string): fs.Stats;
    readlink(target: string): string;
    realpathNative(target: string): string;
    readdir(target: string): fs.Dirent[];
    /**
     * ⚠ THE CREATE PATH'S OPEN, AND IT IS CREATE-EXCLUSIVE BY CONSTRUCTION (`wx`).
     *
     * It cannot overwrite, cannot truncate, and cannot follow anything that already exists — the
     * OS refuses with `EEXIST` before any of our logic runs. That is deliberate: this module is a
     * dependency of the READ-ONLY Reader as well as of the write surface, and a primitive that
     * cannot destroy data is a much smaller thing to have sitting there unused than one that can.
     *
     * ⚠⚠ THIS SAID "THE ONLY WRITE PRIMITIVE" UNTIL 2026-09-08, AND IT WAS FALSE RATHER THAN
     * merely dated. FOUR of the primitives below this line are write-capable: `openExclusive` and
     * `openAppend` obtain the writable descriptor, and `writeAll` and `appendOnce` put the bytes
     * on it. `openAppend`'s `'existing'` mode in particular opens a file that already exists for
     * writing, which is precisely what the retired sentence said no primitive here could do. The
     * non-destructive property the paragraph above states is real and survives the correction —
     * none of the four can truncate or overwrite an existing file's contents — but that is a claim
     * about what the write primitives CAN DO, not a claim that there is one of them.
     */
    openExclusive(target: string): number;
    writeAll(fd: number, buffer: Buffer): number;
    /**
     * The append path's open, in two modes, and the MODE IS THE CALLER'S DECISION rather than a
     * flag combination that covers both.
     *
     * · `'exclusive-create'` → `ax`. The probe found nothing, so the name must still be free at
     *   open time; anything that appeared in between fails `EEXIST` rather than being appended to.
     * · `'existing'` → `O_WRONLY | O_APPEND`, **with no `O_CREAT`**. The probe found a regular
     *   file, and if that file was deleted in between, the open must FAIL rather than silently
     *   recreate an empty one — a recreated file is a lineage log that lost its history and looks
     *   healthy afterwards.
     *
     * ⚠ `O_APPEND` IS ON BOTH BRANCHES (`ax` implies it). It is what makes offset selection and
     * the write atomic against competing appenders; see `appendLineInGrant` for what that does and
     * does not buy.
     */
    openAppend(target: string, mode: 'existing' | 'exclusive-create'): number;
    /**
     * EXACTLY ONE `fs.writeSync`, AND IT MUST NOT SHARE `writeAll`'s COMPLETION LOOP.
     *
     * `writeAll` resumes from a byte offset, which is correct for a descriptor whose position the
     * caller owns and wrong for one opened `O_APPEND`: every write re-selects the current end of
     * file, so a retry after a partial write appends the remainder AFTER anything another appender
     * landed in the meantime, splicing one record through the middle of another. A short count is
     * therefore a failure to report, never a state to resume from.
     */
    appendOnce(fd: number, buffer: Buffer): number;
}

export interface CreateFsGateOptions {
    readonly rawGrant: string;
    readonly primitives?: Primitives;
}

/*
 * ⚠⚠ THERE IS NO `windowsNameRules` OPTION, AND ITS ABSENCE IS DELIBERATE — DO NOT ADD ONE BACK.
 *
 * One existed for about an hour on 2026-08-31, as a test seam for the two Win32 name screens. BOTH
 * round-1 review lenses independently returned HIGH on it, converging on the same reading: an
 * option that can turn a containment screen OFF is a containment opt-out, and on Windows it
 * re-admits the alternate-data-stream resolution class that was REPRODUCED writing outside the
 * grant. This module's whole discipline is that containment is STRUCTURAL, not configurable.
 *
 * ⚠ AND IT WAS REACHABLE BY A THIRD PARTY, WHICH THE FIRST VERSION OF THIS BLOCK DENIED. That
 * version called the knob latent because the Reader's `main.ts` types the factory as
 * `{ rawGrant: string }` and "the package ships `bin` only". A TypeScript parameter type is not a
 * runtime fence, and the packaging half was false too. The removal was right either way; the
 * reasoning given for it was wrong, and the correction stays here rather than being quietly
 * dropped because this is precisely the sentence a later round would cite to argue that the next
 * knob is harmless too.
 *
 * ⚠⚠ AND THE REACHABILITY IS NOW DECLARED RATHER THAN ACCIDENTAL, WHICH MAKES IT STRONGER, NOT
 * WEAKER. This module used to be `dist/fsgate.js` inside a package that shipped all of `dist` with
 * no `exports` map — publicly consumable by accident. It is now the sole declared entry point of
 * `wyrd-fence`, and the Reader that once re-exported it declares an `exports` map exposing nothing
 * at all. So `createFsGate` has exactly ONE public path, this one, and it is versioned. Any option
 * added to `CreateFsGateOptions` is a first-class part of a published API from the moment it
 * compiles — there is no longer even a bad argument that it is internal.
 *
 * ⚠ WHAT REMOVING IT COSTS, STATED RATHER THAN HIDDEN: the POSIX branch of these screens is now
 * unexercised on a Windows host, and this repo's suite runs on Windows. That is honest — it folds
 * into the standing `POSIX is reasoned, never measured` row — and it is the better trade. The seam
 * bought SIMULATED POSIX coverage by opening a REAL Windows hole.
 */

/* ------------------------------------------------------------------ *
 * MODULE-PRIVATE PRIMITIVES — never exported, never reachable outside *
 * ------------------------------------------------------------------ */

const _open: Primitives['open'] = (target, flags) => fs.openSync(target, flags);
const _close: Primitives['close'] = fd => fs.closeSync(fd);
const _read: Primitives['read'] = (fd, buffer, offset, length, position) =>
    fs.readSync(fd, buffer, offset, length, position);
const _fstat: Primitives['fstat'] = fd => fs.fstatSync(fd);
const _lstat: Primitives['lstat'] = target => fs.lstatSync(target);
const _readlink: Primitives['readlink'] = target => fs.readlinkSync(target, 'utf8');
const _realpathNative: Primitives['realpathNative'] = target => fs.realpathSync.native(target);
const _readdir: Primitives['readdir'] = target => fs.readdirSync(target, { withFileTypes: true });
const _openExclusive: Primitives['openExclusive'] = target => fs.openSync(target, 'wx');
/**
 * ⚠ IT LOOPS, AND THE SINGLE-CALL VERSION WAS A DATA-LOSS DEFECT. `fs.writeSync` may return fewer
 * bytes than requested; the first version returned that short count as `Created.bytes` alongside
 * `ok: true`, so a truncated file reported success and the Scribe's provenance would have been
 * computed over something other than what it was handed. The name asserted a property the body
 * did not have.
 */
const _writeAll: Primitives['writeAll'] = (fd, buffer) => {
    let written = 0;
    while (written < buffer.length) {
        const n = fs.writeSync(fd, buffer, written, buffer.length - written, written);
        if (n <= 0) break;
        written += n;
    }
    return written;
};

/**
 * ⚠ THE EXISTING BRANCH CARRIES NO `O_CREAT`, AND ADDING ONE WOULD BE A SILENT-RECREATION DEFECT.
 * `'a'` is `O_WRONLY|O_APPEND|O_CREAT`, so a leaf deleted between the probe and the open would be
 * recreated empty and appended to — a lineage file that lost every prior record and reads as
 * healthy. Spelled with the constants rather than a mode string because no mode string means
 * "append to an existing file only".
 */
const _openAppend: Primitives['openAppend'] = (target, mode) =>
    mode === 'exclusive-create'
        ? fs.openSync(target, 'ax')
        : fs.openSync(target, fs.constants.O_WRONLY | fs.constants.O_APPEND);
/** ⚠ ONE CALL. See the `appendOnce` declaration for why a completion loop is wrong here. */
const _appendOnce: Primitives['appendOnce'] = (fd, buffer) =>
    fs.writeSync(fd, buffer, 0, buffer.length, null);

const DEFAULT_PRIMITIVES: Primitives = {
    open: _open,
    close: _close,
    read: _read,
    fstat: _fstat,
    lstat: _lstat,
    readlink: _readlink,
    realpathNative: _realpathNative,
    readdir: _readdir,
    openExclusive: _openExclusive,
    writeAll: _writeAll,
    openAppend: _openAppend,
    appendOnce: _appendOnce
};

/* ---------------------------------- *
 * Refusals                            *
 * ---------------------------------- */

function refuse(reason: FenceReason, detail: string, resolvedPath = ''): FenceRefusal {
    return Object.freeze({ ok: false as const, reason, detail, resolvedPath });
}

export function isRefusal(value: unknown): value is FenceRefusal {
    return typeof value === 'object' && value !== null && (value as { ok?: unknown }).ok === false;
}

/**
 * Errno taxonomy. Each condition gets its own reason; MISSING is never conflated with ESCAPES.
 *
 * ⚠ A null byte arrives as a `TypeError` with `code === 'ERR_INVALID_ARG_VALUE'` and no errno,
 * so this cannot be the only place null bytes are caught — stage (a) rejects them lexically.
 */
function mapFsError(error: unknown, what: string): FenceRefusal {
    const code = (error as { code?: unknown } | null)?.code;
    switch (code) {
        case 'ENOENT':
            return refuse('MISSING', `no such path in the grant: ${what}`);
        case 'ENOTDIR':
            return refuse('NOT_A_DIRECTORY', `a component of ${what} is not a directory`);
        case 'EISDIR':
            return refuse('NOT_A_FILE', `${what} is a directory`);
        case 'EACCES':
        case 'EPERM':
            // ⚠ NO VERB, DELIBERATELY. Until 2026-08-31 this read "permission denied READING",
            // which is false on the create path — the reason code was right and the sentence was a
            // small lie, in the one string a human actually reads when a create fails. No arm
            // asserted the literal, which is why nothing noticed.
            //
            // ⚠⚠ THE FIRST REPAIR WAS AN `action` PARAMETER, AND IT WAS INCOMPLETE — a code-review
            // lens found that pre-open failures (the leaf probe, nested-create resolution, the
            // parent stat) reach this mapper through the SHARED walk, which does not know which
            // path called it. Threading the verb far enough to be true means routing a cosmetic
            // parameter through the most-reviewed code in this module. Not worth the risk for a
            // string: the reason code and the path carry the information, and a neutral sentence is
            // true on BOTH paths, which the parameterised one was not.
            return refuse('DENIED', `permission denied on ${what}`);
        case 'ELOOP':
            return refuse('ELOOP', `too many links resolving ${what}`);
        case 'ENAMETOOLONG':
            return refuse('NAME_TOO_LONG', `path too long: ${what}`);
        case 'ERR_INVALID_ARG_VALUE':
        case 'ERR_INVALID_ARG_TYPE':
            return refuse('BAD_INPUT', `unusable path: ${what}`);
        default:
            return refuse('IO_ERROR', `filesystem error (${String(code)}) on ${what}`);
    }
}

/* ---------------------------------- *
 * Write-path refusals                 *
 * ---------------------------------- */

/** The only `Retained` shape there is — see `Retained` for why it cannot be narrowed. */
function retained(rel: string): Retained {
    return Object.freeze({ rel, state: 'indeterminate' as const });
}

/**
 * ⚠ THE SINGLE PLACE A `WriteRefusal` IS BUILT, and that is the point. `writeRefuse` and
 * `mapWriteError` both come through here, so a refusal shape cannot be assembled anywhere else
 * with the field forgotten — the guard sits at the primitive rather than at each call site.
 *
 * It also carries `resolvedPath` through unchanged, which is why a `resolveNew` refusal is
 * re-wrapped rather than rebuilt: rebuilding one would drop whatever it was carrying.
 */
function asWriteRefusal(base: FenceRefusal, left: Retained | null): WriteRefusal {
    return Object.freeze({
        ok: false as const,
        reason: base.reason,
        detail: base.detail,
        resolvedPath: base.resolvedPath,
        retained: left
    });
}

/** The write-path sibling of `refuse`. */
function writeRefuse(reason: FenceReason, detail: string, left: Retained | null): WriteRefusal {
    return asWriteRefusal(refuse(reason, detail), left);
}

/** The write-path sibling of `mapFsError`, reusing its errno taxonomy rather than restating it. */
function mapWriteError(error: unknown, what: string, left: Retained | null): WriteRefusal {
    return asWriteRefusal(mapFsError(error, what), left);
}

/* ---------------------------------- *
 * Exact object identity               *
 * ---------------------------------- */

/** A physical object's identity, read exactly. `null` when the filesystem could not supply one. */
interface ObjectIdentity {
    readonly dev: bigint;
    readonly ino: bigint;
    /**
     * The object's LINK COUNT, carried here because this is already the only place the bigint stats
     * are read, and a separate `lstat`/`fstat` for it would open a second window between the two
     * readings — the exact window this field exists to close.
     *
     * ⚠ IT IS DELIBERATELY NOT PART OF `sameObject`. Identity answers "is this the same object";
     * the link count answers "how many names does that object have", which is a different question
     * whose answer can legitimately change between two readings of the SAME object. Folding it into
     * the equality would turn an unrelated `link()` by another process into a spurious
     * `TARGET_CHANGED` — a reason that says the object was replaced, when it was not. The append
     * path reads it separately, at both sites, and refuses on it with its own reason there.
     */
    readonly nlink: bigint;
}

/**
 * ⚠⚠ READ AS `BigInt`, AND THE NUMBER FORM IS NOT MERELY IMPRECISE HERE — IT IS WRONG ROUGHLY HALF
 * THE TIME FOR THE EXACT CASE `TARGET_CHANGED` EXISTS TO CATCH. MEASURED ON THIS VOLUME, 2026-09-02:
 * NTFS file ids exceed `Number.MAX_SAFE_INTEGER`, so `fs.Stats.ino` is a float64 whose ULP is 4 at
 * that magnitude — and 200 files created in one directory came back with ADJACENT inodes differing
 * by 1, one pair of which collapsed to the same rounded value. A file deleted and recreated under
 * the same name receives the very next id, which is precisely the pair the rounding merges. So a
 * number-form comparison would report "unchanged" for a genuine replacement, which is the failure
 * direction that matters. (Same defect class as the release gate's `exactFileId`, found there on
 * 2026-09-02, one package over and pointing the other way.)
 *
 * ⚠ IT READS THE FILESYSTEM DIRECTLY RATHER THAN THROUGH THE INJECTABLE TABLE, AND THAT IS A
 * DELIBERATE, NARROW EXCEPTION rather than an oversight. `Primitives.lstat` and `Primitives.fstat`
 * are typed `=> fs.Stats`, the number form, so no injected implementation can supply an exact id;
 * widening their signatures would change two LOCKED members of a published type surface to repair
 * a third. What the append path does instead is call the injected primitive for the TYPE PREDICATES
 * (`isFile`, `isSymbolicLink`) — so a test still drives what the fence concludes about the object's
 * KIND, and the containment guard still sees every path — and takes the identity from here.
 *
 * ⚠ WHAT THAT COSTS, STATED: identity cannot be staged by injection, so the `TARGET_CHANGED`
 * identity arms drive it with real files on the real filesystem instead. That is a weaker seam and
 * a stronger measurement.
 *
 * `null` when the filesystem supplies no inode (`0`, which network shares report) or when the call
 * throws. Every caller treats `null` as "cannot prove it unchanged" and refuses.
 */
function exactIdentityOf(target: string): ObjectIdentity | null {
    try {
        const stats = fs.lstatSync(target, { bigint: true });
        return stats.ino === 0n ? null : { dev: stats.dev, ino: stats.ino, nlink: stats.nlink };
    } catch {
        return null;
    }
}

/** The same reading, taken from a DESCRIPTOR — the only one that names an object rather than a name. */
function exactIdentityOfDescriptor(fd: number): ObjectIdentity | null {
    try {
        const stats = fs.fstatSync(fd, { bigint: true });
        return stats.ino === 0n ? null : { dev: stats.dev, ino: stats.ino, nlink: stats.nlink };
    } catch {
        return null;
    }
}

/** Both must be present AND equal. A missing identity is never "the same". */
function sameObject(left: ObjectIdentity | null, right: ObjectIdentity | null): boolean {
    return left !== null && right !== null && left.dev === right.dev && left.ino === right.ino;
}

/* ---------------------------------- *
 * Lexical helpers                     *
 * ---------------------------------- */

function segmentsBelow(root: string, absolute: string): string[] {
    const rel = path.relative(root, absolute);
    if (rel === '') return [];
    return rel.split(path.sep).filter(segment => segment.length > 0);
}

function joinSegments(root: string, segments: readonly string[]): string {
    return segments.length === 0 ? root : path.join(root, ...segments);
}

function contains(root: string, candidate: string): boolean {
    if (candidate.includes('\0')) return false;
    if (!path.isAbsolute(candidate)) return false;
    const rel = path.relative(root, path.normalize(candidate));
    if (rel === '') return true;
    if (rel === '..') return false;
    if (rel.startsWith(`..${path.sep}`)) return false;
    return !path.isAbsolute(rel);
}

/**
 * The internal, absolute-tolerant containment check.
 *
 * ⚠ This is deliberately NOT stage (a). Stage (a) rejects every absolute path as BAD_INPUT,
 * because a request is untrusted user input; a derived path is one the fence itself built and
 * is always absolute. Re-running stage (a) on a derived path is the defect that made revision 4
 * refuse every ordinary in-grant symlink. Never exported.
 */
function _validateDerivedAbsolute(root: string, candidate: string): FenceRefusal | null {
    return contains(root, candidate) ? null : refuse('ESCAPES', 'the resolved path leaves the granted folder');
}

/**
 * Whether a write's parent directory is the one its spelling named.
 *
 * ⚠ CASE-FOLDED, AND `PARENT_ALIAS`'s declaration carries the measurement that settles it. Both
 * inputs are absolute paths the fence itself produced: `spelled` from `lexicalStage`, `actual` from
 * `resolveInGrant`'s `realpathNative` arbitration. `path.normalize` is applied to both so a
 * trailing separator or a `.` segment on one side is not read as an alias.
 *
 * ⚠ NEVER EXPORTED, AND CALLED ON WRITE PATHS ONLY. The read path resolves through in-grant
 * aliases deliberately; this predicate is what makes the two paths differ.
 *
 * ⚠⚠ THE ACCEPTED CASE-SENSITIVE COST IS SHARED BY EVERY CALLER, AND SAYING SO HERE IS THE POINT OF
 * SAYING IT ONCE. `PARENT_ALIAS`'s declaration states the trade: on a case-SENSITIVE filesystem a
 * genuine `mage -> Mage` alias folds equal and is ALLOWED. Because both write paths and therefore
 * every write above them come through this ONE predicate, that cost applies identically to the
 * CREATE path, the APPEND path, and a consumer's config create — which is `createFileInGrant` again
 * and inherits it without a second decision. A reader who finds the cost stated at one call site
 * and not the others would reasonably infer the others are tighter; they are not, and there is no
 * per-caller variation to look for.
 *
 * ⚠ A SECOND CONSEQUENCE OF THE FOLD, and it is what makes the post-create size branch in the
 * consumer's stamp path reachable at all: `toLowerCase()` can change a string's BYTE WIDTH. The
 * Kelvin sign `K` (U+212A) is three UTF-8 bytes and folds to a one-byte `k`; the Ohm and Angstrom
 * signs behave the same way. So on a case-sensitive volume a fold-equal alias between spellings of
 * DIFFERENT byte width is accepted by design, and the canonical parent handed back can be longer
 * than the one the caller spelled.
 */
function _parentIsAliased(spelled: string, actual: string): boolean {
    return path.normalize(spelled).toLowerCase() !== path.normalize(actual).toLowerCase();
}

/* ---------------------------------- *
 * Stage (a) — lexical, no I/O         *
 * ---------------------------------- */

interface LexicalOk {
    readonly ok: true;
    readonly rel: string;
    readonly spelled: string;
}

/**
 * The reserved DOS device names, which Windows resolves to DEVICES rather than to entries in the
 * containing directory — at any depth, with any extension, and with trailing dots or spaces
 * stripped by the Win32 layer before resolution.
 *
 * ⚠ SCREENED ON WIN32 ONLY, via `NameScreens.device`. The paragraph that stood here argued the
 * opposite at length — that refusing everywhere bought one behaviour across synced machines — and
 * it was the last surviving copy of a rationale retracted in two other places on 2026-08-31. It is
 * deleted rather than annotated, per this workspace's clean-edit regime, because a reader editing
 * the device set arrives HERE and would otherwise meet the retired doctrine stated with a ⚠ and no
 * contradiction in view. The live rationale is on `RESERVED_NAME`; this is a PORTABILITY screen and
 * nothing about containment rides on it.
 */
const RESERVED_DEVICE_NAMES = new Set([
    // The documented Win32 set.
    'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$',
    'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
    'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    // ⚠ THE SUPERSCRIPT FORMS ARE RESERVED TOO, and a review lens found them missing. Win32 folds
    // `COM¹`/`COM²`/`COM³` onto `COM1`/`COM2`/`COM3` through legacy codepage handling.
    'COM¹', 'COM²', 'COM³', 'LPT¹', 'LPT²', 'LPT³',
    // ⚠ `COM0` AND `LPT0` ARE **NOT** IN THE DOCUMENTED SET, and they are here deliberately rather
    // than by mistake — two review lenses independently flagged them as false entries, which is
    // fair, so the reason is written down instead of the entries being quietly dropped. They cost
    // two unusable filenames nobody writes, and they remove a boundary that has to be re-argued
    // every time this set is edited. **This is portability policy, not a claim about Win32.**
    'COM0', 'LPT0'
]);

/**
 * ⚠ The stem is taken before the FIRST dot, not the last: Win32 resolves `NUL.md` and even
 * `NUL.tar.gz` to the device. Trailing dots and spaces are stripped first, because Win32 strips
 * them before resolution and `NUL.` is therefore the device too — checking the raw segment would
 * miss it. Measured 2026-08-29: `NUL`, `CON`, `COM1`, `nul.md` and `NUL.` all resolved as ordinary
 * filenames through the write seam before this existed.
 */
function isReservedDeviceName(segment: string): boolean {
    // ⚠ THE STEM IS TRIMMED, NOT ONLY THE WHOLE COMPONENT, AND TRIMMING ONLY THE COMPONENT WAS A
    // GAP. `NUL .txt` and `COM1 .log` carry the trailing space BEFORE the extension, so stripping
    // from the end of the component left `NUL ` / `COM1 ` as the stem and the lookup missed. Win32
    // strips trailing spaces from the stem, so those are the device.
    const trimmed = segment.replace(/[. ]+$/, '');
    const stem = (trimmed.split('.')[0] ?? '').replace(/[ ]+$/, '');
    return RESERVED_DEVICE_NAMES.has(stem.toUpperCase());
}

/**
 * Stage (a). Nothing here touches the filesystem, so every refusal it produces has probed
 * nothing — which is what makes the outside-existence oracle closed for these inputs.
 */
/**
 * Which of the two Win32 name screens apply to one request.
 *
 * ⚠⚠ THEY ARE SEPARATE FIELDS BECAUSE THEY ARE SEPARATE KINDS OF GUARD, AND MERGING THEM ONTO ONE
 * PREDICATE WAS A DEFECT — found by the cross-vendor escalation lens on 2026-08-31, after two
 * same-vendor lenses had converged on a different part of the change and missed this entirely.
 *
 * · `device` is a PORTABILITY screen. The module's own measurement (see `RESERVED_NAME`) is that
 *   these names create and list as ordinary files on this runtime, so nothing about containment
 *   rides on it and conditioning it on the host is coherent.
 *
 * · `stream` is a CONTAINMENT screen, and on the CREATE path it is the ONLY one. `resolveNew`
 *   resolves the PARENT through the fence and then joins the leaf LEXICALLY — the leaf never
 *   reaches the walk, so `realpathNative` is never consulted for it. A leaf spelled
 *   `<link>:<stream>` therefore passes the existence probe (the stream does not exist yet) and the
 *   containment test (pure string arithmetic on a path that is lexically inside), and the create
 *   lands wherever the OS resolves the name. That is the escape REPRODUCED on 2026-08-29.
 *   On the READ path the same screen is defence-in-depth rather than the guard: every successful
 *   walk arbitrates through `realpathNative`, and that call was measured returning the `:stream`
 *   suffix intact, so an escaping stream dies at the containment check with or without the screen.
 *
 * ⚠ SO THE SPLIT IS BY PATH, NOT BY SCREEN, and it costs nothing in either direction. The
 * regression this whole change exists to fix is a READ regression — a legal POSIX filename that
 * `0.1.1` reads and a conditioned screen refuses. Keeping `stream` unconditional on CREATE takes
 * none of that back, because the write surface is inert: `server.ts` registers no write tool and
 * `E2-one-tool` asserts `tools/list` is exactly `read`. No POSIX user can create anything through
 * wyrd today, so nothing is refused that anyone can currently ask for.
 *
 * ⚠ AND THE REASON THE HOST IS THE WRONG PREDICATE FOR A CONTAINMENT SCREEN, stated once here
 * because it is the thing to remember: `process.platform` is a proxy for *"this filesystem applies
 * Win32 name resolution"*, and the two come apart — a volume with Win32 semantics can be reached
 * from a POSIX host. The predicate names the host; the hazard belongs to the volume. Nothing in
 * this repo measures either, so the conservative side of that gap is the only defensible one.
 */
interface NameScreens {
    readonly stream: boolean;
    readonly device: boolean;
}

function lexicalStage(root: string, request: unknown, screens: NameScreens): LexicalOk | FenceRefusal {
    if (typeof request !== 'string') return refuse('BAD_INPUT', 'the path must be a string');
    if (request.includes('\0')) return refuse('BAD_INPUT', 'the path contains a null byte');
    if (path.isAbsolute(request)) return refuse('BAD_INPUT', 'the path must be relative to the granted folder');
    if (DRIVE_RELATIVE.test(request)) {
        // `path.isAbsolute('C:notes')` is false, so the clause above does not fire and the
        // input would otherwise survive the whole predicate as contained. Measured.
        return refuse('BAD_INPUT', 'drive-relative paths are not accepted');
    }

    // `..` absorbed at a volume root produces a path the containment check would refuse for a
    // DIFFERENT reason, so the clamp is detected before the join or it is untestable.
    //
    // ⚠⚠ THE SAME LOOP NOW SCREENS EACH COMPONENT FOR TWO NAME CLASSES THAT ARE NOT FILENAMES
    // ON WIN32. Both were found by the 2026-08-29 review round on the write seam, and both are
    // placed HERE, in the shared lexical stage, rather than in the caller that surfaced them: a
    // guard applied at one call site is a claim that the call site is the whole set, and the READ
    // path resolves the same spellings. Neither class is detectable downstream — `lstat` reports
    // ENOENT for a device name and addresses a stream for a colon, so every containment check
    // passes on a name that does not denote a file inside the grant.
    //
    // ⚠ THEY ARE WIN32-ONLY, AND SHIPPING THEM UNCONDITIONALLY WAS A REGRESSION CAUGHT BEFORE
    // RELEASE. Both classes are artefacts of Win32 name resolution, not properties of the string:
    // on POSIX a colon and `NUL` are ordinary filename characters, so an unconditional screen
    // refuses files that really are inside the grant. `0.1.1` reads
    // `2026-08-29 10:30 standup.md` on Linux; an unconditional screen would have broken that for
    // every POSIX reader already running it. Two review rounds flagged the cross-platform cost.
    const rootPrefix = path.parse(root).root;
    let depth = root.slice(rootPrefix.length).split(path.sep).filter(s => s.length > 0).length;
    for (const segment of request.split(/[\\/]/)) {
        if (segment === '' || segment === '.') continue;
        if (segment === '..') {
            depth -= 1;
            if (depth < 0) return refuse('CLAMPED', 'the path climbs past the root of the volume');
            continue;
        }
        // ⚠ THE TWO SCREENS ARE GATED SEPARATELY — see `NameScreens` above for why, and note that
        // `stream` is TRUE ON EVERY HOST for a create. Neither flag is read inline from
        // `process.platform` here: the gate derives them once and threads them, so there is exactly
        // one place in this module that consults the host.
        if (screens.stream && segment.includes(':')) {
            return refuse('STREAM_SYNTAX', 'the path contains a colon, which names a data stream rather than a file');
        }
        if (screens.device && isReservedDeviceName(segment)) {
            return refuse('RESERVED_NAME', `"${segment}" is a reserved device name, not a file in the granted folder`);
        }
        depth += 1;
    }

    const spelled = path.normalize(path.join(root, request));
    if (!contains(root, spelled)) return refuse('ESCAPES', 'the path leaves the granted folder');

    const rel = path.relative(root, spelled);
    if (rel === '') return refuse('IS_ROOT', 'that path is the granted folder itself');

    return { ok: true, rel, spelled };
}

/* ---------------------------------- *
 * Stage (b) — the walk                *
 * ---------------------------------- */

interface WalkContext {
    readonly visited: Set<string>;
    hops: number;
    sawReparse: boolean;
    /**
     * Set when the two readings of a link DIFFER, so the walk had to choose one. The chosen
     * branch is a guess about a reparse tag Node does not expose, and a guess that fails is
     * evidence about the branch, never about the request.
     */
    guessed: boolean;
}

function bump(context: WalkContext, key: string): FenceRefusal | null {
    if (context.visited.has(key)) return refuse('ELOOP', 'the links form a cycle');
    context.visited.add(key);
    context.hops += 1;
    if (context.hops > MAX_HOPS) return refuse('ELOOP', 'too many links to follow (hop limit)');
    return null;
}

/**
 * Stage (b). Walks the request as spelled, one component at a time, inspecting each for a
 * reparse point — which is the part `realpathSync.native` destroys by resolving silently and
 * returning only the endpoint.
 *
 * Screening rule: a reparse point whose target escapes under EVERY candidate resolution is
 * refused here, without following it. That is what keeps the outside-existence oracle closed
 * for the plain escapes, and it is why a junction pointing at `C:\outside` is refused before
 * anything names `C:\outside`.
 *
 * ⚠ When the candidates disagree the fence cannot decide alone: which one the operating system
 * uses depends on the reparse TAG of an earlier component, and Node exposes no tag — a junction
 * and an absolute-target directory symlink are byte-identical through `lstat`. Those cases are
 * arbitrated by `realpathNative` on the spelled request, which names only an in-grant path.
 */
function resolveInGrant(
    root: string,
    prim: Primitives,
    request: unknown,
    screens: NameScreens
): { ok: true; actual: string; rel: string } | FenceRefusal {
    const lexical = lexicalStage(root, request, screens);
    if (isRefusal(lexical)) return lexical;

    const context: WalkContext = { visited: new Set<string>(), hops: 0, sawReparse: false, guessed: false };
    const walked = walk(root, prim, lexical.spelled, context);

    // ⚠⚠ A REFUSAL REACHED DOWN A GUESSED BRANCH IS NOT AN ANSWER, AND RETURNING ONE WAS A
    // DEFECT.
    //
    // "Arbitration lets the walk be merely conservative rather than exact" is true on the
    // SUCCESS path and false on the FAILURE path. `walk` returns a `FenceRefusal` the moment the
    // branch it guessed hits ENOENT, ENOTDIR, EACCES, ELOOP or a link that escapes — and
    // returning that from here skips the arbitration entirely. Both consequences were measured,
    // both on ordinary in-grant content served happily by every other reader on the machine: a
    // directory symlink whose traversal reading did not exist was refused MISSING, and one whose
    // traversal reading was itself a link pointing outside was refused ESCAPES — the server
    // accusing in-grant content of leaving the grant.
    //
    // A refusal is therefore final only when NO guess was involved. Otherwise the operating
    // system is asked, exactly as it is on the success path.
    if (isRefusal(walked) && !context.guessed) return walked;

    let actual = isRefusal(walked) ? '' : walked;
    // ⚠⚠ UNCONDITIONAL SINCE 2026-08-29, AND THE DELETED CONDITION WAS `context.sawReparse ||`.
    //
    // `sawReparse` is set from `stats.isSymbolicLink()` and from nothing else. A component carrying
    // a reparse tag this runtime cannot classify therefore left it FALSE, no arbitration ran, and
    // `actual` stayed the spelled in-grant path — which the caller then opened, letting Win32
    // follow the tag. That is the unclassified-reparse limit in README.md, "Security boundary and
    // limits", and the gate on this line was what left it open. ⚠ The header used to describe that
    // class as the one that would defeat the design entirely; it no longer does, because removing
    // this gate is what stopped that being true.
    //
    // `realpathNative` is `GetFinalPathNameByHandle` on a handle opened FOLLOWING reparse points,
    // so it reports what the operating system actually resolved to for EVERY tag, classified or
    // not. Running it on every resolution converts that class from undetectable into ordinary: a
    // tag Win32 does not follow yields an in-grant answer, and one it does follow yields an
    // out-of-grant answer that `_validateDerivedAbsolute` refuses.
    //
    // ⚠⚠ "UNCONDITIONAL" MEANS SUCCESSFUL WALKS **AND GUESSED REFUSALS**, NOT SUCCESSES ALONE —
    // saying it flatly was inaccurate, and saying "successful walks only" was the correction's own
    // second error, caught by a later round.
    // Two earlier returns are still above this line and BOTH ARE DELIBERATE: a lexical refusal
    // returns having touched nothing, and a walk refusal with `guessed === false` returns without
    // arbitrating — which is what `A30-no-arbitration` asserts and what keeps a plain escape from
    // probing an outside name. So the exact claim is: **every successful resolution arbitrates**.
    //
    // ⚠ What that leaves open, stated rather than implied: an intermediate tag the runtime cannot
    // classify is walked as an ordinary component, and if the outside descendant is missing or
    // denied the walk refuses BEFORE arbitration — so the refusal reason still distinguishes those
    // outcomes. The containment property holds (the request is refused either way); the closed
    // ORACLE property does not, for that shape. Closing it needs a change to the refusal
    // normalisation, not to this line.
    //
    // ⚠ THE COST: one extra `realpath` on each successful resolution whose walk saw no CLASSIFIED
    // link — link-free paths and successful unclassified-reparse paths alike. Zero extra on lexical
    // refusals, non-guessed walk refusals, classified-link successes and guessed refusals. A
    // direct-root create does not call `resolveInGrant` at all and gains nothing; a nested create
    // gains one for its parent. `listGrantRoot` is unaffected.
    if (true) {
        // ⚠ DELIBERATELY after ANY reparse point, not only after the two readings disagree.
        //
        // When they disagree the walk picks whichever stays inside — a GUESS, because the
        // choice depends on the reparse tag of an earlier component and Node exposes no tag.
        // Making the operating system authoritative whenever any link was involved is what
        // makes that guess safe: the walk then only has to be CONSERVATIVE (refuse what
        // plainly escapes), never EXACT. Narrowing this to the disagreement case would put the
        // guess back on the serving path, which is the class of defect that killed five
        // revisions. ⚠ THE OLD COST LINE HERE SAID "one realpath call, and only on link-bearing
        // paths" — that stopped being true when the gate above was removed, and it contradicted the
        // corrected accounting a few lines up. Every successful walk arbitrates now, link-bearing
        // or not; see that accounting for the exact delta.
        //
        // It names only the in-grant spelling, and what comes back is validated before use.
        let resolved: string;
        try {
            resolved = prim.realpathNative(lexical.spelled);
        } catch (error) {
            return mapFsError(error, lexical.rel);
        }
        const escaped = _validateDerivedAbsolute(root, resolved);
        if (escaped) return escaped;
        actual = path.normalize(resolved);
    }

    return { ok: true, actual, rel: path.relative(root, actual) };
}

function walk(root: string, prim: Primitives, spelledInit: string, context: WalkContext): string | FenceRefusal {
    let spelled = spelledInit;

    for (let pass = 0; ; pass += 1) {
        if (pass > MAX_HOPS) return refuse('ELOOP', 'too many links to follow (hop limit)');

        const segments = segmentsBelow(root, spelled);
        let actual = root;
        let restart: string | null = null;

        for (let index = 0; index < segments.length && restart === null; index += 1) {
            const name = segments[index] as string;
            let candidate = path.join(actual, name);

            for (let chain = 0; ; chain += 1) {
                if (chain > MAX_HOPS) return refuse('ELOOP', 'too many links to follow (hop limit)');

                let stats: fs.Stats;
                try {
                    stats = prim.lstat(candidate);
                } catch (error) {
                    return mapFsError(error, path.relative(root, candidate));
                }

                if (!stats.isSymbolicLink()) {
                    actual = candidate;
                    break;
                }

                context.sawReparse = true;

                let target: string;
                try {
                    target = prim.readlink(candidate);
                } catch (error) {
                    return mapFsError(error, path.relative(root, candidate));
                }

                const rest = segments.slice(index + 1);
                const absoluteTarget = path.isAbsolute(target);

                // The two readings resolve the LINK ITSELF. Components after it are appended by
                // whichever loop consumes them, never here — folding them in twice was a bug.
                //
                // Candidate 1 — the traversal spelling. What a JUNCTION does.
                const baseTrav = path.normalize(
                    absoluteTarget ? target : path.join(joinSegments(root, segments.slice(0, index)), target)
                );
                // Candidate 2 — the substituted spelling. What a DIRECTORY SYMLINK does.
                const baseSubst = path.normalize(
                    absoluteTarget ? target : path.join(path.dirname(candidate), target)
                );

                const travOk = contains(root, baseTrav);
                const substOk = contains(root, baseSubst);

                if (!travOk && !substOk) {
                    // Every reading of this link leaves the grant. Refused WITHOUT following it,
                    // so nothing has named the target.
                    return refuse('ESCAPES', 'a link in the path points outside the granted folder');
                }

                // Continue the walk down whichever reading stays inside, so the walk itself never
                // names a path outside the grant. The operating system's own answer is taken at
                // the end of `resolveInGrant`; this is containment screening, not resolution.
                //
                // ⚠ WHEN THE READINGS DIFFER THIS IS A GUESS, and it is recorded as one. Which
                // reading the OS uses depends on the reparse tag of an earlier component —
                // traversal under a junction, substituted under a directory symlink — and the
                // two are byte-identical through `lstat`. A failure reached down a guessed
                // branch says nothing about the request, so `resolveInGrant` must not report it.
                if (baseTrav !== baseSubst) context.guessed = true;
                const base = travOk ? baseTrav : baseSubst;
                // The components after the link are appended by whichever loop consumes them.
                // The absolute branch leaves them to the outer loop; folding them into the
                // substituted candidate as well appended them twice.
                const derived = path.normalize(rest.length === 0 ? base : path.join(base, ...rest));

                if (absoluteTarget) {
                    // A junction never rewrites the spelling later relative targets resolve
                    // against, so the substitution is re-walked in place rather than restarting.
                    const key = `A\u0000${derived.toLowerCase()}\u0000${index}\u0000${spelled.toLowerCase()}`;
                    const looped = bump(context, key);
                    if (looped) return looped;
                    // ⚠⚠ NEVER `lstat` a multi-component target as an opaque path. `lstat` does
                    // not follow the FINAL component, but it does traverse the intermediates —
                    // so an unscreened reparse point inside the target gets traversed, and
                    // whether the outside path it lands on exists becomes observable through
                    // the errno. That is an outside-existence oracle, which README.md, "Security
                    // boundary and limits", claims is closed for every shape `lstat` classifies.
                    // Re-walk the target component by component instead, screening each one.
                    const resolvedTarget = walk(root, prim, base, context);
                    if (isRefusal(resolvedTarget)) return resolvedTarget;
                    candidate = resolvedTarget;
                    continue;
                }

                const key = `R\u0000${derived.toLowerCase()}`;
                const looped = bump(context, key);
                if (looped) return looped;
                restart = derived;
                break;
            }
        }

        if (restart !== null) {
            spelled = restart;
            continue;
        }
        return actual;
    }
}

/* ---------------------------------- *
 * Reads                               *
 * ---------------------------------- */

const MAX_LIMIT = 1 << 20;

/**
 * Trim a byte slice back to the last whole UTF-8 codepoint (D5a). A slice may come back up to
 * 3 bytes shorter than the window; `nextOffset` is the first byte of the next whole codepoint,
 * so following it to exhaustion reconstructs the file byte-for-byte.
 */
function trimToCodepointBoundary(buffer: Buffer, length: number): number {
    if (length === 0) return 0;
    for (let back = 1; back <= 4 && back <= length; back += 1) {
        const byte = buffer[length - back] as number;
        if ((byte & 0xc0) === 0x80) continue; // continuation byte, keep walking back
        let needed = 1;
        if ((byte & 0x80) === 0x00) needed = 1;
        else if ((byte & 0xe0) === 0xc0) needed = 2;
        else if ((byte & 0xf0) === 0xe0) needed = 3;
        else if ((byte & 0xf8) === 0xf0) needed = 4;
        else return length; // not a lead byte at all; leave the bytes alone
        return needed <= back ? length : length - back;
    }
    return length;
}

type KindSource = Pick<fs.Dirent, 'isSymbolicLink' | 'isDirectory' | 'isFile'>;

function entryKind(entry: KindSource): Entry['kind'] {
    if (entry.isSymbolicLink()) return 'link';
    if (entry.isDirectory()) return 'directory';
    if (entry.isFile()) return 'file';
    return 'other';
}

function readEntries(prim: Primitives, target: string): Entry[] | FenceRefusal {
    let dirents: fs.Dirent[];
    try {
        dirents = prim.readdir(target);
    } catch (error) {
        return mapFsError(error, target);
    }
    return dirents.map(dirent => {
        let size: number | null = null;
        if (dirent.isFile()) {
            try {
                size = prim.lstat(path.join(target, dirent.name)).size;
            } catch {
                size = null;
            }
        }
        return Object.freeze({ name: dirent.name, kind: entryKind(dirent), size });
    });
}

/* ---------------------------------- *
 * The bootstrap seam                  *
 * ---------------------------------- */

/**
 * Validate the configured grant lexically. Runs before any filesystem access, and lives here
 * rather than in `main` so a direct caller of `createFsGate` cannot skip it.
 */
/**
 * The volume a path names, as an identity rather than as a spelling: separators folded to `\\`
 * and case folded, because Windows treats `C:/x`, `C:\x` and `c:\X` as the same location.
 *
 * ⚠⚠ COMPARING ROOT STRINGS INSTEAD OF VOLUME IDENTITIES WAS A SHIPPED DEFECT. `path.parse`
 * PRESERVES THE INPUT SEPARATOR — `path.parse('C:/x').root` is `'C:/'` while
 * `path.parse(path.normalize('C:/x')).root` is `'C:\\'` — so a string comparison refused every
 * forward-slash grant, which is how almost everyone writes a Windows path inside an MCP
 * client's JSON config (the alternative is escaping every separator twice). It also passed
 * MIXED separators, because `path.parse` takes the root from the FIRST separator only. Wrong
 * answer, incoherent rule, and a false message naming a volume that had not changed.
 */
function volumeIdentity(candidate: string): string {
    const root = path.parse(candidate).root.replace(/[\\/]+/g, '\\').toLowerCase();
    if (root === '') return '';
    // ⚠⚠ SEPARATOR PRESENCE, NOT ONLY SEPARATOR FORM. Folding `/` to `\\` was not enough:
    // `path.parse('\\\\nas\\vault').root` is `\\\\nas\\vault` with NO trailing separator, while its
    // normalized form's root HAS one. So a UNC SHARE ROOT — an ordinary network vault, and the
    // exact shape the UNC validator below exists to accept — was refused with the same false
    // "changes the volume it names" message this function was written to eliminate. Twice
    // shipped, and both times the message named a volume that had not changed.
    return root.endsWith('\\') ? root : `${root}\\`;
}

function validateGrantLexically(rawGrant: unknown): { ok: true; normalized: string } | FenceRefusal {
    if (typeof rawGrant !== 'string' || rawGrant.length === 0) {
        return refuse('CONFIG_EMPTY', 'the grant is empty');
    }
    if (rawGrant.includes('\0')) {
        return refuse('CONFIG_NULL_BYTE', 'the grant contains a null byte');
    }

    // ⚠⚠ THE GRANT PATH IS RENDERED INTO THE MODEL'S INSTRUCTION CHANNEL, WHICH MAKES IT AN
    // INJECTION SURFACE. `disclosure()` interpolates this value into `initialize.instructions` —
    // the highest-trust text wyrd emits. A directory name containing a newline can therefore
    // synthesize entire counterfeit disclosure lines, including a fake "Known limits" paragraph
    // claiming there are none. NTFS forbids most of these in a name, but this package declares no
    // `os` restriction, and on macOS and Linux a directory name may contain newlines freely. The
    // person who chose those ancestor names is not necessarily the person granting the folder — a
    // cloned repo, a shared drive, a downloaded dataset.
    //
    // Rejected at the door rather than escaped at the point of use, because there is more than one
    // point of use (the model channel, the operator's stderr, and any future surface) and a guard
    // at the primitive is the only one the next caller inherits.
    const control = UNSAFE_IN_DISCLOSURE.exec(rawGrant);
    if (control !== null) {
        const code = control[0].charCodeAt(0).toString(16).padStart(2, '0');
        return refuse(
            'CONFIG_CONTROL_CHAR',
            `the grant contains a control character (0x${code}) at position ${control.index}`
        );
    }

    // A bound, so a pathological name cannot flood the instruction channel and push the real
    // disclosure out of a model's attention.
    //
    // ⚠ THIS IS A DISCLOSURE-SIZE POLICY, NOT A FILESYSTEM LIMIT, and an earlier comment claiming
    // it sat "well past any legitimate path" was wrong: with long paths enabled, a legal Windows
    // path can exceed this. Such a grant is refused deliberately -- a path too long to state in a
    // disclosure is one the user cannot verify -- and the message says "disclosure limit" so the
    // refusal is not mistaken for a filesystem error.
    if (rawGrant.length > MAX_GRANT_LENGTH) {
        return refuse(
            'CONFIG_TOO_LONG',
            `the grant is ${rawGrant.length} characters; the disclosure limit is ${MAX_GRANT_LENGTH}`
        );
    }

    // ⚠ THE MANGLING CHECK RUNS BEFORE THE NAMESPACE CHECK, AND THE ORDER IS THE POINT.
    // Measured: `path.normalize('\\?\C:\..\foo')` is `'\\?\foo'` — `..` absorbed THROUGH the
    // device prefix, so the path now names a different volume than the one written. In front of it, the user is told the true defect — the path is
    // malformed — instead of being told device paths are unsupported.
    //
    // ⚠ AN EARLIER VERSION OF THIS COMMENT CLAIMED that every volume-changing input is
    // device-namespaced, so that behind the namespace check this guard was merely dead code.
    // That was WRONG and the wrongness had teeth: `\\\\nas\\vault` is not namespaced and the guard
    // fired on it. Do not restate the claim — the guard is reachable on ordinary UNC input, and
    // `volumeIdentity` is the only thing keeping it from misfiring there.
    const normalized = path.normalize(rawGrant);
    if (volumeIdentity(rawGrant) !== volumeIdentity(normalized)) {
        return refuse(
            'CONFIG_MALFORMED',
            `the grant is malformed: normalizing it changes the volume it names, from ` +
                `${path.parse(rawGrant).root} to ${path.parse(normalized).root}`,
            normalized
        );
    }

    if (NAMESPACED.test(rawGrant)) {
        // Measured: with root `\\?\C:\vault`, the legitimate child `C:\vault\a.md` yields
        // `rel = "C:\vault\a.md"` and refuses. A root whose every child fails is worse than a
        // refused root.
        return refuse('CONFIG_NAMESPACED', 'device- and UNC-namespaced grant paths are not accepted', rawGrant);
    }
    if (DRIVE_RELATIVE.test(rawGrant)) {
        return refuse('CONFIG_DRIVE_RELATIVE', 'the grant must be an absolute path', rawGrant);
    }
    if (!path.isAbsolute(rawGrant)) {
        return refuse('CONFIG_RELATIVE', 'the grant must be an absolute path', rawGrant);
    }
    if (/^[\\/][\\/]/.test(rawGrant)) {
        const parts = rawGrant.slice(2).split(/[\\/]/).filter(s => s.length > 0);
        if (parts.length < 2) {
            return refuse('CONFIG_MALFORMED', 'the grant is a malformed UNC path', rawGrant);
        }
    }

    // `path.normalize` has already folded the separators, so `C:/vault`, `C:\vault`,
    // `C:\vault/` and `C:/vault\` all arrive at step 6a as the same native path.
    return { ok: true, normalized };
}

/**
 * The bootstrap seam.
 *
 * Validates the raw grant lexically, `lstat`s the path the user named, canonicalizes it ONCE
 * with `realpathSync.native`, and freezes the canonical root into a closure. There is no
 * setter and no writable property holding the root, so nothing can later point the server at
 * a different folder.
 *
 * ⚠ Exactly two filesystem primitives run here, both naming the path the user named: `lstat`
 * then `realpathNative`. The canonical root is disclosed by `disclosedRoot()` because the named
 * root and the canonical root can differ, and the canonical one is the boundary.
 */
export function createFsGate(options: CreateFsGateOptions): FsGate | FenceRefusal {
    const lexical = validateGrantLexically(options.rawGrant);
    if (isRefusal(lexical)) return lexical;
    const named = lexical.normalized;

    // Do not retain the caller's object: copy the functions into individual closure locals so a
    // later mutation of the passed record cannot re-point the gate's primitives.
    //
    // ⚠⚠ AND NEVER INVOKE ONE AS A PROPERTY OF AN AGGREGATE. `table.lstat(p)` binds `this` to the
    // table, so a supplied `function lstat() { leaked = this }` receives the whole primitive
    // record — `leaked.open` and `leaked.read` included — and the fence is bypassed entirely.
    // Freezing the table does not help: its members are still callable. Every call below goes
    // through `Reflect.apply(fn, undefined, args)`, so an injected callback gets `this === undefined`.
    // ⚠ THE ONE PLACE THIS MODULE CONSULTS THE HOST. No caller can influence it — see the block
    // above `CreateFsGateOptions` for why the option that used to sit here was removed. Read once
    // and captured for the gate's lifetime, the same treatment the primitives get below, so the
    // value cannot shift under a live gate.
    const windowsNameRules = process.platform === 'win32';

    // ⚠⚠ TWO SCREEN SETS, AND THE DIFFERENCE IS `stream` ON CREATE. See `NameScreens`. The read
    // set is host-derived for both screens; the create set keeps the stream screen ON EVERY HOST,
    // because on the create path it is the only guard between a `<link>:<stream>` leaf and an
    // `openExclusive` that lands outside the grant. Deriving these here rather than at the call
    // sites is deliberate: a call site that has to remember which set it needs is a guard applied
    // at N places, and the next entry point added would inherit nothing.
    const readScreens: NameScreens = { stream: windowsNameRules, device: windowsNameRules };
    const createScreens: NameScreens = { stream: true, device: windowsNameRules };

    const supplied = options.primitives;
    const openFn = supplied?.open ?? DEFAULT_PRIMITIVES.open;
    const closeFn = supplied?.close ?? DEFAULT_PRIMITIVES.close;
    const readFn = supplied?.read ?? DEFAULT_PRIMITIVES.read;
    const fstatFn = supplied?.fstat ?? DEFAULT_PRIMITIVES.fstat;
    const lstatFn = supplied?.lstat ?? DEFAULT_PRIMITIVES.lstat;
    const readlinkFn = supplied?.readlink ?? DEFAULT_PRIMITIVES.readlink;
    const realpathNativeFn = supplied?.realpathNative ?? DEFAULT_PRIMITIVES.realpathNative;
    const readdirFn = supplied?.readdir ?? DEFAULT_PRIMITIVES.readdir;
    const openExclusiveFn = supplied?.openExclusive ?? DEFAULT_PRIMITIVES.openExclusive;
    const writeAllFn = supplied?.writeAll ?? DEFAULT_PRIMITIVES.writeAll;
    const openAppendFn = supplied?.openAppend ?? DEFAULT_PRIMITIVES.openAppend;
    const appendOnceFn = supplied?.appendOnce ?? DEFAULT_PRIMITIVES.appendOnce;

    const unbound: Primitives = {
        open: (target, flags) => Reflect.apply(openFn, undefined, [target, flags]) as number,
        close: fd => Reflect.apply(closeFn, undefined, [fd]) as void,
        read: (fd, buffer, offset, length, position) =>
            Reflect.apply(readFn, undefined, [fd, buffer, offset, length, position]) as number,
        fstat: fd => Reflect.apply(fstatFn, undefined, [fd]) as fs.Stats,
        lstat: target => Reflect.apply(lstatFn, undefined, [target]) as fs.Stats,
        readlink: target => Reflect.apply(readlinkFn, undefined, [target]) as string,
        realpathNative: target => Reflect.apply(realpathNativeFn, undefined, [target]) as string,
        readdir: target => Reflect.apply(readdirFn, undefined, [target]) as fs.Dirent[],
        openExclusive: target => Reflect.apply(openExclusiveFn, undefined, [target]) as number,
        writeAll: (fd, buffer) => Reflect.apply(writeAllFn, undefined, [fd, buffer]) as number,
        openAppend: (target, mode) => Reflect.apply(openAppendFn, undefined, [target, mode]) as number,
        appendOnce: (fd, buffer) => Reflect.apply(appendOnceFn, undefined, [fd, buffer]) as number
    };
    const prim: Primitives = Object.freeze(unbound);

    let named_stats: fs.Stats;
    try {
        named_stats = prim.lstat(named);
    } catch (error) {
        const code = (error as { code?: unknown } | null)?.code;
        if (code === 'ENOENT' || code === 'ENOTDIR') {
            return refuse('GRANT_MISSING', `the granted folder does not exist: ${named}`, named);
        }
        return refuse('GRANT_MISSING', `the granted folder could not be read: ${named}`, named);
    }
    if (!named_stats.isDirectory() && !named_stats.isSymbolicLink()) {
        return refuse('GRANT_NOT_A_DIRECTORY', `the grant is not a directory: ${named}`, named);
    }

    let canonicalRoot: string;
    try {
        canonicalRoot = path.normalize(prim.realpathNative(named));
    } catch (error) {
        const code = (error as { code?: unknown } | null)?.code;
        if (code === 'ENOENT') return refuse('GRANT_MISSING', `the granted folder does not exist: ${named}`, named);
        return refuse('GRANT_MISSING', `the granted folder could not be resolved: ${named}`, named);
    }

    // A symlinked grant root resolves to its canonical target, and THAT becomes the boundary.
    // Resolving once means a later swap of the link cannot move the fence.
    let canonicalStats: fs.Stats;
    try {
        canonicalStats = prim.lstat(canonicalRoot);
    } catch {
        return refuse('GRANT_MISSING', `the granted folder could not be read: ${named}`, named);
    }
    if (!canonicalStats.isDirectory()) {
        return refuse('GRANT_NOT_A_DIRECTORY', `the grant is not a directory: ${named}`, named);
    }

    // The granted directory's OBJECT identity, captured once. `rootStillCanonical` uses it to tell
    // a re-spelling of the same directory from a replacement — see the note there for why neither
    // spelling comparison alone could do it.
    const rootIdentity = { dev: canonicalStats.dev, ino: canonicalStats.ino };

    // ⚠⚠ THE CANONICAL PATH IS GUARDED SEPARATELY, AND SKIPPING THIS WAS THE WHOLE DEFECT.
    // `validateGrantLexically` screens what the USER TYPED. What gets DISCLOSED is what
    // `realpathNative` returned -- and a short, innocuous alias (`/tmp/notes`) can resolve to a
    // directory whose real name carries an injection payload. Validating only the input is
    // validate-before-transform: the checked value and the used value are different strings.
    const canonicalControl = UNSAFE_IN_DISCLOSURE.exec(canonicalRoot);
    if (canonicalControl !== null) {
        const code = canonicalControl[0].charCodeAt(0).toString(16).padStart(4, '0');
        return refuse(
            'CONFIG_CONTROL_CHAR',
            `the granted folder resolves to a path containing an unsafe character ` +
                `(U+${code.toUpperCase()}) at position ${canonicalControl.index}, which cannot be ` +
                `stated honestly in a disclosure`,
            named
        );
    }
    if (canonicalRoot.length > MAX_GRANT_LENGTH) {
        return refuse(
            'CONFIG_TOO_LONG',
            `the granted folder resolves to a path of ${canonicalRoot.length} characters; ` +
                `the disclosure limit is ${MAX_GRANT_LENGTH}`,
            named
        );
    }

    const root = canonicalRoot;

    /**
     * ⚠⚠ THE GATE FREEZES A STRING, NOT A DIRECTORY IDENTITY, AND THE PLAN OVERCLAIMED THIS.
     *
     * §3's "resolving once means a later swap cannot move the boundary" is FALSE. Move the
     * granted folder aside, put a junction to elsewhere in its place, and an ordinary request
     * resolves through the new root, crosses no reparse point the walk can see, and serves
     * out-of-grant content.
     *
     * This check NARROWS THAT WINDOW; it does not close it. It re-resolves the stored root and
     * refuses if the answer moved — so a swap is caught between operations, but not one that
     * lands between this check and the open. Closing it needs handle-relative APIs, and
     * measurement established Node has none on Windows: no `openat`, no `fstatat`, `fs.Dir`
     * carries no fd.
     *
     * It is the root-swap limit in README.md, "Security boundary and limits", beside TOCTOU and
     * hardlinks. Like both of those it needs LOCAL WRITE ACCESS after startup, which is outside the
     * stated threat model — a driving model that is confidently wrong or content-steered, not a
     * local writer.
     *
     * It names only the canonical root, which is in-grant, so the hardlink limit is unaffected.
     */
    function rootStillCanonical(): FenceRefusal | null {
        let current: string;
        try {
            current = path.normalize(prim.realpathNative(root));
        } catch {
            return refuse('ROOT_MOVED', 'the granted folder is no longer reachable');
        }
        // ⚠⚠ OBJECT IDENTITY ON EVERY CALL; SPELLING EXPLAINS HOW THE CHECK GOT HERE. The live
        // predicate does not gate identity on spelling. Three revisions, all measured by review:
        //
        //   1. `toLowerCase()` on both sides, every platform. On a case-SENSITIVE filesystem
        //      `/x/Vault` and `/x/vault` are different directories and this made them compare
        //      equal, so replacing the grant with a link to a differently-cased sibling passed
        //      silently. A FALSE NEGATIVE on a containment control.
        //   2. Exact string comparison. That closed it, and opened the mirror defect: on a
        //      case-INSENSITIVE, case-PRESERVING filesystem — Windows, the primary target — a
        //      case-only rename of the granted folder leaves the SAME directory reachable while
        //      `realpathNative` returns the new spelling. Every subsequent request then refuses
        //      `ROOT_MOVED` until restart. A FALSE POSITIVE, and a hard one to diagnose.
        //
        //   3. Object identity, because the question is not how the directory is SPELLED — it is
        //      whether it is the same directory. This revision first used changed spelling as the
        //      trigger to ask. That still had a hole: DESTROY the granted directory and create a
        //      different one under the same name, and the identity question was never asked. Every
        //      surface then served the replacement: read, list, hash, create and append. Reproduced
        //      first attempt against the shipped build; `A55-same-path-replacement` and `M71` were
        //      written to PIN the gap, so closing it turns them red ON PURPOSE and that redness is
        //      the review event, not a regression.
        //
        // Since 2026-09-03 the identity check is unconditional: `current` is only the path handed
        // to `lstat`, and the `dev`/`ino` comparison below runs on every call. Those values are zero
        // or unstable on some filesystems and network shares; when either side cannot supply them
        // the code FAILS CLOSED. A spurious `ROOT_MOVED` is a usability failure, and serving
        // through a swapped root is not.
        //
        // ⚠ COST, MEASURED 2026-09-03 rather than asserted: one `lstat` of the granted folder,
        // 3.7 us — 1.5% of a single 5 KB file read, and 10% of the `realpathNative` this function
        // ALREADY pays on every call. 37 ms added to a 10,000-file scan. The visible cost is not
        // speed: if the operator deletes and recreates the granted folder by hand while the server
        // runs, the recreated directory has a new inode and every request refuses ROOT_MOVED until
        // restart. That is indistinguishable, from in here, from the attack — which is exactly why
        // closing the gap produces it.
        let now: fs.Stats;
        try {
            now = prim.lstat(current);
        } catch {
            return refuse('ROOT_MOVED', 'the granted folder has been replaced since startup');
        }
        // Unchanged from the conditional version: when either side cannot supply a usable identity
        // the code FAILS CLOSED. A spurious ROOT_MOVED is a usability failure; serving through a
        // swapped root is not a failure this library is allowed to have.
        const identifiable =
            rootIdentity.ino !== 0 && now.ino !== 0 &&
            rootIdentity.dev === now.dev && rootIdentity.ino === now.ino;
        if (!identifiable) {
            return refuse('ROOT_MOVED', 'the granted folder has been replaced since startup');
        }
        // Same object. If the spelling also changed it has merely been re-spelled, and the stored
        // `root` still names it on this filesystem, so the fence keeps using it — re-pointing at the
        // new spelling would move the boundary, which is what this whole function exists to prevent.
        return null;
    }

    async function readFileInGrant(request: string, offset: number, limit: number): Promise<Slice | FenceRefusal> {
        if (!Number.isSafeInteger(offset) || offset < 0) return refuse('BAD_INPUT', 'offset must be a non-negative integer');
        if (!Number.isSafeInteger(limit) || limit <= 0) return refuse('BAD_INPUT', 'limit must be a positive integer');
        const window = Math.min(limit, MAX_LIMIT);

        const moved = rootStillCanonical();
        if (moved) return moved;

        const resolved = resolveInGrant(root, prim, request, readScreens);
        if (isRefusal(resolved)) return resolved;

        let fd: number;
        try {
            fd = prim.open(resolved.actual, 'r');
        } catch (error) {
            return mapFsError(error, resolved.rel);
        }
        try {
            const stats = prim.fstat(fd);
            if (stats.isDirectory()) return refuse('NOT_A_FILE', `${resolved.rel} is a directory`);
            const size = stats.size;
            if (offset > size) return refuse('BAD_INPUT', `offset ${offset} is past the end of the file (${size} bytes)`);

            const buffer = Buffer.allocUnsafe(window);
            const read = prim.read(fd, buffer, 0, window, offset);
            const kept = read < window ? read : trimToCodepointBoundary(buffer, read);
            const nextOffset = offset + kept;
            return Object.freeze({
                ok: true as const,
                bytes: Buffer.from(buffer.subarray(0, kept)),
                offset,
                nextOffset,
                truncated: nextOffset < size,
                size
            });
        } catch (error) {
            return mapFsError(error, resolved.rel);
        } finally {
            try {
                prim.close(fd);
            } catch {
                /* the read already succeeded or failed; a close error changes neither */
            }
        }
    }

    async function listDirInGrant(request: string): Promise<Entry[] | FenceRefusal> {
        const moved = rootStillCanonical();
        if (moved) return moved;

        const resolved = resolveInGrant(root, prim, request, readScreens);
        if (isRefusal(resolved)) return resolved;
        let stats: fs.Stats;
        try {
            stats = prim.lstat(resolved.actual);
        } catch (error) {
            return mapFsError(error, resolved.rel);
        }
        if (!stats.isDirectory()) return refuse('NOT_A_DIRECTORY', `${resolved.rel} is not a directory`);
        return readEntries(prim, resolved.actual);
    }

    async function listGrantRoot(): Promise<Entry[] | FenceRefusal> {
        const moved = rootStillCanonical();
        if (moved) return moved;
        return readEntries(prim, root);
    }

    async function probeInGrant(request: string): Promise<Probe | FenceRefusal> {
        const moved = rootStillCanonical();
        if (moved) return moved;

        // The resolved target stays inside this operation. Returning it would turn the containment
        // check into a path-handoff seam and leave the caller to race a second filesystem access.
        const resolved = resolveInGrant(root, prim, request, readScreens);
        if (isRefusal(resolved)) return resolved;
        try {
            const stats = prim.lstat(resolved.actual);
            return Object.freeze({ ok: true as const, kind: entryKind(stats) });
        } catch (error) {
            return mapFsError(error, resolved.rel);
        }
    }

    function disclosedRoot(): string {
        return root;
    }

    /* ------------------------------------------------------------------ *
     * THE SHARED CONTAINMENT SEAM — scribe spec D8                        *
     *                                                                     *
     * Both entries below call the SAME `resolveInGrant` the read path      *
     * calls, on the same bound `root` and the same bound `prim`. Not a     *
     * parallel check, not a copy — the identical code path, which is what  *
     * D8 requires and what a vendored or re-derived fence cannot provide.  *
     * ------------------------------------------------------------------ */

    async function hashInGrant(request: unknown): Promise<Hashed | FenceRefusal> {
        const moved = rootStillCanonical();
        if (moved) return moved;

        const resolved = resolveInGrant(root, prim, request, readScreens);
        if (isRefusal(resolved)) return resolved;

        let fd: number;
        try {
            fd = prim.open(resolved.actual, 'r');
        } catch (error) {
            return mapFsError(error, resolved.rel);
        }
        try {
            const stats = prim.fstat(fd);
            if (stats.isDirectory()) return refuse('NOT_A_FILE', `${resolved.rel} is a directory`);

            // Streamed in windows, never slurped: a source is routinely a whole transcript, and the
            // cost model this serves (spec D4) is explicit that hashing is a FULL READ of it.
            const hash = createHash('sha256');
            const buffer = Buffer.allocUnsafe(HASH_WINDOW);
            let position = 0;
            for (;;) {
                const read = prim.read(fd, buffer, 0, HASH_WINDOW, position);
                if (read <= 0) break;
                hash.update(buffer.subarray(0, read));
                position += read;
            }
            return Object.freeze({
                ok: true as const,
                rel: resolved.rel,
                algorithm: 'sha256' as const,
                digest: hash.digest('hex'),
                size: position
            });
        } catch (error) {
            return mapFsError(error, resolved.rel);
        } finally {
            try {
                prim.close(fd);
            } catch {
                /* the read already succeeded or failed; a close error changes neither */
            }
        }
    }

    /**
     * Resolve a path that does not exist yet. **Module-private and NEVER returned to a caller** —
     * the whole point of the gate-mediated shape is that this string does not leave the closure.
     */
    function resolveNew(request: unknown): { ok: true; actual: string; rel: string } | FenceRefusal {
        const moved = rootStillCanonical();
        if (moved) return moved;

        // ⚠ `createScreens`, NOT `readScreens` — the stream screen is unconditional here on every
        // host, and this call covers EVERY component of the request, so a colon anywhere in a
        // create path refuses before the parent is resolved or the leaf is joined.
        const lexical = lexicalStage(root, request, createScreens);
        if (isRefusal(lexical)) return lexical;

        const leaf = path.basename(lexical.spelled);
        // `lexicalStage` normalises, so `.` and `..` cannot survive as the final segment — but
        // asserting it here costs nothing and keeps this function's own precondition local
        // rather than borrowed from a caller three stages up.
        if (leaf === '' || leaf === '.' || leaf === '..') {
            return refuse('BAD_INPUT', 'the path does not name a file to create');
        }

        // The parent must EXIST, and it goes through the real fence to prove where it lands.
        // A leaf directly in the grant root has no parent to resolve: `root` is already the
        // canonical boundary and `rootStillCanonical` above just re-proved it.
        const parentSpelled = path.normalize(path.dirname(lexical.spelled));
        let parentActual: string;
        if (parentSpelled.toLowerCase() === root.toLowerCase()) {
            parentActual = root;
        } else {
            const parent = resolveInGrant(root, prim, path.relative(root, parentSpelled), createScreens);
            if (isRefusal(parent)) return parent;

            let parentStats: fs.Stats;
            try {
                parentStats = prim.lstat(parent.actual);
            } catch (error) {
                return mapFsError(error, parent.rel);
            }
            if (!parentStats.isDirectory()) {
                return refuse('NOT_A_DIRECTORY', `${parent.rel} is not a directory`);
            }
            // ⚠⚠ THE PARENT MUST BE WHERE IT WAS SPELLED, AND THAT IS THE WHOLE RULE — the fence
            // holds no rule about any particular directory, and the consumer's protected subtree
            // below appears as the incident that found this, never as the rule. Every check above
            // is a CONTAINMENT check, and an in-grant junction passes all of them: a junction
            // resolves inside the grant, so the walk is happy, the arbitration is happy, and the
            // write lands in a directory the caller never named. Measured 2026-09-04 against this
            // gate with the Scribe's real vault (`Notes -> Arc`): `Notes/planted.md` created
            // `vault/Arc/planted.md`, inside the user's immutable provenance layer. Containment is
            // not the property being asserted here — the property is that a write goes where the
            // caller said.
            //
            // ⚠ BEFORE THE LEAF IS JOINED AND PROBED, DELIBERATELY. Placing it after the probe
            // would let an existing leaf answer `EXISTS` first, and an ALREADY-PRESENT LEAF WOULD
            // THEN HIDE THE ALIAS — which is how a consumer's own config file, sitting in the
            // directory an aliased parent points at, kept that alias invisible to its config load.
            //
            // ⚠ `retained: null` IS HONEST AT THIS POINT: nothing has been opened on this path.
            // ⚠ THE DETAIL NAMES THE CALLER'S OWN SPELLING, NOT `parent.rel`. `parent.rel` is the
            // CANONICAL relative path — `Arc` for a `Notes -> Arc` junction — so using it would
            // make the refusal report a directory the caller never named, and would say out loud
            // where an alias points. Both are in-grant, so this is a legibility rule rather than a
            // containment one; the caller can only act on the name they wrote.
            if (_parentIsAliased(parentSpelled, parent.actual)) {
                return refuse(
                    'PARENT_ALIAS',
                    `${path.relative(root, parentSpelled)} resolves to a different directory than the one it names`
                );
            }
            parentActual = parent.actual;
        }

        const actual = path.join(parentActual, leaf);

        // ⚠⚠ THE LEAF IS PROBED FOR EXISTENCE, AND DELETING THIS PROBE WAS A MEASURED REGRESSION.
        //
        // `wx` refuses existing OBJECTS. It does not refuse existing NAMES, and on Windows those
        // are different things: `CreateFileW(CREATE_NEW)` without `FILE_FLAG_OPEN_REPARSE_POINT`
        // takes `STATUS_REPARSE` and retries the create AT THE SUBSTITUTED PATH with the
        // disposition preserved. So a leaf that is a link to something that does NOT exist is
        // followed, and the file is created wherever it points. POSIX mandates `EEXIST` for a
        // symlink leaf under `O_CREAT|O_EXCL` regardless of its target; libuv does not emulate it.
        //
        // Measured 2026-08-29 against this gate, twice:
        //   dangling file symlink -> outside/evil.md   createFileInGrant returned CREATED,
        //                                              and outside/evil.md contained the bytes
        //   dangling junction     -> outside/gone      returned a clean-looking NOT_A_FILE refusal
        //                                              having ALREADY created outside/gone
        // The junction case needs no symlink privilege, so it is reachable by anyone.
        //
        // ⚠ THIS IS NOT THE ENUMERATION SHAPE THIS FUNCTION REJECTED. It enumerates nothing and
        // asks nothing about WHAT the object is — only whether the name is already taken. `lstat`
        // succeeds on a dangling symlink and on a dangling junction alike, so both close here
        // without the fence knowing what a reparse tag is.
        //
        // ⚠ THE PROBE AND `wx` CLOSE DIFFERENT THINGS AND BOTH ARE LOAD-BEARING. The probe refuses
        // a name that is already taken; `wx` refuses an ORDINARY object appearing in the window
        // between this check and the open. Removing either re-opens what the other does not cover.
        //
        // ⚠ AND THE `wx` HALF IS NARROWER THAN "whatever appears in the window", which is what this
        // comment used to claim. A *dangling followed reparse name* inserted after the probe is
        // followed by the same `CREATE_NEW` behaviour described above — so that specific race is
        // NOT closed here. It is the documented TOCTOU limit, and it stays documented rather than
        // being described as covered; closing it needs an atomic no-follow create, which this
        // runtime does not offer on Windows.
        try {
            prim.lstat(actual);
            return refuse('EXISTS', `${path.relative(root, actual)} already exists`);
        } catch (error) {
            const code = (error as { code?: unknown } | null)?.code;
            // ENOENT is the ONLY outcome that may proceed — the name is genuinely free.
            if (code !== 'ENOENT') return mapFsError(error, path.relative(root, actual));
        }

        const escaped = _validateDerivedAbsolute(root, actual);
        if (escaped) return escaped;

        return Object.freeze({ ok: true as const, actual, rel: path.relative(root, actual) });
    }

    async function createFileInGrant(request: unknown, bytes: unknown): Promise<Created | WriteRefusal> {
        if (!Buffer.isBuffer(bytes)) return writeRefuse('BAD_INPUT', 'the content must be a Buffer', null);

        const target = resolveNew(request);
        // ⚠ RE-WRAPPED, NOT PASSED THROUGH. `resolveNew` returns a bare `FenceRefusal`, which has no
        // `retained` field; returning it unchanged is what made the first draft of this signature
        // unable to typecheck. Nothing was opened on this path, so the answer is `null`.
        if (isRefusal(target)) return asWriteRefusal(target, null);

        let fd: number;
        try {
            // ⚠ `wx`. An ORDINARY object appearing since the probe refuses here — symlink, hardlink,
            // junction, reparse point, device. This is the line the four escape classes die on.
            fd = prim.openExclusive(target.actual);
        } catch (error) {
            const code = (error as { code?: unknown } | null)?.code;
            // ⚠ `EEXIST` IS THE ONLY OPEN FAILURE THAT MAY CLAIM `null`, and the claim is narrow:
            // something else already owns the name, so THIS INVOCATION created nothing. Whatever
            // sits there is not ours to describe as retained.
            if (code === 'EEXIST') return writeRefuse('EXISTS', `${target.rel} already exists`, null);
            // ⚠ EVERY OTHER ERRNO IS INDETERMINATE, AND SAYING `null` HERE WOULD BE UNSOUND.
            // `openExclusive` is an injectable primitive; its contract offers no guarantee that a
            // throwing implementation materialised nothing. Until it promises that, the fence
            // cannot promise it either.
            return mapWriteError(error, target.rel, retained(target.rel));
        }
        // ⚠ THE FLAG RECORDS THE ATTEMPT, NEVER THE SUCCESS, AND IT IS SET BEFORE THE CALL.
        // Setting it after `prim.close(fd)` returns leaves it false when close THROWS, so the
        // `finally` closes the same descriptor a second time — acting on one the runtime may have
        // already released and reused. Closes per path, with it set before: pre-open refusals 0,
        // write-throw 1, short-write 1, successful close 1, throwing close 1.
        let closeAttempted = false;
        try {
            const written = prim.writeAll(fd, bytes);
            // ⚠ A SHORT WRITE IS A FAILURE, NOT A SMALLER SUCCESS. Reporting `ok` with a reduced
            // count is how a truncated file reaches a caller that has no way to notice — and the
            // truncated file STAYS, which is why the refusal has to say so.
            if (written !== bytes.length) {
                return writeRefuse(
                    'IO_ERROR',
                    `${target.rel} wrote ${written} of ${bytes.length} bytes`,
                    retained(target.rel)
                );
            }
            closeAttempted = true;
            try {
                prim.close(fd);
            } catch {
                // ⚠ THE CLOSE OUTCOME IS CONSULTED BEFORE ANY SUCCESS IS COMMITTED. A close or
                // writeback failure can mean the bytes never reached the disk, so an `ok` returned
                // above this point would be a claim the fence has no way to back.
                return writeRefuse(
                    'IO_ERROR',
                    `${target.rel} failed to close after writing`,
                    retained(target.rel)
                );
            }
            return Object.freeze({ ok: true as const, rel: target.rel, bytes: written });
        } catch (error) {
            return mapWriteError(error, target.rel, retained(target.rel));
        } finally {
            // The safety net for paths whose outcome is already decided and which never reached
            // the close above. Deliberately NOT a `return` from `finally`: that is legal JS and it
            // swallows in-flight exceptions.
            if (!closeAttempted) {
                try {
                    prim.close(fd);
                } catch {
                    /* the refusal above already decided the outcome; a close error cannot improve it */
                }
            }
        }
    }

    /**
     * Append ONE line to a file under the grant. See the `FsGate` declaration for the contract this
     * keeps and — more importantly — the two things it deliberately does NOT promise.
     *
     * ⚠ IT DOES NOT CALL `resolveNew`, AND THE REASON IS THE WHOLE DIFFERENCE BETWEEN THE TWO PATHS.
     * `resolveNew` refuses `EXISTS` the moment its leaf probe finds anything, which is correct for a
     * create and fatal for an append: the second append to a lineage file would refuse. So the
     * parent resolution and the derived-absolute check are performed HERE, by the same calls
     * `resolveNew` makes and in the same order, and only the leaf's disposition differs.
     */
    async function appendLineInGrant(request: unknown, line: unknown): Promise<Appended | WriteRefusal> {
        /* (1) THE LINE'S FRAMING, CHECKED WITHOUT PARSING IT. The fence has no opinion about the
         *     record's content — it is already serialised by the caller — but it must not append
         *     something that is not one whole line, because a file of LF-delimited records with a
         *     fragment or two records in one call is corrupt in a way no later reader can undo. */
        if (!Buffer.isBuffer(line)) return writeRefuse('BAD_INPUT', 'the line must be a Buffer', null);
        if (line.length === 0) return writeRefuse('BAD_INPUT', 'the line must not be empty', null);
        const firstLf = line.indexOf(0x0a);
        if (firstLf !== line.length - 1) {
            return writeRefuse(
                'BAD_INPUT',
                firstLf === -1
                    ? 'the line must end with a newline'
                    : 'the line must contain exactly one newline, at its end',
                null
            );
        }

        /* (2) THE ROOT, RE-PROVED. Identical to every other entry point, and that is the whole
         *     claim: `rootStillCanonical` proves object identity UNCONDITIONALLY (ruled
         *     2026-09-03), so this path inherits the closed same-path-replacement gap rather than
         *     carrying a weaker copy of the check. ⚠ THIS COMMENT SAID THE OPPOSITE UNTIL
         *     2026-09-08 — that the identity comparison sat inside a changed-spelling branch this
         *     path did not tighten. That branch is gone; see `rootStillCanonical`'s own note. */
        const moved = rootStillCanonical();
        if (moved) return asWriteRefusal(moved, null);

        /* (3) THE CREATE SCREENS, VERBATIM — `createScreens`, not `readScreens`. A colon anywhere in
         *     an append request is stream syntax on every host, for the same reason it is on the
         *     create path: the leaf is joined lexically below and never reaches the walk. */
        const lexical = lexicalStage(root, request, createScreens);
        if (isRefusal(lexical)) return asWriteRefusal(lexical, null);

        const leaf = path.basename(lexical.spelled);
        if (leaf === '' || leaf === '.' || leaf === '..') {
            return writeRefuse('BAD_INPUT', 'the path does not name a file to append to', null);
        }

        /* (4) THE PARENT, THROUGH THE REAL FENCE — `resolveNew`'s resolution, call for call. The
         *     parent must EXIST: this path creates no directory, so a Scribe whose `.wyrd/` is
         *     missing is refused rather than having one made for it. */
        const parentSpelled = path.normalize(path.dirname(lexical.spelled));
        let parentActual: string;
        if (parentSpelled.toLowerCase() === root.toLowerCase()) {
            parentActual = root;
        } else {
            // ⚠ THE LOCAL IS `appendParent`, NOT `parent`, AND THE NAME IS LOAD-BEARING RATHER THAN
            // STYLISTIC. The mutation matrix anchors on the compiled text of a line, and a line
            // spelled identically here and in `resolveNew` makes `M47`'s anchor ambiguous — a string
            // replace then mutates the FIRST occurrence only and leaves a half-applied mutant that
            // reports on neither path. The matrix's own preflight refuses on that, which is how this
            // was found; keeping the two copies textually distinct is what keeps both rows honest.
            const appendParent = resolveInGrant(root, prim, path.relative(root, parentSpelled), createScreens);
            if (isRefusal(appendParent)) return asWriteRefusal(appendParent, null);

            let appendParentStats: fs.Stats;
            try {
                appendParentStats = prim.lstat(appendParent.actual);
            } catch (error) {
                return mapWriteError(error, appendParent.rel, null);
            }
            if (!appendParentStats.isDirectory()) {
                return writeRefuse('NOT_A_DIRECTORY', `${appendParent.rel} is not a directory`, null);
            }
            // ⚠⚠ `resolveNew`'S PARENT-ALIAS COMPARISON, MIRRORED, AND IT GUARDS A SECOND ROUTE
            // RATHER THAN DUPLICATING THE FIRST. The append path's parent can be an alias with no
            // create involved at all, so it is a complete attack on its own — which is what the
            // consumer's fixed ledger path made concrete: measured 2026-09-04, with the Scribe's
            // `.wyrd` made a junction to `Arc`, an ordinary `Mage/answer.md` stamp returned
            // `stamp_ok: true` and wrote `lineage.jsonl` into the protected directory. This path
            // does not call `resolveNew` (see the header), so the comparison has to be duplicated
            // with the resolution it belongs to.
            //
            // ⚠ THE LOCAL ABOVE IS STILL `appendParent`, AND THE ARGUMENT SPELLING HERE MATTERS FOR
            // THE SAME REASON — the matrix anchors on compiled text, and a line spelled identically
            // in both copies makes a row's anchor ambiguous.
            if (_parentIsAliased(parentSpelled, appendParent.actual)) {
                return writeRefuse(
                    'PARENT_ALIAS',
                    `${path.relative(root, parentSpelled)} resolves to a different directory than the one it names`,
                    null
                );
            }
            parentActual = appendParent.actual;
        }

        /* (5) THE LEAF, JOINED AND RE-CONTAINED. Same check `resolveNew` performs on the same
         *     string: the parent is proven, but the join is arithmetic the containment predicate
         *     has not seen yet. */
        const actual = path.join(parentActual, leaf);
        const rel = path.relative(root, actual);
        const escaped = _validateDerivedAbsolute(root, actual);
        if (escaped) return asWriteRefusal(escaped, null);

        /* (6) THE LEAF PROBE, WHICH SELECTS THE MODE AND NOTHING ELSE.
         *
         * ⚠ ONLY `ENOENT` SELECTS CREATE. Every other errno is a refusal, exactly as it is on the
         * create path — a probe that cannot answer must not be read as "the name is free".
         *
         * ⚠ AN EXISTING LEAF MUST BE A REGULAR, NON-LINK FILE, AND THIS IS WHERE THE FOUR ESCAPE
         * CLASSES DIE. `createFileInGrant` gets that structurally from `wx`; an append cannot,
         * because it must open something that already exists. So the probe inspects — and it
         * inspects the LINK ITSELF (`lstat`, never `stat`), so a symlink, a junction, a dangling
         * link of either kind, a directory and a device all refuse here, before anything is opened. */
        let mode: 'existing' | 'exclusive-create';
        let observed: ObjectIdentity | null = null;
        try {
            const leafStats = prim.lstat(actual);
            if (leafStats.isSymbolicLink() || !leafStats.isFile()) {
                return writeRefuse('NOT_A_FILE', `${rel} is not a regular file`, null);
            }
            observed = exactIdentityOf(actual);
            if (observed === null) {
                // The name exists and the filesystem will not say what it is. Nothing below could
                // then prove the object did not change, so the honest answer is the same refusal.
                return writeRefuse(
                    'TARGET_CHANGED',
                    `${rel} could not be identified strongly enough to append to safely`,
                    null
                );
            }
            /* ⚠⚠ A LEAF WITH MORE THAN ONE NAME REFUSES, AND THIS IS THE ONE PLACE THE APPEND PATH
             * IS STRICTER THAN THE READ PATH RATHER THAN MATCHING IT.
             *
             * A pre-existing HARD LINK inside the grant whose other name is outside it defeats
             * every path-based check there is: `isSymbolicLink()` is false, `readlink` throws
             * `EINVAL`, `realpathNative` returns the in-grant name, and the dev/ino identity
             * binding below agrees with itself perfectly — because it IS one object, and the
             * in-grant name is a genuine name for it. The read path lives with that: it reads
             * through the alias, which discloses a file the grant does not cover. An append
             * WRITES through it, and that is an outside write, which is a different promise.
             *
             * The link count is the one reading that distinguishes them. It does not say WHERE the
             * other name is — it cannot, and no API here can — so this refuses on multiplicity
             * rather than on escape: a file with a second name ANYWHERE, in-grant siblings
             * included, is not appended to. That is deliberately conservative, and the cost is
             * stated in README.md's limits section beside the residual it leaves.
             *
             * ⚠ THE REASON IS `NOT_A_FILE`, NOT `DENIED`. `DENIED` is this module's mapping for
             * `EACCES`/`EPERM` and nothing else; a caller reading it concludes a permission
             * problem and may retry with more privilege, which would be wrong and would never
             * succeed. `NOT_A_FILE` is already the fence's own "the object under this name is not
             * something this path will append to" — it carries the directory case and the
             * symlink/non-regular case above — and the remedy it points a caller at, choose a
             * different name, is the correct one here.
             *
             * ⚠ CHECKED AGAIN AFTER THE OPEN, at step (8). A link created in the window between
             * this reading and the open would otherwise pass here and be written through. */
            if (observed.nlink > 1n) {
                return writeRefuse(
                    'NOT_A_FILE',
                    `${rel} has more than one name (${observed.nlink} links) and may alias a file outside the grant`,
                    null
                );
            }
            mode = 'existing';
        } catch (error) {
            const code = (error as { code?: unknown } | null)?.code;
            if (code !== 'ENOENT') return mapWriteError(error, rel, null);
            mode = 'exclusive-create';
        }

        /* (7) THE OPEN. `ax` when the probe found nothing, append-only-no-create when it found a
         *     file — and the two race outcomes are the same answer from opposite directions. */
        let fd: number;
        try {
            fd = prim.openAppend(actual, mode);
        } catch (error) {
            const code = (error as { code?: unknown } | null)?.code;
            if (mode === 'exclusive-create' && code === 'EEXIST') {
                return writeRefuse('TARGET_CHANGED', `${rel} appeared since it was observed to be absent`, null);
            }
            if (mode === 'existing' && code === 'ENOENT') {
                return writeRefuse('TARGET_CHANGED', `${rel} disappeared since it was observed`, null);
            }
            // ⚠ EVERY OTHER ERRNO IS INDETERMINATE, for `createFileInGrant`'s reason exactly:
            // `openAppend` is an injectable primitive and its contract makes no promise that a
            // throwing implementation materialised nothing.
            return mapWriteError(error, rel, retained(rel));
        }

        let appendCloseAttempted = false;
        try {
            /* (8) THE PRE-WRITE VERIFICATION — THREE READINGS THAT MUST AGREE, AND THIS IS THE ONLY
             *     PLACE THE DESCRIPTOR'S OWN IDENTITY IS AVAILABLE.
             *
             * `fstat` names the OBJECT this call will write to; the second `lstat` and the
             * `realpathNative` name whatever the NAME resolves to now. A name that has been
             * re-pointed since the open makes those disagree, which is the whole point — a
             * path-based check before the open cannot establish what the descriptor holds.
             *
             * ⚠ AND IT RUNS ON BOTH BRANCHES. On the existing branch it also compares against the
             * PRE-OPEN identity, which is the swap-after-probe case. On the create branch there is
             * no pre-open identity to compare — the leaf did not exist — so what is checked is that
             * the descriptor and the name still denote one regular, contained, non-link file. */
            let descriptorStats: fs.Stats;
            try {
                descriptorStats = prim.fstat(fd);
            } catch (error) {
                return mapWriteError(error, rel, retained(rel));
            }
            if (descriptorStats.isDirectory() || !descriptorStats.isFile()) {
                return writeRefuse('TARGET_CHANGED', `${rel} is not a regular file`, retained(rel));
            }

            let postStats: fs.Stats;
            try {
                postStats = prim.lstat(actual);
            } catch (error) {
                const code = (error as { code?: unknown } | null)?.code;
                if (code === 'ENOENT') {
                    return writeRefuse('TARGET_CHANGED', `${rel} disappeared after it was opened`, retained(rel));
                }
                return mapWriteError(error, rel, retained(rel));
            }
            if (postStats.isSymbolicLink() || !postStats.isFile()) {
                return writeRefuse('TARGET_CHANGED', `${rel} is no longer a regular file`, retained(rel));
            }

            const descriptorIdentity = exactIdentityOfDescriptor(fd);
            const postIdentity = exactIdentityOf(actual);
            if (!sameObject(descriptorIdentity, postIdentity)) {
                return writeRefuse(
                    'TARGET_CHANGED',
                    `${rel} does not name the object that was opened`,
                    retained(rel)
                );
            }
            if (mode === 'existing' && !sameObject(observed, descriptorIdentity)) {
                return writeRefuse(
                    'TARGET_CHANGED',
                    `${rel} is not the object that was observed before it was opened`,
                    retained(rel)
                );
            }

            /* ⚠⚠ THE LINK COUNT AGAIN, FROM THE DESCRIPTOR — the pre-open reading's other half.
             *
             * The pre-open check at (6) reads a NAME, and a `link()` issued between that reading
             * and the open would make the object multiply-named without the probe ever seeing it.
             * This reading comes off `fstat` of the descriptor the write will actually use, so it
             * is the object's own answer at the latest moment the fence can still refuse.
             *
             * ⚠ AND IT RUNS ON BOTH BRANCHES, unlike the pre-open identity comparison above. The
             * create branch has no pre-open reading to compare — the leaf did not exist — but a
             * name created by `ax` and hard-linked before this line is exactly as shared as one
             * that arrived that way, so the descriptor's count is checked regardless of how the
             * descriptor was obtained.
             *
             * ⚠ `descriptorIdentity` IS NULLABLE and a null one has already been refused above by
             * `sameObject`, which is false whenever either side is null — so reaching this line
             * means the reading exists. The guard is written to survive that changing anyway. */
            if (descriptorIdentity !== null && descriptorIdentity.nlink > 1n) {
                return writeRefuse(
                    'NOT_A_FILE',
                    `${rel} has more than one name (${descriptorIdentity.nlink} links) and may alias a file outside the grant`,
                    retained(rel)
                );
            }

            // ⚠ THE POST-OPEN REAL PATH, RE-CONTAINED. `realpathNative` follows every reparse point
            // and returns the on-disk casing, so this is the operating system's own answer to
            // "where did that name land" — the same arbitration the read path takes, applied to the
            // name after it was opened rather than before.
            let realPath: string;
            try {
                realPath = path.normalize(prim.realpathNative(actual));
            } catch (error) {
                return mapWriteError(error, rel, retained(rel));
            }
            const stillContained = _validateDerivedAbsolute(root, realPath);
            if (stillContained) return asWriteRefusal(stillContained, retained(rel));

            /* (9) ONE WRITE. NEVER RETRIED — see the primitive's own declaration for why a retry
             *     under `O_APPEND` is how this fence would itself cause the interleaving it exists
             *     to prevent. A short count is a failure, not a smaller success. */
            const written = prim.appendOnce(fd, line);
            if (written !== line.length) {
                return writeRefuse(
                    'IO_ERROR',
                    `${rel} appended ${written} of ${line.length} bytes`,
                    retained(rel)
                );
            }

            /* (10) THE CLOSE, CONSULTED BEFORE SUCCESS IS COMMITTED, with the attempt flag set
             *      BEFORE the call — `createFileInGrant`'s pattern, for its reason: setting it
             *      after leaves it false when close throws and the `finally` closes a descriptor
             *      the runtime may already have reused. */
            // ⚠ THE FLAG IS `appendCloseAttempted`, NOT `closeAttempted`, FOR THE MUTATION MATRIX'S
            // SAKE. `M68` and `M69` anchor on the create path's `closeAttempted = true;` followed by
            // its close block, and a byte-identical copy here made both anchors ambiguous — a string
            // replace mutates the first occurrence and leaves a partial mutant that grades nothing.
            // Found by the matrix's own uniqueness preflight, 2026-09-02.
            appendCloseAttempted = true;
            try {
                prim.close(fd);
            } catch {
                return writeRefuse('IO_ERROR', `${rel} failed to close after appending`, retained(rel));
            }
            return Object.freeze({ ok: true as const, rel, bytes: written });
        } catch (error) {
            return mapWriteError(error, rel, retained(rel));
        } finally {
            if (!appendCloseAttempted) {
                try {
                    prim.close(fd);
                } catch {
                    /* the refusal above already decided the outcome; a close error cannot improve it */
                }
            }
        }
    }

    const gate = Object.create(null) as FsGate;
    Object.defineProperties(gate, {
        readFileInGrant: { value: Object.freeze(readFileInGrant), enumerable: true },
        listDirInGrant: { value: Object.freeze(listDirInGrant), enumerable: true },
        listGrantRoot: { value: Object.freeze(listGrantRoot), enumerable: true },
        probeInGrant: { value: Object.freeze(probeInGrant), enumerable: true },
        disclosedRoot: { value: Object.freeze(disclosedRoot), enumerable: true },
        createFileInGrant: { value: Object.freeze(createFileInGrant), enumerable: true },
        appendLineInGrant: { value: Object.freeze(appendLineInGrant), enumerable: true },
        hashInGrant: { value: Object.freeze(hashInGrant), enumerable: true }
    });
    return Object.freeze(gate);
}
