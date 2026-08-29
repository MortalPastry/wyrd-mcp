import fs from 'node:fs';
import path from 'node:path';

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
 * ⛔ NOT COVERED, BY CONSTRUCTION — the companion to what this module does guarantee.
 *
 * 1. HARDLINKS. `mklink /H` needs no privilege. Under NTFS the link genuinely IS an in-grant
 *    name for the file: `isSymbolicLink()` is false, `readlink` throws EINVAL, and every
 *    canonicalization API correctly reports an in-grant path. No path-based fence can see it.
 *
 * 2. TOCTOU. Validate a path, replace a component with a junction before the open. Node on
 *    Windows has no `openat`; measurement found no `*at` family in the binding at all.
 *
 * 3. THE ROOT-SWAP WINDOW. `rootStillCanonical()` narrows it; a swap landing between that check
 *    and the open is unhandled. Same missing primitive as (2).
 *
 * 4. ⚠⚠ REPARSE TAGS `lstat` DOES NOT MAP TO `isSymbolicLink()` — WSL `LX_SYMLINK`, Windows
 *    Container `WCI`, `APPEXECLINK`, and cloud-provider tags. If Win32 traversal follows one of
 *    these, this module never sees a link: `sawReparse` stays false, the arbitration never runs,
 *    and the open takes the spelled path. THIS IS THE ONE CLASS THAT WOULD DEFEAT THE
 *    ARBITRATION ENTIRELY rather than merely diverge from it — every other shape is caught
 *    because `realpathNative` is consulted, and here it never is. Creating one needs privileged
 *    or platform-specific tooling (WSL, a container runtime, a cloud-sync provider), so it is
 *    UNTESTED here rather than tested-and-passing. Do not read the differential fuzz results as
 *    covering it: every shape in them is one `isSymbolicLink()` reports.
 *
 * 5. Alternate data streams, and any bypass reaching the filesystem outside this module
 *    (`process.getBuiltinModule`, `process.binding`, child processes, native addons).
 *
 * (1) to (3) all need LOCAL WRITE ACCESS after startup, which is outside the stated threat model
 * — a driving model that is confidently wrong or content-steered, not a local writer. (4) does
 * not: a vault under a cloud-sync provider or a WSL mount could hold one with nobody acting
 * adversarially at all.
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

/** Windows drive-relative input: `C:notes`. `path.isAbsolute` returns FALSE for these. */
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
    | 'IO_ERROR';

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

export interface FsGate {
    readFileInGrant(request: string, offset: number, limit: number): Promise<Slice | FenceRefusal>;
    listDirInGrant(request: string): Promise<Entry[] | FenceRefusal>;
    listGrantRoot(): Promise<Entry[] | FenceRefusal>;
    disclosedRoot(): string;
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
}

export interface CreateFsGateOptions {
    readonly rawGrant: string;
    readonly primitives?: Primitives;
}

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

const DEFAULT_PRIMITIVES: Primitives = {
    open: _open,
    close: _close,
    read: _read,
    fstat: _fstat,
    lstat: _lstat,
    readlink: _readlink,
    realpathNative: _realpathNative,
    readdir: _readdir
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
            return refuse('DENIED', `permission denied reading ${what}`);
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

/* ---------------------------------- *
 * Stage (a) — lexical, no I/O         *
 * ---------------------------------- */

interface LexicalOk {
    readonly ok: true;
    readonly rel: string;
    readonly spelled: string;
}

/**
 * Stage (a). Nothing here touches the filesystem, so every refusal it produces has probed
 * nothing — which is what makes the outside-existence oracle closed for these inputs.
 */
function lexicalStage(root: string, request: unknown): LexicalOk | FenceRefusal {
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
    const rootPrefix = path.parse(root).root;
    let depth = root.slice(rootPrefix.length).split(path.sep).filter(s => s.length > 0).length;
    for (const segment of request.split(/[\\/]/)) {
        if (segment === '' || segment === '.') continue;
        if (segment === '..') {
            depth -= 1;
            if (depth < 0) return refuse('CLAMPED', 'the path climbs past the root of the volume');
        } else {
            depth += 1;
        }
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
    request: unknown
): { ok: true; actual: string; rel: string } | FenceRefusal {
    const lexical = lexicalStage(root, request);
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
    if (context.sawReparse || isRefusal(walked)) {
        // ⚠ DELIBERATELY after ANY reparse point, not only after the two readings disagree.
        //
        // When they disagree the walk picks whichever stays inside — a GUESS, because the
        // choice depends on the reparse tag of an earlier component and Node exposes no tag.
        // Making the operating system authoritative whenever any link was involved is what
        // makes that guess safe: the walk then only has to be CONSERVATIVE (refuse what
        // plainly escapes), never EXACT. Narrowing this to the disagreement case would put the
        // guess back on the serving path, which is the class of defect that killed five
        // revisions. The cost is one realpath call, and only on link-bearing paths.
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
                    // the errno. That is an outside-existence oracle, which §6 claims is closed.
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

function entryKind(dirent: fs.Dirent): Entry['kind'] {
    if (dirent.isSymbolicLink()) return 'link';
    if (dirent.isDirectory()) return 'directory';
    if (dirent.isFile()) return 'file';
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
    const supplied = options.primitives;
    const openFn = supplied?.open ?? DEFAULT_PRIMITIVES.open;
    const closeFn = supplied?.close ?? DEFAULT_PRIMITIVES.close;
    const readFn = supplied?.read ?? DEFAULT_PRIMITIVES.read;
    const fstatFn = supplied?.fstat ?? DEFAULT_PRIMITIVES.fstat;
    const lstatFn = supplied?.lstat ?? DEFAULT_PRIMITIVES.lstat;
    const readlinkFn = supplied?.readlink ?? DEFAULT_PRIMITIVES.readlink;
    const realpathNativeFn = supplied?.realpathNative ?? DEFAULT_PRIMITIVES.realpathNative;
    const readdirFn = supplied?.readdir ?? DEFAULT_PRIMITIVES.readdir;

    const unbound: Primitives = {
        open: (target, flags) => Reflect.apply(openFn, undefined, [target, flags]) as number,
        close: fd => Reflect.apply(closeFn, undefined, [fd]) as void,
        read: (fd, buffer, offset, length, position) =>
            Reflect.apply(readFn, undefined, [fd, buffer, offset, length, position]) as number,
        fstat: fd => Reflect.apply(fstatFn, undefined, [fd]) as fs.Stats,
        lstat: target => Reflect.apply(lstatFn, undefined, [target]) as fs.Stats,
        readlink: target => Reflect.apply(readlinkFn, undefined, [target]) as string,
        realpathNative: target => Reflect.apply(realpathNativeFn, undefined, [target]) as string,
        readdir: target => Reflect.apply(readdirFn, undefined, [target]) as fs.Dirent[]
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
     * It belongs in §6(3)'s not-covered list beside TOCTOU and hardlinks. Like both of those it
     * needs LOCAL WRITE ACCESS after startup, which is outside the stated threat model — a
     * driving model that is confidently wrong or content-steered, not a local writer.
     *
     * It names only the canonical root, which is in-grant, so §6(1) is unaffected.
     */
    function rootStillCanonical(): FenceRefusal | null {
        let current: string;
        try {
            current = path.normalize(prim.realpathNative(root));
        } catch {
            return refuse('ROOT_MOVED', 'the granted folder is no longer reachable');
        }
        if (current.toLowerCase() !== root.toLowerCase()) {
            return refuse('ROOT_MOVED', 'the granted folder has been replaced since startup');
        }
        return null;
    }

    async function readFileInGrant(request: string, offset: number, limit: number): Promise<Slice | FenceRefusal> {
        if (!Number.isSafeInteger(offset) || offset < 0) return refuse('BAD_INPUT', 'offset must be a non-negative integer');
        if (!Number.isSafeInteger(limit) || limit <= 0) return refuse('BAD_INPUT', 'limit must be a positive integer');
        const window = Math.min(limit, MAX_LIMIT);

        const moved = rootStillCanonical();
        if (moved) return moved;

        const resolved = resolveInGrant(root, prim, request);
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

        const resolved = resolveInGrant(root, prim, request);
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

    function disclosedRoot(): string {
        return root;
    }

    const gate = Object.create(null) as FsGate;
    Object.defineProperties(gate, {
        readFileInGrant: { value: Object.freeze(readFileInGrant), enumerable: true },
        listDirInGrant: { value: Object.freeze(listDirInGrant), enumerable: true },
        listGrantRoot: { value: Object.freeze(listGrantRoot), enumerable: true },
        disclosedRoot: { value: Object.freeze(disclosedRoot), enumerable: true }
    });
    return Object.freeze(gate);
}
