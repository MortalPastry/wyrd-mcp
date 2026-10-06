# wyrd-fence

The path-containment fence: one granted folder in, a fenced read-and-create surface out.

```js
import { createFsGate, isRefusal } from 'wyrd-fence';

const gate = createFsGate({ rawGrant: 'C:\\Users\\me\\Notes' });
if (isRefusal(gate)) throw new Error(`${gate.reason}: ${gate.detail}`);

const slice = await gate.readFileInGrant('subdir/note.md', 0, 64 * 1024);
```

Every operation that names a path, including `readFileInGrant`, `fileMetadataInGrant` and
`hashInGrant`, takes an **untrusted request string** and fences it itself. `listGrantRoot()`
lists the granted folder, `grantPlaceholderSummary()` counts file placeholders without opening
content, and `disclosedRoot()` returns that folder's canonical path as resolved when the gate was built. Nothing exported accepts an
already-resolved path, and apart from `disclosedRoot`, which returns the grant itself, no operation
returns an absolute one: a result names its target relative to the granted folder.
The filesystem primitives are module-private by default, and `createFsGate` also accepts a
`primitives` record, in which case the gate calls what it is given.

A refusal is a value, never a thrown error: `isRefusal` narrows it, and `reason` names the class
(`ESCAPES`, `CLAMPED`, `IS_ROOT`, `ELOOP`, `MISSING`, `STREAM_SYNTAX`, and the rest).

On Windows, placeholder detection uses `FindFirstFileW` through a persistent built-in PowerShell
helper. It checks the offline and recall attributes and cloud reparse tags before a content open;
no native npm dependency is added. `readFileInGrant` refuses a detected placeholder unless its
fourth argument is `true`, an opt-in for that call only. `hashInGrant` refuses one before hashing.
`fileMetadataInGrant` returns grant-relative `rel` with forward slashes, logical byte `size`, `mtimeMs`,
`dehydrated` and `placeholder_detection`. The summary reports a count and fraction, or null
counts with `placeholder_detection: unavailable` if detection did not complete. On platforms
without a detector, reads remain possible but detection is reported unavailable. A path swapped
after metadata inspection and before open remains subject to the documented race below.
If PowerShell cannot load the helper (`Add-Type` fails), it reports that failure and exits.
Constrained Language Mode and application-control policies are common causes. Windows reads,
hashes, overwrites and appends of existing content refuse with `IO_ERROR` and that cause. Creating
a new file, including appending to an absent target, does not consult the helper because there is
no existing content to open. Search reports `placeholder_detection: unavailable` and no files.

## Security boundary and limits

`wyrd-fence` confines only filesystem calls made through its exported operations. It is not a
complete filesystem containment control.

- A pre-existing hard link inside the granted folder is genuinely an in-grant name for a file whose
  other name may be outside it. `isSymbolicLink()` is false, `readlink` throws `EINVAL`, and every
  canonicalization API correctly reports an in-grant path. No path-based fence can see it, so the
  read operations (`readFileInGrant`, `hashInGrant`) go through it and disclose a file the grant
  does not cover. `appendLineInGrant` does not, because writing through such a name is a write
  outside the grant rather than a read of one: see its own item below.
- A path component can be replaced after validation and before the operation opens it, so the
  operation can act on a different object than the one that was checked.
- The Windows placeholder check runs before opening content and again after the descriptor is
  opened, before its first read or append. A sync provider can dehydrate a file between the first
  check and the open; opening a recall-on-open file can itself start a download before the second
  check. It can also change state between the second path-based check and the content operation.
  Node does not expose the placeholder attributes of an open descriptor, so these intervals remain.
- Before each operation that touches the filesystem, the fence re-resolves the granted folder's
  canonical path and re-checks its object identity (matching device and inode numbers). It refuses
  if the folder is no longer reachable, if its identity differs, or if the filesystem cannot supply
  a usable identity. **A replacement at the same canonical path is therefore refused.** What
  remains is the interval between that re-check and opening the file, together with the
  component/leaf/link/rename races listed below. The root re-check also does not make append
  all-or-nothing: a refused append may have retained no line, a fragment, or the complete line, as
  the `appendLineInGrant` item and API documentation explain.
- Every successful resolution is passed through `realpath`, including one whose walk crossed a
  reparse tag this runtime cannot classify, and the result is checked against the grant. What that
  leaves open is narrower: if an unclassified intermediate tag leads to a missing or denied outside
  descendant, the walk refuses before that check, so the refusal class still distinguishes those two
  outcomes. Containment holds. What does not hold is the property that a refusal tells you nothing.
- The boundary is this module's exported operations, and anything reaching the filesystem by another
  route is outside it: direct `node:fs` or `node:fs/promises` calls, child processes, native addons,
  `process.getBuiltinModule`, `process.binding`. So is the `primitives` record `createFsGate`
  accepts. It is part of this package's public options, and every filesystem call the gate makes
  goes through the functions it was handed, so supplying primitives that do something other than
  what their names say puts the operation outside the boundary while it still reads as a gated call.
- A request component containing a colon is refused as stream syntax on Windows, and refused on
  every host when the operation is `createFileInGrant`. On a non-Windows host it is accepted for
  read, list and hash, where a colon is an ordinary filename character. Reserved device names
  (`CON`, `NUL`, `COM1` and the rest) are screened on Windows only, on both paths. A stream reached
  through a resolved link target, or through a route outside this module, is outside that lexical
  guard.
- A `createFileInGrant` that fails after the target was opened leaves what it wrote in place, by
  design, and never removes it. The refusal carries `retained`: `null` means this call created
  nothing, and a value means the target may or may not exist and its content may be absent, partial
  or written but unflushed. A caller that needs the path clean has to handle that itself.
- `appendLineInGrant` issues one write to a descriptor opened for append, and never retries it.
  **What that buys a caller: no interleaving, but no all-or-nothing.** Two processes appending whole
  lines cannot splice their bytes through each other; a full disk, a device error or an interrupted
  syscall can still leave a partial line, and the refusal says the write was short rather than
  hiding it. **So a reader of an appended file has to survive a trailing fragment** — that is the
  one obligation this method puts on its caller. Why the stronger wording would be false, why a
  retry is not offered, and the exact three-clause promise are stated once in
  `appendLineInGrant`'s doc comment in `dist/fsgate.d.ts`, which ships in this package and is what
  your editor shows on hover. That comment is the home, and this bullet is deliberately not a
  second copy of it.
- The append path checks that the file it opened is the file it looked at — comparing the
  descriptor's own device and inode numbers against the name's, before and after the open — and
  refuses when they disagree or when the filesystem will not supply them. That detects a
  replacement of the object under the name.
- A hard link is refused rather than appended to, by link count. `appendLineInGrant` reads the
  number of names the object has, once before it opens the leaf and once from the descriptor
  afterwards so a link created in between is caught, and refuses `NOT_A_FILE` when it exceeds one.
  What the count cannot say is *where* the other name is, so the refusal is on multiplicity: a file
  with a second name anywhere is refused, including one whose other name is also inside the granted
  folder. After the fence's last check, the real-path containment check that follows the descriptor's
  reading, and before the single write, the file can be renamed out of the folder or a folder above
  it renamed, and neither is seen; a hard link is the one case that can also slip in earlier, after
  the link-count reading, because adding a name does not move the opened one — the same class of
  window the create path documents for a dangling reparse point, and not closable in pure Node for
  the same reason: there
  is no share mode and no way to forbid `link()` or `rename()` against an open descriptor. It is not
  an outside write: the file was single-named and inside the folder when it was opened, so the
  appended bytes land in the file that was opened, never in a file that already existed outside.
  What the window buys is that those bytes can end up under a name the other party chose. The
  residual is the filesystem's own reporting — a hard link on a filesystem that does not supply a
  link count cannot
  be detected this way, and the read operations are unaffected either way.
- An `appendLineInGrant` whose leaf does not exist creates it with the same `CREATE_NEW` open
  `createFileInGrant` uses, and inherits that call's window: on Windows a dangling reparse point
  inserted at the leaf after the existence probe is followed, and the target is created outside the
  granted folder. The append then refuses at the post-open identity check, so no byte of the line is
  written, but the outside file exists and is empty. This is the same accepted window as the create
  path's, reached through a second entry point rather than a new one; closing it needs an atomic
  no-follow create, which is not available in pure Node on this platform.
- Component screening splits a request on both `/` and `\` on every host. The path that is actually
  resolved is built by joining the request onto the granted folder under the host's own path rules.
- `overwriteFileInGrant` requires a lowercase SHA-256 digest of the existing file's exact bytes and
  stages the replacement in the same directory. A missing target or mismatch seen at the first
  check refuses before any stage exists. A mismatch seen at the final recheck refuses without
  replacing the target, but the stage is retained and reported; its relative hint is a recovery
  clue, never authority to delete. The precondition protects cooperating Wyrd writers when they
  serialize publication and detects external edits at every check it makes; it is not an
  unconditional compare-and-swap. Concurrent Wyrd calls without serialization share the same race.
  Node has no atomic replace-if-digest operation: a non-Wyrd writer can change the target between
  the final recheck and rename, and a parent swap in that window can redirect the path-based rename.
  The stage's exclusive create also inherits the Windows dangling-reparse behavior documented above:
  a dangling reparse name occupying a generated stage name can be followed outside the grant.
  The post-open binding refuses before writing the replacement bytes, but an empty outside file
  can have been created.
  Refusals never delete a stage by pathname. `effect` reports this call's observed actions, not a
  promise about the disk after return.
  The generated stage name inherits the create path's Windows exclusive-create window described
  in the `appendLineInGrant` item above: a dangling reparse point raced into that name can leave
  an empty file outside the grant before the post-open check refuses. The first target hash read
  also inherits the read path's root-check-to-open window described in the root re-check and path
  component items above: a grant root swapped after the first check can make that read reach a file
  in the replacement directory before `ROOT_MOVED` is detected; it writes no bytes there.
  After rename, the operation checks the grant root, then samples the parent directory, target
  name identity and link count, the staged object's bytes through a descriptor opened before
  rename, the parent again, the target's real path for equality with the expected path, and the
  target name identity and link count again. It closes the held descriptor before returning `ok`.
  No file content is opened for reading or read through a path after rename; metadata and real-path
  queries still resolve paths. The descriptor byte guard compares identity, size and
  `mtimeMs` around its hash; a same-size rewrite that restores `mtimeMs` can pass that guard.
  These post-rename checks are separate, non-atomic samples, not a binding: a parent swapped and
  restored between samples can pass unnoticed. A separate path-based publication race can reach
  another file.
  Node has no handle-relative lookup (`openat`) or descriptor-to-final-path query to close that
  window. An `ok` result reports only that the individual samples passed; it cannot promise the
  target still names the staged object or that no other file was replaced. The window between
  post-rename samples joins the final-check-to-rename race and the later-swap race above.

This section is the authoritative account. The source header records how the limits were measured;
it does not restate them.

## Why it is its own package

Two products need the **same** fence code path: `wyrd-mcp` (the read-only MCP server) and the
provenance-stamping write surface beside it. A vendored second copy is a second thing to get
wrong, and seven review rounds went into getting one right. The shared package is what makes
"the same code path" a fact about resolution rather than a promise in a comment.

## Compatibility

The runtime surface is exactly `createFsGate` and `isRefusal`, pinned by an inventory arm. The
**type** surface is versioned too: `dist/fsgate.d.ts` is compared against a reviewed baseline, so
a change to any exported shape is a deliberate, reviewed act rather than a silent break.

MIT.
