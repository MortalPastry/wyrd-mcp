# wyrd-fence

The path-containment fence: one granted folder in, a fenced read-and-create surface out.

```js
import { createFsGate, isRefusal } from 'wyrd-fence';

const gate = createFsGate({ rawGrant: 'C:\\Users\\me\\Notes' });
if (isRefusal(gate)) throw new Error(`${gate.reason}: ${gate.detail}`);

const slice = await gate.readFileInGrant('subdir/note.md', 0, 64 * 1024);
```

The four operations that name a path (`readFileInGrant`, `listDirInGrant`, `hashInGrant`,
`createFileInGrant`) take an **untrusted request string** and fence it themselves. The other two
take no argument: `listGrantRoot()` lists the granted folder, and `disclosedRoot()` returns that
folder's canonical path as resolved when the gate was built. Nothing exported accepts an
already-resolved path, and apart from `disclosedRoot`, which returns the grant itself, no operation
returns an absolute one: a result names its target relative to the granted folder.
The filesystem primitives are module-private by default, and `createFsGate` also accepts a
`primitives` record, in which case the gate calls what it is given.

A refusal is a value, never a thrown error: `isRefusal` narrows it, and `reason` names the class
(`ESCAPES`, `CLAMPED`, `IS_ROOT`, `ELOOP`, `MISSING`, `STREAM_SYNTAX`, and the rest).

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
