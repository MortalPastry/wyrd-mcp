# wyrd

**An MCP server that exposes one folder to an AI client, read-only.**

Point Claude Code, Codex, Cursor, ChatGPT or Claude Desktop at a folder of notes and let it read
them. Wyrd checks every file request against the folder you grant.

If the folder happens to be a Mage vault, one organised into `Arc/` and `Mage/` layers, wyrd
notices and says which layers it found. If it is an ordinary folder of notes it works the same
way; vault structure is a detected bonus, never a requirement.

## What it can reach

**Wyrd serves the folder you name.** The only tool it registers is `read`. There is no tool that
writes, moves, renames or deletes, and the test suite asserts the tool list is exactly `read`.

⚠ **Grant a subfolder containing only what you mean to share.** There is no extension filter and
no ignore-file support, hidden entries are not excluded, and there is no cap on how much may be
read in total: any path inside the granted folder can be requested, `.env` and `.git/config`
included.

The one narrowing on the request side is a handful of **name spellings refused as input** before
anything is opened, so a file whose name takes one sits on the disk and cannot be requested: a name
beginning with a drive letter and a colon, such as `C:notes`, on every host — including the hosts
where that is an ordinary filename — and, on Windows, a component containing a colon (which names a
data stream rather than a file) or a reserved device name such as `NUL.md` or `COM1`. These are name
shapes, not a filter on kind, location or size.

What comes back is narrower than what can be requested, in two ways:

- A **directory** is refused (`NOT_A_FILE`). So `.git` and `.ssh` are refused as directories,
  while the files inside them are readable.
- Bytes that are not **valid UTF-8** are refused (`NOT_TEXT`) rather than returned altered. ⚠ The
  rule is over **the bytes of the requested slice, never the file extension**. A Latin-1 note is
  refused; so is any slice of a PDF or an image that contains a byte sequence UTF-8 forbids, which
  most such slices do. It is not a guarantee about a file type: a `.pdf`, `.png` or `.bin` whose
  requested slice happens to be valid UTF-8 comes back, and the opening slice of a PDF often is,
  because a PDF begins with ASCII header text. Read this as a property of bytes, not as a filter.

Both of those limit what is *readable*, not what is *reachable*. Treat the folder as the whole of
the restriction.

A path that resolves outside the granted folder is refused, and the refusal names the rule that
fired rather than pretending the file is absent.

### Known limits

- ⚠ **A hard link inside the granted folder makes the file it points at readable, wherever on the
  disk that file lives.** The link has to be there already; wyrd creates none. **Ordinary folder
  inspection will not show it as a link**: it looks like a normal file in Explorer, in Finder and
  in `ls`, with the ordinary size and the ordinary icon. Two practical answers:
    - **Grant a folder you freshly copied the files into.** Copying makes new files rather than
      new links, so a copied staging folder cannot carry one in. This is the answer that works on
      every platform and needs nothing special.
    - **Or look for them.** On macOS and Linux, `find <folder> -type f -links +1` lists every file
      with more than one name. On Windows there is no equivalent folder-wide scan: `fsutil
      hardlink list <file>` answers for one file at a time, which is only practical for a small
      folder.
- A path component **swapped between validation and opening** may be read instead of the one that
  was checked. That needs write access to the granted folder.
- Some **filesystem reparse points cannot be classified by this runtime**. ⚠ **This one needs no
  attacker**: an ordinary cloud-synced or WSL-mounted folder can contain one in normal use. A path
  that resolves through one is still checked against the granted folder, so it cannot be used to
  read outside it. What it can do is narrower: if such a component leads to a file outside the
  folder that is missing or unreadable, the refusal you get back distinguishes those two cases,
  which tells a caller one bit about a file outside the grant. The practical answer is to grant a
  plain local folder rather than one inside a cloud-sync root such as OneDrive, Dropbox or iCloud,
  or under a WSL mount.
- A refusal distinguishes *"outside the grant"* from *"does not exist"*, which tells a caller one
  bit about whether a file outside the folder exists.

This list is what is known, not a proof that nothing else exists. The limits were measured on
Windows; behaviour on macOS and Linux is reasoned but unmeasured, and the package declares no OS
restriction.

## Install

```
npm install -g wyrd-mcp
```

Node 20 or newer.

## Use

Wyrd refuses to start until you grant it a folder. Grant one on the command line or in the
environment:

```
wyrd-mcp --grant /absolute/path/to/notes
WYRD_GRANT=/absolute/path/to/notes wyrd-mcp
```

**Claude Code**: save as `wyrd.mcp.json` and pass `--mcp-config wyrd.mcp.json`:

```json
{
  "mcpServers": {
    "wyrd": {
      "command": "wyrd-mcp",
      "args": ["--grant", "/absolute/path/to/notes"]
    }
  }
}
```

**Codex**: MCP servers arrive as config overrides:

```
codex exec -c 'mcp_servers.wyrd.command="wyrd-mcp"' \
           -c 'mcp_servers.wyrd.args=["--grant","/absolute/path/to/notes"]' "..."
```

Other clients take a `command` and `args` in their own MCP configuration; the shape is the same.

## Changing the grant, revoking it, and what is kept

**To change it**, stop the server, edit the configuration, start it again. The granted folder is
fixed for the life of the process and no request can move it.

**Granting a symbolic link grants the folder it points at.** The link is resolved once, at start,
and the folder it resolved to is the boundary for the life of the process. Re-pointing the link
afterwards does not move the grant: the fence checks on every request that the granted path still
names the same folder, and once it does not, every request is refused until you restart the
server. This is what makes a vault symlinked into a cloud-sync folder work, and it is also why a
link is not a way to narrow a grant: the fence sees the real folder, whole.

**To revoke it**, stop the server *and* remove wyrd from your client's MCP configuration. Stopping
it alone may not be enough: a client that still has wyrd configured can start it again.

**Wyrd keeps nothing it read.** There is no cache, no index and no database; each request opens
the file on demand and hands back the bytes. The one thing that can persist on your disk is the
optional observation log below. What your AI client retains of the content it received is that
client's business, governed by its policy rather than by wyrd.

## What leaves your machine

**Nothing that wyrd sends.** It is a local stdio server: it reads files and hands them to the
client that launched it. It opens no network connection of its own and phones nothing home.

⚠ **What your AI client does with the content is between you and that client.** Wyrd cannot see or
control that, and no server on this side of the protocol can.

## The observation log, `WYRD_OBSERVE`

A local diagnostic, off unless you set the variable. Set it to a file path and wyrd records the
filesystem calls it makes and attempts to write them to that file when the process exits.

- It records **pathnames**, not file contents. A log can therefore expose absolute paths, your
  username, and where things are installed on your machine.
- It is written to **exactly the path you supply, and that path is not checked**. A UNC path, a
  network share or a cloud-synced folder is accepted and written to, so the log stays on your disk
  only if the path you named is on your disk and unsynchronised.
- Who else can read it is whatever your operating system's permissions on that file say.
- ⚠ **Do not put it inside the granted folder.** It would be readable through wyrd in a later
  session.
- The write is attempted at exit and a failure is silent. A missing log means "not written", not
  "nothing happened".

## Tests

```
npm test              # the full battery
npm run test:portable # the arms that need no symlink privilege
```

⚠ **`npm test` needs the Windows symlink privilege** (Developer Mode, or an elevated shell) because
most fence arms build link fixtures. Without it the suite **refuses to run rather than skipping**, so
a green never means "the arms that could run, ran."

`npm run test:portable` runs the arms that need no privilege and **states its own denominator**: how
many ran, how many were held back, and which. A green there is not a green fence; it is a partial run
that says so.

## Licence

MIT. See `LICENSE`.

---

*wyrd, Old English, "that which has become": the accumulated weight of what has already happened,
constraining what can happen next.*
