# wyrd

**An MCP server that exposes one folder to an AI client, read-only.**

Point Claude Code, Codex, Cursor, ChatGPT or Claude Desktop at a folder of notes and let it read
them. Wyrd checks every file request against the folder you grant.

If the folder happens to be a Mage vault, one organised into `Arc/` and `Mage/` layers, wyrd
notices and says which layers it found. If it is an ordinary folder of notes it works the same
way; vault structure is a detected bonus, never a requirement.

## What it can reach

**Wyrd serves the folder you name.** It registers `read` and `search`. Neither tool
writes, moves, renames or deletes, and the test suite asserts both tools are listed.
The current two-tool wire surface is recorded in `test/v2-reader.golden.json`; the v1 golden
remains a historical record. One startup option changes who answers `search`; see
*An additional search backend module* below before you use it.

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

- The search path caches normalized terms using a file's modification time and
  logical size. A same-size edit that preserves modification time can stay stale indefinitely;
  another change to either value causes a fresh scan.

- `npm run measure:search` measures the core engine; `--end-to-end` includes MCP stdio dispatch.

- ⚠ **A hard link inside the granted folder makes the file it points at readable and searchable, wherever on the
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

Cloud placeholders are detected on Windows before the `read` tool opens content. A placeholder
read refuses by default and names the download it would trigger; `hydrate: true` permits that
one call to download it. Every `read` result includes `placeholder_detection`, a count and
fraction when measured, and a warning if the grant contains a known placeholder. Unsupported
platforms report `unavailable` with null counts rather than claiming none were found.
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

### HTTP and its Reader token

HTTP is opt-in and refuses to listen unless exactly one Reader-token source is configured. **It
listens on `127.0.0.1` unless you explicitly say otherwise** — see *Listening on a network
interface* below. Generate a fresh token with:

```
wyrd-mcp token
```

That command prints one random 256-bit base64url token to stdout and writes nothing. Supply the
token through `WYRD_READ_TOKEN`, or put only that token (with an optional final LF or CRLF) in a
regular file and pass its absolute path:

```
WYRD_READ_TOKEN=<Reader-token> wyrd-mcp --grant /absolute/path/to/notes --http 127.0.0.1:8787
wyrd-mcp --grant /absolute/path/to/notes --http 127.0.0.1:8787 --read-token-file /absolute/path/to/token
```

Every request must send `Authorization: Bearer <Reader-token>` to `POST /mcp`. Query strings on
`/mcp` are refused; never put a token in a URL.

On POSIX systems the token file must have no group or world permissions (`chmod 600` is the usual
setting). On Windows, its expected DACL grants access only to the account running Wyrd and any
administrators required by local policy, with access for other users and groups removed. **Wyrd has
not verified that Windows DACL**: Node exposes no trustworthy portable DACL check, so Wyrd checks
that the path can be read as a regular file and validates its contents, but the operator must check
the DACL.

### Listening on a network interface

**By default wyrd listens on `127.0.0.1` only, and no other machine can reach it.** To let another
device on your network connect, name a concrete interface address **and** add `--http-public`:

```
WYRD_READ_TOKEN=<Reader-token> wyrd-mcp --grant /absolute/path/to/notes --http 192.168.1.20:8787 --http-public
```

**Two separate acts are required on purpose.** A non-loopback address without `--http-public` is
refused (*"a non-loopback HTTP address requires `--http-public`"*), so exposure cannot happen through
a one-character edit to a config file.

**What is refused, and why:** `0.0.0.0` and `::` (a wildcard names every interface, including VPN,
container and virtual ones — name the one you mean); hostnames (they are not interface addresses);
scoped IPv6 such as `fe80::1%12`; multicast, broadcast and IPv4-mapped IPv6. `--http-public` on a
loopback address is refused as redundant, and the flag takes no value.

⚠ **Read the startup disclosure. It is the honest version of this section for your machine.** It
names the interface, and it states plainly what wyrd does **not** know: wyrd does not check what can
route to that address, and firewalls, VPN routes, container port publication and virtual-machine
forwarding can all deliver traffic to it from outside the network you are picturing. **The address
is checked once, at startup** — if the machine later joins a VPN or changes networks, wyrd will not
re-check it and will not warn you again.

⚠⚠ **Without TLS the Reader token travels in the clear and can be replayed by anyone who captures
it.** That is stated in the startup disclosure too. Treat a plain-HTTP network listener as suitable
only for a network you control and trust.

### HTTPS and a self-signed certificate

Generate a certificate and private key in the current directory:

```
wyrd-mcp cert --host reader.example.test
```

The host may be a hostname, IPv4 address or raw IPv6 address. IDNA hostnames are converted to their
ASCII form and printed back. The certificate also covers `127.0.0.1` and `localhost`. Wildcards,
URLs, ports, bracketed or scoped IPv6, wildcard, multicast, broadcast and IPv4-mapped addresses are
refused. Wyrd does no DNS lookup and does not claim the host belongs to this machine.

The result is a self-signed RSA-2048/SHA-256 certificate, valid for 397 days with a five-minute
clock-skew allowance. It is a CA with path length zero and has server-authentication EKU only; the
same certificate is deliberately both the trust anchor and the server certificate.

The command creates `wyrd-cert.pem` and `wyrd-key.pem`, refusing to overwrite either existing name,
including a link. It prints the certificate's fingerprint, SANs and validity dates as read from the
created certificate, followed by Windows, macOS, iOS/iPadOS and Android trust steps. **Those trust
steps change device trust; read them and verify the printed fingerprint on every device.**

On POSIX, the key is created with no group or world permission bits and checked after creation. On
Windows, it inherits the current directory's NTFS permissions; verify that ACL before using it. Two
filenames cannot be committed atomically on every supported filesystem. If the second create fails,
wyrd removes only an output it can verify this invocation created and names any rollback failure.

Supply both files to the listener:

```
WYRD_READ_TOKEN=<Reader-token> wyrd-mcp --grant /absolute/path/to/notes --http 192.168.1.20:8787 --http-public --tls-cert /absolute/path/to/wyrd-cert.pem --tls-key /absolute/path/to/wyrd-key.pem
```

`--tls-cert` and `--tls-key` are both-or-neither. Wyrd parses the certificate, verifies that the key
matches, and refuses expired or not-yet-valid material before binding. Under TLS the endpoint and
default Origin use `https://`, startup prints the certificate fingerprint and expiry, and the
plain-HTTP clear-text-token warning is absent. Plain HTTP remains available with neither TLS flag.

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

**Search uses a lazy in-memory cache of normalized terms and anchors.** It holds no raw text,
writes no search data to disk, and reopens a file when it needs an excerpt. Outside the explicit `cert` command, **the one thing
that can persist on your disk is the optional observation log** below; the generator separately
leaves the certificate pair you asked it to create. What your AI client retains of the content it
received is that client's business, governed by its policy rather than by wyrd.

## An additional search backend module (optional)

**By default wyrd answers `search` itself, and everything else on this page describes that.** You
can instead name one module file at startup, and wyrd will ask it to answer `search`:

```
npx wyrd-mcp --grant /absolute/path/to/notes --search-backend /absolute/path/to/module.mjs
```

`WYRD_SEARCH_BACKEND` does the same from the environment; the command line wins. The value must be
an absolute path to a file. If the module cannot be loaded or answers with the wrong shape, wyrd
refuses to start. It never falls back silently.

⚠ **A module you name runs inside the wyrd process with that process's permissions. It is not
confined to the granted folder.** Wyrd hands it only bounded reads of the granted folder and checks
every result it returns against that folder before showing it, but wyrd cannot stop the module from
opening other files, writing to disk, holding your text in memory or using the network. The
statements on this page about what search keeps, what is written and what leaves your machine are
statements about wyrd's built-in search only. Load a module only if you trust it the way you trust
wyrd itself, and read what it says about itself: wyrd prints the module's own statement at startup,
marked as the module's, next to its own.

Wyrd ships no such module and needs none.

## What leaves your machine

**Nothing that wyrd sends on its own.** In stdio mode it opens no network connection of its own: it
reads files and hands them to the client that launched it. In HTTP or HTTPS mode it listens for
connections that clients initiate. In every mode it phones nothing home and initiates no outbound
connection.

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
