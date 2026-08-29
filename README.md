# wyrd

**An MCP server that exposes one folder of Markdown to an AI client, read-only.**

Point Claude Code, Codex, Cursor, ChatGPT or Claude Desktop at a folder of notes and let it read
them. Wyrd serves exactly the folder you grant and refuses everything else, and it tells you plainly
what that means before you grant anything.

If the folder happens to be a [Mage](https://github.com/MortalPastry/wyrd) vault, wyrd notices and
says which layers it found. If it is an ordinary folder of notes, it works the same way — vault
structure is a detected bonus, never a requirement.

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

**Claude Code** — save as `wyrd.mcp.json` and pass `--mcp-config wyrd.mcp.json`:

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

**Codex** — MCP servers arrive as config overrides:

```
codex exec -c 'mcp_servers.wyrd.command="wyrd-mcp"' \
           -c 'mcp_servers.wyrd.args=["--grant","/absolute/path/to/notes"]' "..."
```

Other clients take a `command` and `args` in their own MCP configuration; the shape is the same.

## What it can reach — read this before granting

**Wyrd serves the folder you name, read-only. It does not serve anything above it.**

⚠ **EVERY file inside that folder can be read**, of any type, including hidden files and directories
such as `.git`, `.env` and `.ssh`. There is no extension filter and no ignore-file support. **Grant a
subfolder containing only what you mean to share.**

A path that resolves outside the granted folder is refused, and the refusal names the rule that
fired rather than pretending the file is absent.

### Known limits, stated before you grant rather than after

A containment claim without its limits would be false, so:

- A **hard link** created inside the granted folder can reach a file outside it.
- A path component **swapped between validation and opening** may be read instead of the one
  checked. Both of these need write access to the granted folder.
- Some **filesystem reparse points are invisible to this runtime** and are not detected at all — not
  partially. ⚠ **This one needs no attacker**: an ordinary cloud-synced or WSL-mounted folder can
  contain one in normal use.
- A refusal distinguishes *"outside the grant"* from *"does not exist"*, which tells a caller one bit
  about whether a file outside the folder exists.

**This list is what is known, not a proof that nothing else exists.** The limits were measured on
Windows; behaviour on macOS and Linux is reasoned but unmeasured, and the package declares no OS
restriction.

## What leaves your machine

**Nothing, by wyrd.** It is a local stdio server: it reads files and hands them to the client that
launched it. It opens no network connection and phones nothing home.

⚠ **What your AI client does with the content is between you and that client.** Wyrd cannot see or
control that, and no server on this side of the protocol can.

## Tests

```
npm test              # the full battery
npm run test:portable # the arms that need no symlink privilege
```

⚠ **`npm test` needs the Windows symlink privilege** (Developer Mode, or an elevated shell) because
most fence arms build link fixtures. Without it the suite **refuses to run rather than skipping**, so
a green never means "the arms that could run, ran."

`npm run test:portable` runs the arms that need no privilege and **states its own denominator** — how
many ran, how many were held back, and which. A green there is not a green fence; it is a partial run
that says so.

## Licence

MIT. See `LICENSE`.

---

*wyrd — Old English, "that which has become": the accumulated weight of what has already happened,
constraining what can happen next.*
