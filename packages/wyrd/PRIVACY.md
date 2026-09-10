# Privacy

**wyrd, an MCP server that exposes one folder to an AI client, read-only.**

This document describes what wyrd does with your data. It is short because wyrd does very little.

---

## What wyrd collects

**Nothing by default.** There is no telemetry, no analytics, no crash reporting, no usage counter, no
update check, and no account. wyrd has no server to send anything to.

There is one opt-in exception, `WYRD_OBSERVE`, described under *What wyrd writes* below.

## What wyrd transmits

**Nothing that wyrd sends.** It is a local program that speaks the Model Context Protocol over
standard input and output to the client that launched it. It opens no network connection of its own.

That is a statement about wyrd's own sockets. It is not a statement about where your files end up,
and the two are not the same thing.

## ⚠ What that does NOT mean, and this is the part that matters

**wyrd's entire purpose is to hand the contents of your files to an AI client, and that client will
almost certainly send them to a model provider over the network.** Plainly:

- You point wyrd at a folder. Your AI client asks wyrd to read files in it. wyrd reads them from
  your disk and returns the bytes to that client.
- **What happens next is between you and that client**, and is governed by its privacy policy,
  not this one. If your client sends conversations to a hosted model, the file content wyrd
  returned goes with them.
- wyrd cannot see, control, or limit that, and **no server on this side of the protocol can.** This
  is a property of the protocol, not a shortcoming of this implementation.

**So the operative question is not what wyrd sends. It is which folder you grant it, and which
client you attach it to.** Grant deliberately.

## What wyrd can reach

**The one folder you name when you launch it.** That folder is called the grant. Every request is
checked against a path-containment fence before any file is opened.

⚠ **Any path inside the granted folder can be requested**, of any type, hidden entries included, not
only Markdown. There is no extension filter and no ignore-file support. If a folder contains
something you would not hand to an AI client, do not grant that folder.

The one narrowing on the request side is a handful of **name spellings refused as input** before
anything is opened, so a file whose name takes one sits on the disk and cannot be requested: a name
beginning with a drive letter and a colon, such as `C:notes`, on every host — including the hosts
where that is an ordinary filename — and, on Windows, a component containing a colon (which names a
data stream rather than a file) or a reserved device name such as `NUL.md` or `COM1`. Treat that as
a quirk of spelling rather than as protection: it narrows nothing you would be relying on.

What comes back is narrower than what can be requested: a directory is refused, and so are bytes
that are not valid UTF-8. That limits what is readable, not what is reachable, so the folder is
still the whole of the restriction.

The fence's known limits are listed in the README under *What it can reach*, and the running server
discloses them to your client at startup. The sharpest one for a reader of this document: **a hard
link that already exists inside the granted folder makes the file it points at readable, wherever
that file lives, and ordinary folder inspection will not show it as a link.**

## What wyrd writes

**No tool writes, moves, renames or deletes.** The server registers exactly one tool, `read`, and the
test suite asserts that the tool list is exactly `read`.

The process itself can write in exactly one case. If you set `WYRD_OBSERVE` to a file path, wyrd
records the filesystem calls it makes and attempts to write them to that file when the process
exits. It is off unless you set that variable, and:

- A record holds the name of the filesystem primitive that was called and its **first argument**.
  For most calls that argument is a **pathname**. For a call made against an already-open file it
  is a descriptor rather than a name, recorded as `<fd 3>`; one record is an `instrumentation-ready`
  marker with an empty argument, written so a log that exists but saw nothing is distinguishable
  from one whose hook never armed. **No record holds file contents.**
- Because it records pathnames, the log can expose absolute paths, your username, and where things
  are installed on your machine.
- It is written to **exactly the path you supply, and that path is not checked**. A UNC path, a
  network share or a cloud-synced folder is accepted and written to. The log stays on your disk
  only if the path you named is on your disk and unsynchronised.
- Who else can read it is whatever your operating system's permissions on that file say.
- ⚠ **Do not put it inside the granted folder.** It would be readable through wyrd in a later
  session.
- The write is attempted at exit and a failure is silent, so a missing log means "not written",
  not "nothing happened".

## What wyrd keeps

**Nothing it read.** There is no cache, no index and no database; each request opens the file on
demand and hands back the bytes. The granted folder is fixed for the life of the process, so
changing it means stopping the server, editing the configuration and starting it again. Revoking it
means stopping the server *and* removing wyrd from your client's MCP configuration, because a client
that still has wyrd configured can start it again.

The optional observation log is the one thing wyrd can leave behind. What your AI client retains of
the content it received is that client's business, as above.

## Children, and who this is for

wyrd is a developer tool with no user accounts and no age gate. It has no server and sends nothing
anywhere, so we hold no data about children or about anyone else.

## Changes

This policy travels in the package and in the repository. If it changes, it changes there, with the
version that carries the change. There is no separate hosted copy that could quietly diverge.

## Contact

Security reports and privacy questions: **support@wyrdmcp.com**.

⚠ **What that address is today:** a forwarding address monitored by one person, not a staffed
support desk, and it carries no response-time commitment. It is the right place to send a security
report, and you should expect a human rather than a process.

---

*Last updated 2026-09-01.*
