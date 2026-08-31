# Privacy

**wyrd — an MCP server that exposes one folder of Markdown to an AI client, read-only.**

This document describes what wyrd does with your data. It is short because wyrd does very little.

---

## What wyrd collects

**Nothing.** There is no telemetry, no analytics, no crash reporting, no usage counter, no update
check, and no account. wyrd has no server to send anything to.

## What wyrd transmits

**Nothing, by wyrd.** It is a local program that speaks the Model Context Protocol over standard
input and output to the client that launched it. It opens no network connection of its own.

## ⚠ What that does NOT mean — read this part

**wyrd's entire purpose is to hand the contents of your files to an AI client, and that client will
almost certainly send them to a model provider over the network.**

A privacy policy that stopped at *"we transmit nothing"* would be true and misleading. So, plainly:

- You point wyrd at a folder. Your AI client asks wyrd to read files in it. wyrd reads them from
  your disk and returns the bytes to that client.
- **What happens next is between you and that client**, and is governed by its privacy policy — not
  this one. If your client sends conversations to a hosted model, the file content wyrd returned
  goes with them.
- wyrd cannot see, control, or limit that, and **no server on this side of the protocol can.** This
  is a property of the protocol, not a shortcoming of this implementation.

**So the operative question is not what wyrd sends. It is which folder you grant it, and which
client you attach it to.** Grant deliberately.

## What wyrd can reach

**The one folder you name when you launch it, and nothing above it.** That folder is called the
grant. Every request is checked against a path-containment fence before any file is opened.

⚠ **Every file inside the granted folder can be read** — of any type, including hidden files and
directories, not only Markdown. If a folder contains something you would not hand to an AI client,
do not grant that folder.

**The known limits of that fence are published, not buried** — they are listed in the README under
*What it can reach*, and the running server discloses them to your client at startup. They are
stated as what is known rather than as a proof that nothing else exists.

## What wyrd writes

**Nothing.** The server registers exactly one tool, `read`. There is no tool that writes, moves,
renames or deletes, and the test suite asserts that the tool list is exactly `read`.

## Children, and who this is for

wyrd is a developer tool with no user accounts and no age gate. It collects nothing from anyone, so
it holds no data about children or anyone else.

## Changes

This policy travels in the package and in the repository. If it changes, it changes there, with the
version that carries the change. There is no separate hosted copy that could quietly diverge.

## Contact

Security reports and privacy questions: **support@wyrdmcp.com**.

⚠ **An honest statement of what that address is today:** it is a forwarding address monitored by one
person, not a staffed support desk, and it carries no response-time commitment. It is the right
place to send a security report, and you should expect a human rather than a process.

---

*Last updated 2026-08-31.*
