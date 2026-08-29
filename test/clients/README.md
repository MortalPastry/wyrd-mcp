# Real-client probes

**The arms in `test/` drive wyrd through the SDK's own client. These probes drive it through clients
that are not ours.** That distinction is the whole point: the SDK client proves the protocol
exchange, and only an independent client implementation proves the *product surface* — what a driving
model actually receives and can act on.

⚠ **These are not unit arms and they are not in `npm test`.** They need a real client binary and a
real model, so they are non-deterministic, cost tokens, and cannot assert. **They are measurements,
and a human reads the output.** Run them when the disclosure text, the tool description, or the
refusal strings change — those are the three things a client can silently mangle.

⚠ **Grant a disposable folder, never a real one.** These probes hand a folder to a third-party model.
`wyrd.mcp.json` in this directory has a placeholder where the grant path goes; fill it with something
you would not mind a stranger reading.

---

## Claude Code

```
claude -p --mcp-config test/clients/wyrd.mcp.json --strict-mcp-config \
       --allowedTools "mcp__wyrd" --model sonnet "<probe prompt>"
```

`--strict-mcp-config` is load-bearing: without it the session also loads whatever MCP configuration
is already on the machine, and you are no longer measuring wyrd alone.

## Codex

```
codex exec -c 'mcp_servers.wyrd.command="node"' \
           -c 'mcp_servers.wyrd.args=["<abs>/dist/index.js","--grant","<abs>/<disposable folder>"]' \
           "<probe prompt>"
```

Codex does not read `wyrd.mcp.json` — it takes MCP servers as config overrides, so the paths are
repeated inline. Keep the two in sync by hand; nothing checks them.

⚠ **KNOWN LIMITATION: `codex exec` cannot execute an MCP tool call.** Every call returns
`user cancelled MCP tool call`, under both `read-only` and `workspace-write` sandboxes, with approval
set to never. **This is Codex's approval layer, NOT a wyrd refusal, and it must never be recorded as
one.** So the Codex probe measures the *metadata* channels only — instructions and tool description —
and the read and refusal paths need a client that can actually call.

---

## What a probe prompt should ask for

Write the prompt to make the model a **witness, not an assistant.** The ones that have earned their
place:

- Tell it to report only what it observes and to write `NOT PRESENT` rather than guess. Without this
  a helpful model reconstructs plausible text and you measure its politeness.
- Ask for the **final** sentence of a text, not the first. A truncated channel can always produce an
  opening; only the tail proves arrival.
- Ask a **targeted yes/no on a phrase buried deep in the text.** A phrase from the last line of the
  known-limits paragraph works well.
- Ask whether a tool's description is available **without searching for it.** That question is what
  caught deferred tool loading.
- Ask for refusal text **verbatim and in full**, then diff it against `src/server.ts` yourself.

## What these probes have found

In one sitting they established that a tool description does not always reach the model at all — one
client deferred it by name only, and returned it truncated mid-sentence when searched for, cutting
the paragraph that makes the containment claim honest. Meanwhile `initialize.instructions`, which was
assumed to reach nobody, arrived complete on both clients tested.

**Neither disclosure channel has a floor. Both must carry the load-bearing text independently.**

No unit arm could have found that, because no unit arm looks at what a client does with what the
server sends.
