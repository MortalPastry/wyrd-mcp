# wyrd-scribe

`wyrd-scribe` is a Tier-A MCP server for creating provenance-stamped Markdown pages inside one
folder you explicitly grant. Tier A is create-only: it can create a new page and append its lineage
record, but it cannot overwrite, rename, or delete a page, and it exposes no lineage-query tool.

## Installation and configuration

Install it with `npm install -g wyrd-scribe`.
The executable is `wyrd-scribe`. It communicates over stdio, so an MCP client configuration can
launch it directly:

```json
{
  "command": "wyrd-scribe",
  "args": ["--grant", "/absolute/path/to/folder"]
}
```

The granted folder may instead be supplied as `WYRD_GRANT`. An explicit `--grant` argument takes
precedence over `WYRD_GRANT`. `WYRD_SCRIBE_TIER` selects the tier and defaults to `A` when absent.
This build recognises tiers B and C but refuses to start with either because those tiers are not
implemented.

## `write_page`

The server exposes one tool with this exact input shape:

```json
{
  "path": "Notes/new-page.md",
  "content": "Page text\n",
  "derived_from": [
    {
      "source": "Sources/source.md",
      "spans": [
        { "offset": 0, "length": 9 },
        { "quote": "source text" },
        { "offset": 0, "length": 9, "quote": "source te" }
      ]
    }
  ]
}
```

`path` and every `derived_from[].source` are relative to the granted folder. Each span is exactly
one of: byte `offset` plus positive byte `length`; a non-empty, uniquely occurring `quote`; or all
three fields, in which case the bytes and quote must agree. Unknown input keys are refused.

The granted folder must already contain a `.wyrd/` directory. The Scribe does not create that
directory. On the first eligible write it mints `.wyrd/scribe.json` with this shape:

```json
{
  "schema": "wyrd.scribe/v1",
  "vault_id": "a server-minted UUID v4",
  "write_frontmatter": false
}
```

`write_frontmatter` defaults to `false`. Set it to `true` in the vault configuration to opt into a
`wyrd_lineage` key in created pages.

## Outcomes and recovery

A successful call creates the page first and then appends one LF-terminated JSON record to
`.wyrd/lineage.jsonl`. If the ledger append fails after page creation, the page is retained. The
result is `PAGE_WRITTEN_LEDGER_FAILED`, includes the created-page information and underlying
`cause`, and may report retained bytes. Inspect the retained page and ledger before repairing or
retrying; a retry at the same page path is create-only and will refuse `EXISTS`.

Each ledger line is a `wyrd.lineage/v1` object with `event: "page_written"`, a server-minted
`event_id`, `recorded_at`, the `wyrd-scribe` writer and version, the vault UUID, the created page's
path and SHA-256 content identity, and a `sources` array. Every source carries its grant-relative
path and content identity; every span records byte offset and length plus stored quote text, byte
counts, full-quote SHA-256, and whether the stored text was truncated.

When frontmatter projection is enabled, the created page receives one `wyrd_lineage` key containing
single-line JSON. The projection carries the schema, event, event ID, timestamp, writer, vault, and
sources. It deliberately omits the page identity and page content hash; `event_id` joins it to the
complete ledger record.

## Security boundary and limits

All granted-folder reads and writes go through `wyrd-fence`. The containment guarantees, hard-link
limits, residual filesystem races, and recovery consequences are defined in the Fence's
[authoritative Security boundary and limits section](https://github.com/MortalPastry/wyrd-mcp/blob/main/packages/wyrd-fence/README.md#security-boundary-and-limits).
The Scribe additionally refuses directly addressed `Arc/` targets and performs create-only page
writes. These controls are a scoped filesystem boundary, not an operating-system sandbox.

## Privacy and data flow

The server uses stdio only; it does not open a network transport. It reads the vault configuration
and cited source bytes inside the granted folder, and writes only the new page, the minted config
when needed, and the lineage ledger there. The connected MCP client receives tool metadata and the
structured result or refusal, including lineage and recovery information; it does not receive
absolute host paths or uncited source-file contents from the Scribe.

## Build and test from source

From the workspace root:

```sh
npm install
npm --workspace wyrd-fence run build
npm --workspace wyrd-mcp run build
npm --workspace wyrd-scribe test
```

The package's `test` lifecycle builds the Reader prerequisite before running the Scribe suite.

## License

Apache-2.0. See [LICENSE](LICENSE).
