# Install the Wyrd Reader for a user

Requires Node 20 or newer. The published npm package `wyrd-mcp` is the whole install.
Do not clone the repository, build from source, or write probe scripts.
The Reader serves exactly one folder and provides two tools: `read` and `search`.

1. Ask the user for the absolute path of the ONE folder to share. Explain that anything
   inside it becomes readable, subject to the documented read limits. Recommend a subfolder
   holding only what they mean to share. See the [Reader README](packages/wyrd/README.md)
   for the security boundary and known limits, including refused directories and invalid
   UTF-8 bytes. The Reader server refuses to start without a grant.
2. Locate the client's MCP settings file. Add this entry, preserving existing settings,
   and replace `<absolute folder>` with the path the user chose:

```json
{
  "mcpServers": {
    "wyrd": {
      "command": "npx",
      "args": ["-y", "wyrd-mcp", "--grant", "<absolute folder>"]
    }
  }
}
```

Codex reads TOML instead. Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.wyrd]
command = "npx"
args = ["-y", "wyrd-mcp", "--grant", "<absolute folder>"]
```

For Claude Code, the one-line equivalent is
`claude mcp add wyrd -- npx -y wyrd-mcp --grant "<absolute folder>"`.

In JSON, use forward slashes in Windows paths or escape each backslash as `\\`.
On Windows, if a desktop client cannot start the server, use `"command": "cmd"` and
prepend `"/c", "npx"` to `args`, keeping the remaining arguments as shown.

3. Save the settings and restart or reload the client. Fully quit and reopen a client
   that reads its settings only at startup.
4. Verify through the client: call `search` for a word the user knows is in their notes,
   then call `read` on the best matching path. Each read opens with a header naming the
   file and the bytes returned, followed by the file's text. Example:

```text
wyrd read notes/kettle.md — bytes 0..37 of 37 · truncated: false
```
