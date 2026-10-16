# Wyrd

Wyrd is a collection of MCP servers and their containment library. Each server operates over one
folder explicitly granted by the user and applies the library's documented path boundary.

## Install the Reader

The published npm package is `wyrd-mcp`. For Claude Code, run:

```sh
claude mcp add wyrd -- npx -y wyrd-mcp --grant "<absolute folder>"
```

See [the Reader README](packages/wyrd/README.md) for other clients, the security boundary,
and known limits. AI agents should follow [llms-install.md](llms-install.md).

## Build from source

Build the workspaces from a clean checkout with:

```sh
npm install --ignore-scripts --package-lock=false
npm run build
```

Each package's README documents that package's usage, behavior, security boundary, and test
surface. Its package-local `LICENSE` defines its license. The repository scaffold itself is MIT.
Published npm artifacts remain the supported installation path; this repository exposes source and
configuration for inspection and building, with dependencies resolving inside their declared
ranges.
