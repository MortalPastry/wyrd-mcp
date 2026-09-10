# Wyrd

Wyrd is an MCP server that exposes one granted folder to AI clients, read-only, behind a
path-containment fence with documented limits.

This source repository contains two npm workspaces:

- [`packages/wyrd`](packages/wyrd) — the `wyrd-mcp` server
- [`packages/wyrd-fence`](packages/wyrd-fence) — the independently published containment fence

Build both packages from a clean checkout with:

```sh
npm install --ignore-scripts --package-lock=false
npm run build
```

The packages’ READMEs document usage, security boundaries, and test surfaces. Published npm
artifacts remain the supported installation path. This repository exposes the two packages’ source
and configuration for inspection and building; dependencies resolve within their declared ranges.
