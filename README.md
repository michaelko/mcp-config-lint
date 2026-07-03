# mcp-config-lint

Security lint MCP JSON and JSONC configuration files before a coding agent starts them.

`mcp-lint` looks for the risky patterns that make Model Context Protocol server configs hard to review: shell wrappers, remote install scripts, unpinned packages, hardcoded secrets, broad filesystem access, and insecure remote URLs.

## Install

```bash
npm install -g github:michaelko/mcp-config-lint
```

Run without installing:

```bash
npx github:michaelko/mcp-config-lint --format text
```

Or run from a checkout:

```bash
npm install
npm run build
npx mcp-lint
```

## Usage

```bash
mcp-lint
mcp-lint ~/.config/Claude/claude_desktop_config.json
mcp-lint . --format json
mcp-lint . --format sarif --fail-on medium
mcp-lint . --quiet
mcp-lint --help
mcp-lint --version
```

When no path is provided, `mcp-lint` discovers common files such as `mcp.json`, `.mcp.jsonc`, `.cursor/mcp.json`, `.vscode/mcp.json`, and `claude_desktop_config.json`.

Options:

| Option | Description |
| --- | --- |
| `--format text\|json\|sarif` | Output format. Defaults to `text`. |
| `--fail-on low\|medium\|high\|critical\|none` | Exit with status `1` when findings meet or exceed this severity. Defaults to `high`. |
| `--quiet`, `-q` | Suppress success and summary text output. |
| `--help`, `-h` | Show help. |
| `--version`, `-v` | Show version. |

## Example Output

```text
mcp-lint: 6 findings across 1 file.

[CRITICAL] MCP003 Remote fetch execution
  examples/unsafe.mcp.jsonc server=installer /mcpServers/installer/args
  Server appears to download remote content and execute it.
  Fix: Vendor the server, pin a package version, or install through a reviewed package manager step outside the MCP config.
```

## Rules

| Rule | Severity | What it checks |
| --- | --- | --- |
| MCP000 | Critical | Invalid JSON/JSONC syntax |
| MCP001 | High | Server without `command` or `url` |
| MCP002 | High/Critical | Shell-based execution such as `bash -c` |
| MCP003 | Critical | Remote fetch piped into a shell |
| MCP004 | High | Unpinned package, Git, or URL execution through `npx`, `uvx`, `bunx`, `pnpm`, or `yarn` |
| MCP005 | High | Unpinned container images |
| MCP006 | Critical | Hardcoded secrets in env or headers |
| MCP007 | High | Secret-like CLI arguments |
| MCP008 | High | Broad filesystem access such as `/`, `~`, `$HOME`, OS roots, or root container mounts |
| MCP009 | High | Non-local `http://` URLs |
| MCP010 | Low/Critical | Risky host environment expansion such as `$TOKEN`, `${SECRET}`, `%PASSWORD%`, or shell command substitution |

## Safe Configuration Patterns

The examples in `examples/safe-*.mcp.jsonc` show patterns intended to stay free of high-severity findings:

- Pin package-based servers, for example `@modelcontextprotocol/server-filesystem@2025.4.1`.
- Pin Git or URL package specs to a commit SHA, digest, or stable tag rather than a moving branch.
- Pin container images with stable tags or digests; avoid `latest`, `main`, and untagged images.
- Grant narrow repository-relative filesystem paths such as `./src`, `./docs`, or `./workspace`.
- Prefer HTTPS for remote MCP endpoints.
- Keep secrets out of config files. Use documented environment setup outside the MCP config instead of literal credentials.

## GitHub Actions

```yaml
name: MCP config lint

on:
  pull_request:
  push:
    branches: [main]

jobs:
  mcp-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: actions/setup-node@v6
        with:
          node-version: 22
      - run: npm install -g github:michaelko/mcp-config-lint
      - run: mcp-lint . --format sarif --fail-on high > mcp-lint.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcp-lint.sarif
```

## Design Principles

- No runtime dependencies.
- Deterministic output for CI.
- Human-readable text and machine-readable JSON/SARIF.
- Fails closed on malformed config files.
- Flags high-risk patterns, but keeps final approval with the maintainer.

## Development

```bash
npm install
npm test
npm run build
node dist/cli.js examples/unsafe.mcp.jsonc
```

## Contributing

Issues and pull requests are welcome. New rules should include a fixture, a test, and a README entry that explains the risk without overstating certainty.

## License

MIT
