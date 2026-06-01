# Contributing

Thanks for helping improve `mcp-config-lint`.

## Local Setup

```bash
npm install
npm test
npm run build
```

## Pull Request Checklist

- Add or update tests for changed behavior.
- Update `README.md` when rules, CLI options, or output formats change.
- Keep findings actionable and avoid claiming a config is malicious when it is only risky.
- Run `npm run check` before opening a PR.

## Rule Guidelines

Good rules are deterministic, explain the risk in plain language, and include a concrete remediation. Prefer a medium-severity warning when intent is ambiguous.
