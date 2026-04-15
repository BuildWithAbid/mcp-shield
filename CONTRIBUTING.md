# Contributing to mcp-shield

Thanks for your interest in improving MCP security! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/BuildWithAbid/mcp-shield.git
cd mcp-shield
npm install
npm run build
npm test
```

## Project Structure

```
src/
  index.ts            # CLI entry point (Commander.js)
  mcp-server.ts       # MCP server mode (stdio transport)
  types.ts            # Shared types, interfaces, constants
  scanner/
    index.ts          # Orchestrator — collects files, runs all scanners
    secrets-leak.ts   # Hardcoded secrets detection
    dependency-audit.ts # npm audit wrapper
    tool-description.ts # Prompt injection detection
    permission-check.ts # Overly broad tool schemas
    rug-pull-detect.ts  # Mutable tool descriptions
    transport-security.ts # HTTP, CORS, TLS issues
    supply-chain.ts     # Typosquatting, install scripts
  reporter/
    terminal.ts       # Color terminal output
    markdown.ts       # Markdown report
    json.ts           # JSON output
  utils/
    patterns.ts       # Regex patterns for all scanners
    ast-helpers.ts    # File collection, parsing helpers
tests/
  fixtures/           # Vulnerable and safe test servers
  scanner.test.ts     # Scanner unit tests
  reporter.test.ts    # Reporter unit tests
```

## Adding a New Scanner

1. Create `src/scanner/your-scanner.ts` implementing the `Scanner` interface
2. Add your scanner name to `ScannerName` in `src/types.ts`
3. Add display names to `SCANNER_DISPLAY_NAMES` in `src/types.ts`
4. Register it in `src/scanner/index.ts`
5. Add tests in `tests/scanner.test.ts`
6. Add test fixtures if needed

## Adding Detection Patterns

Detection patterns live in `src/utils/patterns.ts`. To add a new secret pattern, injection pattern, or schema check, add it to the appropriate array with a name, regex, and severity.

## Running Tests

```bash
npm test            # Run all tests once
npm run test:watch  # Watch mode
npm run lint        # Type-check without emitting
```

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new functionality
- Make sure `npm test` and `npm run lint` pass
- Use clear commit messages

## Areas Where Help Is Needed

- **New detection patterns** — more prompt injection techniques, secret formats, dangerous APIs
- **Live server scanning** — connecting to running MCP servers to test tool responses
- **PyPI / pip support** — extending to Python MCP servers
- **CI/CD integrations** — GitHub Actions, pre-commit hooks
- **Documentation** — guides, tutorials, examples
