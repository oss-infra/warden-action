# AGENTS.md

GitHub Action + Node.js CLI that runs remote Yuanxi security/license scans. See [README.md](README.md) for usage, inputs, failure policy, JSON report schema, and the `src/` module map.

## Commands

- `pnpm check` — typecheck + test + build. Run before finishing any change.
- `pnpm test` — `tsx --test test/*.test.ts` (Node built-in runner).
- `pnpm build` — `ncc` bundles into `dist/` (Action) and `dist/cli/` (CLI).
- `pnpm warden --help` — run the CLI from source. Needs a real token and network; don't run it just to verify changes.

## Rules

- **`dist/` is committed and is what the Action executes.** After any `src/` change, run `pnpm build` and include the regenerated `dist/` files.
- **Keep `action.ts` thin.** It calls `void main()` on import and can't be unit-tested. Put logic in `config.ts`, `github-context.ts`, `scanner.ts`, `policy.ts`, or `format.ts` and test it there.
- **`@actions/core` and `@actions/github` are ESM-only; this package is CommonJS.** Keep the dynamic `await import(...)` calls in [src/action.ts](src/action.ts). Don't turn them into static imports.
- Relative imports have no extension (`./config`), matching the CommonJS + `NodeNext` setup.
- `tsconfig` enables `exactOptionalPropertyTypes` and `noUncheckedIndexedAccess`. To pass an optional field only when it's set, use a conditional spread (`...(x ? { key: x } : {})`), as in [src/run.ts](src/run.ts).
- Yuanxi returns Chinese values (`扫描完成`, `高危`, `已修复`, …). Match on them literally and don't translate them in code.
- Never log or print the token. It goes in a URL query parameter and gets redacted in [src/api-client.ts](src/api-client.ts). Don't read `.env`, because it holds real credentials.

## Adding or changing an input

Update all of these together:

1. [action.yml](action.yml): the input and its default
2. [src/action.ts](src/action.ts): `core.getInput(...)`
3. [src/cli.ts](src/cli.ts): the `HELP` text, `VALUE_OPTIONS`/`BOOLEAN_OPTIONS`, and `main()`. The flag is the kebab-case form of the input name.
4. [src/config.ts](src/config.ts): `ConfigValues` and validation in `buildConfig`, plus `ScanConfig` in [src/types.ts](src/types.ts)
5. The input tables in **both** [README.md](README.md) and [README_CN.md](README_CN.md). They mirror each other section by section.

Outputs follow the same pattern: `action.yml` → `core.setOutput` → both READMEs. If you change the JSON report shape, bump `schemaVersion` in [src/format.ts](src/format.ts).

## Tests

- Use `node:test` with `node:assert/strict`, one file per module in `test/`, importing from `../src/...`.
- Never hit the network. Inject a fake `ScannerClient`, `fetchImpl`, and `sleep: async () => {}` (see [test/scanner.test.ts](test/scanner.test.ts) and [test/api-client.test.ts](test/api-client.test.ts)).
