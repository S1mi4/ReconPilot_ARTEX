# Repository Guidelines

## Project Structure & Module Organization

ARTEX is a Go backend with a Next.js frontend. The Go entry point is `cmd/artex`; backend packages include `agent/`, `server/`, `db/`, `traffic/`, and `llmpool/`. The frontend lives in `web/`. Supporting material is in `docs/`, `screenshots/`, and `skills/`. Go tests sit beside their packages as `*_test.go` files.

## Build, Test, and Development Commands

- `./dev.sh` starts the Go backend, traffic proxy, and Next.js dev server.
- `go test ./...` runs the Go test suite.
- `cd web && npm ci && npm run dev` installs frontend dependencies and starts Next.js.
- `cd web && npm run check` runs Biome checks; `npm run build:static` creates the static frontend bundle.
- `./build.sh --target linux/amd64` builds one release target; `./build.sh --release` packages the supported targets.

## Coding Style & Naming Conventions

Format Go with `gofmt`; keep Go tests in `*_test.go` files. Frontend code uses TypeScript and React; run Biome through the `web/package.json` scripts and follow existing component and file naming patterns. Keep changes focused and avoid committing build output or local configuration.

## Testing Guidelines

Add Go tests beside changed packages and name them for the behavior they cover. Run `go test ./...` for backend changes. For frontend changes, run `cd web && npm run check` and build when the change affects compilation. No coverage threshold is configured.

## Commit & Pull Request Guidelines

Recent history uses both imperative subjects and conventional prefixes such as `build:` and `docs(changelog):`. Prefer a concise `type(scope): imperative summary`, for example `fix(server): validate request origin`. Pull requests should explain behavior changes, link related issues when available, and list checks run; include screenshots for UI changes.

## Security & Configuration

Use `.env.example` as the template for local `.env` values; never commit credentials or private keys. Follow the README's usage restrictions: keep testing inside an isolated, authorized lab and do not target online or production systems.

## Agent skills

### Issue tracker

Issues for this repo live in GitHub Issues (`S1mi4/ReconPilot_ARTEX`). See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default triage label names. See `docs/agents/triage-labels.md`.

### Domain docs

Use the single-context layout. See `docs/agents/domain.md`.
