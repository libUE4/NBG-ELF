# Repository Guidelines

## Project Structure & Module Organization

This is a Go 1.22 CLI module named `nbg-elf`. The entry point lives in `cmd/nbg-elf/main.go` and exposes `inspect`, `encrypt`, `manifest`, and `verify`. Core ELF scanning, encryption, manifest handling, runtime injection, and AArch64 callsite logic are in `internal/elfstr/`. Embedded runtime bytes and their Go wrapper are in `internal/assets/`. ARM64 runtime stub source and linker script are in `stub/arm64/`. The `build/` directory contains generated binaries, manifests, and stub objects; treat it as output unless intentionally refreshing artifacts.

Tests are colocated with the code they exercise, using Go `_test.go` files such as `cmd/nbg-elf/main_test.go` and `internal/elfstr/elfstr_test.go`.

## Build, Test, and Development Commands

- `go test ./...`: run all unit tests across the CLI and internal packages.
- `go test ./internal/elfstr -run TestName`: run a focused package test while iterating.
- `go build -o build/nbg-elf ./cmd/nbg-elf`: build the CLI into `build/`.
- `go run ./cmd/nbg-elf --help`: run the CLI locally without creating a binary.
- `go run ./cmd/nbg-elf inspect -min 6 <input.elf>`: scan an ELF for candidate strings.

## Coding Style & Naming Conventions

Use standard Go formatting: tabs for indentation and `gofmt` before committing. Keep package names short and lowercase. Export identifiers only when they are part of a package boundary; prefer unexported helpers inside `internal/elfstr`. Tests should use descriptive names like `TestResolveManifestOutputPath`. Keep command flags lowercase and hyphenated, matching existing examples such as `-manifest-detail` and `-lazy-callsite-limit`.

## Testing Guidelines

Use Go's built-in `testing` package. Add focused unit tests beside the changed package, especially for manifest resolution, ELF parsing, encryption option validation, and AArch64 callsite behavior. Prefer `t.TempDir()` for filesystem tests. When modifying output validation or manifests, run `go test ./...` and include at least one strict-path or error-case test.

## Commit & Pull Request Guidelines

This checkout does not include `.git` history, so no repository-specific commit convention can be verified locally. Use short, imperative commit subjects such as `Add manifest validation test` or `Fix lazy callsite limit handling`. Pull requests should describe the behavior change, list commands run, mention generated artifacts touched under `build/`, and link relevant issues. Include terminal output snippets for CLI behavior changes and explain any compatibility impact for existing manifests or encrypted ELF outputs.

## Security & Configuration Tips

Avoid committing private ELF samples, watermarks, or sensitive manifests. Manifest detail mode may expose per-string offsets and hashes, so use it only when needed for diagnostics.
