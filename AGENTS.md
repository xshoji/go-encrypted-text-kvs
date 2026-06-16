# AGENTS.md

## Project overview

This repository contains `go-encrypted-text-kvs`, a Go CLI tool named `ek`.

`ek` stores text key-value pairs in an encrypted local YAML file. The encrypted file contains only an envelope and ciphertext. The data encryption key (DEK) is stored in the macOS Keychain.

v1 supports macOS only. Linux and Windows should return:

```text
unsupported OS: ek currently supports macOS Keychain only
```

## User-facing documentation

- `README.md` is for end users.
- Keep user-facing instructions concise and practical.
- Do not put internal implementation notes only meant for agents into `README.md`.

## Agent-facing specification

- `docs/spec.md` is the detailed product and implementation specification.
- This `AGENTS.md` summarizes repository structure, constraints, and common commands for coding agents.
- If behavior conflicts with implementation, check `docs/spec.md` and update docs/tests together with code when appropriate.

## Current structure

```text
cmd/ek/main.go                 CLI parsing, commands, validation, store loading
cmd/ek/store.go                encryption envelope, recovery file, atomic writes
cmd/ek/keychain_darwin.go      macOS Keychain and LocalAuthentication integration
cmd/ek/keystore_unsupported.go unsupported OS keystore stubs
cmd/ek/os_darwin.go            darwin OS support hook
cmd/ek/os_unsupported.go       unsupported OS hook
cmd/ek/store_test.go           unit tests
docs/spec.md                   detailed specification
README.md                      user documentation
```

The code is currently intentionally small and mostly kept under `cmd/ek`. Do not introduce new packages or dependencies unless the requested change clearly needs them.

## CLI behavior

Global form:

```sh
ek [--file PATH] <command> [args...]
```

Store file resolution order:

1. `--file PATH`
2. `EK_FILE`
3. `$HOME/.ek.yaml`

Supported commands:

- `init`
- `list [--detail|-d]`
- `get KEY`
- `set KEY VALUE`
- `unset KEY`
- `export-to-environment-var KEY...`
- `unset-environment-var`
- `destroy`
- `recovery export-key`
- `recovery import-key`

stdout is reserved for command data only. Prompts, warnings, and errors must go to stderr or the TTY.

## Data constraints

Keys must match:

```text
[A-Za-z_][A-Za-z0-9_]*
```

Values are single-line UTF-8 text. Empty strings are allowed. Values containing `\n`, `\r`, or NUL are invalid. Multiline and binary values are not supported in v1.

## Security constraints

- Never log plaintext values, DEKs, recovery passphrases, or plaintext stores.
- Do not include secrets in error messages.
- Do not create plaintext temp files.
- Store file writes must be atomic.
- Store files must be written with mode `0600`.
- Reads may reject files with permissions other than `0600`.
- Generate new nonces for each encrypted write.
- Recovery files must not contain plaintext KVS values.

## Cryptography and storage

- Store encryption: XChaCha20-Poly1305.
- DEK size: 32 bytes from `crypto/rand`.
- Store format: YAML envelope with encrypted YAML payload.
- Recovery key wrapping: Argon2id + XChaCha20-Poly1305.
- Keychain item:
  - class: Generic Password
  - service: `go-encrypted-text-kvs`
  - account: `key_id`
  - secret: raw 32-byte DEK

## Implementation guidance

- Prefer small, local changes that preserve the existing style.
- Use the standard library where possible.
- The CLI currently uses `flag` and `switch`; do not add a CLI framework for routine changes.
- Keep stdout script-safe for commands used with `eval`.
- Ensure `export-to-environment-var` validates all requested keys before printing any output.
- Use POSIX shell single-quote escaping for exported values.
- Maintain exit codes:
  - `0`: success
  - `1`: runtime error
  - `2`: usage or validation error

## Build and test

Run the focused tests before finishing code changes:

```sh
go test ./...
```

For changes that may affect formatting:

```sh
gofmt -w <changed-go-files>
```

Avoid dumping large command logs into the conversation. Redirect noisy output to a temporary log and inspect only failures.
