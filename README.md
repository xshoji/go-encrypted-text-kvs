# go-encrypted-text-kvs

`ek` (pronounced "E-K") is a tiny encrypted replacement for `.env` files in local development.

## Why ek

`.env` is the default way to manage local secrets, and it fails in predictable ways:

- **Plaintext on disk** — `.env` sits in cleartext, so file indexers, backup tools, and any process with read access can see your secrets.
- **AI assistants** — AI coding assistants like Claude Code, Cursor, and GitHub Copilot read your project files as part of normal operation, so they see every secret in `.env` automatically — and may send file contents to remote model APIs.
- **Screen-share exposure** — opening `.env` in an editor during a call or screen share leaks every line at once.
- **Commit accidents** — a `.env` slipped into git history leaks every secret it held, and `git rm` does not undo the leak.
- **Lost inventory** — the same key reused across projects scatters copies you can't track.

`ek` keeps secrets in one encrypted file and never writes plaintext to disk. The decryption key stays in your OS keystore, so a commit can't leak what was never written.

`ek` is designed for local development and personal secret storage. It is not a team secret management system.

## Demo

[demo.mp4](https://github.com/user-attachments/assets/bfe16e5e-5694-418f-a721-bd6cee5db3b5)

## How it works

`ek` keeps two things separate:

1. **The encrypted store** — a single YAML file (`~/.ek.yaml` by default) holding only ciphertext and an envelope. No plaintext values are ever written to disk.
2. **The data encryption key** — a 32-byte key stored in your OS keystore, never in the store file.

On every operation, `ek` reads the key from the keystore, decrypts the store in memory, performs the change, re-encrypts with a fresh nonce, and writes the file back atomically with mode `0600`. Plaintext exists only in memory.

The store is encrypted with XChaCha20-Poly1305. The keystore backing depends on your OS.

## Supported platforms

`ek` is primarily built for macOS. Windows is also supported. Linux currently has a basic, software-only implementation.

| OS | Status | Key protection | Auth on access |
|---|---|---|---|
| macOS | Primary | Keychain + LocalAuthentication | Touch ID / login password |
| Windows | Supported | DPAPI (current user) | None |
| Linux | Basic | Passphrase-wrapped local file | Local passphrase |

For the threat model on each platform, see [Security notes](#security-notes).

## Use cases

Every workflow below starts with `ek init`, which creates the encrypted store at `~/.ek.yaml` and saves the data encryption key in your OS keystore. Run it once per store; then use `ek set` / `ek get` / `ek export-env` as needed.

### Replace `.env` in a personal project

```sh
ek set OPENAI_API_KEY sk-...
ek set STRIPE_SECRET_KEY sk_live_...
eval "$(ek export-env)"          # load into the current shell
```

No `.env` file, nothing to gitignore, nothing to leak.

### Keep secrets off your screen on calls

Instead of opening `.env` in an editor during a screen share or pasting it into an AI prompt, copy one value at a time:

```sh
ek copy STRIPE_SECRET_KEY
```

The value goes straight to your clipboard and is cleared automatically after 30 seconds. Override the lifetime with `--ttl`:

```sh
ek copy --ttl 10s STRIPE_SECRET_KEY
```

No plaintext file is ever on screen.

### Switch secrets per project without juggling `.env` files

Point each project at its own encrypted store with `--file` or `EK_FILE`:

```sh
ek --file ~/stores/work.yaml set JIRA_TOKEN ...
ek --file ~/stores/personal.yaml set GITHUB_TOKEN ...
EK_FILE=~/stores/work.yaml ek export-env
```

One encrypted store per project, no plaintext files scattered across project directories.

## Install

```sh
brew install xshoji/tap/ek --cask
```

## Quick start

Initialize the encrypted store:

```sh
ek init
```

By default, `ek` uses `~/.ek.yaml`. You can choose another file with `--file` or `EK_FILE`:

```sh
ek --file ./secrets.yaml init
EK_FILE=./secrets.yaml ek list
```

Set and read values:

```sh
ek set API_TOKEN "xxxxx"
ek get API_TOKEN
ek list
```

Move or copy a value:

```sh
ek mv API_TOKEN NEW_API_TOKEN
ek copy NEW_API_TOKEN
```

Delete a value:

```sh
ek unset API_TOKEN
```

Destroy the encrypted store and its keystore item:

```sh
ek destroy
```

You must type `DELETE` at the confirmation prompt before deletion.

## Commands

### `ek init`

Creates a new encrypted store and saves its data encryption key in the platform keystore.

On Linux and Windows, `ek init` asks for a local key passphrase and stores a passphrase-wrapped key file.

### `ek list`

Lists key-value pairs in sorted key order.

```sh
ek list
```

Prints `KEY=value` lines.

### `ek get KEY`

Prints the value for `KEY` to stdout without adding a trailing newline.

### `ek set KEY [VALUE]`

Adds or updates a key-value pair.

If `VALUE` is omitted, reads the value from stdin:

```sh
cat memo.txt | ek set MEMO
ek set MEMO < memo.txt
```

Keys must match:

```text
[A-Za-z_][A-Za-z0-9_]*
```

Values must be UTF-8 text. Multiline values are supported; NUL bytes and carriage returns are not.

### `ek mv OLD_KEY NEW_KEY`

Moves a key without changing its value. Fails if `OLD_KEY` does not exist or `NEW_KEY` already exists.

### `ek copy KEY`

Copies the value for `KEY` to the clipboard and clears it after 30 seconds if unchanged.

```sh
ek copy API_TOKEN
ek copy --ttl 10s API_TOKEN
```

`--ttl` must appear before `KEY`. The clipboard is cleared only if it still holds the copied value, so anything you copy in the meantime is left alone.

### `ek unset KEY`

Deletes a key-value pair.

### `ek export-env [KEY...]`

Prints shell `export` statements. With no keys, prints all keys:

```sh
eval "$(ek export-env)"
eval "$(ek export-env API_TOKEN DB_PASSWORD)"
```

### `ek unset-env`

Prints shell `unset` statements for all keys in the store:

```sh
eval "$(ek unset-env)"
```

### `ek recovery export-key`

Exports a recovery file that wraps the data encryption key with a passphrase:

```sh
ek recovery export-key > ek-recovery.yaml
```

Keep this recovery file and passphrase safe. The recovery file does not contain plaintext values.

### `ek recovery import-key`

Restores the data encryption key to the platform keystore from a recovery file:

```sh
ek recovery import-key < ek-recovery.yaml
```

The encrypted store file must already exist at the selected store path.

### `ek recovery export-yaml`

Exports all decrypted key-values as plaintext YAML:

```sh
umask 077
ek recovery export-yaml > ek-plaintext.yaml
```

This file contains secrets. Protect it and delete it when no longer needed.

### `ek recovery export-json`

Exports all decrypted key-values as plaintext JSON:

```sh
umask 077
ek recovery export-json > ek-plaintext.json
```

This file contains secrets. Protect it and delete it when no longer needed.

### `ek recovery import-yaml`

Imports plaintext YAML from stdin and overwrites the encrypted store:

```sh
ek recovery import-yaml < ek-plaintext.yaml
```

This keeps the existing store key ID and does not modify the platform keystore.

## File location

Store file resolution order:

1. `--file PATH`
2. `EK_FILE`
3. `~/.ek.yaml`

Specify `--file PATH` before the command name, for example `ek --file store.yaml list`.

The encrypted store file is written with file mode `0600`.

Platform key material is stored separately:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/ek/keys/<key_id>.yaml`
- Windows: `%LocalAppData%\ek\dpapi-keys\<key_id>.yaml`

## Security notes

- File contents are encrypted with XChaCha20-Poly1305.
- On macOS, the data encryption key is stored in the macOS Keychain and reading or changing the store requires device owner authentication.
- On Windows, the data encryption key is protected by DPAPI for the current Windows user. Normal commands do not prompt for a passphrase.
- Windows DPAPI does not provide a guaranteed per-command Windows Hello prompt; malware running as the same Windows user may also call DPAPI.
- On Linux, the data encryption key is protected by a local passphrase-wrapped key file. This is not hardware-backed or biometric-protected.
- If an attacker obtains both the encrypted store and the Linux local key file, security depends on the strength of the local key passphrase.
- Plaintext values, recovery passphrases, and encryption keys should not be logged or passed through environment variables.


## Development

### Build

```bash
# Go
go build -ldflags="-s" -trimpath -o ek ./...

# Cross-compiling with GoReleaser
goreleaser build --snapshot --clean
```

### Test

```bash
go test -v ./...
```

## Release

The release flow for this repository is automated with GitHub Actions.
Pushing Git tags triggers the release job.

```
# Release
git tag 0.0.1 && git push --tags


# Delete tag
v="0.0.1"; git tag -d "${v}" && git push origin :"${v}"

# Delete tag and recreate new tag and push
v="0.0.1"; git tag -d "${v}" && git push origin :"${v}"; git tag "${v}"; git push --tags
```


## License

MIT — see [LICENSE](LICENSE).
