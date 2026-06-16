# go-encrypted-text-kvs

`go-encrypted-text-kvs` is a small CLI tool for storing text key-value pairs in an encrypted local file.

The command name is `ek` (pronounced "E-K"). It stores encrypted data in a YAML file, with the data encryption key protected by the macOS Keychain.


## Requirements

- macOS

Linux and Windows are not supported in v1.

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

Delete a value:

```sh
ek unset API_TOKEN
```

Destroy the encrypted store and its Keychain item:

```sh
ek destroy
```

## Commands

### `ek init`

Creates a new encrypted store and saves its data encryption key in the macOS Keychain.

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

Values must be UTF-8 text. NUL bytes and carriage returns are not supported.

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

Restores the data encryption key to the macOS Keychain from a recovery file:

```sh
ek recovery import-key < ek-recovery.yaml
```

### `ek recovery export-yaml`

Exports all decrypted key-values as plaintext YAML:

```sh
umask 077
ek recovery export-yaml > ek-plaintext.yaml
```

This file contains secrets. Protect it and delete it when no longer needed.

### `ek recovery import-yaml`

Imports plaintext YAML from stdin and overwrites the encrypted store:

```sh
ek recovery import-yaml < ek-plaintext.yaml
```

## File location

Store file resolution order:

1. `--file PATH`
2. `EK_FILE`
3. `~/.ek.yaml`

The encrypted store file is written with file mode `0600`.

## Security notes

- File contents are encrypted with XChaCha20-Poly1305.
- The data encryption key is stored in the macOS Keychain.
- Reading or changing the store requires macOS device owner authentication.
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
