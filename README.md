# go-encrypted-text-kvs

`go-encrypted-text-kvs` is a small CLI tool for storing text key-value pairs in an encrypted local file.

The command name is `ek`. It stores the encrypted data in a YAML file and protects the data encryption key with the macOS Keychain.

## Requirements

- macOS
- Go, if building from source

Linux and Windows are not supported in v1.

## Install

```sh
go install github.com/xshoji/go-encrypted-text-kvs/cmd/ek@latest
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

Lists keys in sorted order.

```sh
ek list
ek list --detail
ek list -d
```

`--detail` / `-d` prints `KEY=value` lines.

### `ek get KEY`

Prints the value for `KEY` to stdout without adding a trailing newline.

### `ek set KEY VALUE`

Adds or updates a key-value pair.

Keys must match:

```text
[A-Za-z_][A-Za-z0-9_]*
```

Values must be single-line UTF-8 text. Multiline and binary values are not supported in v1.

### `ek unset KEY`

Deletes a key-value pair.

### `ek export-to-environment-var [KEY...]`

Prints shell `export` statements. With no keys, prints all keys:

```sh
eval "$(ek export-to-environment-var)"
eval "$(ek export-to-environment-var API_TOKEN DB_PASSWORD)"
```

### `ek unset-environment-var`

Prints shell `unset` statements for all keys in the store:

```sh
eval "$(ek unset-environment-var)"
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
