# go-encrypted-text-kvs

`go-encrypted-text-kvs` is a small CLI tool for storing text key-value pairs in an encrypted local file.

Use it to store API keys and secrets locally without committing `.env` files.

The command name is `ek` (pronounced "E-K"). It stores encrypted data in a YAML file, with the data encryption key protected by the macOS Keychain or a passphrase-protected local software keystore.


[demo.mp4](https://github.com/user-attachments/assets/bfe16e5e-5694-418f-a721-bd6cee5db3b5)



## Requirements

- macOS: Keychain-backed storage
- Linux / Windows: passphrase-protected local key storage

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

Rename or copy a value:

```sh
ek rename API_TOKEN NEW_API_TOKEN
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

### `ek rename OLD_KEY NEW_KEY`

Renames a key without changing its value. Fails if `OLD_KEY` does not exist or `NEW_KEY` already exists.

### `ek copy KEY`

Copies the value for `KEY` to the clipboard and clears it after 30 seconds if unchanged.

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

On Linux and Windows, the local software key file is stored separately:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/ek/keys/<key_id>.yaml`
- Windows: `%AppData%\ek\keys\<key_id>.yaml`

## Security notes

- File contents are encrypted with XChaCha20-Poly1305.
- On macOS, the data encryption key is stored in the macOS Keychain and reading or changing the store requires device owner authentication.
- On Linux and Windows, the data encryption key is protected by a local passphrase-wrapped key file. This is not hardware-backed or biometric-protected.
- If an attacker obtains both the encrypted store and the local key file, security depends on the strength of the local key passphrase.
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
