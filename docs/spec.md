# go-encrypted-text-kvs 仕様

## 概要

`go-encrypted-text-kvs` は、暗号化されたローカルファイルにテキストの key-value を保存するシンプルな CLI ツールである。コマンド名は `ek` とする。

初回 `ek init` で暗号化ファイルを作成し、復号に使う 32-byte DEK(Data Encryption Key) を OS の keystore に保存する。v1 は macOS Keychain のみ対応し、Linux / Windows は未対応とする。

既存実装 `/Users/user/Develop/ghq/github.com/xshoji/go-keychain-text-crypto` の以下の方針をベースにする。

- macOS Keychain + LocalAuthentication による DEK 保護
- XChaCha20-Poly1305 によるファイル暗号化
- Argon2id + XChaCha20-Poly1305 による recovery key wrap
- YAML envelope 形式
- atomic write と file mode `0600`
- plaintext / DEK / recovery secret をログに出さない

## 対応 OS

v1 は macOS のみ対応する。

macOS 以外で操作コマンドを実行した場合は、stderr に以下を出して非 zero exit する。

```text
unsupported OS: ek currently supports macOS Keychain only
```

`--help` や `--version` は OS に関係なく動作してよい。

## CLI 基本仕様

```sh
ek [--file PATH] <command> [args...]
```

暗号化 KVS ファイルのパス解決順は以下とする。

1. `--file PATH`
2. `EK_FILE`
3. カレントディレクトリの `.ek.yaml`

stdout は各コマンドのデータ出力専用にする。エラー、警告、認証や passphrase の prompt は stderr または TTY に出す。

## Key / Value 制約

v1 の key は環境変数名としてそのまま使える形式に限定する。

```text
[A-Za-z_][A-Za-z0-9_]*
```

value は単一行 UTF-8 text とする。

- 空文字は許可する
- `\n`, `\r`, NUL byte は禁止する
- 複数行値や binary 値は v1 では非対応とし、必要なら利用者側で base64 化する

## コマンド仕様

### `ek init`

空の暗号化 KVS ファイルを作成し、ランダムな DEK を keystore に保存する。

```sh
ek init
```

処理:

1. 対象ファイルが存在しないことを確認する
2. `crypto/rand` で 32-byte DEK を生成する
3. ランダムな `key_id` を生成する
4. 空の KVS payload を XChaCha20-Poly1305 で暗号化する
5. encrypted YAML envelope を `0600` で atomic write する
6. DEK を macOS Keychain に保存する

成功時は stdout なし、exit code `0` とする。途中で失敗した場合は、作成済みファイルや Keychain item を best-effort で rollback する。

### `ek list`

key 一覧を辞書順で表示する。

```sh
ek list
ek list --detail
ek list -d
```

処理:

1. LocalAuthentication で認証する
2. Keychain から DEK を取得する
3. KVS ファイルを復号する
4. key を辞書順で stdout に出す

通常出力:

```text
API_TOKEN
DB_PASSWORD
```

`--detail` / `-d` 出力:

```text
API_TOKEN=xxxxx
DB_PASSWORD=yyyyy
```

空の KVS の場合は stdout なし、exit code `0` とする。

### `ek get KEY`

指定 key の value を stdout に出す。

```sh
ek get API_TOKEN
```

処理:

1. KEY を validate する
2. LocalAuthentication で認証する
3. Keychain から DEK を取得する
4. KVS ファイルを復号する
5. value のみを stdout に出す

script-safe にするため、value には末尾改行を付けず `fmt.Print(value)` 相当で出力する。

key が存在しない場合は stderr に以下を出して失敗する。

```text
key not found: API_TOKEN
```

### `ek set KEY VALUE`

key-value を追加または更新する。

```sh
ek set API_TOKEN "xxxxx"
```

処理:

1. KEY / VALUE を validate する
2. LocalAuthentication で認証する
3. Keychain から DEK を取得する
4. 既存 KVS ファイルを復号する
5. `entries[KEY] = VALUE` に更新する
6. 新しい nonce で envelope 全体を再暗号化する
7. `0600` で atomic write する

同じ key が存在する場合は上書きする。成功時は stdout なしとする。

### `ek unset KEY`

指定 key を削除する。

```sh
ek unset API_TOKEN
```

処理:

1. KEY を validate する
2. LocalAuthentication で認証する
3. Keychain から DEK を取得する
4. KVS ファイルを復号する
5. key が存在することを確認する
6. `entries` から削除する
7. 新しい nonce で再暗号化し、atomic write する

key が存在しない場合は失敗する。

```text
key not found: API_TOKEN
```

### `ek export-to-environment-var KEY...`

指定 key の value を、現在の shell に取り込める `export` 文として stdout に出す。

```sh
ek export-to-environment-var API_TOKEN DB_PASSWORD
```

出力例:

```sh
export API_TOKEN='xxxxx'
export DB_PASSWORD='yyyyy'
```

利用例:

```sh
eval "$(ek export-to-environment-var API_TOKEN DB_PASSWORD)"
```

CLI プロセスは親 shell の environment を直接変更できないため、このコマンドは shell code を出力する。stdout には `export` 文以外を出してはならない。

処理:

1. KEY が 1 個以上あることを確認する
2. すべての KEY を validate する
3. LocalAuthentication で認証する
4. Keychain から DEK を取得する
5. KVS ファイルを復号する
6. すべての KEY が存在することを確認する
7. shell-safe に quote した `export KEY='VALUE'` を stdout に出す

エラー時に途中まで export 文を出さないよう、すべての validate と存在確認を終えてから stdout に書く。

shell quote は POSIX sh / bash / zsh で有効な single quote 形式とし、value 内の single quote は `foo'bar` を `'foo'"'"'bar'` に変換する。

### `ek unset-environment-var`

KVS に登録されている key すべてについて、現在の shell から unset できる shell code を stdout に出す。

```sh
ek unset-environment-var
```

出力例:

```sh
unset API_TOKEN
unset DB_PASSWORD
```

利用例:

```sh
eval "$(ek unset-environment-var)"
```

処理:

1. LocalAuthentication で認証する
2. Keychain から DEK を取得する
3. KVS ファイルを復号する
4. key を辞書順で stdout に `unset KEY` として出す

stdout には `unset` 文以外を出してはならない。

### `ek destroy`

KVS ファイルと対応する Keychain item を破棄する。

```sh
ek destroy
```

処理:

1. LocalAuthentication で認証する
2. Keychain から DEK を取得する
3. KVS ファイルを復号できることを確認する
4. macOS Keychain から該当 `key_id` の DEK を削除する
5. encrypted KVS ファイルを削除する

認証失敗、認証キャンセル、復号失敗時は何も削除しない。成功時は stdout なしとする。

## Recovery コマンド

Recovery コマンドはサブコマンド形式にする。

```sh
ek recovery export-key
ek recovery import-key
```

### `ek recovery export-key`

DEK を recovery passphrase で wrap し、recovery YAML を stdout に出す。

```sh
ek recovery export-key > ek-recovery.yaml
```

処理:

1. LocalAuthentication で認証する
2. Keychain から DEK を取得する
3. TTY から recovery passphrase を入力させる
4. 確認のため passphrase を再入力させる
5. Argon2id で wrap key を導出する
6. DEK を XChaCha20-Poly1305 で暗号化する
7. recovery YAML を stdout に出す

passphrase は argv / env var では受け取らない。stdout は recovery YAML 専用にする。

### `ek recovery import-key`

recovery YAML を stdin から読み、passphrase で unwrap した DEK を macOS Keychain に戻す。

```sh
ek recovery import-key < ek-recovery.yaml
```

処理:

1. recovery YAML を stdin から読む
2. TTY から recovery passphrase を入力させる
3. Argon2id で wrap key を導出する
4. XChaCha20-Poly1305 で DEK を unwrap する
5. payload が 32 bytes であることを確認する
6. KVS ファイルが存在する場合、envelope の `key_id` と recovery YAML の `key_id` が一致することを確認する
7. 同じ `key_id` の DEK が Keychain に存在しないことを確認する
8. DEK を macOS Keychain に保存する
9. KVS ファイルが存在する場合、復号できることを確認する

既に同じ `key_id` の DEK が Keychain に存在する場合、v1 では上書きしない。

```text
decrypt key already exists in OS keystore
```

## Encrypted KVS file format

暗号化ファイルは YAML envelope とする。

```yaml
version: 1
type: encrypted-text-kvs
key_id: "2f7b9e4c-8d4c-4f3a-9c3f-9d0b5e7f3d01"
created_at: "2026-06-15T00:00:00Z"
updated_at: "2026-06-15T00:00:00Z"
cipher:
  algorithm: xchacha20poly1305
  nonce: "base64-encoded-24-byte-nonce"
payload:
  encoding: base64
  ciphertext: "base64-encoded-ciphertext"
```

| field | description |
| --- | --- |
| `version` | envelope version。v1 では `1` 固定 |
| `type` | `encrypted-text-kvs` 固定 |
| `key_id` | Keychain 上の DEK を特定する ID |
| `created_at` | RFC3339 UTC |
| `updated_at` | RFC3339 UTC |
| `cipher.algorithm` | `xchacha20poly1305` 固定 |
| `cipher.nonce` | 24-byte nonce の base64 |
| `payload.encoding` | `base64` 固定 |
| `payload.ciphertext` | encrypted plaintext store の base64 |

暗号化前の plaintext payload も YAML とする。

```yaml
version: 1
type: kvs
entries:
  API_TOKEN: xxxxx
  DB_PASSWORD: yyyyy
```

暗号化仕様:

- DEK: 32 bytes from `crypto/rand`
- cipher: XChaCha20-Poly1305
- nonce: 24 bytes from `crypto/rand`
- nonce は write ごとに必ず新規生成する
- ciphertext は plaintext YAML + auth tag
- base64 は standard base64

AAD は以下を推奨する。

```text
go-encrypted-text-kvs:v1:encrypted-text-kvs:<key_id>:xchacha20poly1305
```

復号前後で `version`, `type`, `cipher.algorithm`, `payload.encoding` を厳密に validate する。

## Recovery file format

`ek recovery export-key` は以下の YAML を stdout に出す。

```yaml
version: 1
type: ek-recovery-key
key_id: "2f7b9e4c-8d4c-4f3a-9c3f-9d0b5e7f3d01"
created_at: "2026-06-15T00:00:00Z"
kdf:
  algorithm: argon2id
  time: 3
  memory_kib: 65536
  threads: 4
  salt: "base64-encoded-salt"
wrap:
  algorithm: xchacha20poly1305
  nonce: "base64-encoded-24-byte-nonce"
  ciphertext: "base64-encoded-wrapped-dek"
```

KDF:

- algorithm: Argon2id
- memory: 64 MiB
- time: 3
- threads: 4
- output length: 32 bytes
- salt: 16 bytes以上 from `crypto/rand`

Payload は raw 32-byte DEK を XChaCha20-Poly1305 で暗号化したものとする。recovery file に KVS plaintext や secret value は含めない。

## macOS Keychain

Keychain item は Generic Password を使う。

| item | value |
| --- | --- |
| class | Generic Password |
| service | `go-encrypted-text-kvs` |
| account | `key_id` |
| secret | raw 32-byte DEK |

推奨 attribute:

- `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
- iCloud Keychain sync は前提にしない
- access group は使わない

DEK read の前に `LAPolicyDeviceOwnerAuthentication` で LocalAuthentication を実行する。Touch ID、Apple Watch、password fallback など、OS が許可する device owner authentication を使う。

認証対象コマンド:

- `list`
- `get`
- `set`
- `unset`
- `export-to-environment-var`
- `unset-environment-var`
- `destroy`
- `recovery export-key`

`init` は既存 DEK を読む操作ではないため、アプリ側の LocalAuthentication は必須ではない。`recovery import-key` は passphrase で DEK を unwrap して Keychain に保存する操作であり、既存 item は上書きしない。

## File safety

KVS file write は atomic write にする。

推奨手順:

1. 同じ directory に temp file を作る
2. mode `0600` で書く
3. file を `fsync` する
4. `rename` で置き換える
5. 可能なら parent directory も `fsync` する

禁止事項:

- plaintext temp file を作らない
- plaintext value を log に出さない
- error に secret value を含めない
- panic / debug dump で DEK や plaintext store を出さない

read 時に group / others permission が付いている場合は拒否してよい。

```text
insecure file permissions: expected 0600
```

## Error handling

代表的なエラー文言は以下とする。

| case | message example |
| --- | --- |
| unsupported OS | `unsupported OS: ek currently supports macOS Keychain only` |
| file not initialized | `not initialized: run "ek init"` |
| already initialized | `already initialized: .ek.yaml` |
| invalid key | `invalid key name: must match [A-Za-z_][A-Za-z0-9_]*` |
| invalid value | `invalid value: multiline values are not supported in v1` |
| key not found | `key not found: API_TOKEN` |
| auth canceled / failed | `authentication failed or canceled` |
| missing keystore DEK | `decrypt key not found in OS keystore; run "ek recovery import-key"` |
| decrypt failed | `failed to decrypt store: file may be corrupted or key is wrong` |
| recovery unwrap failed | `failed to unwrap recovery key: wrong passphrase or corrupted recovery file` |
| insecure permissions | `insecure file permissions: expected 0600` |

Exit code は v1 では最低限以下とする。

| code | meaning |
| --- | --- |
| `0` | success |
| `1` | runtime error |
| `2` | usage / validation error |

## 実装方針

最小実装では CLI framework を追加せず、標準 library の `flag` と `switch` で実装する。

推奨構成:

```text
cmd/ek/main.go
internal/cli/
internal/store/
internal/crypto/envelope/
internal/keystore/
internal/recovery/
internal/atomicfile/
internal/shellquote/
```

`internal/keystore` は build tags で分ける。

```text
keystore_darwin.go
keystore_unsupported.go
```

`keystore_unsupported.go` は操作時に常に以下の error を返す。

```text
unsupported OS: ek currently supports macOS Keychain only
```

既存 `go-keychain-text-crypto` から優先して流用する実装:

1. XChaCha20-Poly1305 envelope の encrypt / decrypt
2. macOS Security.framework Keychain wrapper
3. LocalAuthentication wrapper
4. Argon2id recovery key wrap / unwrap
5. atomic write helper
6. file mode `0600` enforcement
7. plaintext をファイルやログに残さない設計

## テスト方針

最低限の unit test:

- key validation
- value validation
- shell quote
- envelope encrypt / decrypt roundtrip
- wrong DEK で decrypt failure
- recovery wrap / unwrap roundtrip
- wrong passphrase で recovery failure
- atomic write 後の file mode が `0600`
- `list` の sort order
- `export-to-environment-var` が partial output しないこと

CLI test は fake keystore を使う。macOS Keychain integration test は darwin のみ、明示的に有効化した場合だけ実行する。

## v1 の非目標

- Linux Secret Service 対応
- Windows Credential Manager 対応
- cloud sync
- multi-user sharing
- multiline / binary value の native support
- editor integration
- JSON output mode
- key alias / env var alias
- remote backup
- CI など non-interactive 環境での利用
