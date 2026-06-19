# go-encrypted-text-kvs 仕様

## 概要

`go-encrypted-text-kvs` は、暗号化されたローカルファイルにテキストの key-value を保存するシンプルな CLI ツールである。コマンド名は `ek` とする。

初回 `ek init` で暗号化ファイルを作成し、復号に使う 32-byte DEK(Data Encryption Key) を keystore に保存する。macOS では Keychain、Linux / Windows では passphrase-protected local software keystore を使う。

既存実装 `/Users/user/Develop/ghq/github.com/xshoji/go-keychain-text-crypto` の以下の方針をベースにする。

- macOS Keychain + LocalAuthentication による DEK 保護
- Linux / Windows では Argon2id + XChaCha20-Poly1305 による passphrase-wrapped DEK 保護
- XChaCha20-Poly1305 によるファイル暗号化
- Argon2id + XChaCha20-Poly1305 による recovery key wrap
- YAML envelope 形式
- atomic write と file mode `0600`
- plaintext / DEK / recovery secret をログに出さない

## 対応 OS / keystore

macOS は Keychain に DEK を保存し、読み出し時に LocalAuthentication で device owner authentication を要求する。

Linux / Windows は passphrase-protected local software keystore を使う。`ek init` はローカル鍵 passphrase を確認入力させ、DEK を Argon2id + XChaCha20-Poly1305 で wrap した YAML ファイルとして保存する。通常コマンド実行時は `Local key passphrase:` を TTY で prompt する。

software keystore の保存先:

- Linux: `${XDG_CONFIG_HOME:-$HOME/.config}/ek/keys/<key_id>.yaml`
- Windows: `%AppData%\ek\keys\<key_id>.yaml`

software key file 形式:

```yaml
version: 1
type: ek-software-key
key_id: "..."
created_at: "..."
kdf:
  algorithm: argon2id
  time: 3
  memory_kib: 65536
  threads: 4
  salt: "..."
wrap:
  algorithm: xchacha20poly1305
  nonce: "..."
  ciphertext: "..."
```

Linux / Windows fallback は hardware-backed / biometric-protected ではない。store file 単体の漏洩や casual inspection には有効だが、encrypted store と software key file の両方を取得された場合は passphrase 強度に依存する。malware、root/admin compromise、keylogger、弱い passphrase brute force は防げない。

macOS / Linux / Windows 以外で操作コマンドを実行した場合は、stderr に以下を出して非 zero exit する。

```text
unsupported OS: ek supports macOS Keychain and Linux/Windows software keystore
```

`--help` や `--version` は OS に関係なく動作してよい。

## CLI 基本仕様

```sh
ek [--file PATH] <command> [args...]
```

暗号化 KVS ファイルのパス解決順は以下とする。

1. `--file PATH`
2. `EK_FILE`
3. home directory の `.ek.yaml`

グローバルフラグのファイル指定は `--file` のみ対応する。`-file` は非対応とする。

stdout は各コマンドのデータ出力専用にする。エラー、警告、認証や passphrase の prompt は stderr または TTY に出す。

## Key / Value 制約

v1 の key は環境変数名としてそのまま使える形式に限定する。

```text
[A-Za-z_][A-Za-z0-9_]*
```

value は UTF-8 text とする。

- 空文字は許可する
- 改行 `\n` は許可する
- 複数行 value は許可する
- `\r`, NUL byte は禁止する
- binary 値は v1 では非対応とし、必要なら利用者側で base64 化する

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
6. DEK を platform keystore に保存する

成功時は stdout なし、exit code `0` とする。途中で失敗した場合は、作成済みファイルや keystore item を best-effort で rollback する。

### `ek list`

key-value 一覧を key の辞書順で表示する。

```sh
ek list
```

処理:

1. LocalAuthentication で認証する
2. keystore から DEK を取得する
3. KVS ファイルを復号する
4. key-value を key の辞書順で stdout に出す

出力:

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
3. keystore から DEK を取得する
4. KVS ファイルを復号する
5. value のみを stdout に出す

script-safe にするため、value には末尾改行を付けず `fmt.Print(value)` 相当で出力する。

key が存在しない場合は stderr に以下を出して失敗する。

```text
key not found: API_TOKEN
```

### `ek set KEY [VALUE]`

key-value を追加または更新する。

```sh
ek set API_TOKEN "xxxxx"
cat memo.txt | ek set MEMO
ek set MEMO < memo.txt
```

処理:

1. KEY を validate する
2. VALUE が省略された場合は stdin 全体を VALUE として読む
3. VALUE を validate する
4. LocalAuthentication で認証する
5. keystore から DEK を取得する
6. 既存 KVS ファイルを復号する
7. `entries[KEY] = VALUE` に更新する
8. 新しい nonce で envelope 全体を再暗号化する
9. `0600` で atomic write する

同じ key が存在する場合は上書きする。成功時は stdout なしとする。

### `ek unset KEY`

指定 key を削除する。

```sh
ek unset API_TOKEN
```

処理:

1. KEY を validate する
2. LocalAuthentication で認証する
3. keystore から DEK を取得する
4. KVS ファイルを復号する
5. key が存在することを確認する
6. `entries` から削除する
7. 新しい nonce で再暗号化し、atomic write する

key が存在しない場合は失敗する。

```text
key not found: API_TOKEN
```

### `ek mv OLD_KEY NEW_KEY`

指定 key の名前を変更する。value は変更しない。

```sh
ek mv API_TOKEN NEW_API_TOKEN
```

処理:

1. OLD_KEY と NEW_KEY を validate する
2. LocalAuthentication で認証する
3. keystore から DEK を取得する
4. KVS ファイルを復号する
5. OLD_KEY が存在することを確認する
6. NEW_KEY が存在しないことを確認する
7. `entries[NEW_KEY] = entries[OLD_KEY]` として OLD_KEY を削除する
8. 新しい nonce で再暗号化し、atomic write する

OLD_KEY が存在しない場合は失敗する。

```text
key not found: API_TOKEN
```

NEW_KEY が既に存在する場合は失敗する。

```text
key already exists: NEW_API_TOKEN
```

### `ek copy KEY`

指定 key の value をクリップボードにコピーし、30 秒後にクリップボードが同じ内容のままならクリアする。

```sh
ek copy API_TOKEN
```

処理:

1. KEY を validate する
2. LocalAuthentication で認証する
3. keystore から DEK を取得する
4. KVS ファイルを復号する
5. value を OS のクリップボードにコピーする
6. 30 秒待つ
7. クリップボードがコピーした value と同じ場合のみ空文字で上書きする

stdout は使用しない。key が存在しない場合は失敗する。

### `ek export-env [KEY...]`

指定 key の value を、現在の shell に取り込める `export` 文として stdout に出す。KEY が未指定の場合は全 key を対象にする。

```sh
ek export-env
ek export-env API_TOKEN DB_PASSWORD
```

出力例:

```sh
export API_TOKEN='xxxxx'
export DB_PASSWORD='yyyyy'
```

利用例:

```sh
eval "$(ek export-env)"
eval "$(ek export-env API_TOKEN DB_PASSWORD)"
```

CLI プロセスは親 shell の environment を直接変更できないため、このコマンドは shell code を出力する。stdout には `export` 文以外を出してはならない。

処理:

1. KEY が指定されている場合、すべての KEY を validate する
2. LocalAuthentication で認証する
3. keystore から DEK を取得する
4. KVS ファイルを復号する
5. KEY が未指定の場合、store 内の全 key を対象にする
6. KEY が指定されている場合、すべての KEY が存在することを確認する
7. shell-safe に quote した `export KEY='VALUE'` を KEY の辞書順で stdout に出す

エラー時に途中まで export 文を出さないよう、すべての validate と存在確認を終えてから stdout に書く。

shell quote は POSIX sh / bash / zsh で有効な single quote 形式とし、value 内の single quote は `foo'bar` を `'foo'"'"'bar'` に変換する。

### `ek unset-env`

KVS に登録されている key すべてについて、現在の shell から unset できる shell code を stdout に出す。

```sh
ek unset-env
```

出力例:

```sh
unset API_TOKEN
unset DB_PASSWORD
```

利用例:

```sh
eval "$(ek unset-env)"
```

処理:

1. LocalAuthentication で認証する
2. keystore から DEK を取得する
3. KVS ファイルを復号する
4. key を辞書順で stdout に `unset KEY` として出す

stdout には `unset` 文以外を出してはならない。

### `ek destroy`

KVS ファイルと対応する keystore item を破棄する。

```sh
ek destroy
```

処理:

1. TTY に `Type DELETE to continue:` と表示し、`DELETE` と入力されたことを確認する
2. LocalAuthentication で認証する
3. keystore から DEK を取得する
4. KVS ファイルを復号できることを確認する
5. encrypted KVS ファイルを一時パスへ rename する
6. platform keystore から該当 `key_id` の DEK を削除する
7. 一時パスの encrypted KVS ファイルを削除する

確認入力不一致、認証失敗、認証キャンセル、復号失敗、ファイル退避失敗時は何も削除しない。keystore 削除失敗時は退避したファイルを元のパスへ戻す。成功時は stdout なしとする。

## Recovery コマンド

Recovery コマンドはサブコマンド形式にする。

```sh
ek recovery export-key
ek recovery import-key
ek recovery export-yaml
ek recovery export-json
ek recovery import-yaml
```

### `ek recovery export-key`

DEK を recovery passphrase で wrap し、recovery YAML を stdout に出す。

```sh
ek recovery export-key > ek-recovery.yaml
```

処理:

1. LocalAuthentication で認証する
2. keystore から DEK を取得する
3. TTY から recovery passphrase を入力させる
4. 確認のため passphrase を再入力させる
5. Argon2id で wrap key を導出する
6. DEK を XChaCha20-Poly1305 で暗号化する
7. recovery YAML を stdout に出す

passphrase は argv / env var では受け取らない。stdout は recovery YAML 専用にする。

### `ek recovery import-key`

recovery YAML を stdin から読み、passphrase で unwrap した DEK を platform keystore に戻す。

```sh
ek recovery import-key < ek-recovery.yaml
```

処理:

1. recovery YAML を stdin から読む
2. TTY から recovery passphrase を入力させる
3. Argon2id で wrap key を導出する
4. XChaCha20-Poly1305 で DEK を unwrap する
5. payload が 32 bytes であることを確認する
6. KVS ファイルが存在することを確認する
7. envelope の `key_id` と recovery YAML の `key_id` が一致することを確認する
8. 同じ `key_id` の DEK が keystore に存在しないことを確認する
9. DEK で KVS ファイルを復号できることを確認する
10. DEK を platform keystore に保存する

既に同じ `key_id` の DEK が keystore に存在する場合、v1 では上書きしない。

```text
decrypt key already exists in OS keystore
```

### `ek recovery export-yaml`

暗号化された KVS payload を復号し、plaintext YAML を stdout にそのまま出す。出力にはすべての plaintext value が含まれる。

```sh
umask 077
ek recovery export-yaml > ek-plaintext.yaml
```

処理:

1. LocalAuthentication で認証する
2. keystore から DEK を取得する
3. KVS ファイルを復号する
4. plaintext YAML が v1 store schema と key / value 制約を満たすことを確認する
5. 復号された YAML bytes を stdout に出す

stdout は plaintext YAML 専用にする。コマンド自身は plaintext ファイルを作成しない。

### `ek recovery export-json`

暗号化された KVS payload を復号し、plaintext JSON を stdout に出す。出力にはすべての plaintext value が含まれる。

```sh
umask 077
ek recovery export-json > ek-plaintext.json
```

処理:

1. LocalAuthentication で認証する
2. keystore から DEK を取得する
3. KVS ファイルを復号する
4. v1 store schema と key / value 制約を満たすことを確認する
5. 復号された store を pretty-print JSON として stdout に出す

stdout は plaintext JSON 専用にする。コマンド自身は plaintext ファイルを作成しない。

### `ek recovery import-yaml`

stdin から plaintext YAML を読み、既存 store を上書きする。

```sh
ek recovery import-yaml < ek-plaintext.yaml
```

処理:

1. plaintext YAML を stdin から読む
2. v1 store schema と key / value 制約を満たすことを確認する
3. LocalAuthentication で認証する
4. Keychain から既存 DEK を取得する
5. 既存 envelope の `key_id` / `created_at` を維持する
6. 新しい nonce で stdin の YAML bytes を暗号化する
7. `updated_at` を更新し、`0600` で atomic write する

store は事前に `ek init` 済みである必要がある。keystore item は変更しない。import は merge ではなく全体上書きとし、validate に失敗した場合は何も書き込まない。

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
| `key_id` | keystore 上の DEK を特定する ID |
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

keystore item は Generic Password を使う。

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
- `mv`
- `copy`
- `unset`
- `export-env`
- `unset-env`
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
| unsupported OS | `unsupported OS: ek supports macOS Keychain and Linux/Windows software keystore` |
| file not initialized | `not initialized: run "ek init"` |
| already initialized | `already initialized: .ek.yaml` |
| invalid key | `invalid key name: must match [A-Za-z_][A-Za-z0-9_]*` |
| invalid value | `invalid value: carriage return and NUL bytes are not supported` |
| key not found | `key not found: API_TOKEN` |
| auth canceled / failed | `authentication failed or canceled` |
| missing keystore DEK | `local software key not found: run "ek recovery import-key" to restore it` |
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
unsupported OS: ek supports macOS Keychain and Linux/Windows software keystore
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
- `export-env` が partial output しないこと

CLI test は fake keystore を使う。macOS Keychain integration test は darwin のみ、明示的に有効化した場合だけ実行する。

## v1 の非目標

- Linux Secret Service 対応
- Windows Credential Manager 対応
- cloud sync
- multi-user sharing
- binary value の native support
- editor integration
- JSON output mode
- key alias / env var alias
- remote backup
- CI など non-interactive 環境での利用
