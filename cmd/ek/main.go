package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

const defaultStoreFile = ".ek.yaml"

func main() {
	code := 1
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) || errors.Is(err, errValidation) {
			code = 2
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(code)
	}
}

var errUsage = errors.New("usage error")
var errValidation = errors.New("validation error")

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }
func (e usageError) Unwrap() error { return errUsage }

type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }
func (e validationError) Unwrap() error { return errValidation }

func run(args []string) error {
	if len(args) == 0 {
		printUsage(os.Stdout)
		return nil
	}
	if args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		printUsage(os.Stdout)
		return nil
	}

	filePath, rest, err := parseGlobalFlags(args)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		return usageError{"command is required"}
	}

	switch rest[0] {
	case "init":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runInit(filePath, rest[1:])
	case "list":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runList(filePath, rest[1:])
	case "get":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runGet(filePath, rest[1:])
	case "set":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runSet(filePath, rest[1:])
	case "unset":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runUnset(filePath, rest[1:])
	case "export-to-environment-var":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runExportEnv(filePath, rest[1:])
	case "unset-environment-var":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runUnsetEnv(filePath, rest[1:])
	case "destroy":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runDestroy(filePath, rest[1:])
	case "recovery":
		if err := ensureSupportedOS(); err != nil {
			return err
		}
		return runRecovery(filePath, rest[1:])
	default:
		return usageError{fmt.Sprintf("unknown command %q", rest[0])}
	}
}

func parseGlobalFlags(args []string) (string, []string, error) {
	filePath := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--file" {
			if i+1 >= len(args) {
				return "", nil, usageError{"--file requires a path"}
			}
			filePath = args[i+1]
			i++
			continue
		}
		if strings.HasPrefix(a, "--file=") {
			filePath = strings.TrimPrefix(a, "--file=")
			continue
		}
		return filePath, args[i:], nil
	}
	return filePath, nil, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "ek")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  ek [--file PATH] init")
	fmt.Fprintln(w, "  ek [--file PATH] list [--detail|-d]")
	fmt.Fprintln(w, "  ek [--file PATH] get KEY")
	fmt.Fprintln(w, "  ek [--file PATH] set KEY VALUE")
	fmt.Fprintln(w, "  ek [--file PATH] unset KEY")
	fmt.Fprintln(w, "  ek [--file PATH] export-to-environment-var KEY...")
	fmt.Fprintln(w, "  ek [--file PATH] unset-environment-var")
	fmt.Fprintln(w, "  ek [--file PATH] destroy")
	fmt.Fprintln(w, "  ek [--file PATH] recovery export-key")
	fmt.Fprintln(w, "  ek [--file PATH] recovery import-key")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func runInit(filePath string, args []string) error {
	fs := newFlagSet("init")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{"init does not accept positional arguments"}
	}
	path, err := resolveStorePath(filePath)
	if err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("already initialized: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	key, err := randomBytes(32)
	if err != nil {
		return err
	}
	keyID, err := randomID()
	if err != nil {
		return err
	}
	if err := keychainStore(keyID, key); err != nil {
		return fmt.Errorf("store key in Keychain: %w", err)
	}
	now := time.Now().UTC()
	env := &storeEnvelope{Version: 1, Type: "encrypted-text-kvs", KeyID: keyID, CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339)}
	encoded, err := encryptStore(storePlaintext{Version: 1, Type: "kvs", Entries: map[string]string{}}, env, key, now)
	if err != nil {
		_ = keychainDelete(keyID)
		return err
	}
	if err := writeFileAtomic(path, encoded, 0o600); err != nil {
		_ = keychainDelete(keyID)
		return err
	}
	return nil
}

func runList(filePath string, args []string) error {
	fs := newFlagSet("list")
	detail := fs.Bool("detail", false, "show values")
	shortDetail := fs.Bool("d", false, "show values")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return usageError{"list does not accept positional arguments"}
	}
	store, _, err := loadAuthenticatedStore(filePath, "Authenticate to list encrypted keys")
	if err != nil {
		return err
	}
	keys := sortedKeys(store.Entries)
	for _, k := range keys {
		if *detail || *shortDetail {
			fmt.Fprintf(os.Stdout, "%s=%s\n", k, store.Entries[k])
		} else {
			fmt.Fprintln(os.Stdout, k)
		}
	}
	return nil
}

func runGet(filePath string, args []string) error {
	if len(args) != 1 {
		return usageError{"get requires KEY"}
	}
	keyName := args[0]
	if err := validateKey(keyName); err != nil {
		return err
	}
	store, _, err := loadAuthenticatedStore(filePath, "Authenticate to get encrypted value")
	if err != nil {
		return err
	}
	value, ok := store.Entries[keyName]
	if !ok {
		return fmt.Errorf("key not found: %s", keyName)
	}
	fmt.Fprint(os.Stdout, value)
	return nil
}

func runSet(filePath string, args []string) error {
	if len(args) != 2 {
		return usageError{"set requires KEY and VALUE"}
	}
	keyName, value := args[0], args[1]
	if err := validateKey(keyName); err != nil {
		return err
	}
	if err := validateValue(value); err != nil {
		return err
	}
	store, env, key, path, err := loadAuthenticatedStoreForWrite(filePath, "Authenticate to set encrypted value")
	if err != nil {
		return err
	}
	store.Entries[keyName] = value
	encoded, err := encryptStore(store, env, key, time.Now().UTC())
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o600)
}

func runUnset(filePath string, args []string) error {
	if len(args) != 1 {
		return usageError{"unset requires KEY"}
	}
	keyName := args[0]
	if err := validateKey(keyName); err != nil {
		return err
	}
	store, env, key, path, err := loadAuthenticatedStoreForWrite(filePath, "Authenticate to unset encrypted value")
	if err != nil {
		return err
	}
	if _, ok := store.Entries[keyName]; !ok {
		return fmt.Errorf("key not found: %s", keyName)
	}
	delete(store.Entries, keyName)
	encoded, err := encryptStore(store, env, key, time.Now().UTC())
	if err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o600)
}

func runExportEnv(filePath string, args []string) error {
	if len(args) == 0 {
		return usageError{"export-to-environment-var requires at least one KEY"}
	}
	for _, k := range args {
		if err := validateKey(k); err != nil {
			return err
		}
	}
	store, _, err := loadAuthenticatedStore(filePath, "Authenticate to export encrypted values")
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, k := range args {
		v, ok := store.Entries[k]
		if !ok {
			return fmt.Errorf("key not found: %s", k)
		}
		fmt.Fprintf(&b, "export %s=%s\n", k, shellQuote(v))
	}
	_, err = io.WriteString(os.Stdout, b.String())
	return err
}

func runUnsetEnv(filePath string, args []string) error {
	if len(args) != 0 {
		return usageError{"unset-environment-var does not accept positional arguments"}
	}
	store, _, err := loadAuthenticatedStore(filePath, "Authenticate to unset encrypted environment variables")
	if err != nil {
		return err
	}
	for _, k := range sortedKeys(store.Entries) {
		fmt.Fprintf(os.Stdout, "unset %s\n", k)
	}
	return nil
}

func runDestroy(filePath string, args []string) error {
	if len(args) != 0 {
		return usageError{"destroy does not accept positional arguments"}
	}
	_, env, key, path, err := loadAuthenticatedStoreForWrite(filePath, "Authenticate to destroy encrypted store")
	if err != nil {
		return err
	}
	if _, err := decryptStore(env, key); err != nil {
		return err
	}
	if err := keychainDelete(env.KeyID); err != nil {
		return fmt.Errorf("delete key from Keychain: %w", err)
	}
	return os.Remove(path)
}

func runRecovery(filePath string, args []string) error {
	if len(args) == 0 {
		return usageError{"recovery requires a subcommand"}
	}
	switch args[0] {
	case "export-key":
		return runRecoveryExportKey(filePath, args[1:])
	case "import-key":
		return runRecoveryImportKey(filePath, args[1:])
	default:
		return usageError{fmt.Sprintf("unknown recovery subcommand %q", args[0])}
	}
}

func runRecoveryExportKey(filePath string, args []string) error {
	if len(args) != 0 {
		return usageError{"recovery export-key does not accept positional arguments"}
	}
	path, err := resolveStorePath(filePath)
	if err != nil {
		return err
	}
	env, err := readStoreEnvelope(path)
	if err != nil {
		return err
	}
	key, err := keychainLoad(env.KeyID, "Authenticate to export the recovery key")
	if err != nil {
		return fmt.Errorf("read key from Keychain: %w", err)
	}
	passphrase, err := promptPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)
	confirm, err := promptPassphrase("Confirm recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(confirm)
	if !bytes.Equal(passphrase, confirm) {
		return fmt.Errorf("recovery passphrases did not match")
	}
	recovery, err := newRecoveryFile(env.KeyID, key, passphrase, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := yaml.Marshal(recovery)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(encoded)
	return err
}

func runRecoveryImportKey(filePath string, args []string) error {
	if len(args) != 0 {
		return usageError{"recovery import-key does not accept positional arguments"}
	}
	var recovery recoveryFile
	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(content, &recovery); err != nil {
		return fmt.Errorf("parse recovery file: %w", err)
	}
	passphrase, err := promptPassphrase("Recovery passphrase: ")
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)
	key, err := unwrapRecoveryKey(&recovery, passphrase)
	if err != nil {
		return fmt.Errorf("failed to unwrap recovery key: wrong passphrase or corrupted recovery file")
	}
	path, err := resolveStorePath(filePath)
	if err != nil {
		return err
	}
	if env, err := readStoreEnvelope(path); err == nil {
		if env.KeyID != recovery.KeyID {
			return fmt.Errorf("recovery key_id %q does not match store key_id %q", recovery.KeyID, env.KeyID)
		}
		if _, err := decryptStore(env, key); err != nil {
			return fmt.Errorf("failed to decrypt store: file may be corrupted or key is wrong")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if keychainExists(recovery.KeyID) {
		return fmt.Errorf("decrypt key already exists in OS keystore")
	}
	return keychainStore(recovery.KeyID, key)
}

func resolveStorePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = os.Getenv("EK_FILE")
	}
	if strings.TrimSpace(path) == "" {
		path = defaultStoreFile
	}
	return filepath.Abs(path)
}

func loadAuthenticatedStore(filePath, prompt string) (storePlaintext, *storeEnvelope, error) {
	store, env, _, _, err := loadAuthenticatedStoreForWrite(filePath, prompt)
	return store, env, err
}

func loadAuthenticatedStoreForWrite(filePath, prompt string) (storePlaintext, *storeEnvelope, []byte, string, error) {
	path, err := resolveStorePath(filePath)
	if err != nil {
		return storePlaintext{}, nil, nil, "", err
	}
	env, err := readStoreEnvelope(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return storePlaintext{}, nil, nil, "", fmt.Errorf("not initialized: run \"ek init\"")
		}
		return storePlaintext{}, nil, nil, "", err
	}
	key, err := keychainLoad(env.KeyID, prompt)
	if err != nil {
		return storePlaintext{}, nil, nil, "", fmt.Errorf("read key from Keychain: %w", err)
	}
	store, err := decryptStore(env, key)
	if err != nil {
		return storePlaintext{}, nil, nil, "", fmt.Errorf("failed to decrypt store: file may be corrupted or key is wrong")
	}
	return store, env, key, path, nil
}

func promptPassphrase(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, fmt.Errorf("a terminal is required for passphrase input")
	}
	fmt.Fprint(os.Stderr, prompt)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(value) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	return value, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
