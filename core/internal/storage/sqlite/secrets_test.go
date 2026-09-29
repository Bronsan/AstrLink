package sqlite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/QuantumNous/astrlink/core/contract"
	"github.com/QuantumNous/astrlink/core/internal/accesstoken"
	"github.com/QuantumNous/astrlink/core/internal/secretstore"
	storagecontract "github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/migrate"
)

// Plaintext secrets as the release before sealing stored them. Each must
// only exist sealed after the first start.
const (
	fixtureServiceID     = contract.ServiceID("service_before_sealing")
	fixtureServiceKey    = "sk-PLAINTEXT-service-key-before-sealing"
	fixtureToolKey       = "tvly-PLAINTEXT-tool-key-before-sealing"
	fixtureProxyPassword = "PLAINTEXT-proxy-password"
	fixtureTokenID       = contract.AccessTokenID("access_token_before_sealing")
)

var fixtureToken = "astr_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))

// writePlaintextSecretsFixture builds a database at the given migration
// version with one plaintext row in each secret table.
func writePlaintextSecretsFixture(t *testing.T, path string, version int64) {
	t.Helper()
	database, err := sql.Open(driverName, sqliteFileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var released []migrate.Migration
	for _, migration := range migrate.DefaultMigrations() {
		if migration.Version <= version {
			released = append(released, migration)
		}
	}
	runner, err := migrate.New(migrate.SQLDatabase{DB: database}, released)
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	service := contract.ServiceFromEndpoint(testEndpoint(fixtureServiceID))
	service.HTTP.CredentialRef = localRef(fixtureServiceID)
	document, err := encodeService(service)
	if err != nil {
		t.Fatal(err)
	}
	name, nameKey, err := normalizeAccessTokenName("before sealing")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(fixtureToken))
	stamp := "2026-09-20T00:00:00Z"
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO services (id, document_json, created_at, updated_at, sort_position) VALUES (?, ?, ?, ?, 0)`,
			[]any{fixtureServiceID, string(document), stamp, stamp}},
		{`INSERT INTO service_credentials (service_id, credential_value, created_at, updated_at) VALUES (?, ?, ?, ?)`,
			[]any{fixtureServiceID, []byte(fixtureServiceKey), stamp, stamp}},
		{`INSERT INTO builtin_tool_credentials (kind, credential_value) VALUES ('web_search', ?)`,
			[]any{[]byte(fixtureToolKey)}},
		{`INSERT INTO service_proxy_credentials (service_id, credential_value) VALUES (?, ?)`,
			[]any{fixtureServiceID, []byte(`{"username":"proxy-user","password":"` + fixtureProxyPassword + `"}`)}},
		{`INSERT INTO local_access_tokens (id, name, name_key, token_hash, token_hint, source, created_at) VALUES (?, ?, ?, ?, ?, 'user', ?)`,
			[]any{fixtureTokenID, name, nameKey, hash[:], accessTokenHint(fixtureToken), stamp}},
		{`INSERT INTO local_access_token_secrets (token_id, token_value) VALUES (?, ?)`,
			[]any{fixtureTokenID, fixtureToken}},
		{`INSERT INTO local_access_token_bootstrap_state (singleton, completed_at) VALUES (1, ?)`,
			[]any{stamp}},
	} {
		if _, err := database.Exec(statement.query, statement.args...); err != nil {
			t.Fatalf("fixture %q: %v", statement.query, err)
		}
	}
}

type storedSecret struct {
	value  []byte
	sealed int
}

func readStoredSecrets(t *testing.T, store *Store) map[string]storedSecret {
	t.Helper()
	secrets := map[string]storedSecret{}
	for _, column := range secretColumns {
		sealedColumn := "1"
		if column.flagged {
			sealedColumn = "sealed"
		}
		rows, err := store.db.Query(`SELECT ` + column.key + `, ` + column.value + `, ` + sealedColumn + ` FROM ` + column.table)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var key string
			var row storedSecret
			if err := rows.Scan(&key, &row.value, &row.sealed); err != nil {
				t.Fatal(err)
			}
			secrets[column.table+"/"+key] = row
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		_ = rows.Close()
	}
	return secrets
}

func TestUpgradeSealsEverySecretOnceAndScrubsThePlaintext(t *testing.T) {
	for _, version := range []int64{41, 44} {
		t.Run(migrate.DefaultMigrations()[version-1].Name, func(t *testing.T) {
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "astrlink.db")
			writePlaintextSecretsFixture(t, path, version)
			localKey := testLocalKey(t, 0x21)

			var logs []string
			store := openWithKey(t, path, localKey, &logs)
			secrets := readStoredSecrets(t, store)
			if len(secrets) != 4 {
				t.Fatalf("stored secrets = %d, want 4", len(secrets))
			}
			for name, secret := range secrets {
				if secret.sealed != 1 {
					t.Fatalf("%s is not sealed", name)
				}
			}
			for _, plaintext := range []string{fixtureServiceKey, fixtureToolKey, fixtureProxyPassword, fixtureToken} {
				if fileContains(t, path, []byte(plaintext)) {
					t.Fatalf("plaintext %q survived the upgrade in the database file", plaintext[:8])
				}
			}
			if got := countRows(t, store, "pending_file_scrub"); got != 0 {
				t.Fatalf("pending_file_scrub = %d after the upgrade scrub", got)
			}
			if len(logs) != 1 || logs[0] != "astrlink storage: sealed 4 stored credential(s) under the local key" {
				t.Fatalf("logs = %q", logs)
			}

			if secret, err := store.Get(ctx, secretstore.Ref(localRef(fixtureServiceID))); err != nil || string(secret) != fixtureServiceKey {
				t.Fatalf("service credential after sealing = %v", err)
			}
			if secret, err := store.Get(ctx, "local://builtin-tool/web_search"); err != nil || string(secret) != fixtureToolKey {
				t.Fatalf("tool credential after sealing = %v", err)
			}
			if secret, err := store.Get(ctx, secretstore.Ref("local://service-proxy/"+string(fixtureServiceID))); err != nil ||
				!bytes.Contains(secret, []byte(fixtureProxyPassword)) {
				t.Fatalf("proxy credential after sealing = %v", err)
			}
			manager, err := accesstoken.NewManager(store)
			if err != nil {
				t.Fatal(err)
			}
			if id, err := manager.Authenticate(ctx, fixtureToken); err != nil || id != fixtureTokenID {
				t.Fatalf("Authenticate after sealing = %q, %v", id, err)
			}
			if revealed, err := manager.Reveal(ctx, fixtureTokenID); err != nil || revealed != fixtureToken {
				t.Fatalf("Reveal after sealing = %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			// A second start rewrites nothing and asks for no scrub.
			logs = nil
			store = openWithKey(t, path, localKey, &logs)
			defer store.Close()
			again := readStoredSecrets(t, store)
			for name, secret := range secrets {
				if !bytes.Equal(again[name].value, secret.value) {
					t.Fatalf("restart rewrote %s", name)
				}
			}
			if sealed, err := store.SealPlaintextSecrets(ctx); err != nil || sealed != 0 {
				t.Fatalf("SealPlaintextSecrets on a sealed store = %d, %v", sealed, err)
			}
			if got := countRows(t, store, "pending_file_scrub"); got != 0 || len(logs) != 0 {
				t.Fatalf("restart scrub = %d, logs = %q", got, logs)
			}
		})
	}
}

func TestPlaintextRowsStayReadableUntilSealed(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "astrlink.db"))
	defer store.Close()
	mustExec(t, store, `INSERT INTO builtin_tool_credentials (kind, credential_value, sealed) VALUES ('image_generation', ?, 0)`, []byte("plain-tool-key"))
	if secret, err := store.Get(ctx, "local://builtin-tool/image_generation"); err != nil || string(secret) != "plain-tool-key" {
		t.Fatalf("plaintext row = %q, %v", secret, err)
	}
	if sealed, err := store.SealPlaintextSecrets(ctx); err != nil || sealed != 1 {
		t.Fatalf("SealPlaintextSecrets = %d, %v", sealed, err)
	}
	if got := countRows(t, store, "pending_file_scrub"); got != 1 {
		t.Fatalf("sealing a plaintext row requested %d scrubs, want 1", got)
	}
	if secret, err := store.Get(ctx, "local://builtin-tool/image_generation"); err != nil || string(secret) != "plain-tool-key" {
		t.Fatalf("sealed row = %q, %v", secret, err)
	}
}

func TestSealedValuesAreBoundToTheirRow(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "astrlink.db"))
	defer store.Close()
	for _, id := range []contract.ServiceID{"service_alpha", "service_beta"} {
		if _, err := store.CreateService(ctx, contract.ServiceFromEndpoint(testEndpoint(id)), storagecontract.CredentialMutation{
			Present: true, Secret: []byte("sk-" + string(id)),
		}); err != nil {
			t.Fatal(err)
		}
	}
	var alpha []byte
	if err := store.db.QueryRow(`SELECT credential_value FROM service_credentials WHERE service_id = 'service_alpha'`).Scan(&alpha); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(alpha, []byte("sk-service_alpha")) || len(alpha) != len("sk-service_alpha")+29 {
		t.Fatalf("stored value is not a sealed column (%d bytes)", len(alpha))
	}
	mustExec(t, store, `UPDATE service_credentials SET credential_value = ? WHERE service_id = 'service_beta'`, alpha)
	if _, err := store.Get(ctx, "local://service/service_beta"); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("a value copied from another row = %v, want ErrUnavailable", err)
	}
	status, err := store.LocalDataStatus(ctx)
	if err != nil || status.UnreadableCredentials != 1 {
		t.Fatalf("LocalDataStatus = %+v, %v", status, err)
	}
}

func TestSubscriptionCredentialsAreSealedAndFollowTheirService(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t, filepath.Join(t.TempDir(), "astrlink.db"))
	defer store.Close()
	id := contract.ServiceID("service_codex")
	if _, err := store.CreateService(ctx, contract.ServiceFromEndpoint(testEndpoint(id)), storagecontract.CredentialMutation{}); err != nil {
		t.Fatal(err)
	}
	ref := secretstore.Ref(subscriptionRefPrefix + string(id))
	tokens := []byte(`{"access_token":"PLAINTEXT-oauth-access","refresh_token":"PLAINTEXT-oauth-refresh"}`)
	if err := store.Put(ctx, ref, tokens); err != nil {
		t.Fatal(err)
	}
	var stored []byte
	if err := store.db.QueryRow(`SELECT credential_value FROM subscription_credentials WHERE service_id = ?`, id).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PLAINTEXT-oauth")) {
		t.Fatal("OAuth tokens are stored in plaintext")
	}
	if got, err := store.Get(ctx, ref); err != nil || !bytes.Equal(got, tokens) {
		t.Fatalf("Get = %v", err)
	}
	for _, bad := range []struct {
		ref    secretstore.Ref
		secret []byte
	}{
		{secretstore.Ref(subscriptionRefPrefix + "BAD ID"), tokens},
		{ref, nil},
		{ref, bytes.Repeat([]byte("x"), maxSubscriptionCredentialLen+1)},
	} {
		if err := store.Put(ctx, bad.ref, bad.secret); err == nil {
			t.Fatalf("Put(%q, %d bytes) succeeded", bad.ref, len(bad.secret))
		}
	}
	if err := store.Delete(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, ref); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("Get after Delete = %v", err)
	}
	if err := store.Delete(ctx, ref); !errors.Is(err, secretstore.ErrNotFound) {
		t.Fatalf("second Delete = %v", err)
	}

	if err := store.Put(ctx, ref, tokens); err != nil {
		t.Fatal(err)
	}
	record, err := store.GetService(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteService(ctx, id, record.ETag); err != nil {
		t.Fatal(err)
	}
	if got := countRows(t, store, subscriptionCredentialsTable); got != 0 {
		t.Fatalf("deleting the service left %d subscription credentials", got)
	}
}

func TestLostLocalKeyLeavesSecretsUnavailableUntilReentered(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	writePlaintextSecretsFixture(t, path, 44)
	store := openWithKey(t, path, testLocalKey(t, 0x31), nil)
	ref := secretstore.Ref(subscriptionRefPrefix + string(fixtureServiceID))
	if err := store.Put(ctx, ref, []byte(`{"access_token":"a","refresh_token":"r"}`)); err != nil {
		t.Fatal(err)
	}
	if status, err := store.LocalDataStatus(ctx); err != nil || status != (contract.LocalDataStatus{}) {
		t.Fatalf("LocalDataStatus with the right key = %+v, %v", status, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = openWithKey(t, path, testLocalKey(t, 0x32), nil)
	defer store.Close()
	for _, ref := range []secretstore.Ref{
		secretstore.Ref(localRef(fixtureServiceID)),
		"local://builtin-tool/web_search",
		secretstore.Ref("local://service-proxy/" + string(fixtureServiceID)),
		ref,
	} {
		if _, err := store.Get(ctx, ref); !errors.Is(err, secretstore.ErrUnavailable) {
			t.Fatalf("Get(%s) under a replacement key = %v, want ErrUnavailable", ref, err)
		}
	}
	status, err := store.LocalDataStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if status != (contract.LocalDataStatus{UnreadableCredentials: 4, UnreadableAccessTokens: 1, AuditKeyMissing: true}) {
		t.Fatalf("LocalDataStatus under a replacement key = %+v", status)
	}
	manager, err := accesstoken.NewManager(store)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := manager.Authenticate(ctx, fixtureToken); err != nil || id != fixtureTokenID {
		t.Fatalf("Authenticate under a replacement key = %q, %v", id, err)
	}
	if _, err := manager.Reveal(ctx, fixtureTokenID); !errors.Is(err, secretstore.ErrUnavailable) {
		t.Fatalf("Reveal under a replacement key = %v", err)
	}

	// Entering the credential again stores it under the new key.
	if err := store.Put(ctx, secretstore.Ref(localRef(fixtureServiceID)), []byte("sk-entered-again")); err != nil {
		t.Fatal(err)
	}
	if secret, err := store.Get(ctx, secretstore.Ref(localRef(fixtureServiceID))); err != nil || string(secret) != "sk-entered-again" {
		t.Fatalf("re-entered credential = %v", err)
	}
	if status, err := store.LocalDataStatus(ctx); err != nil || status.UnreadableCredentials != 3 {
		t.Fatalf("LocalDataStatus after re-entry = %+v, %v", status, err)
	}
}

func BenchmarkSecretGet(b *testing.B) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(b.TempDir(), "astrlink.db"), WithLocalKey(bytes.Repeat([]byte{0x41}, 32)), WithLogger(func(string, ...any) {}))
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	for _, id := range []contract.ServiceID{"service_plain", "service_sealed"} {
		if _, err := store.CreateService(ctx, contract.ServiceFromEndpoint(testEndpoint(id)), storagecontract.CredentialMutation{
			Present: true, Secret: []byte("sk-benchmark-" + string(id) + "-0123456789abcdef0123456789abcdef"),
		}); err != nil {
			b.Fatal(err)
		}
	}
	// service_plain keeps the pre-sealing layout: the same read without the
	// AES-GCM open.
	if _, err := store.db.Exec(`UPDATE service_credentials SET credential_value = ?, sealed = 0 WHERE service_id = 'service_plain'`,
		[]byte("sk-benchmark-service_plain-0123456789abcdef0123456789abcdef")); err != nil {
		b.Fatal(err)
	}
	for _, id := range []string{"plain", "sealed"} {
		ref := secretstore.Ref("local://service/service_" + id)
		b.Run(id, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				secret, err := store.Get(ctx, ref)
				if err != nil {
					b.Fatal(err)
				}
				clear(secret)
			}
		})
	}
}
