package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/QuantumNous/astrlink/core/contract"
	"github.com/QuantumNous/astrlink/core/internal/secretstore"
	storagecontract "github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/migrate"
	"github.com/QuantumNous/astrlink/core/internal/storage/rawseal"
)

const (
	unsealAccount   = contract.ServiceID("service_codex_unseal")
	unsealRequestID = contract.RequestID("request_unseal")
	unsealRawPrompt = "PLAINTEXT raw prompt"
)

var unsealTokens = `{"access_token":"PLAINTEXT-oauth-access","refresh_token":"PLAINTEXT-oauth-refresh","expires_at":"2026-09-30T00:00:00Z"}`

// sealedUnsealFixture builds what a user of this release has: the older
// release's plaintext secrets, now sealed, a connected account whose tokens
// moved into the database, and a raw part next to a shareable one.
func sealedUnsealFixture(t *testing.T, path string, localKey []byte) (*Store, rawTestKey) {
	t.Helper()
	ctx := context.Background()
	writePlaintextSecretsFixture(t, path, unsealTargetVersion)
	store := openWithKey(t, path, localKey, nil)
	now := time.Now().UTC()
	if _, err := store.CreateService(ctx, contract.Service{
		ID: unsealAccount, Name: "Codex", Kind: contract.ServiceKindCodexSubscription,
		Enabled: true, Models: []string{"gpt-5"}, Capabilities: contract.DefaultOpenAICodexCapabilities(),
		Subscription: &contract.SubscriptionConnection{
			Provider: contract.SubscriptionProviderOpenAICodex, Status: contract.SubscriptionStatusConnected,
			ProviderAccountID: "acct_unseal_123456", CredentialRef: subscriptionRefPrefix + string(unsealAccount), TokenExpiresAt: &now,
		},
	}, storagecontract.CredentialMutation{}); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(ctx, secretstore.Ref(subscriptionRefPrefix+string(unsealAccount)), []byte(unsealTokens)); err != nil {
		t.Fatal(err)
	}
	insertRecord(t, store, unsealRequestID, contract.RequestStatusSucceeded)
	auditKey, err := store.GetAuditKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := createRawTestKey(t, store, 51)
	insertRawTestBlob(t, store, sealedPayload(t, auditKey, unsealRequestID, storagecontract.AuditDirectionRequest, unsealRawPrompt), storagecontract.AuditExposureRaw)
	insertRawTestBlob(t, store, sealedPayload(t, auditKey, unsealRequestID, storagecontract.AuditDirectionUpstreamRequest, "shareable prompt"), storagecontract.AuditExposureShareable)
	return store, key
}

func openUnsealedDatabase(t *testing.T, path string) *sql.DB {
	t.Helper()
	database, err := sql.Open(driverName, sqliteFileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func releasedMigrations() []migrate.Migration {
	var released []migrate.Migration
	for _, migration := range migrate.DefaultMigrations() {
		if migration.Version <= unsealTargetVersion {
			released = append(released, migration)
		}
	}
	return released
}

// readSchema lists every schema object as type, name, table and definition.
func readSchema(t *testing.T, database *sql.DB) []string {
	t.Helper()
	rows, err := database.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var schema []string
	for rows.Next() {
		var kind, name, table, definition string
		if err := rows.Scan(&kind, &name, &table, &definition); err != nil {
			t.Fatal(err)
		}
		schema = append(schema, fmt.Sprintf("%s %s ON %s: %s", kind, name, table, definition))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return schema
}

// assertReleasedSchema compares the database with one the older release
// migrated itself, and runs that release's migrations over it.
func assertReleasedSchema(t *testing.T, database *sql.DB) {
	t.Helper()
	fresh := openUnsealedDatabase(t, filepath.Join(t.TempDir(), "released.db"))
	runner, err := migrate.New(migrate.SQLDatabase{DB: fresh}, releasedMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	want, got := readSchema(t, fresh), readSchema(t, database)
	if !slices.Equal(got, want) {
		for _, entry := range got {
			if !slices.Contains(want, entry) {
				t.Errorf("unexpected: %s", entry)
			}
		}
		for _, entry := range want {
			if !slices.Contains(got, entry) {
				t.Errorf("missing: %s", entry)
			}
		}
		t.Fatal("the unsealed schema differs from migration 41")
	}
	runner, err = migrate.New(migrate.SQLDatabase{DB: database}, releasedMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(context.Background()); err != nil {
		t.Fatalf("the older release's migrations reject the unsealed database: %v", err)
	}
	var version int64
	if err := database.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != unsealTargetVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	if rows, err := database.Query(`PRAGMA foreign_key_check`); err != nil || rows.Next() {
		t.Fatalf("foreign key check after unseal failed: %v", err)
	} else {
		_ = rows.Close()
	}
}

func auditPartsUnderKey(t *testing.T, database *sql.DB, auditKey []byte) map[storagecontract.AuditDirection]string {
	t.Helper()
	rows, err := database.Query(`SELECT b.direction, p.nonce, p.ciphertext
FROM audit_blobs b JOIN audit_payloads p ON p.id = b.payload_id WHERE b.request_id = ?`, unsealRequestID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	parts := map[storagecontract.AuditDirection]string{}
	for rows.Next() {
		var direction string
		var nonce, ciphertext []byte
		if err := rows.Scan(&direction, &nonce, &ciphertext); err != nil {
			t.Fatal(err)
		}
		plain, err := storagecontract.OpenAuditBlob(auditKey, nonce, ciphertext)
		if err != nil {
			t.Fatalf("%s does not open under audit_keys: %v", direction, err)
		}
		parts[storagecontract.AuditDirection(direction)] = string(plain)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return parts
}

func TestUnsealLeavesTheDatabaseAsTheOlderReleaseMigratedIt(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	localKey := testLocalKey(t, 0x71)
	store, rawKey := sealedUnsealFixture(t, path, localKey)
	auditKey, err := store.GetAuditKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exported := map[contract.SubscriptionAccountID]string{}
	options := UnsealOptions{
		OpenRawPart: func(blob storagecontract.AuditBlob) ([]byte, error) {
			return rawseal.OpenBlobKey(rawKey.private, rawseal.BlobKeyInfo(string(blob.RequestID), string(blob.Direction)), blob.WrappedKey)
		},
		ExportSubscription: func(_ context.Context, id contract.SubscriptionAccountID, tokens []byte) error {
			exported[id] = string(tokens)
			return nil
		},
	}
	result, err := store.Unseal(ctx, options)
	if err != nil || result != (UnsealResult{Credentials: 4, Subscriptions: 1, RawParts: 1}) {
		t.Fatalf("Unseal = %+v, %v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	database := openUnsealedDatabase(t, path)
	assertReleasedSchema(t, database)
	for _, secret := range []struct{ query, want string }{
		{`SELECT credential_value FROM service_credentials`, fixtureServiceKey},
		{`SELECT credential_value FROM builtin_tool_credentials`, fixtureToolKey},
		{`SELECT json_extract(CAST(credential_value AS TEXT), '$.password') FROM service_proxy_credentials`, fixtureProxyPassword},
		{`SELECT token_value FROM local_access_token_secrets WHERE typeof(token_value) = 'text'`, fixtureToken},
		{`SELECT json_extract(document_json, '$.subscription.credential_ref') FROM services WHERE id = '` + string(unsealAccount) + `'`,
			legacySubscriptionRefPrefix + string(unsealAccount)},
	} {
		var got string
		if err := database.QueryRow(secret.query).Scan(&got); err != nil || got != secret.want {
			t.Fatalf("%s: got %d bytes, %v", secret.query, len(got), err)
		}
	}
	if exported[unsealAccount] != unsealTokens || len(exported) != 1 {
		t.Fatalf("exported %d account(s)", len(exported))
	}
	var restored []byte
	if err := database.QueryRow(`SELECT key_bytes FROM audit_keys WHERE id = 1`).Scan(&restored); err != nil || !slices.Equal(restored, auditKey) {
		t.Fatalf("audit_keys is not dek_audit: %v", err)
	}
	parts := auditPartsUnderKey(t, database, auditKey)
	if parts[storagecontract.AuditDirectionRequest] != unsealRawPrompt || parts[storagecontract.AuditDirectionUpstreamRequest] != "shareable prompt" {
		t.Fatalf("parts under audit_keys = %q", parts)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	// This release upgrades the rolled-back database again, and unsealing
	// from there arrives at the same schema.
	store = openWithKey(t, path, localKey, nil)
	defer store.Close()
	if secret, err := store.Get(ctx, secretstore.Ref(localRef(fixtureServiceID))); err != nil || string(secret) != fixtureServiceKey {
		t.Fatalf("service credential after upgrading again = %v", err)
	}
	if again, err := store.GetAuditKey(ctx); err != nil || !slices.Equal(again, auditKey) {
		t.Fatalf("upgrading again did not adopt audit_keys: %v", err)
	}
	exported = map[contract.SubscriptionAccountID]string{}
	if result, err := store.Unseal(ctx, options); err != nil || result != (UnsealResult{Credentials: 4}) {
		t.Fatalf("second Unseal = %+v, %v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	assertReleasedSchema(t, openUnsealedDatabase(t, path))
}

func TestUnsealStopsBeforeDroppingWhatItCannotRead(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store, _ := sealedUnsealFixture(t, path, testLocalKey(t, 0x72))
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// Another local key: every sealed value is unreadable and both data keys
	// are set aside.
	store = openWithKey(t, path, testLocalKey(t, 0x73), nil)
	defer store.Close()
	exports := 0
	options := UnsealOptions{ExportSubscription: func(context.Context, contract.SubscriptionAccountID, []byte) error {
		exports++
		return nil
	}}
	want := UnsealUnreadable{Credentials: 4, Subscriptions: 1, RawParts: 1, SetAsideKeys: 2}
	_, err := store.Unseal(ctx, options)
	var unreadable *UnsealUnreadableError
	if !errors.As(err, &unreadable) || unreadable.Unreadable != want {
		t.Fatalf("Unseal with unreadable data = %v", err)
	}
	var version int64
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil || version != unsealSourceVersion {
		t.Fatalf("a refused unseal changed the schema version to %d, %v", version, err)
	}
	if exports != 0 || countRows(t, store, "key_envelopes") != 4 || countRows(t, store, subscriptionCredentialsTable) != 1 ||
		countRows(t, store, "audit_payloads") != 2 {
		t.Fatal("a refused unseal changed the database")
	}

	options.DiscardUnreadable = true
	result, err := store.Unseal(ctx, options)
	if err != nil || result != (UnsealResult{Discarded: want}) || exports != 0 {
		t.Fatalf("Unseal discarding = %+v, %v (exports %d)", result, err, exports)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database := openUnsealedDatabase(t, path)
	assertReleasedSchema(t, database)
	for _, table := range []string{serviceCredentialsTable, builtinToolCredentialsTable, serviceProxyCredentialsTable,
		accessTokenSecretsTable, "local_access_tokens"} {
		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s kept %d unreadable row(s), %v", table, count, err)
		}
	}
	var directions []string
	rows, err := database.Query(`SELECT direction FROM audit_blobs WHERE request_id = ? ORDER BY direction`, unsealRequestID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var direction string
		if err := rows.Scan(&direction); err != nil {
			t.Fatal(err)
		}
		directions = append(directions, direction)
	}
	_ = rows.Close()
	if !slices.Equal(directions, []string{string(storagecontract.AuditDirectionUpstreamRequest)}) {
		t.Fatalf("parts after discarding = %q", directions)
	}
	var captured, upstreamCaptured bool
	if err := database.QueryRow(`SELECT json_extract(audit_json, '$.request_body_captured'), json_extract(audit_json, '$.upstream_request_body_captured')
FROM request_records WHERE id = ?`, unsealRequestID).Scan(&captured, &upstreamCaptured); err != nil || captured || !upstreamCaptured {
		t.Fatalf("capture flags after discarding = %t, %t, %v", captured, upstreamCaptured, err)
	}
	var ref string
	if err := database.QueryRow(`SELECT json_extract(document_json, '$.subscription.credential_ref') FROM services WHERE id = ?`, unsealAccount).
		Scan(&ref); err != nil || ref != legacySubscriptionRefPrefix+string(unsealAccount) {
		t.Fatalf("credential_ref of a discarded account = %q, %v", ref, err)
	}
}

func TestUnsealRollsBackWhenAnExportFails(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store, rawKey := sealedUnsealFixture(t, path, testLocalKey(t, 0x74))
	defer store.Close()
	before := readStoredSecrets(t, store)
	_, err := store.Unseal(ctx, UnsealOptions{
		OpenRawPart: func(blob storagecontract.AuditBlob) ([]byte, error) {
			return rawseal.OpenBlobKey(rawKey.private, rawseal.BlobKeyInfo(string(blob.RequestID), string(blob.Direction)), blob.WrappedKey)
		},
		ExportSubscription: func(context.Context, contract.SubscriptionAccountID, []byte) error {
			return errors.New("keystore locked")
		},
	})
	if err == nil {
		t.Fatal("Unseal succeeded although the export failed")
	}
	after := readStoredSecrets(t, store)
	for name, secret := range before {
		if after[name].sealed != 1 || !slices.Equal(after[name].value, secret.value) {
			t.Fatalf("a failed unseal changed %s", name)
		}
	}
	var sealing string
	if err := store.db.QueryRow(`SELECT p.sealing FROM audit_blobs b JOIN audit_payloads p ON p.id = b.payload_id
WHERE b.request_id = ? AND b.direction = 'request'`, unsealRequestID).Scan(&sealing); err != nil || sealing != string(storagecontract.AuditSealingRawV1) {
		t.Fatalf("a failed unseal resealed the raw part: %q, %v", sealing, err)
	}
	// The store still works on the schema it opened.
	if secret, err := store.Get(ctx, secretstore.Ref(localRef(fixtureServiceID))); err != nil || string(secret) != fixtureServiceKey {
		t.Fatalf("Get after a failed unseal = %v", err)
	}
}
