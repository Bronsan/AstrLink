package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/astrlink/core/contract"
	"github.com/QuantumNous/astrlink/core/internal/localkey"
	storage "github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/envelope"
	"github.com/QuantumNous/astrlink/core/internal/storage/migrate"
)

const upgradeRequestID = contract.RequestID("request_before_envelopes")

// knownPrompt stands in for a captured prompt; it must only exist encrypted.
const knownPrompt = "ZEBRA-QUARTZ upgrade prompt fragment"

type envelopeRow struct {
	kind, createdAt string
	nonce, wrapped  []byte
}

func testLocalKey(t *testing.T, fill byte) []byte {
	t.Helper()
	return bytes.Repeat([]byte{fill}, envelope.KeyBytes)
}

// writeV42Fixture builds a database as the release before envelopes left it:
// a plaintext audit_keys row and a captured body sealed under it.
func writeV42Fixture(t *testing.T, path string) (auditKey []byte) {
	t.Helper()
	database, err := sql.Open(driverName, sqliteFileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	migrations := migrate.DefaultMigrations()
	var released []migrate.Migration
	for _, migration := range migrations {
		if migration.Version <= 42 {
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
	auditKey, err = envelope.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO audit_keys (id, key_bytes, created_at) VALUES (1, ?, '2026-09-20T00:00:00Z')`, auditKey); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO request_records (id, started_at, status, input_protocol, streaming, audit_json, created_at)
VALUES (?, '2026-09-20T00:00:00Z', 'succeeded', 'openai.responses', 0, '{}', '2026-09-20T00:00:00Z')`, upgradeRequestID); err != nil {
		t.Fatal(err)
	}
	blob := sealedPayload(t, auditKey, upgradeRequestID, storage.AuditDirectionRequest, knownPrompt)
	if _, err := database.Exec(`INSERT INTO audit_blobs (request_id, direction, media_type, nonce, ciphertext, truncated, captured_bytes, created_at)
VALUES (?, ?, ?, ?, ?, 0, ?, '2026-09-20T00:00:00Z')`,
		blob.RequestID, blob.Direction, blob.MediaType, blob.Nonce, blob.Ciphertext, blob.CapturedBytes); err != nil {
		t.Fatal(err)
	}
	return auditKey
}

func openWithKey(t *testing.T, path string, localKey []byte, logs *[]string) *Store {
	t.Helper()
	store, err := Open(context.Background(), path, WithLocalKey(localKey), WithLogger(func(format string, args ...any) {
		if logs != nil {
			*logs = append(*logs, fmt.Sprintf(format, args...))
		}
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return store
}

func readEnvelopes(t *testing.T, store *Store) map[string]envelopeRow {
	t.Helper()
	rows, err := store.db.Query(`SELECT kind, nonce, wrapped, created_at FROM key_envelopes`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	envelopes := map[string]envelopeRow{}
	for rows.Next() {
		var row envelopeRow
		if err := rows.Scan(&row.kind, &row.nonce, &row.wrapped, &row.createdAt); err != nil {
			t.Fatal(err)
		}
		envelopes[row.kind] = row
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return envelopes
}

func countRows(t *testing.T, store *Store, table string) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// fileContains reports whether the database or its WAL holds needle.
func fileContains(t *testing.T, path string, needle []byte) bool {
	t.Helper()
	for _, candidate := range []string{path, path + "-wal"} {
		content, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(content, needle) {
			return true
		}
	}
	return false
}

func assertUpgradeBodyReadable(t *testing.T, store *Store, auditKey []byte) {
	t.Helper()
	key, err := store.GetAuditKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, auditKey) {
		t.Fatal("dek_audit differs from the adopted audit_keys value")
	}
	assertAuditPlaintexts(t, store, key, upgradeRequestID, map[storage.AuditDirection]string{
		storage.AuditDirectionRequest: knownPrompt,
	})
}

func TestUpgradeMovesAuditKeyIntoEnvelopeAndScrubsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	localKey := testLocalKey(t, 0x11)

	store := openWithKey(t, path, localKey, nil)
	if got := countRows(t, store, "audit_keys"); got != 0 {
		t.Fatalf("audit_keys keeps %d row(s)", got)
	}
	envelopes := readEnvelopes(t, store)
	if len(envelopes) != 2 {
		t.Fatalf("key_envelopes = %d rows, want secrets and audit", len(envelopes))
	}
	audit := envelopes[envelope.KindAudit]
	dek, err := envelope.Unwrap(localKey, audit.nonce, audit.wrapped, envelope.KindAudit)
	if err != nil || !bytes.Equal(dek, auditKey) {
		t.Fatalf("audit envelope does not hold the adopted key: %v", err)
	}
	secrets := envelopes[envelope.KindSecrets]
	if _, err := envelope.Unwrap(localKey, secrets.nonce, secrets.wrapped, envelope.KindSecrets); err != nil {
		t.Fatalf("secrets envelope: %v", err)
	}
	assertUpgradeBodyReadable(t, store, auditKey)
	if store.HasOrphanedAuditKey() {
		t.Fatal("a clean upgrade reports an orphaned audit key")
	}
	if got := countRows(t, store, "pending_file_scrub"); got != 0 {
		t.Fatal("the file scrub did not finish")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if fileContains(t, path, auditKey) {
		t.Fatal("the plaintext audit key survives in the database file")
	}
	if fileContains(t, path, []byte(knownPrompt)) {
		t.Fatal("a captured prompt is stored in plaintext")
	}
	if _, err := os.Stat(path + ".scrub"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scrub copy left behind: %v", err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		if info, err := os.Stat(candidate); err == nil && info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %04o", filepath.Base(candidate), info.Mode().Perm())
		}
	}
}

func TestRestartKeepsEnvelopesUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	localKey := testLocalKey(t, 0x22)
	store := openWithKey(t, path, localKey, nil)
	before := readEnvelopes(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		var logs []string
		store = openWithKey(t, path, localKey, &logs)
		after := readEnvelopes(t, store)
		if len(after) != len(before) {
			t.Fatalf("restart %d: %d envelopes, want %d", attempt, len(after), len(before))
		}
		for kind, row := range before {
			got := after[kind]
			if !bytes.Equal(got.nonce, row.nonce) || !bytes.Equal(got.wrapped, row.wrapped) || got.createdAt != row.createdAt {
				t.Fatalf("restart %d rewrote the %s envelope", attempt, kind)
			}
		}
		assertUpgradeBodyReadable(t, store, auditKey)
		if len(logs) != 0 {
			t.Fatalf("restart %d logged %q", attempt, logs)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFreshDatabaseCreatesBothEnvelopesWithoutAScrub(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store := openWithKey(t, path, testLocalKey(t, 0x33), nil)
	defer store.Close()
	envelopes := readEnvelopes(t, store)
	if _, ok := envelopes[envelope.KindSecrets]; !ok {
		t.Fatal("missing secrets envelope")
	}
	if _, ok := envelopes[envelope.KindAudit]; !ok {
		t.Fatal("missing audit envelope")
	}
	first, err := store.GetOrCreateAuditKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.GetAuditKey(context.Background())
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("GetAuditKey() differs from GetOrCreateAuditKey(): %v", err)
	}
	if countRows(t, store, "audit_keys") != 0 || countRows(t, store, "pending_file_scrub") != 0 {
		t.Fatal("a fresh database wrote a plaintext key or asked for a scrub")
	}
}

func TestOpenWithoutAKeyUsesLocalKeyFileBesideTheDatabase(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "astrlink.db")
	store := openTestStore(t, path)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(filepath.Join(directory, localkey.FileName))
	if err != nil {
		t.Fatalf("local.key was not created: %v", err)
	}
	key, err := localkey.Parse(content)
	if err != nil {
		t.Fatal(err)
	}
	store = openWithKey(t, path, key, nil)
	defer store.Close()
	if store.HasOrphanedAuditKey() || len(readEnvelopes(t, store)) != 2 {
		t.Fatal("the generated local.key does not open its own envelopes")
	}
}

func TestMissingLocalKeySetsEnvelopesAsideAndReportsTheAuditKeyMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	original := testLocalKey(t, 0x44)
	store := openWithKey(t, path, original, nil)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	var logs []string
	replacement := testLocalKey(t, 0x55)
	store = openWithKey(t, path, replacement, &logs)
	envelopes := readEnvelopes(t, store)
	var orphaned []string
	for kind := range envelopes {
		if strings.Contains(kind, ".orphaned.") {
			orphaned = append(orphaned, strings.SplitN(kind, ".", 2)[0])
		}
	}
	if len(envelopes) != 4 || len(orphaned) != 2 {
		t.Fatalf("envelopes = %v, want two current and two orphaned", envelopes)
	}
	if !store.HasOrphanedAuditKey() {
		t.Fatal("HasOrphanedAuditKey() = false after the local key changed")
	}
	key, err := store.GetAuditKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, auditKey) {
		t.Fatal("a replacement local key recovered the old audit key")
	}
	blobs, err := store.GetAuditBlobsByRequest(context.Background(), upgradeRequestID)
	if err != nil || len(blobs) != 1 {
		t.Fatalf("metadata was lost: %d blobs, %v", len(blobs), err)
	}
	if _, err := storage.OpenAuditBlob(key, blobs[0].Nonce, blobs[0].Ciphertext); !errors.Is(err, storage.ErrAuditDecrypt) {
		t.Fatalf("old body opened under the new key: %v", err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "could not be decrypted") || strings.Contains(logs[0], "key") {
		t.Fatalf("logs = %q", logs)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// Restarting with the replacement key is stable.
	store = openWithKey(t, path, replacement, nil)
	if got := len(readEnvelopes(t, store)); got != 4 {
		t.Fatalf("restart with the replacement key changed envelopes to %d", got)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	// The original key coming back restores its envelopes.
	store = openWithKey(t, path, original, nil)
	defer store.Close()
	assertUpgradeBodyReadable(t, store, auditKey)
	if got := len(readEnvelopes(t, store)); got != 4 {
		t.Fatalf("recovery left %d envelopes, want 4", got)
	}
}

func TestStrayLegacyAuditKeyIsWrappedNotKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	localKey := testLocalKey(t, 0x66)
	store := openWithKey(t, path, localKey, nil)
	// An older build ran in between and created its own plaintext key.
	stray := testLocalKey(t, 0x77)
	if _, err := store.db.Exec(`INSERT INTO audit_keys (id, key_bytes, created_at) VALUES (1, ?, '2026-09-21T00:00:00Z')`, stray); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store = openWithKey(t, path, localKey, nil)
	defer store.Close()
	assertUpgradeBodyReadable(t, store, auditKey)
	if countRows(t, store, "audit_keys") != 0 {
		t.Fatal("the stray plaintext key was kept")
	}
	var found bool
	for kind, row := range readEnvelopes(t, store) {
		if strings.HasPrefix(kind, "audit.legacy.") {
			dek, err := envelope.Unwrap(localKey, row.nonce, row.wrapped, envelope.KindAudit)
			found = err == nil && bytes.Equal(dek, stray)
		}
	}
	if !found {
		t.Fatal("the stray key was not kept wrapped for recovery")
	}
	if fileContains(t, path, stray) {
		t.Fatal("the stray plaintext key survives in the file")
	}
}

func TestAWrappedLegacyKeyIsNeverRestoredAsTheAuditKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	original := testLocalKey(t, 0x68)
	store := openWithKey(t, path, original, nil)
	stray := testLocalKey(t, 0x79)
	if _, err := store.db.Exec(`INSERT INTO audit_keys (id, key_bytes, created_at) VALUES (1, ?, '2026-09-21T00:00:00Z')`, stray); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The stray key is wrapped under the original local key, newer than the
	// audit envelope, so it is the first row a loose match would try.
	for _, key := range [][]byte{original, testLocalKey(t, 0x5A)} {
		store = openWithKey(t, path, key, nil)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}

	store = openWithKey(t, path, original, nil)
	defer store.Close()
	assertUpgradeBodyReadable(t, store, auditKey)
	legacy := 0
	for kind, row := range readEnvelopes(t, store) {
		if !strings.HasPrefix(kind, "audit.legacy.") {
			continue
		}
		legacy++
		if dek, err := envelope.Unwrap(original, row.nonce, row.wrapped, envelope.KindAudit); err != nil || !bytes.Equal(dek, stray) {
			t.Fatalf("the legacy envelope changed: %v", err)
		}
	}
	if legacy != 1 {
		t.Fatalf("legacy envelopes = %d, want the one kept for recovery", legacy)
	}
}

func TestInterruptedScrubKeepsTheOriginalAndRetries(t *testing.T) {
	for _, step := range []string{"before_close", "before_replace", "after_replace"} {
		t.Run(step, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "astrlink.db")
			auditKey := writeV42Fixture(t, path)
			localKey := testLocalKey(t, 0x88)
			interrupted := errors.New("simulated crash")
			scrubHook = func(current string) error {
				if current == step {
					return interrupted
				}
				return nil
			}
			var logs []string
			store := openWithKey(t, path, localKey, &logs)
			scrubHook = nil
			if len(logs) != 1 || !strings.Contains(logs[0], "simulated crash") {
				t.Fatalf("logs = %q", logs)
			}
			// The store keeps working, on the original or the complete copy.
			assertUpgradeBodyReadable(t, store, auditKey)
			if countRows(t, store, "audit_keys") != 0 {
				t.Fatal("the interrupted scrub restored the plaintext key row")
			}
			if countRows(t, store, "pending_file_scrub") != 1 {
				t.Fatal("the interrupted scrub dropped its request")
			}
			if _, err := os.Stat(path + ".scrub"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("scrub copy left behind: %v", err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
			// Until the copy replaces it, the original still holds the freed
			// key bytes, which shows the grep below can find them.
			if step != "after_replace" && !fileContains(t, path, auditKey) {
				t.Fatal("the original file no longer holds the deleted key")
			}

			store = openWithKey(t, path, localKey, nil)
			defer store.Close()
			assertUpgradeBodyReadable(t, store, auditKey)
			if countRows(t, store, "pending_file_scrub") != 0 {
				t.Fatal("the retry did not finish the scrub")
			}
			if fileContains(t, path, auditKey) {
				t.Fatal("the plaintext audit key survives the retried scrub")
			}
		})
	}
}

func TestScrubReplacesAStaleCopyFromACrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	if err := os.WriteFile(path+".scrub", []byte("half-written copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := openWithKey(t, path, testLocalKey(t, 0x99), nil)
	defer store.Close()
	assertUpgradeBodyReadable(t, store, auditKey)
	if countRows(t, store, "pending_file_scrub") != 0 {
		t.Fatal("a stale copy blocked the scrub")
	}
	if _, err := os.Stat(path + ".scrub"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale copy left behind: %v", err)
	}
}

func TestScrubWaitsWhileAnotherConnectionHasTheFileOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	auditKey := writeV42Fixture(t, path)
	other, err := sql.Open(driverName, sqliteFileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	connection, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	var logs []string
	store := openWithKey(t, path, testLocalKey(t, 0xaa), &logs)
	if len(logs) != 1 || !strings.Contains(logs[0], errScrubBusy.Error()) {
		t.Fatalf("logs = %q", logs)
	}
	assertUpgradeBodyReadable(t, store, auditKey)
	if countRows(t, store, "pending_file_scrub") != 1 {
		t.Fatal("a busy scrub dropped its request")
	}
	// The other connection still sees the same file.
	var envelopes int
	if err := connection.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM key_envelopes`).Scan(&envelopes); err != nil || envelopes != 2 {
		t.Fatalf("other connection sees %d envelopes: %v", envelopes, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	_ = other.Close()

	store = openWithKey(t, path, testLocalKey(t, 0xaa), nil)
	defer store.Close()
	if countRows(t, store, "pending_file_scrub") != 0 {
		t.Fatal("the scrub did not run once the file was free")
	}
}

func TestExistingDatabaseOpenNeverCreatesOrSetsAside(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	path := filepath.Join(directory, "astrlink.db")
	if _, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 1)), WithExistingDatabase()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database: %v", err)
	}
	if entries, _ := os.ReadDir(directory); len(entries) != 0 {
		t.Fatalf("a missing database left %d file(s) behind", len(entries))
	}
	if _, err := Open(ctx, path, WithExistingDatabase()); !errors.Is(err, storage.ErrInvalidArgument) {
		t.Fatalf("open without a local key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, localkey.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("an existing-database open created a local key")
	}

	store := openWithKey(t, path, testLocalKey(t, 1), nil)
	before := readEnvelopes(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 2)), WithExistingDatabase()); !errors.Is(err, ErrLocalKeyMismatch) {
		t.Fatalf("wrong local key: %v", err)
	}
	store, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 1)), WithExistingDatabase())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	after := readEnvelopes(t, store)
	if len(after) != len(before) || store.HasOrphanedAuditKey() {
		t.Fatalf("envelopes changed: before=%d after=%d", len(before), len(after))
	}
	for kind, row := range before {
		if !bytes.Equal(after[kind].wrapped, row.wrapped) {
			t.Fatalf("%s envelope was rewritten", kind)
		}
	}
}

// databaseFiles reads the database and its WAL; the -shm index is left out
// because every reader updates it.
func databaseFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	for _, candidate := range []string{path, path + "-wal"} {
		content, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(candidate)] = content
	}
	return files
}

func assertDatabaseFilesUnchanged(t *testing.T, path string, before map[string][]byte) {
	t.Helper()
	after := databaseFiles(t, path)
	for name, content := range before {
		if !bytes.Equal(after[name], content) {
			t.Fatalf("a read-only open changed %s", name)
		}
	}
}

func TestReadOnlyOpenReadsBesideAServingStoreAndWritesNothing(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	path := filepath.Join(directory, "astrlink.db")
	if _, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 1)), WithReadOnly()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing database: %v", err)
	}
	if entries, _ := os.ReadDir(directory); len(entries) != 0 {
		t.Fatalf("a missing database left %d file(s) behind", len(entries))
	}

	// A serving Core keeps the database open, with its latest writes still
	// in the WAL.
	serving := openWithKey(t, path, testLocalKey(t, 1), nil)
	defer serving.Close()
	auditKey, err := serving.GetAuditKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := serving.InsertRequestRecord(ctx, contract.RequestRecord{
		ID: upgradeRequestID, StartedAt: time.Now().UTC(), Status: contract.RequestStatusSucceeded,
		InputProtocol: contract.ProtocolOpenAIChat,
	}); err != nil {
		t.Fatal(err)
	}
	if err := serving.InsertAuditBlob(ctx, sealedPayload(t, auditKey, upgradeRequestID, storage.AuditDirectionRequest, knownPrompt)); err != nil {
		t.Fatal(err)
	}
	before := databaseFiles(t, path)
	if len(before["astrlink.db-wal"]) == 0 {
		t.Fatal("the serving store left nothing in the WAL")
	}

	if _, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 2)), WithReadOnly()); !errors.Is(err, ErrLocalKeyMismatch) {
		t.Fatalf("wrong local key: %v", err)
	}
	reader, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 1)), WithReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	assertUpgradeBodyReadable(t, reader, auditKey)
	if err := reader.InsertRequestRecord(ctx, contract.RequestRecord{
		ID: "request_read_only_write", StartedAt: time.Now().UTC(), Status: contract.RequestStatusSucceeded,
		InputProtocol: contract.ProtocolOpenAIChat,
	}); err == nil {
		t.Fatal("a read-only store wrote a request record")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	assertDatabaseFilesUnchanged(t, path, before)
	if err := serving.InsertRequestRecord(ctx, contract.RequestRecord{
		ID: "request_after_reader", StartedAt: time.Now().UTC(), Status: contract.RequestStatusSucceeded,
		InputProtocol: contract.ProtocolOpenAIChat,
	}); err != nil {
		t.Fatalf("the serving store cannot write after a reader: %v", err)
	}
}

// writeCurrentFixtureWithoutKeys migrates a database to the current schema
// without the store's key setup, as if a Core stopped right after migrating.
func writeCurrentFixtureWithoutKeys(t *testing.T, path string, legacyAuditKey bool) {
	t.Helper()
	database, err := sql.Open(driverName, sqliteFileDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	runner, err := migrate.New(migrate.SQLDatabase{DB: database}, migrate.DefaultMigrations())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Up(context.Background()); err != nil {
		t.Fatal(err)
	}
	if legacyAuditKey {
		if _, err := database.Exec(`INSERT INTO audit_keys (id, key_bytes, created_at) VALUES (1, ?, '2026-09-20T00:00:00Z')`,
			testLocalKey(t, 9)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReadOnlyOpenRefusesADatabaseThatNeedsACoreStart(t *testing.T) {
	ctx := context.Background()
	for _, testCase := range []struct {
		name     string
		write    func(t *testing.T, path string)
		fragment string
	}{
		{"older schema", func(t *testing.T, path string) { writeV42Fixture(t, path) }, "older"},
		{"plaintext audit key", func(t *testing.T, path string) { writeCurrentFixtureWithoutKeys(t, path, true) }, "plaintext audit key"},
		{"no data keys", func(t *testing.T, path string) { writeCurrentFixtureWithoutKeys(t, path, false) }, "has not been created"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "astrlink.db")
			testCase.write(t, path)
			before := databaseFiles(t, path)
			_, err := Open(ctx, path, WithLocalKey(testLocalKey(t, 1)), WithReadOnly())
			if !errors.Is(err, ErrNeedsCoreStart) || !strings.Contains(err.Error(), testCase.fragment) {
				t.Fatalf("read-only open = %v", err)
			}
			assertDatabaseFilesUnchanged(t, path, before)
			store := openWithKey(t, path, testLocalKey(t, 1), nil)
			defer store.Close()
			if len(readEnvelopes(t, store)) != 2 {
				t.Fatal("a normal open after the refusal did not set up the data keys")
			}
		})
	}
}
