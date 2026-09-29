package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QuantumNous/astrlink/core/contract"
	storage "github.com/QuantumNous/astrlink/core/internal/storage"
)

// createLocalOnlyRawKey stores a raw sealing key only the local envelope
// opens, as the signed macOS app creates before a raw password is set.
func createLocalOnlyRawKey(t *testing.T, store *Store, id int64) rawTestKey {
	t.Helper()
	key, stored := newRawTestKey(t, id)
	local, err := store.WrapLocalRawKey(key.id, key.public, key.private)
	if err != nil {
		t.Fatal(err)
	}
	stored.Envelopes = []storage.RawKeyEnvelope{local}
	if err := store.CreateRawSealingKey(context.Background(), stored); err != nil {
		t.Fatal(err)
	}
	return key
}

// checkpoint folds the WAL into the database file, as the next checkpoint
// would, so fileContains sees only what is still stored.
func checkpoint(t *testing.T, store *Store) {
	t.Helper()
	if _, err := store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
}

// assertRawMarker checks that a part is kept only as a withheld marker, with
// nothing left that dek_audit opens.
func assertRawMarker(t *testing.T, store *Store, id contract.RequestID, direction storage.AuditDirection) {
	t.Helper()
	blob, ok := blobsByDirection(t, store, id)[direction]
	if !ok {
		t.Fatalf("%s part is missing", direction)
	}
	if blob.Sealing != storage.AuditSealingNone || blob.Exposure != storage.AuditExposureRaw || len(blob.Ciphertext) != 0 {
		t.Fatalf("%s part = sealing %q exposure %q with %d ciphertext bytes, want a raw marker",
			direction, blob.Sealing, blob.Exposure, len(blob.Ciphertext))
	}
	if count := countRows(t, store, "audit_blobs WHERE payload_id IS NOT NULL AND request_id = '"+string(id)+"' AND direction = '"+string(direction)+"'"); count != 0 {
		t.Fatalf("%s part still references a payload", direction)
	}
}

func TestRawCapturesAreNotKeptWithoutARawPassword(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, *Store)
	}{
		{name: "no raw key", setup: func(*testing.T, *Store) {}},
		{name: "local envelope only", setup: func(t *testing.T, store *Store) { createLocalOnlyRawKey(t, store, 61) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "astrlink.db")
			store := openWithKey(t, path, testLocalKey(t, 0x81), nil)
			defer store.Close()
			ctx := context.Background()
			const id = contract.RequestID("request_without_password")
			auditKey := auditPayloadFixture(t, store, id)
			test.setup(t, store)
			if store.keepsRawCaptures() {
				t.Fatal("raw captures are kept without a raw password")
			}

			raw := sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, "RAW-"+strings.Repeat("prompt without password ", 32))
			insertRawTestBlob(t, store, raw, storage.AuditExposureRaw)
			shareable := sealedPayload(t, auditKey, id, storage.AuditDirectionUpstreamRequest, "shareable prompt")
			insertRawTestBlob(t, store, shareable, storage.AuditExposureShareable)

			assertRawMarker(t, store, id, storage.AuditDirectionRequest)
			if fileContains(t, path, raw.Ciphertext) {
				t.Fatal("the database or its WAL holds the raw part's ciphertext")
			}
			// Shareable content is kept as before.
			upstream := blobsByDirection(t, store, id)[storage.AuditDirectionUpstreamRequest]
			if plain, err := storage.OpenAuditBlob(auditKey, upstream.Nonce, upstream.Ciphertext); err != nil || string(plain) != "shareable prompt" {
				t.Fatalf("shareable part = %q, %v", plain, err)
			}

			// Raw is sticky: a recapture labelled shareable is not kept either.
			recapture := sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, "RECAPTURE-"+strings.Repeat("sticky ", 32))
			insertRawTestBlob(t, store, recapture, storage.AuditExposureShareable)
			assertRawMarker(t, store, id, storage.AuditDirectionRequest)
			if fileContains(t, path, recapture.Ciphertext) {
				t.Fatal("the database or its WAL holds the recaptured raw part")
			}
			if result, err := store.ResealRawParts(ctx, 0); err != nil || result.Resealed != 0 {
				t.Fatalf("ResealRawParts = %+v, %v", result, err)
			}
			assertRawMarker(t, store, id, storage.AuditDirectionRequest)
		})
	}
}

func TestPendingPartsAreDroppedWhenTheySettleWithoutARawPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store := openWithKey(t, path, testLocalKey(t, 0x82), nil)
	defer store.Close()
	ctx := context.Background()
	const (
		settled   = contract.RequestID("request_settled_raw")
		cleared   = contract.RequestID("request_settled_shareable")
		recovered = contract.RequestID("request_interrupted")
		ended     = contract.RequestID("request_ended_unsettled")
		inFlight  = contract.RequestID("request_still_running")
	)
	auditKey := auditPayloadFixture(t, store, settled)
	insertRecord(t, store, cleared, contract.RequestStatusPending)
	pendingBody := func(id contract.RequestID, body string) storage.AuditBlob {
		blob := sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, body+"-"+strings.Repeat("pending body ", 32))
		insertRawTestBlob(t, store, blob, storage.AuditExposurePending)
		return blob
	}

	// A decision that the part is raw drops its content.
	settledBlob := pendingBody(settled, "SETTLED")
	if err := store.UpdateAuditExposure(ctx, settled, storage.AuditDirectionRequest, storage.AuditExposureRaw); err != nil {
		t.Fatal(err)
	}
	assertRawMarker(t, store, settled, storage.AuditDirectionRequest)
	// A decision that clears it keeps it.
	pendingBody(cleared, "CLEARED")
	if err := store.UpdateAuditExposure(ctx, cleared, storage.AuditDirectionRequest, storage.AuditExposureShareable); err != nil {
		t.Fatal(err)
	}
	if blob := blobsByDirection(t, store, cleared)[storage.AuditDirectionRequest]; blob.Sealing != storage.AuditSealingAudit ||
		blob.Exposure != storage.AuditExposureShareable {
		t.Fatalf("cleared part = %+v", blob)
	}
	checkpoint(t, store)
	if fileContains(t, path, settledBlob.Ciphertext) {
		t.Fatal("the settled raw part's content is still stored")
	}

	// A body an interrupted request left pending is dropped by recovery.
	insertRecord(t, store, recovered, contract.RequestStatusPending)
	recoveredBlob := pendingBody(recovered, "RECOVERED")
	if _, err := store.db.Exec(`UPDATE request_records SET status = 'succeeded' WHERE id = ?`, cleared); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecoverPendingRequestRecords(ctx); err != nil {
		t.Fatal(err)
	}
	assertRawMarker(t, store, recovered, storage.AuditDirectionRequest)
	if fileContains(t, path, recoveredBlob.Ciphertext) {
		t.Fatal("recovery kept an interrupted request's pending content")
	}

	// A pending part whose request ended without a decision goes with the
	// next reseal pass; one still in flight waits for its decision.
	insertRecord(t, store, ended, contract.RequestStatusSucceeded)
	endedBlob := pendingBody(ended, "ENDED")
	insertRecord(t, store, inFlight, contract.RequestStatusPending)
	pendingBody(inFlight, "IN-FLIGHT")
	result, err := store.ResealRawParts(ctx, 0)
	if err != nil || result.Dropped != 1 || result.Resealed != 0 || !result.Done {
		t.Fatalf("ResealRawParts = %+v, %v", result, err)
	}
	assertRawMarker(t, store, ended, storage.AuditDirectionRequest)
	if fileContains(t, path, endedBlob.Ciphertext) {
		t.Fatal("the reseal pass kept an ended request's pending content")
	}
	if blob := blobsByDirection(t, store, inFlight)[storage.AuditDirectionRequest]; blob.Sealing != storage.AuditSealingAudit ||
		blob.Exposure != storage.AuditExposurePending {
		t.Fatalf("in-flight part = %+v", blob)
	}
}

func TestAPartAFailedSettleLeftPendingGoesWithItsRequestsEnd(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, *Store) *rawTestKey
		check func(*testing.T, *Store, *rawTestKey, contract.RequestID)
	}{
		{
			name:  "no raw password",
			setup: func(*testing.T, *Store) *rawTestKey { return nil },
			check: func(t *testing.T, store *Store, _ *rawTestKey, id contract.RequestID) {
				assertRawMarker(t, store, id, storage.AuditDirectionRequest)
			},
		},
		{
			name: "raw password set",
			setup: func(t *testing.T, store *Store) *rawTestKey {
				key := createRawTestKey(t, store, 63)
				return &key
			},
			check: func(t *testing.T, store *Store, key *rawTestKey, id contract.RequestID) {
				if got := openRawPart(t, *key, blobsByDirection(t, store, id)[storage.AuditDirectionRequest]); got != "FAILED SETTLE" {
					t.Fatalf("resealed part = %q", got)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := openWithKey(t, filepath.Join(t.TempDir(), "astrlink.db"), testLocalKey(t, 0x83), nil)
			defer store.Close()
			ctx := context.Background()
			const (
				id    = contract.RequestID("request_settle_failed")
				ended = contract.RequestID("request_settle_failed_late")
			)
			auditKey := auditPayloadFixture(t, store, "request_settle_fixture")
			key := test.setup(t, store)
			insertRecord(t, store, id, contract.RequestStatusPending)
			insertRawTestBlob(t, store, sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, "FAILED SETTLE"), storage.AuditExposurePending)
			passes := 0
			store.OnResealDeferred(func() {
				passes++
				if _, err := store.ResealRawParts(ctx, 0); err != nil {
					t.Errorf("ResealRawParts: %v", err)
				}
			})
			stillPending := func(when string) {
				t.Helper()
				if blob := blobsByDirection(t, store, id)[storage.AuditDirectionRequest]; blob.Sealing != storage.AuditSealingAudit ||
					blob.Exposure != storage.AuditExposurePending {
					t.Fatalf("%s: part = sealing %q exposure %q", when, blob.Sealing, blob.Exposure)
				}
			}

			// A settle whose context ended first leaves the part pending, and
			// the pass it asks for leaves a part of an in-flight request alone.
			cancelled, cancel := context.WithCancel(ctx)
			cancel()
			if err := store.UpdateAuditExposure(cancelled, id, storage.AuditDirectionRequest, storage.AuditExposureRaw); err == nil {
				t.Fatal("a settle under an ended context succeeded")
			}
			if passes != 1 {
				t.Fatalf("passes after the failed settle = %d, want 1", passes)
			}
			stillPending("after the failed settle")
			// A pending snapshot does not end the request.
			record := contract.RequestRecord{
				ID: id, StartedAt: store.now(), Status: contract.RequestStatusPending,
				InputProtocol: contract.ProtocolOpenAIResponses, Audit: contract.NotCapturedAuditSummary(),
			}
			if err := store.UpsertRequestRecord(ctx, record); err != nil {
				t.Fatal(err)
			}
			if passes != 1 {
				t.Fatalf("passes after a pending snapshot = %d, want 1", passes)
			}

			// The request's end asks for the pass that settles the part.
			record.Status = contract.RequestStatusSucceeded
			if err := store.UpsertRequestRecord(ctx, record); err != nil {
				t.Fatal(err)
			}
			if passes != 2 {
				t.Fatalf("passes after the request ended = %d, want 2", passes)
			}
			test.check(t, store, key, id)
			if err := store.UpsertRequestRecord(ctx, record); err != nil {
				t.Fatal(err)
			}
			if passes != 2 {
				t.Fatalf("a request ended twice asked for %d passes, want 2", passes)
			}

			// A settle that fails after its request ended is covered by the
			// pass it asks for at once and is not remembered.
			insertRecord(t, store, ended, contract.RequestStatusSucceeded)
			insertRawTestBlob(t, store, sealedPayload(t, auditKey, ended, storage.AuditDirectionRequest, "LATE"), storage.AuditExposurePending)
			if err := store.UpdateAuditExposure(cancelled, ended, storage.AuditDirectionRequest, storage.AuditExposureRaw); err == nil {
				t.Fatal("a settle under an ended context succeeded")
			}
			if _, waiting := store.settleDeferred.Load(ended); waiting || passes != 3 {
				t.Fatalf("late settle: remembered=%v passes=%d", waiting, passes)
			}
		})
	}
}

func TestMigratedRawHistoryWaitsForTheRawPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store := openWithKey(t, path, testLocalKey(t, 0x83), nil)
	defer store.Close()
	ctx := context.Background()
	const id = contract.RequestID("request_before_upgrade")
	auditKey := auditPayloadFixture(t, store, id)
	// Raw parts an earlier release kept under the audit key: one inline and
	// one in a shared payload.
	inlineBody := "HISTORY-" + strings.Repeat("inline raw prompt ", 32)
	inline := sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, inlineBody)
	insertInlineBlob(t, store.db, inline, storage.AuditExposureRaw)
	shared := sealedPayload(t, auditKey, id, storage.AuditDirectionResponse, "HISTORY-"+strings.Repeat("shared raw answer ", 32))
	insertRawTestBlob(t, store, shared, storage.AuditExposurePending)
	if _, err := store.db.Exec(`UPDATE audit_blobs SET exposure = 'raw' WHERE request_id = ? AND direction = 'response'`, id); err != nil {
		t.Fatal(err)
	}

	// Without a raw key the history is kept as it is, not dropped.
	if result, err := store.ResealRawParts(ctx, 0); err != nil || result.Resealed != 0 || result.Dropped != 0 {
		t.Fatalf("reseal without a key = %+v, %v", result, err)
	}
	for direction, blob := range blobsByDirection(t, store, id) {
		if blob.Sealing != storage.AuditSealingAudit || blob.Exposure != storage.AuditExposureRaw {
			t.Fatalf("%s history = sealing %q exposure %q", direction, blob.Sealing, blob.Exposure)
		}
	}

	// A local-only key takes the history off dek_audit, though nothing reads
	// it until a raw password is set.
	key := createLocalOnlyRawKey(t, store, 62)
	result, err := store.ResealRawParts(ctx, 0)
	if err != nil || result.Resealed != 2 || !result.Done {
		t.Fatalf("reseal with a local-only key = %+v, %v", result, err)
	}
	blobs := blobsByDirection(t, store, id)
	if got := openRawPart(t, key, blobs[storage.AuditDirectionRequest]); got != inlineBody {
		t.Fatalf("resealed history = %q", got)
	}
	if count := countRows(t, store, `audit_blobs b LEFT JOIN audit_payloads p ON p.id = b.payload_id
WHERE b.exposure = 'raw' AND length(b.ciphertext) > 0 OR p.sealing = 'audit' AND b.exposure = 'raw'`); count != 0 {
		t.Fatalf("%d raw part(s) left under dek_audit", count)
	}
	if fileContains(t, path, inline.Ciphertext) || fileContains(t, path, shared.Ciphertext) {
		t.Fatal("the database or its WAL still holds the history's old ciphertext")
	}
}

func TestMigratedRawHistoryMovesOnceARawPasswordIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store := openWithKey(t, path, testLocalKey(t, 0x84), nil)
	defer store.Close()
	ctx := context.Background()
	const id = contract.RequestID("request_before_upgrade")
	auditKey := auditPayloadFixture(t, store, id)
	historyBody := "HISTORY-" + strings.Repeat("raw prompt ", 32)
	history := sealedPayload(t, auditKey, id, storage.AuditDirectionRequest, historyBody)
	insertInlineBlob(t, store.db, history, storage.AuditExposureRaw)

	key := createRawTestKey(t, store, 63)
	if !store.keepsRawCaptures() {
		t.Fatal("a key with a raw password does not keep raw captures")
	}
	result, err := store.ResealRawParts(ctx, 0)
	if err != nil || result.Resealed != 1 || result.Dropped != 0 {
		t.Fatalf("ResealRawParts = %+v, %v", result, err)
	}
	if got := openRawPart(t, key, blobsByDirection(t, store, id)[storage.AuditDirectionRequest]); got != historyBody {
		t.Fatalf("resealed history = %q", got)
	}
	if fileContains(t, path, history.Ciphertext) {
		t.Fatal("the database or its WAL still holds the history under dek_audit")
	}
	// New raw captures are kept, sealed to the raw key.
	capture := sealedPayload(t, auditKey, id, storage.AuditDirectionResponse, "kept raw answer")
	insertRawTestBlob(t, store, capture, storage.AuditExposureRaw)
	if got := openRawPart(t, key, blobsByDirection(t, store, id)[storage.AuditDirectionResponse]); got != "kept raw answer" {
		t.Fatalf("raw capture = %q", got)
	}
}

func TestUnsealDropsPartsThatWereNotKept(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	store := openWithKey(t, path, testLocalKey(t, 0x85), nil)
	auditKey := auditPayloadFixture(t, store, unsealRequestID)
	if _, err := store.db.Exec(`UPDATE request_records SET audit_json = json_set(audit_json,
    '$.request_body_captured', json('true'), '$.upstream_request_body_captured', json('true')) WHERE id = ?`, unsealRequestID); err != nil {
		t.Fatal(err)
	}
	insertRawTestBlob(t, store, sealedPayload(t, auditKey, unsealRequestID, storage.AuditDirectionRequest, unsealRawPrompt), storage.AuditExposureRaw)
	insertRawTestBlob(t, store, sealedPayload(t, auditKey, unsealRequestID, storage.AuditDirectionUpstreamRequest, "shareable prompt"), storage.AuditExposureShareable)
	assertRawMarker(t, store, unsealRequestID, storage.AuditDirectionRequest)

	result, err := store.Unseal(ctx, UnsealOptions{})
	if err != nil || result.RawParts != 0 || result.Discarded != (UnsealUnreadable{}) {
		t.Fatalf("Unseal = %+v, %v", result, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	database := openUnsealedDatabase(t, path)
	assertReleasedSchema(t, database)
	parts := auditPartsUnderKey(t, database, auditKey)
	if len(parts) != 1 || parts[storage.AuditDirectionUpstreamRequest] != "shareable prompt" {
		t.Fatalf("parts after unseal = %q", parts)
	}
	var markers int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_blobs WHERE payload_id IS NULL AND length(ciphertext) = 0`).Scan(&markers); err != nil || markers != 0 {
		t.Fatalf("unseal left %d marker(s), %v", markers, err)
	}
	var captured, upstreamCaptured bool
	if err := database.QueryRow(`SELECT json_extract(audit_json, '$.request_body_captured'), json_extract(audit_json, '$.upstream_request_body_captured')
FROM request_records WHERE id = ?`, unsealRequestID).Scan(&captured, &upstreamCaptured); err != nil || captured || !upstreamCaptured {
		t.Fatalf("capture flags after unseal = %t, %t, %v", captured, upstreamCaptured, err)
	}
}
