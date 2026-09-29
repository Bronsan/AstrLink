package controlapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/astrlink/core/contract"
	"github.com/QuantumNous/astrlink/core/internal/localkey"
	"github.com/QuantumNous/astrlink/core/internal/secretstore"
	"github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/rawseal"
	"github.com/QuantumNous/astrlink/core/internal/storage/sqlite"
)

// rawVaultTestKDF keeps Argon2id cheap in tests.
var rawVaultTestKDF = rawseal.KDFParams{Algorithm: "argon2id", Version: 19, Time: 1, MemoryKiB: 64, Threads: 1}

const rawVaultNewPassword = "a brand new phrase"

type rawTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func newRawTestClock() *rawTestClock {
	return &rawTestClock{now: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
}

func (clock *rawTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *rawTestClock) Advance(delta time.Duration) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = clock.now.Add(delta)
}

func newTestRawVault(store storage.RawSealingStore, local bool, clock *rawTestClock) *Vault {
	vault := NewRawVault(store, RawVaultOptions{LocalEnvelope: local, KDF: rawVaultTestKDF})
	if clock != nil {
		vault.now = clock.Now
	}
	return vault
}

func passwordProof(password string) RawProof { return RawProof{Password: []byte(password)} }

var localPresenceProof = RawProof{LocalPresence: true}

func mustSetRawPassword(t *testing.T, vault *Vault, password string, proof RawProof) RawVaultStatus {
	t.Helper()
	outcome, err := vault.ChangePassword(context.Background(), RawPasswordSet, []byte(password), proof)
	if err != nil {
		t.Fatalf("set raw password: %v", err)
	}
	return outcome.Status
}

// resealAll moves the fixture's audit-sealed raw parts onto the raw key, as
// the vault's background pass does.
func resealAll(t *testing.T, store *sqlite.Store) {
	t.Helper()
	if _, err := store.ResealRawParts(context.Background(), rawResealBatch); err != nil {
		t.Fatal(err)
	}
}

func rawPartByDirection(t *testing.T, store *sqlite.Store, direction storage.AuditDirection) storage.AuditBlob {
	t.Helper()
	blobs, err := store.GetAuditBlobsByRequest(context.Background(), rawTestRequestID)
	if err != nil {
		t.Fatal(err)
	}
	for _, blob := range blobs {
		if blob.Direction == direction {
			return blob
		}
	}
	t.Fatalf("no %s part", direction)
	return storage.AuditBlob{}
}

func openWithOpener(t *testing.T, opener RawKeyOpener, blob storage.AuditBlob) string {
	t.Helper()
	key, err := opener.OpenBlobKey(blob)
	if err != nil {
		t.Fatalf("OpenBlobKey: %v", err)
	}
	defer clear(key)
	plaintext, err := storage.OpenAuditBlob(key, blob.Nonce, blob.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	return string(plaintext)
}

func TestRawVaultPasswordLifecycle(t *testing.T) {
	ctx := context.Background()
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, false, nil)

	status, err := vault.Status(ctx)
	if err != nil || status.Configured || status.PasswordSet || status.LocalPresence {
		t.Fatalf("fresh status=%#v err=%v", status, err)
	}
	if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); !errors.Is(err, ErrRawNotConfigured) {
		t.Fatalf("unlock before set: %v", err)
	}
	// Key file platforms get no key without a password.
	if err := vault.EnsureRawSealing(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _ := vault.Status(ctx); status.Configured {
		t.Fatal("EnsureRawSealing created a key without the keychain")
	}
	for _, testCase := range []struct {
		password string
		want     error
	}{
		{"", ErrRawPasswordRequired},
		{"short", ErrRawPasswordPolicy},
		{strings.Repeat("a", rawseal.MaxPasswordRunes+1), ErrRawPasswordPolicy},
	} {
		if _, err := vault.ChangePassword(ctx, RawPasswordSet, []byte(testCase.password), RawProof{}); !errors.Is(err, testCase.want) {
			t.Fatalf("set %q: %v want %v", testCase.password, err, testCase.want)
		}
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordChange, []byte(rawVaultNewPassword), passwordProof(rawTestPassword)); !errors.Is(err, ErrRawPasswordNotSet) {
		t.Fatalf("change before set: %v", err)
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordReset, []byte(rawVaultNewPassword), RawProof{}); !errors.Is(err, ErrRawNotConfigured) {
		t.Fatalf("reset before set: %v", err)
	}

	status = mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	if !status.Configured || !status.PasswordSet || status.LocalEnvelope || status.LocalPresence || !status.KeyVerified || status.Unlocked {
		t.Fatalf("status after set=%#v", status)
	}
	state, err := store.LoadRawSealing(ctx)
	if err != nil || state.Local != nil || state.Password == nil {
		t.Fatalf("stored state=%#v err=%v", state, err)
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordSet, []byte(rawVaultNewPassword), RawProof{}); !errors.Is(err, ErrRawPasswordAlreadySet) {
		t.Fatalf("second set: %v", err)
	}

	for _, testCase := range []struct {
		proof RawProof
		want  error
	}{
		{RawProof{}, ErrRawProofRequired},
		{localPresenceProof, ErrRawProofRequired},
		{passwordProof("wrong password"), ErrRawPasswordInvalid},
	} {
		if _, err := vault.ChangePassword(ctx, RawPasswordChange, []byte(rawVaultNewPassword), testCase.proof); !errors.Is(err, testCase.want) {
			t.Fatalf("change with %#v: %v want %v", testCase.proof, err, testCase.want)
		}
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordChange, []byte(rawVaultNewPassword), passwordProof(rawTestPassword)); err != nil {
		t.Fatal(err)
	}
	changed, err := store.LoadRawSealing(ctx)
	if err != nil || changed.KeyID != state.KeyID || string(changed.Password.Salt) == string(state.Password.Salt) {
		t.Fatalf("change did not rewrap under a fresh salt: %v", err)
	}
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(RawKeyOpener) error { return nil }); !errors.Is(err, ErrRawPasswordInvalid) {
		t.Fatalf("old password still opens: %v", err)
	}
	if err := vault.WithProof(ctx, passwordProof(rawVaultNewPassword), func(RawKeyOpener) error { return nil }); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if _, err := vault.ChangePassword(ctx, "rotate", nil, RawProof{}); !errors.Is(err, storage.ErrInvalidArgument) {
		t.Fatalf("unknown action: %v", err)
	}
}

func TestRawVaultBacksOffWrongPasswords(t *testing.T) {
	ctx := context.Background()
	clock := newRawTestClock()
	vault := newTestRawVault(newRawAccessFixture(t, nil).store, false, clock)
	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	wrong := passwordProof("wrong password")
	noop := func(RawKeyOpener) error { return nil }

	for attempt := 1; attempt <= 3; attempt++ {
		if err := vault.WithProof(ctx, wrong, noop); !errors.Is(err, ErrRawPasswordInvalid) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	// From the third failure on, the next attempt waits 2^(n-3) s.
	for failures, want := 3, time.Second; failures <= 9; failures++ {
		var backoff *RawBackoffError
		if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); !errors.As(err, &backoff) || backoff.Remaining != want {
			t.Fatalf("after %d failures: %v want backoff %s", failures, err, want)
		}
		if err := vault.WithProof(ctx, localPresenceProof, noop); !errors.As(err, &backoff) {
			t.Fatalf("backoff did not cover every proof: %v", err)
		}
		if status, _ := vault.Status(ctx); status.RetryAfter != want {
			t.Fatalf("status retry after %s want %s", status.RetryAfter, want)
		}
		clock.Advance(want)
		if err := vault.WithProof(ctx, wrong, noop); !errors.Is(err, ErrRawPasswordInvalid) {
			t.Fatalf("after waiting %s: %v", want, err)
		}
		want = min(want*2, rawBackoffCap)
	}
	clock.Advance(rawBackoffCap)
	if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); err != nil {
		t.Fatalf("right password after the wait: %v", err)
	}
	// Success resets the count.
	for attempt := 1; attempt <= 3; attempt++ {
		if err := vault.WithProof(ctx, wrong, noop); !errors.Is(err, ErrRawPasswordInvalid) {
			t.Fatalf("attempt %d after reset: %v", attempt, err)
		}
	}
}

func TestRawVaultParallelGuessesQueueBehindTheBackoff(t *testing.T) {
	clock := newRawTestClock()
	vault := newTestRawVault(newRawAccessFixture(t, nil).store, false, clock)
	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	var invalid sync.WaitGroup
	results := make(chan error, 12)
	for range 12 {
		invalid.Add(1)
		go func() {
			defer invalid.Done()
			results <- vault.WithProof(context.Background(), passwordProof("wrong password"), func(RawKeyOpener) error { return nil })
		}()
	}
	invalid.Wait()
	close(results)
	counts := map[string]int{}
	for err := range results {
		var backoff *RawBackoffError
		switch {
		case errors.Is(err, ErrRawPasswordInvalid):
			counts["invalid"]++
		case errors.As(err, &backoff):
			counts["backoff"]++
		default:
			t.Fatalf("unexpected result %v", err)
		}
	}
	if counts["invalid"] != 3 || counts["backoff"] != 9 {
		t.Fatalf("parallel guesses=%v", counts)
	}
}

func TestRawVaultProofZeroesThePrivateKeyAndLeavesTheSessionLocked(t *testing.T) {
	ctx := context.Background()
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, false, nil)
	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	resealAll(t, store)
	var cleared [][]byte
	vault.privateCleared = func(private []byte) { cleared = append(cleared, private) }

	blob := rawPartByDirection(t, store, storage.AuditDirectionRequest)
	if blob.Sealing != storage.AuditSealingRawV1 {
		t.Fatalf("fixture part was not resealed: %q", blob.Sealing)
	}
	var kept RawKeyOpener
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(opener RawKeyOpener) error {
		if !strings.Contains(openWithOpener(t, opener, blob), rawTestSecret) {
			t.Fatal("proof opener did not open the raw part")
		}
		kept = opener
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(cleared) != 1 || len(cleared[0]) != rawseal.PrivateKeyBytes {
		t.Fatalf("cleared hook saw %d keys", len(cleared))
	}
	for _, value := range cleared[0] {
		if value != 0 {
			t.Fatal("the private key was not zeroed after the proof")
		}
	}
	if _, err := kept.OpenBlobKey(blob); !errors.Is(err, rawseal.ErrBlobKey) {
		t.Fatalf("an opener outlived its proof: %v", err)
	}
	if _, unlocked := vault.UnlockedOpener(); unlocked {
		t.Fatal("a proof started an unlock session")
	}
	// A failing callback still zeroes the key.
	failure := errors.New("callback failed")
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(RawKeyOpener) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("callback error: %v", err)
	}
	if len(cleared) != 2 {
		t.Fatalf("cleared hook saw %d keys", len(cleared))
	}
	// Parts sealed to another key are refused before HPKE runs.
	foreign := blob
	foreign.RawKeyID++
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(opener RawKeyOpener) error {
		_, err := opener.OpenBlobKey(foreign)
		return err
	}); !errors.Is(err, rawseal.ErrBlobKey) {
		t.Fatalf("foreign part: %v", err)
	}
}

func TestRawVaultUnlockSessionIdlesOut(t *testing.T) {
	ctx := context.Background()
	clock := newRawTestClock()
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, false, clock)
	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	resealAll(t, store)
	blob := rawPartByDirection(t, store, storage.AuditDirectionResponse)

	if _, err := vault.Unlock(ctx, RawProof{}); !errors.Is(err, ErrRawProofRequired) {
		t.Fatalf("unlock without proof: %v", err)
	}
	status, err := vault.Unlock(ctx, passwordProof(rawTestPassword))
	if err != nil || !status.Unlocked || status.UnlockExpiresAt == nil || !status.UnlockExpiresAt.Equal(clock.Now().Add(rawUnlockIdle)) {
		t.Fatalf("unlock status=%#v err=%v", status, err)
	}
	for range 3 {
		clock.Advance(rawUnlockIdle - time.Minute)
		opener, unlocked := vault.UnlockedOpener()
		if !unlocked || !strings.Contains(openWithOpener(t, opener, blob), rawTestSecret) {
			t.Fatal("a raw read inside the idle window did not keep the session")
		}
	}
	opener, _ := vault.UnlockedOpener()
	clock.Advance(rawUnlockIdle)
	if _, unlocked := vault.UnlockedOpener(); unlocked {
		t.Fatal("the session outlived its idle window")
	}
	if _, err := opener.OpenBlobKey(blob); !errors.Is(err, rawseal.ErrBlobKey) {
		t.Fatalf("an expired session still opens parts: %v", err)
	}
	vault.mu.Lock()
	session := vault.session
	vault.mu.Unlock()
	if session != nil {
		t.Fatal("the expired session kept its key")
	}

	if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); err != nil {
		t.Fatal(err)
	}
	vault.Lock()
	if status, _ := vault.Status(ctx); status.Unlocked || status.UnlockExpiresAt != nil {
		t.Fatalf("status after lock=%#v", status)
	}
	// The expiry timer zeroes an abandoned session without any read.
	if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); err != nil {
		t.Fatal(err)
	}
	clock.Advance(rawUnlockIdle)
	vault.expireSession()
	vault.mu.Lock()
	session = vault.session
	vault.mu.Unlock()
	if session != nil {
		t.Fatal("the expiry timer left the session key in memory")
	}
}

func TestRawVaultKeychainPathNeedsNoPassword(t *testing.T) {
	ctx := context.Background()
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, true, nil)
	if err := vault.EnsureRawSealing(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := vault.Status(ctx)
	if err != nil || !status.Configured || status.PasswordSet || !status.LocalEnvelope || !status.LocalPresence || !status.KeyVerified {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	first, err := store.LoadRawSealing(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.EnsureRawSealing(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.LoadRawSealing(ctx); again.KeyID != first.KeyID {
		t.Fatal("EnsureRawSealing replaced an existing key")
	}
	resealAll(t, store)
	blob := rawPartByDirection(t, store, storage.AuditDirectionRequest)
	if err := vault.WithProof(ctx, localPresenceProof, func(opener RawKeyOpener) error {
		if !strings.Contains(openWithOpener(t, opener, blob), rawTestSecret) {
			t.Fatal("local presence did not open the raw part")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A password proof means nothing until a password is set.
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(RawKeyOpener) error { return nil }); !errors.Is(err, ErrRawProofRequired) {
		t.Fatalf("password proof without a password: %v", err)
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordSet, []byte(rawTestPassword), RawProof{}); !errors.Is(err, ErrRawProofRequired) {
		t.Fatalf("set without presence: %v", err)
	}
	status = mustSetRawPassword(t, vault, rawTestPassword, localPresenceProof)
	if !status.PasswordSet || !status.LocalPresence {
		t.Fatalf("status after set=%#v", status)
	}
	// A forgotten password is rewrapped from the local envelope without
	// losing a single part.
	if _, err := vault.ChangePassword(ctx, RawPasswordChange, []byte(rawVaultNewPassword), localPresenceProof); err != nil {
		t.Fatal(err)
	}
	if err := vault.WithProof(ctx, passwordProof(rawVaultNewPassword), func(opener RawKeyOpener) error {
		if !strings.Contains(openWithOpener(t, opener, blob), rawTestSecret) {
			t.Fatal("rewrapped key lost the raw part")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Reset may leave the new key with only its local envelope.
	outcome, err := vault.ChangePassword(ctx, RawPasswordReset, nil, RawProof{})
	if err != nil || outcome.Reset == nil || outcome.Reset.DeletedParts != 2 || outcome.Status.PasswordSet || !outcome.Status.LocalPresence {
		t.Fatalf("reset outcome=%#v err=%v", outcome, err)
	}
}

func TestRawVaultRepairsAKeyTheKeychainLost(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "astrlink.db")
	first := newRawAccessFixtureAt(t, path, nil).store
	vault := newTestRawVault(first, true, nil)
	if err := vault.EnsureRawSealing(ctx); err != nil {
		t.Fatal(err)
	}
	mustSetRawPassword(t, vault, rawTestPassword, localPresenceProof)
	resealAll(t, first)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	// The keychain entry is gone: Core starts with a new local key, so the
	// local envelope and the public key MAC no longer verify.
	lost, err := sqlite.Open(ctx, path, sqlite.WithLocalKey(make([]byte, storage.AuditKeyBytes)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lost.Close() })
	if lost.HasRawSealingKey() {
		t.Fatal("a public key failing its MAC was used for sealing")
	}
	// A read-only reader such as audit show opens with the password but
	// leaves the repair to Core.
	reader := NewRawVault(lost, RawVaultOptions{KDF: rawVaultTestKDF, ReadOnly: true})
	if err := reader.WithProof(ctx, passwordProof(rawTestPassword), func(RawKeyOpener) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if lost.HasRawSealingKey() {
		t.Fatal("a read-only vault repaired the public key MAC")
	}
	repaired := newTestRawVault(lost, true, nil)
	if err := repaired.EnsureRawSealing(ctx); err != nil {
		t.Fatal(err)
	}
	status, err := repaired.Status(ctx)
	if err != nil || !status.Configured || status.LocalPresence || status.KeyVerified || !status.LocalEnvelope {
		t.Fatalf("status with a lost keychain=%#v err=%v", status, err)
	}
	if _, err := repaired.Unlock(ctx, localPresenceProof); !errors.Is(err, ErrRawProofRequired) {
		t.Fatalf("local presence with a lost keychain: %v", err)
	}
	if _, err := repaired.Unlock(ctx, passwordProof(rawTestPassword)); err != nil {
		t.Fatal(err)
	}
	status, _ = repaired.Status(ctx)
	if !status.LocalPresence || !status.KeyVerified || !lost.HasRawSealingKey() {
		t.Fatalf("status after the password repaired the key=%#v", status)
	}
	if err := repaired.WithProof(ctx, localPresenceProof, func(RawKeyOpener) error { return nil }); err != nil {
		t.Fatalf("rebuilt local envelope: %v", err)
	}
}

func TestRawVaultResetDiscardsOnlyRawParts(t *testing.T) {
	ctx := context.Background()
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, false, nil)
	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	resealAll(t, store)
	if _, err := vault.Unlock(ctx, passwordProof(rawTestPassword)); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.ChangePassword(ctx, RawPasswordReset, nil, RawProof{}); !errors.Is(err, ErrRawPasswordRequired) {
		t.Fatalf("reset without a password on a key file platform: %v", err)
	}
	outcome, err := vault.ChangePassword(ctx, RawPasswordReset, []byte(rawVaultNewPassword), RawProof{})
	if err != nil || outcome.Reset == nil || outcome.Reset.DeletedParts != 2 || outcome.Reset.AffectedRecords != 1 {
		t.Fatalf("reset outcome=%#v err=%v", outcome, err)
	}
	if outcome.Status.Unlocked {
		t.Fatal("reset kept the unlock session of the discarded key")
	}
	if err := vault.WithProof(ctx, passwordProof(rawTestPassword), func(RawKeyOpener) error { return nil }); !errors.Is(err, ErrRawPasswordInvalid) {
		t.Fatalf("old password after reset: %v", err)
	}
	blobs, err := store.GetAuditBlobsByRequest(ctx, rawTestRequestID)
	if err != nil || len(blobs) != 2 {
		t.Fatalf("parts after reset=%d err=%v", len(blobs), err)
	}
	for _, blob := range blobs {
		if blob.Exposure != storage.AuditExposureShareable {
			t.Fatalf("reset kept a %s part", blob.Exposure)
		}
	}
}

func TestRawVaultRunResealsOnceAKeyAppears(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := newRawAccessFixture(t, nil).store
	vault := newTestRawVault(store, false, nil)
	done := make(chan struct{})
	go func() { defer close(done); vault.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	mustSetRawPassword(t, vault, rawTestPassword, RawProof{})
	deadline := time.Now().Add(5 * time.Second)
	for {
		request := rawPartByDirection(t, store, storage.AuditDirectionRequest)
		response := rawPartByDirection(t, store, storage.AuditDirectionResponse)
		if request.Sealing == storage.AuditSealingRawV1 && response.Sealing == storage.AuditSealingRawV1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the background pass did not reseal the raw parts")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstream := rawPartByDirection(t, store, storage.AuditDirectionUpstreamRequest); upstream.Sealing != storage.AuditSealingAudit {
		t.Fatal("a shareable part left the audit key")
	}
}

// resealSignalStore records the retry the vault registers and each pass it
// runs.
type resealSignalStore struct {
	storage.RawSealingStore
	mu     sync.Mutex
	retry  func()
	passes chan struct{}
}

func (store *resealSignalStore) OnResealDeferred(retry func()) {
	store.mu.Lock()
	store.retry = retry
	store.mu.Unlock()
	store.RawSealingStore.OnResealDeferred(retry)
}

func (store *resealSignalStore) registered() func() {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.retry
}

func (store *resealSignalStore) ResealRawParts(ctx context.Context, limit int) (storage.RawResealResult, error) {
	result, err := store.RawSealingStore.ResealRawParts(ctx, limit)
	store.passes <- struct{}{}
	return result, err
}

func TestRawVaultRunRetriesAPartTheStoreDeferred(t *testing.T) {
	store := &resealSignalStore{RawSealingStore: newRawAccessFixture(t, nil).store, passes: make(chan struct{}, 4)}
	vault := newTestRawVault(store, false, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); vault.Run(ctx) }()
	pass := func(what string) {
		t.Helper()
		select {
		case <-store.passes:
		case <-time.After(5 * time.Second):
			t.Fatalf("no reseal pass %s", what)
		}
	}

	pass("at start")
	retry := store.registered()
	if retry == nil {
		t.Fatal("a running vault took no deferred reseals")
	}
	retry()
	pass("after the store deferred a part")

	cancel()
	<-done
	if store.registered() != nil {
		t.Fatal("a stopped vault still takes deferred reseals")
	}
}

// rawVaultFixture wires the real vault into a handler over the redacted
// fixture request.
type rawVaultFixture struct {
	store   *sqlite.Store
	vault   *Vault
	clock   *rawTestClock
	handler *Handler
}

func newRawVaultFixture(t *testing.T) rawVaultFixture {
	t.Helper()
	store := newRawAccessFixture(t, nil).store
	clock := newRawTestClock()
	vault := newTestRawVault(store, false, clock)
	return rawVaultFixture{store: store, vault: vault, clock: clock, handler: newRawAccessHandler(t, store, vault)}
}

func operatorRawStatus(t *testing.T, handler *Handler) RawSealingStatus {
	t.Helper()
	response := rawHTTP(t, handler, rawAsOperator, http.MethodGet, RawSealingPath, "", "")
	wantRawStatus(t, response, http.StatusOK, "")
	var status RawSealingStatus
	decode(t, response, &status)
	return status
}

func TestRawSealingRoutes(t *testing.T) {
	fixture := newRawVaultFixture(t)
	handler := fixture.handler
	passwordBody := func(action, password, proof string) string {
		body := `{"action":"` + action + `","password":` + password
		if proof != "" {
			body += `,"proof":` + proof
		}
		return body + `}`
	}

	status := operatorRawStatus(t, handler)
	if status.Configured || status.RawAvailable || len(status.Envelopes) != 0 || status.UnlockIdleSeconds != 900 ||
		status.PasswordMinRunes != rawseal.MinPasswordRunes || status.PasswordMaxRunes != rawseal.MaxPasswordRunes {
		t.Fatalf("fresh status=%#v", status)
	}
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath,
		`{"proof":{"password":`+rawTestPasswordJS+`}}`, ""), http.StatusConflict, "raw_access_unavailable")

	// Observers may read availability only, and never write.
	observed := rawHTTP(t, handler, rawAsAgent, http.MethodGet, RawSealingPath, "", "")
	wantRawStatus(t, observed, http.StatusOK, "")
	if strings.TrimSpace(observed.Body.String()) != `{"raw_available":false}` {
		t.Fatalf("observer view=%s", observed.Body.String())
	}
	for _, path := range []string{RawPasswordPath, RawUnlockPath, RawLockPath} {
		wantRawStatus(t, rawHTTP(t, handler, rawAsAgent, http.MethodPost, path,
			passwordBody("set", rawTestPasswordJS, ""), ""), http.StatusForbidden, "forbidden")
	}

	for _, body := range []string{
		passwordBody("rotate", rawTestPasswordJS, ""),
		passwordBody("set", `"short"`, ""),
		passwordBody("set", `42`, ""),
		`{"action":"set"}`,
	} {
		wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath, body, ""),
			http.StatusBadRequest, "validation_failed")
	}
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath,
		`{"action":"set","password":"long enough","pin":"1"}`, ""), http.StatusBadRequest, "invalid_json")

	set := rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath, passwordBody("set", rawTestPasswordJS, ""), "")
	wantRawStatus(t, set, http.StatusOK, "")
	var created RawPasswordResponse
	decode(t, set, &created)
	if !created.Configured || !created.PasswordSet || created.Reset != nil || len(created.Envelopes) != 1 || created.Envelopes[0] != "password" {
		t.Fatalf("set response=%#v", created)
	}
	if strings.Contains(set.Body.String(), "horse") {
		t.Fatal("a response echoed the password")
	}
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath, passwordBody("set", `"another phrase"`, ""), ""),
		http.StatusConflict, "raw_password_already_set")
	setAgentRawAccess(t, fixture.store, true)
	observed = rawHTTP(t, handler, rawAsAgent, http.MethodGet, RawSealingPath, "", "")
	if strings.TrimSpace(observed.Body.String()) != `{"raw_available":true}` {
		t.Fatalf("observer view=%s", observed.Body.String())
	}
	resealAll(t, fixture.store)

	// A locked operator read withholds raw parts.
	full := rawAuditPath(rawTestRequestID)
	content := readRawAudit(t, handler, rawAsOperator, full, "")
	if !content.RequestBody.Withheld || content.RequestBody.Reason != contract.AuditWithheldRawLocked {
		t.Fatalf("locked read=%#v", content.RequestBody)
	}

	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, "", ""),
		http.StatusUnprocessableEntity, "raw_proof_required")
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{}`, ""),
		http.StatusUnprocessableEntity, "raw_proof_required")
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{"proof":{"kind":"local_presence"}}`, ""),
		http.StatusUnprocessableEntity, "raw_proof_required")
	for attempt := 1; attempt <= 3; attempt++ {
		wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{"proof":{"password":"wrong password"}}`, ""),
			http.StatusForbidden, "raw_password_invalid")
	}
	throttled := rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{"proof":{"password":`+rawTestPasswordJS+`}}`, "")
	wantRawStatus(t, throttled, http.StatusTooManyRequests, "raw_password_backoff")
	if throttled.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After=%q", throttled.Header().Get("Retry-After"))
	}
	if status := operatorRawStatus(t, handler); status.RetryAfterSeconds != 1 {
		t.Fatalf("status retry_after_seconds=%d", status.RetryAfterSeconds)
	}
	events := handler.observers.snapshot().RawAccessEvents
	if len(events) != 3 || events[0].Kind != RawAccessEventPasswordInvalid || events[0].GrantID != "" {
		t.Fatalf("observer events=%#v", events)
	}
	fixture.clock.Advance(time.Second)

	unlocked := rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{"proof":{"password":`+rawTestPasswordJS+`}}`, "")
	wantRawStatus(t, unlocked, http.StatusOK, "")
	decode(t, unlocked, &status)
	if !status.Unlocked || status.UnlockExpiresAt == nil || status.RetryAfterSeconds != 0 {
		t.Fatalf("unlocked status=%#v", status)
	}
	content = readRawAudit(t, handler, rawAsOperator, full, "")
	if content.RequestBody.Withheld || !strings.Contains(content.RequestBody.Content, rawTestSecret) {
		t.Fatalf("unlocked read=%#v", content.RequestBody)
	}

	// The unlock session never approves an agent: decisions still need proof,
	// and the proof's private key is zeroed once the part keys are out.
	var cleared []byte
	fixture.vault.privateCleared = func(private []byte) { cleared = private }
	grant := requestRawGrant(t, handler, rawTestRequestID)
	wantRawStatus(t, decideRawGrant(t, handler, grant.GrantID, `{"decision":"once"}`),
		http.StatusUnprocessableEntity, "raw_proof_required")
	wantRawStatus(t, decideRawGrant(t, handler, grant.GrantID, `{"decision":"once","proof":{"password":`+rawTestPasswordJS+`}}`),
		http.StatusOK, "")
	if len(cleared) != rawseal.PrivateKeyBytes || strings.Trim(string(cleared), "\x00") != "" {
		t.Fatal("the approval left the private key in memory")
	}
	granted := readRawAudit(t, handler, rawAsAgent, full, grant.GrantToken)
	if granted.RequestBody.Withheld || !strings.Contains(granted.ResponseContent.Content, rawTestSecret) {
		t.Fatalf("granted read=%#v", granted)
	}
	wantRawStatus(t, rawHTTP(t, handler, rawAsAgent, http.MethodGet, full, "", grant.GrantToken),
		http.StatusForbidden, "raw_grant_invalid")

	// Fifteen idle minutes lock the operator again.
	fixture.clock.Advance(rawUnlockIdle)
	content = readRawAudit(t, handler, rawAsOperator, full, "")
	if !content.RequestBody.Withheld || content.RequestBody.Reason != contract.AuditWithheldRawLocked {
		t.Fatalf("idle read=%#v", content.RequestBody)
	}
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawUnlockPath, `{"proof":{"password":`+rawTestPasswordJS+`}}`, ""),
		http.StatusOK, "")
	locked := rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawLockPath, "", "")
	wantRawStatus(t, locked, http.StatusOK, "")
	decode(t, locked, &status)
	if status.Unlocked {
		t.Fatalf("lock status=%#v", status)
	}

	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath,
		passwordBody("change", `"another phrase"`, `{"password":"wrong password"}`), ""), http.StatusForbidden, "raw_password_invalid")
	wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath,
		passwordBody("change", `"another phrase"`, `{"password":`+rawTestPasswordJS+`}`), ""), http.StatusOK, "")
	reset := rawHTTP(t, handler, rawAsOperator, http.MethodPost, RawPasswordPath, passwordBody("reset", `"a third phrase"`, ""), "")
	wantRawStatus(t, reset, http.StatusOK, "")
	var resetResponse RawPasswordResponse
	decode(t, reset, &resetResponse)
	if resetResponse.Reset == nil || resetResponse.Reset.DeletedParts != 2 || resetResponse.Reset.AffectedRecords != 1 {
		t.Fatalf("reset response=%#v", resetResponse)
	}
	record, err := fixture.store.GetRequestRecord(context.Background(), rawTestRequestID)
	if err != nil || record.Audit.RequestBodyCaptured || record.Audit.ResponseContentCaptured || len(record.PrivacyFindings) != 1 {
		t.Fatalf("record after reset=%#v err=%v", record.Audit, err)
	}

	// Without a vault the operator routes say so instead of pretending.
	bare := newRawAccessHandler(t, fixture.store, nil)
	wantRawStatus(t, rawHTTP(t, bare, rawAsOperator, http.MethodPost, RawLockPath, "", ""),
		http.StatusConflict, "raw_sealing_unavailable")
	wantRawStatus(t, rawHTTP(t, bare, rawAsOperator, http.MethodGet, RawLockPath, "", ""),
		http.StatusMethodNotAllowed, "method_not_allowed")
	wantRawStatus(t, rawHTTP(t, bare, rawAsAgent, http.MethodGet, RawLockPath, "", ""),
		http.StatusForbidden, "forbidden")
}

const (
	secondCoreControlToken  = "second-core-control-token-0123"
	secondCoreObserverToken = "second-core-observer-token-0123"
	secondCoreServiceID     = contract.ServiceID("service_second_core")
	secondCoreAPIKey        = "sk-second-core-credential"
)

// secondCoreHTTP calls a handler as the operator of a Core started with its
// own control token.
func secondCoreHTTP(t *testing.T, handler *Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Authorization", "Bearer "+secondCoreControlToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestAnIndependentCoreCannotReadRawContent starts a second Core on a data
// directory another Core sealed (plan §5.11): it has local.key, so it opens
// the database and every data key, but raw parts stay sealed to the raw key,
// which only the raw password or the desktop's keychain envelope opens.
func TestAnIndependentCoreCannotReadRawContent(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	path := filepath.Join(directory, "astrlink.db")

	// Core A captures a request, sets a raw password and reseals, then stops.
	first := newRawAccessFixtureAt(t, path, nil)
	if _, err := first.store.CreateService(ctx, contract.Service{
		ID: secondCoreServiceID, Name: "second core", Kind: contract.ServiceKindOpenAI, Enabled: true,
		Models: []string{"test-model"},
		HTTP:   &contract.HTTPConnection{BaseURL: "https://example.test", Auth: contract.ServiceAuth{Scheme: contract.AuthSchemeBearer}},
		Capabilities: []contract.Capability{{
			Protocol: contract.ProtocolOpenAIChat, Mode: contract.CapabilityModeNative, Streaming: true,
		}},
	}, storage.CredentialMutation{Present: true, Secret: []byte(secondCoreAPIKey)}); err != nil {
		t.Fatal(err)
	}
	mustSetRawPassword(t, newTestRawVault(first.store, false, nil), rawTestPassword, RawProof{})
	resealAll(t, first.store)
	if err := first.store.Close(); err != nil {
		t.Fatal(err)
	}

	keyText, err := os.ReadFile(filepath.Join(directory, localkey.FileName))
	if err != nil {
		t.Fatal(err)
	}
	localKey, err := localkey.Parse(keyText)
	clear(keyText)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(localKey) })

	startCore := func(t *testing.T, key []byte, localEnvelope bool) (*sqlite.Store, *Handler) {
		t.Helper()
		store, err := sqlite.Open(ctx, path, sqlite.WithLocalKey(key))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		vault := NewRawVault(store, RawVaultOptions{LocalEnvelope: localEnvelope, KDF: rawVaultTestKDF})
		handler, err := NewWithDependencies(contract.DefaultVersionResponse("0.1.0-test", "abc1234"), Dependencies{
			ServiceStore:   store,
			RequestRecords: store,
			AuditSettings:  store,
			AuditKeys:      store,
			AuditBlobs:     store,
			RawVault:       vault,
			ControlToken:   secondCoreControlToken,
			ObserverToken:  secondCoreObserverToken,
		})
		if err != nil {
			t.Fatal(err)
		}
		return store, handler
	}
	full := rawAuditPath(rawTestRequestID)
	wantLockedWithoutProof := func(t *testing.T, handler *Handler) {
		t.Helper()
		response := secondCoreHTTP(t, handler, http.MethodGet, full, "")
		wantRawStatus(t, response, http.StatusOK, "")
		var content contract.AuditContent
		decode(t, response, &content)
		for name, part := range map[string]*contract.AuditContentPart{
			"request body": content.RequestBody, "response content": content.ResponseContent,
		} {
			if part == nil || !part.Withheld || part.Reason != contract.AuditWithheldRawLocked {
				t.Fatalf("%s=%#v, want raw_locked", name, part)
			}
		}
		if strings.Contains(response.Body.String(), rawTestSecret) {
			t.Fatal("the full view carried raw content")
		}
		wantRawStatus(t, secondCoreHTTP(t, handler, http.MethodPost, RawUnlockPath, ""),
			http.StatusUnprocessableEntity, "raw_proof_required")
		wantRawStatus(t, secondCoreHTTP(t, handler, http.MethodPost, RawUnlockPath, `{"proof":{"kind":"local_presence"}}`),
			http.StatusUnprocessableEntity, "raw_proof_required")
		if strings.Contains(secondCoreHTTP(t, handler, http.MethodGet, full, "").Body.String(), rawTestSecret) {
			t.Fatal("a refused unlock opened raw content")
		}
	}

	t.Run("a key file start", func(t *testing.T) {
		store, handler := startCore(t, localKey, false)
		// It is its own Core: the first Core's token means nothing here.
		wantRawStatus(t, rawHTTP(t, handler, rawAsOperator, http.MethodGet, full, "", ""),
			http.StatusUnauthorized, "")
		wantLockedWithoutProof(t, handler)

		auditKey, err := store.GetAuditKey(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(auditKey)
		for _, direction := range []storage.AuditDirection{storage.AuditDirectionRequest, storage.AuditDirectionResponse} {
			blob := rawPartByDirection(t, store, direction)
			if blob.Sealing != storage.AuditSealingRawV1 || len(blob.WrappedKey) == 0 {
				t.Fatalf("%s part sealing=%q", direction, blob.Sealing)
			}
			if _, err := storage.OpenAuditBlob(auditKey, blob.Nonce, blob.Ciphertext); err == nil {
				t.Fatalf("dek_audit opened the raw_v1 %s part", direction)
			}
			info := rawseal.BlobKeyInfo(string(blob.RequestID), string(blob.Direction))
			if partKey, err := rawseal.OpenBlobKey(auditKey, info, blob.WrappedKey); err == nil {
				clear(partKey)
				t.Fatalf("dek_audit opened the %s part key", direction)
			}
		}

		// Not protected, by design: a same-user process holding local.key
		// reads L1 content and saved credentials (plan §5.11 promises raw
		// parts only).
		response := secondCoreHTTP(t, handler, http.MethodGet, full, "")
		var content contract.AuditContent
		decode(t, response, &content)
		if content.UpstreamRequestBody == nil || content.UpstreamRequestBody.Withheld ||
			!strings.Contains(content.UpstreamRequestBody.Content, "<EMAIL_1>") || content.HTTPMeta == nil {
			t.Fatalf("L1 content=%#v meta=%#v", content.UpstreamRequestBody, content.HTTPMeta)
		}
		credential, err := store.Get(ctx, secretstore.Ref("local://service/"+string(secondCoreServiceID)))
		if err != nil || string(credential) != secondCoreAPIKey {
			t.Fatalf("credential=%q err=%v", credential, err)
		}
		clear(credential)
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("a stdin key start without a keychain envelope", func(t *testing.T) {
		key, source, err := localkey.Resolve(localkey.Options{StdinKey: localKey, DataDir: directory})
		if err != nil || source != localkey.SourceStdin {
			t.Fatalf("resolve source=%q err=%v", source, err)
		}
		defer clear(key)
		// The desktop would pass LocalEnvelope, but Core A never stored one.
		_, handler := startCore(t, key, true)
		status := operatorRawStatusWith(t, handler)
		if !status.Configured || status.LocalPresence || status.Unlocked || len(status.Envelopes) != 1 || status.Envelopes[0] != "password" {
			t.Fatalf("status=%#v", status)
		}
		wantLockedWithoutProof(t, handler)
	})
}

func operatorRawStatusWith(t *testing.T, handler *Handler) RawSealingStatus {
	t.Helper()
	response := secondCoreHTTP(t, handler, http.MethodGet, RawSealingPath, "")
	wantRawStatus(t, response, http.StatusOK, "")
	var status RawSealingStatus
	decode(t, response, &status)
	return status
}
