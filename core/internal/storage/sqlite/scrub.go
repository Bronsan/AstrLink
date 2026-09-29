package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// errScrubBusy means another connection still uses the file, so it cannot be
// replaced now. The request stays for the next start.
var errScrubBusy = errors.New("database is in use by another connection")

// scrubHook lets tests stop a scrub at a named step, as a crash would.
var scrubHook func(step string) error

func scrubStep(step string) error {
	if scrubHook == nil {
		return nil
	}
	return scrubHook(step)
}

func filePendingScrub(ctx context.Context, database *sql.DB) (bool, error) {
	var pending bool
	if err := database.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pending_file_scrub)`).Scan(&pending); err != nil {
		return false, fmt.Errorf("read file scrub request: %w", err)
	}
	return pending, nil
}

// scrubFile rewrites the database so free pages and old WAL frames no longer
// hold plaintext that was deleted (the legacy audit key, later plaintext
// secrets). It checkpoints, writes a compact copy with VACUUM INTO, and
// renames it over the original. The request row travels inside the copy and
// is deleted only after the rename, so a crash at any step leaves either the
// original or the copy, each still asking for the scrub; the next start
// retries.
func (store *Store) scrubFile(ctx context.Context, path string) (err error) {
	var busy, walFrames, checkpointed int
	if err := store.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &walFrames, &checkpointed); err != nil {
		return fmt.Errorf("checkpoint before scrub: %w", err)
	}
	if busy != 0 {
		return errScrubBusy
	}
	temporary := path + ".scrub"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale scrub copy: %w", err)
	}
	// VACUUM INTO accepts an empty file, so the copy is private from the start.
	if err := createPrivateFile(temporary); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := store.db.ExecContext(ctx, `VACUUM INTO ?`, temporary); err != nil {
		return fmt.Errorf("write scrub copy: %w", err)
	}
	if err := syncFile(temporary); err != nil {
		return err
	}
	if err := scrubStep("before_close"); err != nil {
		return err
	}

	if err := store.db.Close(); err != nil {
		return fmt.Errorf("close database for scrub: %w", err)
	}
	store.db = nil
	defer func() {
		if store.db != nil {
			return
		}
		// Whatever happened, the store keeps working on whichever file now
		// sits at path.
		database, reopenErr := openDatabase(ctx, path)
		if reopenErr != nil {
			err = errors.Join(err, fmt.Errorf("reopen database after scrub: %w", reopenErr))
			return
		}
		store.db = database
	}()
	// The last connection to close removes the WAL. If it is still there,
	// another process has the database open and must not lose its file.
	// This check and the rename below are not atomic. They assume one Core
	// per data directory, so no other process opens the file in between.
	if _, statErr := os.Lstat(path + "-wal"); statErr == nil {
		return errScrubBusy
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("inspect wal before scrub: %w", statErr)
	}
	if err := scrubStep("before_replace"); err != nil {
		return err
	}
	if err := os.Remove(path + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove shared memory before scrub: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace database with scrub copy: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := scrubStep("after_replace"); err != nil {
		return err
	}

	database, err := openDatabase(ctx, path)
	if err != nil {
		return fmt.Errorf("reopen scrubbed database: %w", err)
	}
	store.db = database
	if _, err := database.ExecContext(ctx, `DELETE FROM pending_file_scrub`); err != nil {
		return fmt.Errorf("clear file scrub request: %w", err)
	}
	return nil
}

func createPrivateFile(path string) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", filepath.Base(path), err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	return nil
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open data directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync data directory: %w", err)
	}
	return nil
}
