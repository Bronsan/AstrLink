package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/QuantumNous/astrlink/core/contract"
	storagecontract "github.com/QuantumNous/astrlink/core/internal/storage"
	"github.com/QuantumNous/astrlink/core/internal/storage/migrate"
)

const (
	// unsealTargetVersion is the last migration of the release before local
	// data protection; Unseal leaves the database exactly there.
	unsealTargetVersion = 41
	// unsealSourceVersion is the newest migration Unseal knows how to undo.
	// A later migration must extend the rollback before Unseal accepts it.
	unsealSourceVersion = 45

	legacySubscriptionRefPrefix = "keyring://astrlink/subscription/"
)

// UnsealOptions supplies what Unseal cannot find in the database.
type UnsealOptions struct {
	// OpenRawPart returns the part key of one raw_v1 part. The local key never
	// opens raw content, so without the raw password it is nil and raw parts
	// count as unreadable.
	OpenRawPart func(storagecontract.AuditBlob) ([]byte, error)
	// ExportSubscription writes one account's OAuth token JSON to the OS
	// keystore the older release reads. It runs last, before the commit, so
	// an error rolls the database back; the caller undoes the writes it
	// made. Nil counts every account's tokens as unreadable.
	ExportSubscription func(context.Context, contract.SubscriptionAccountID, []byte) error
	// DiscardUnreadable drops what cannot be carried back instead of failing.
	DiscardUnreadable bool
}

// UnsealUnreadable counts what the older release could not read.
type UnsealUnreadable struct {
	Credentials   int
	Subscriptions int
	RawParts      int
	// SetAsideKeys are data keys an earlier local key wrapped. The older
	// release has nowhere to keep them.
	SetAsideKeys int
}

func (unreadable UnsealUnreadable) empty() bool {
	return unreadable == UnsealUnreadable{}
}

// UnsealResult reports what Unseal carried back and what it dropped.
type UnsealResult struct {
	Credentials   int
	Subscriptions int
	RawParts      int
	Discarded     UnsealUnreadable
}

// UnsealUnreadableError stops Unseal before it changes anything when data
// would be lost and DiscardUnreadable is not set.
type UnsealUnreadableError struct {
	Unreadable UnsealUnreadable
}

func (err *UnsealUnreadableError) Error() string {
	unreadable := err.Unreadable
	return fmt.Sprintf("%d credential(s), %d account credential(s), %d raw part(s) and %d set-aside data key(s) cannot be carried back",
		unreadable.Credentials, unreadable.Subscriptions, unreadable.RawParts, unreadable.SetAsideKeys)
}

// Unseal rolls the database back to migration 41 so the release before
// local data protection opens it (plan §5.6): secrets become plaintext
// again, dek_audit goes back to audit_keys, raw parts are resealed under it,
// OAuth tokens move to the OS keystore, and every table and column added
// since is removed. It runs in one transaction; on any error nothing
// changes. Close the store afterwards: it no longer matches this build.
func (store *Store) Unseal(ctx context.Context, options UnsealOptions) (result UnsealResult, err error) {
	auditKey := store.keys.audit()
	if auditKey == nil {
		return result, fmt.Errorf("%w: audit key", storagecontract.ErrNotFound)
	}
	defer clear(auditKey)
	schema, err := releasedSchema()
	if err != nil {
		return result, err
	}
	err = store.withSecureDelete(ctx, true, func(conn *sql.Conn) (err error) {
		// Foreign keys stay off while tables are rebuilt; the check before the
		// commit covers them. The pragma is a no-op inside a transaction.
		if _, err = conn.ExecContext(ctx, `PRAGMA foreign_keys = OFF`); err != nil {
			return fmt.Errorf("disable foreign keys: %w", err)
		}
		defer func() { _, _ = conn.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`) }()
		transaction, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin unseal: %w", err)
		}
		defer rollbackOnError(transaction, &err)
		result, err = store.unsealTx(ctx, transaction, auditKey, schema, options)
		if err != nil {
			return err
		}
		if err = transaction.Commit(); err != nil {
			return fmt.Errorf("commit unseal: %w", err)
		}
		return nil
	})
	if err != nil {
		return UnsealResult{}, err
	}
	return result, nil
}

type unsealedRow struct {
	column secretColumn
	key    string
	value  []byte
}

type unreadableRawPart struct {
	payloadID int64
	requestID string
	direction storagecontract.AuditDirection
}

func (store *Store) unsealTx(ctx context.Context, transaction *sql.Tx, auditKey []byte, schema releasedStatements, options UnsealOptions) (result UnsealResult, err error) {
	var version int64
	if err = transaction.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return result, fmt.Errorf("read schema version: %w", err)
	}
	if version != unsealSourceVersion {
		return result, fmt.Errorf("%w: unseal undoes migrations %d to %d, this database is at %d",
			storagecontract.ErrPrecondition, unsealTargetVersion+1, unsealSourceVersion, version)
	}

	var unreadable UnsealUnreadable
	var subscriptions []unsealedRow
	defer func() {
		for _, row := range subscriptions {
			clear(row.value)
		}
	}()
	var unreadableRows []unsealedRow
	for _, column := range secretColumns {
		opened, failed, openErr := store.openSealedColumnTx(ctx, transaction, column)
		if openErr != nil {
			err = openErr
			return result, err
		}
		unreadableRows = append(unreadableRows, failed...)
		if !column.flagged {
			subscriptions = opened
			unreadable.Subscriptions = len(failed)
			continue
		}
		unreadable.Credentials += len(failed)
		for _, row := range opened {
			err = restorePlaintextTx(ctx, transaction, row)
			clear(row.value)
			if err != nil {
				return result, err
			}
			result.Credentials++
		}
	}
	if options.ExportSubscription == nil {
		unreadable.Subscriptions += len(subscriptions)
		subscriptions = nil
	}

	resealed, rawFailed, err := resealRawPartsUnderAuditKey(ctx, transaction, auditKey, options.OpenRawPart)
	if err != nil {
		return result, err
	}
	result.RawParts = resealed
	unreadable.RawParts = len(rawFailed)
	if err = transaction.QueryRowContext(ctx, `SELECT COUNT(*) FROM key_envelopes WHERE kind LIKE '%.%'`).Scan(&unreadable.SetAsideKeys); err != nil {
		return result, fmt.Errorf("count set-aside data keys: %w", err)
	}
	if !unreadable.empty() {
		if !options.DiscardUnreadable {
			return result, &UnsealUnreadableError{Unreadable: unreadable}
		}
		if err = discardUnsealTx(ctx, transaction, unreadableRows, rawFailed); err != nil {
			return result, err
		}
		result.Discarded = unreadable
	}

	// Every account points back at the keystore, including those whose
	// tokens were dropped: the older release rejects a local:// ref, and an
	// account without tokens only asks to sign in again.
	if _, err = transaction.ExecContext(ctx, `UPDATE services
SET document_json = json_set(document_json, '$.subscription.credential_ref', ?1 || id)
WHERE json_valid(document_json)
  AND json_extract(document_json, '$.subscription.credential_ref') = ?2 || id`,
		legacySubscriptionRefPrefix, subscriptionRefPrefix); err != nil {
		return result, fmt.Errorf("point accounts at the OS keystore: %w", err)
	}
	if _, err = transaction.ExecContext(ctx, `INSERT OR REPLACE INTO audit_keys (id, key_bytes, created_at) VALUES (1, ?, ?)`,
		auditKey, store.now().UTC().Format(time.RFC3339Nano)); err != nil {
		return result, fmt.Errorf("restore audit key: %w", err)
	}
	if err = restoreReleasedSchemaTx(ctx, transaction, schema); err != nil {
		return result, err
	}
	for _, row := range subscriptions {
		if err = options.ExportSubscription(ctx, contract.SubscriptionAccountID(row.key), row.value); err != nil {
			return result, fmt.Errorf("export account %s: %w", row.key, err)
		}
		result.Subscriptions++
	}
	return result, nil
}

// openSealedColumnTx opens every sealed value in column. The caller owns the
// returned plaintext.
func (store *Store) openSealedColumnTx(ctx context.Context, transaction *sql.Tx, column secretColumn) (opened, failed []unsealedRow, err error) {
	filter := ""
	if column.flagged {
		filter = ` WHERE sealed = 1`
	}
	rows, err := transaction.QueryContext(ctx, fmt.Sprintf(`SELECT %s, %s FROM %s%s`, column.key, column.value, column.table, filter))
	if err != nil {
		return nil, nil, fmt.Errorf("read sealed %s: %w", column.table, err)
	}
	defer rows.Close()
	defer func() {
		if err != nil {
			for _, row := range opened {
				clear(row.value)
			}
			opened = nil
		}
	}()
	for rows.Next() {
		row := unsealedRow{column: column}
		var stored []byte
		if err = rows.Scan(&row.key, &stored); err != nil {
			return nil, nil, fmt.Errorf("read sealed %s: %w", column.table, err)
		}
		plaintext, openErr := store.keys.openColumn(column.table, row.key, stored)
		clear(stored)
		if openErr != nil {
			failed = append(failed, row)
			continue
		}
		row.value = plaintext
		opened = append(opened, row)
	}
	if err = rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("read sealed %s: %w", column.table, err)
	}
	return opened, failed, nil
}

func restorePlaintextTx(ctx context.Context, transaction *sql.Tx, row unsealedRow) error {
	// The older release stores access tokens as TEXT.
	var value any = row.value
	if row.column.table == accessTokenSecretsTable {
		value = string(row.value)
	}
	if _, err := transaction.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET %s = ?, sealed = 0 WHERE %s = ?`,
		row.column.table, row.column.value, row.column.key), value, row.key); err != nil {
		return fmt.Errorf("restore %s %s: %w", row.column.table, row.key, err)
	}
	return nil
}

// resealRawPartsUnderAuditKey turns every raw_v1 payload into an audit
// payload the older release opens with audit_keys. The random content key
// stays; the older release never looks a raw part up by it.
func resealRawPartsUnderAuditKey(ctx context.Context, transaction *sql.Tx, auditKey []byte, openPart func(storagecontract.AuditBlob) ([]byte, error)) (resealed int, failed []unreadableRawPart, err error) {
	type rawPayload struct {
		id, keyID            int64
		wrapped              []byte
		requestID, direction sql.NullString
	}
	rows, err := transaction.QueryContext(ctx, `SELECT p.id, p.key_id, p.wrapped_key, b.request_id, b.direction
FROM audit_payloads p
LEFT JOIN audit_blobs b ON b.rowid = (SELECT MIN(rowid) FROM audit_blobs WHERE payload_id = p.id)
WHERE p.sealing = 'raw_v1'`)
	if err != nil {
		return 0, nil, fmt.Errorf("read raw parts: %w", err)
	}
	var payloads []rawPayload
	for rows.Next() {
		var payload rawPayload
		if err = rows.Scan(&payload.id, &payload.keyID, &payload.wrapped, &payload.requestID, &payload.direction); err != nil {
			_ = rows.Close()
			return 0, nil, fmt.Errorf("read raw part: %w", err)
		}
		payloads = append(payloads, payload)
	}
	if err = rows.Err(); err != nil {
		_ = rows.Close()
		return 0, nil, fmt.Errorf("read raw parts: %w", err)
	}
	_ = rows.Close()

	for _, payload := range payloads {
		if !payload.requestID.Valid {
			// No part references it; the delete trigger missed nothing a
			// reader could reach.
			if _, err = transaction.ExecContext(ctx, `DELETE FROM audit_payloads WHERE id = ?`, payload.id); err != nil {
				return 0, nil, fmt.Errorf("delete unreferenced raw payload: %w", err)
			}
			continue
		}
		part := unreadableRawPart{payloadID: payload.id, requestID: payload.requestID.String,
			direction: storagecontract.AuditDirection(payload.direction.String)}
		ok, resealErr := resealRawPayloadTx(ctx, transaction, auditKey, openPart, storagecontract.AuditBlob{
			RequestID: contract.RequestID(part.requestID), Direction: part.direction,
			Sealing: storagecontract.AuditSealingRawV1, RawKeyID: payload.keyID, WrappedKey: payload.wrapped,
		}, payload.id)
		if resealErr != nil {
			return 0, nil, resealErr
		}
		if !ok {
			failed = append(failed, part)
			continue
		}
		resealed++
	}
	return resealed, failed, nil
}

// resealRawPayloadTx reports false when the part does not open.
func resealRawPayloadTx(ctx context.Context, transaction *sql.Tx, auditKey []byte, openPart func(storagecontract.AuditBlob) ([]byte, error), blob storagecontract.AuditBlob, payloadID int64) (bool, error) {
	if openPart == nil {
		return false, nil
	}
	if err := transaction.QueryRowContext(ctx, `SELECT nonce, ciphertext FROM audit_payloads WHERE id = ?`, payloadID).
		Scan(&blob.Nonce, &blob.Ciphertext); err != nil {
		return false, fmt.Errorf("read raw part: %w", err)
	}
	partKey, err := openPart(blob)
	if err != nil {
		return false, nil
	}
	plain, err := storagecontract.OpenAuditBlob(partKey, blob.Nonce, blob.Ciphertext)
	clear(partKey)
	if err != nil {
		return false, nil
	}
	defer clear(plain)
	nonce, ciphertext, err := storagecontract.SealAuditBlob(auditKey, plain)
	if err != nil {
		return false, err
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE audit_payloads
SET nonce = ?, ciphertext = ?, sealing = 'audit', key_id = NULL, wrapped_key = NULL WHERE id = ?`,
		nonce, ciphertext, payloadID); err != nil {
		return false, fmt.Errorf("reseal raw part: %w", err)
	}
	return true, nil
}

// discardUnsealTx drops unreadable secrets and raw parts. The older release
// rejects an access token without its secret, so the token goes too. Records
// that lose a part no longer claim to have captured it, as after a raw
// password reset. Foreign keys are off, so nothing cascades.
func discardUnsealTx(ctx context.Context, transaction *sql.Tx, rows []unsealedRow, parts []unreadableRawPart) error {
	for _, row := range rows {
		if !row.column.flagged {
			continue
		}
		if _, err := transaction.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE %s = ?`, row.column.table, row.column.key), row.key); err != nil {
			return fmt.Errorf("discard %s %s: %w", row.column.table, row.key, err)
		}
		if row.column.table == accessTokenSecretsTable {
			if _, err := transaction.ExecContext(ctx, `DELETE FROM local_access_tokens WHERE id = ?`, row.key); err != nil {
				return fmt.Errorf("discard access token %s: %w", row.key, err)
			}
		}
	}
	for _, part := range parts {
		if paths, ok := capturedFlagPaths[part.direction]; ok {
			if _, err := transaction.ExecContext(ctx, `UPDATE request_records
SET audit_json = json_set(audit_json, ?1, json('false'), ?2, json('false'))
WHERE id = ?3 AND json_valid(audit_json)`, paths[0], paths[1], part.requestID); err != nil {
				return fmt.Errorf("clear captured flags: %w", err)
			}
		}
		if _, err := transaction.ExecContext(ctx, `DELETE FROM audit_blobs WHERE payload_id = ?`, part.payloadID); err != nil {
			return fmt.Errorf("discard raw part: %w", err)
		}
		if _, err := transaction.ExecContext(ctx, `DELETE FROM audit_payloads WHERE id = ?`, part.payloadID); err != nil {
			return fmt.Errorf("discard raw payload: %w", err)
		}
	}
	return nil
}

// releasedStatements are the exact definitions the older release created,
// taken from its migrations so the restored schema matches a database it
// migrated itself.
type releasedStatements struct {
	auditPayloads, payloadDeleteTrigger, payloadUpdateTrigger string
	serviceCredentials, accessTokenSecrets                    string
}

func releasedSchema() (releasedStatements, error) {
	find := func(prefix string) (string, error) {
		var found string
		for _, migration := range migrate.DefaultMigrations() {
			if migration.Version > unsealTargetVersion {
				break
			}
			for _, statement := range migration.Statements {
				if strings.HasPrefix(statement, prefix) {
					found = statement
				}
			}
		}
		if found == "" {
			return "", fmt.Errorf("%w: migration %d has no %q", storagecontract.ErrInvalidRecord, unsealTargetVersion, prefix)
		}
		return found, nil
	}
	var schema releasedStatements
	var err error
	for _, target := range []struct {
		value  *string
		prefix string
	}{
		{&schema.auditPayloads, "CREATE TABLE audit_payloads ("},
		{&schema.payloadDeleteTrigger, "CREATE TRIGGER audit_blob_payload_delete "},
		{&schema.payloadUpdateTrigger, "CREATE TRIGGER audit_blob_payload_update "},
		{&schema.serviceCredentials, "CREATE TABLE service_credentials ("},
		{&schema.accessTokenSecrets, "CREATE TABLE local_access_token_secrets ("},
	} {
		if *target.value, err = find(target.prefix); err != nil {
			return releasedStatements{}, err
		}
	}
	return schema, nil
}

// restoreReleasedSchemaTx undoes migrations 42 to 45. Rebuilt tables are
// renamed away with legacy_alter_table on, so references to them in other
// tables keep naming the original, which is then created from its exact
// definition.
func restoreReleasedSchemaTx(ctx context.Context, transaction *sql.Tx, schema releasedStatements) error {
	rebuild := func(table, create, columns, selection string) []string {
		return []string{
			`PRAGMA legacy_alter_table = ON`,
			`ALTER TABLE ` + table + ` RENAME TO ` + table + `_unseal`,
			`PRAGMA legacy_alter_table = OFF`,
			create,
			`INSERT INTO ` + table + ` (` + columns + `) SELECT ` + selection + ` FROM ` + table + `_unseal`,
			`DROP TABLE ` + table + `_unseal`,
		}
	}
	var statements []string
	// 45 sealed_secrets
	statements = append(statements, `DROP TABLE subscription_credentials`,
		`ALTER TABLE service_proxy_credentials DROP COLUMN sealed`,
		`ALTER TABLE builtin_tool_credentials DROP COLUMN sealed`)
	statements = append(statements, rebuild(accessTokenSecretsTable, schema.accessTokenSecrets,
		`token_id, token_value`, `token_id, CAST(token_value AS TEXT)`)...)
	statements = append(statements, rebuild(serviceCredentialsTable, schema.serviceCredentials,
		`service_id, credential_value, created_at, updated_at`, `service_id, credential_value, created_at, updated_at`)...)
	// 44 raw_sealing: the payload columns carry a foreign key and a CHECK
	// naming each other, so the table is rebuilt; its triggers name it.
	statements = append(statements, `DROP INDEX audit_payloads_raw_key_idx`,
		`DROP TRIGGER audit_blob_payload_delete`, `DROP TRIGGER audit_blob_payload_update`)
	statements = append(statements, rebuild("audit_payloads", schema.auditPayloads,
		`id, request_id, content_key, nonce, ciphertext`, `id, request_id, content_key, nonce, ciphertext`)...)
	statements = append(statements, schema.payloadDeleteTrigger, schema.payloadUpdateTrigger,
		`DROP TABLE raw_key_envelopes`, `DROP TABLE raw_sealing_keys`,
		// 43 key_envelopes
		`DROP TABLE key_envelopes`, `DROP TABLE pending_file_scrub`,
		// 42 audit_exposure
		`ALTER TABLE audit_settings DROP COLUMN agent_raw_access_enabled`,
		`ALTER TABLE request_records DROP COLUMN privacy_findings_json`,
		`ALTER TABLE request_records DROP COLUMN privacy_decision`,
		`ALTER TABLE audit_blobs DROP COLUMN exposure`,
		fmt.Sprintf(`DELETE FROM schema_migrations WHERE version > %d`, unsealTargetVersion))
	for _, statement := range statements {
		if _, err := transaction.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("restore migration %d schema: %q: %w", unsealTargetVersion, firstLine(statement), err)
		}
	}
	rows, err := transaction.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return fmt.Errorf("check foreign keys: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var table, parent string
		var rowID sql.NullInt64
		var index int
		if err := rows.Scan(&table, &rowID, &parent, &index); err != nil {
			return fmt.Errorf("check foreign keys: %w", err)
		}
		return fmt.Errorf("%w: %s row %d references a missing %s", storagecontract.ErrInvalidRecord, table, rowID.Int64, parent)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("check foreign keys: %w", err)
	}
	return nil
}

func firstLine(statement string) string {
	line, _, _ := strings.Cut(statement, "\n")
	return line
}
