package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/keegancsmith/sqlf"

	"github.com/sourcegraph/sourcegraph/internal/actor"
	"github.com/sourcegraph/sourcegraph/internal/database/basestore"
	"github.com/sourcegraph/sourcegraph/internal/database/dbutil"
)

// ExecutorSecretAccessLog represents a row in the `executor_secret_access_logs` table.
type ExecutorSecretAccessLog struct {
	ID               int64
	ExecutorSecretID int64
	UserID           int32

	CreatedAt time.Time
}

// ExecutorSecretAccessLogNotFoundErr is returned when a log cannot be found.
type ExecutorSecretAccessLogNotFoundErr struct {
	id int64
}

func (err ExecutorSecretAccessLogNotFoundErr) Error() string {
	return fmt.Sprintf("executor secret access log not found: id=%d", err.id)
}

func (ExecutorSecretAccessLogNotFoundErr) NotFound() bool {
	return true
}

// ExecutorSecretAccessLogStore provides access to the `executor_secret_access_logs` table.
type ExecutorSecretAccessLogStore interface {
	basestore.ShareableStore
	With(basestore.ShareableStore) ExecutorSecretAccessLogStore
	Transact(context.Context) (ExecutorSecretAccessLogStore, error)

	// Create inserts the given ExecutorSecretAccessLog into the database.
	Create(ctx context.Context, log *ExecutorSecretAccessLog) error
	// GetByID returns the executor secret access log matching the given ID, or
	// ExecutorSecretAccessLogNotFoundErr if no such record exists.
	GetByID(ctx context.Context, id int64) (*ExecutorSecretAccessLog, error)
	// List returns all logs matching the given options.
	List(context.Context, ExecutorSecretAccessLogsListOpts) ([]*ExecutorSecretAccessLog, int, error)
	// Count counts all logs matching the given options.
	Count(context.Context, ExecutorSecretAccessLogsListOpts) (int, error)
}

// ExecutorSecretAccessLogsListOpts provide the options when listing secret access
// logs.
type ExecutorSecretAccessLogsListOpts struct {
	*LimitOffset

	// ExecutorSecretID filters the access records by the given secret id.
	ExecutorSecretID int64
}

func (opts ExecutorSecretAccessLogsListOpts) sqlConds() *sqlf.Query {
	preds := []*sqlf.Query{}

	if opts.ExecutorSecretID != 0 {
		preds = append(preds, sqlf.Sprintf("executor_secret_id = %s", opts.ExecutorSecretID))
	}

	if len(preds) == 0 {
		preds = append(preds, sqlf.Sprintf("TRUE"))
	}

	return sqlf.Join(preds, "\n AND ")
}

// limitSQL overrides LimitOffset.SQL() to give a LIMIT clause with one extra value
// so we can populate the next cursor.
func (opts *ExecutorSecretAccessLogsListOpts) limitSQL() *sqlf.Query {
	if opts.LimitOffset == nil || opts.Limit == 0 {
		return &sqlf.Query{}
	}

	return (&LimitOffset{Limit: opts.Limit + 1, Offset: opts.Offset}).SQL()
}

type executorSecretAccessLogStore struct {
	*basestore.Store
}

// ExecutorSecretAccessLogsWith instantiates and returns a new ExecutorSecretAccessLogStore using the other store handle.
func ExecutorSecretAccessLogsWith(other basestore.ShareableStore) ExecutorSecretAccessLogStore {
	return &executorSecretAccessLogStore{
		Store: basestore.NewWithHandle(other.Handle()),
	}
}

func (s *executorSecretAccessLogStore) With(other basestore.ShareableStore) ExecutorSecretAccessLogStore {
	return &executorSecretAccessLogStore{
		Store: s.Store.With(other),
	}
}

func (s *executorSecretAccessLogStore) Transact(ctx context.Context) (ExecutorSecretAccessLogStore, error) {
	txBase, err := s.Store.Transact(ctx)
	return &executorSecretAccessLogStore{
		Store: txBase,
	}, err
}

func (s *executorSecretAccessLogStore) Create(ctx context.Context, log *ExecutorSecretAccessLog) error {
	// Set the current actor as the creator.
	if log.UserID == 0 {
		log.UserID = actor.FromContext(ctx).UID
	}

	q := sqlf.Sprintf(
		executorSecretAccessLogCreateQueryFmtstr,
		log.ExecutorSecretID,
		log.UserID,
		sqlf.Join(executorSecretAccessLogsColumns, ", "),
	)

	row := s.QueryRow(ctx, q)
	if err := scanExecutorSecretAccessLog(log, row); err != nil {
		return err
	}

	return nil
}

func (s *executorSecretAccessLogStore) GetByID(ctx context.Context, id int64) (*ExecutorSecretAccessLog, error) {
	q := sqlf.Sprintf(
		"SELECT %s FROM executor_secret_access_logs WHERE id = %s",
		sqlf.Join(executorSecretAccessLogsColumns, ", "),
		id,
	)

	log := ExecutorSecretAccessLog{}
	row := s.QueryRow(ctx, q)
	if err := scanExecutorSecretAccessLog(&log, row); err == sql.ErrNoRows {
		return nil, ExecutorSecretAccessLogNotFoundErr{id: id}
	} else if err != nil {
		return nil, err
	}

	return &log, nil
}

func (s *executorSecretAccessLogStore) List(ctx context.Context, opts ExecutorSecretAccessLogsListOpts) ([]*ExecutorSecretAccessLog, int, error) {
	conds := opts.sqlConds()

	q := sqlf.Sprintf(
		executorSecretAccessLogsListQueryFmtstr,
		sqlf.Join(executorSecretAccessLogsColumns, ", "),
		conds,
		opts.limitSQL(),
	)

	rows, err := s.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	defer func() { err = basestore.CloseRows(rows, err) }()

	var logs []*ExecutorSecretAccessLog
	for rows.Next() {
		log := ExecutorSecretAccessLog{}
		if err := scanExecutorSecretAccessLog(&log, rows); err != nil {
			return nil, 0, err
		}
		logs = append(logs, &log)
	}

	// Check if there were more results than the limit: if so, then we need to
	// set the return cursor and lop off the extra log that we retrieved.
	next := 0
	if opts.LimitOffset != nil && opts.Limit != 0 && len(logs) == opts.Limit+1 {
		next = opts.Offset + opts.Limit
		logs = logs[:len(logs)-1]
	}

	return logs, next, nil
}

func (s *executorSecretAccessLogStore) Count(ctx context.Context, opts ExecutorSecretAccessLogsListOpts) (int, error) {
	conds := opts.sqlConds()

	q := sqlf.Sprintf(
		executorSecretAccessLogsCountQueryFmtstr,
		conds,
	)

	totalCount, _, err := basestore.ScanFirstInt(s.Query(ctx, q))
	if err != nil {
		return 0, err
	}

	return totalCount, nil
}

// executorSecretAccessLogsColumns are the columns that must be selected by
// executor_secret_access_logs queries in order to use scanExecutorSecretAccessLog().
var executorSecretAccessLogsColumns = []*sqlf.Query{
	sqlf.Sprintf("id"),
	sqlf.Sprintf("executor_secret_id"),
	sqlf.Sprintf("user_id"),
	sqlf.Sprintf("created_at"),
}

const executorSecretAccessLogsListQueryFmtstr = `
SELECT %s
FROM executor_secret_access_logs
WHERE %s
ORDER BY created_at DESC
%s  -- LIMIT clause
`

const executorSecretAccessLogsCountQueryFmtstr = `
SELECT COUNT(*)
FROM executor_secret_access_logs
WHERE %s
`

const executorSecretAccessLogCreateQueryFmtstr = `
INSERT INTO
	executor_secret_access_logs (
		executor_secret_id,
		user_id,
		created_at
	)
	VALUES (
		%s,
		%s,
		NOW()
	)
	RETURNING %s
`

// scanExecutorSecretAccessLog scans an ExecutorSecretAccessLog from the given scanner
// into the given ExecutorSecretAccessLog.
func scanExecutorSecretAccessLog(log *ExecutorSecretAccessLog, s dbutil.Scanner) error {
	return s.Scan(
		&log.ID,
		&log.ExecutorSecretID,
		&log.UserID,
		&log.CreatedAt,
	)
}
