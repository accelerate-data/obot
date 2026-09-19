package services

import (
	"bytes"
	"context"
	stdlog "log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const scanSecret = "oauth-client-secret-value"

func openTestDB(t *testing.T, logOutput *bytes.Buffer) *gorm.DB {
	t.Helper()

	base := logger.New(stdlog.New(logOutput, "", 0), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Info,
		IgnoreRecordNotFoundError: true,
	})
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: newParameterizedLogger(base),
	})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db.DB: %v", err)
	}
	// A bare :memory: database is per-connection; pin the pool so the
	// duplicate-key precondition below stays on one connection.
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })

	return db
}

// TestParameterizedLoggerHidesBoundValues guards against bound query parameter
// values reaching the log sink in cleartext. The wrapped logger is a normal,
// non-parameterized GORM logger, so the test fails if the wrapper stops
// stripping the values.
func TestParameterizedLoggerHidesBoundValues(t *testing.T) {
	var logOutput bytes.Buffer
	db := openTestDB(t, &logOutput)

	type sample struct {
		ID     uint
		Secret string
	}
	if err := db.AutoMigrate(&sample{}); err != nil {
		t.Fatalf("AutoMigrate: %v", err)
	}
	if err := db.Create(&sample{ID: 1, Secret: scanSecret}).Error; err != nil {
		t.Fatalf("Create: %v", err)
	}
	// A duplicate primary key forces the logger to emit an error line carrying
	// the query text, exercising the same value-substitution path as a slow query.
	if err := db.Create(&sample{ID: 1, Secret: scanSecret}).Error; err == nil {
		t.Fatal("expected a duplicate key error to force a logged query")
	}

	logged := logOutput.String()
	if strings.Contains(logged, scanSecret) {
		t.Fatalf("bound value leaked into query log: %s", logged)
	}
	if !strings.Contains(logged, "?") {
		t.Fatalf("expected parameterized placeholders in query log, got: %s", logged)
	}
}

// TestParameterizedLoggerSurvivesLogMode pins that the filter is not dropped by
// LogMode, which GORM's Debug() calls and which otherwise returns the wrapped
// logger without the ParamsFilter method.
func TestParameterizedLoggerSurvivesLogMode(t *testing.T) {
	var logOutput bytes.Buffer
	base := logger.New(stdlog.New(&logOutput, "", 0), logger.Config{LogLevel: logger.Info})

	filter, ok := newParameterizedLogger(base).LogMode(logger.Info).(gorm.ParamsFilter)
	if !ok {
		t.Fatalf("LogMode dropped ParamsFilter: %T", newParameterizedLogger(base).LogMode(logger.Info))
	}
	if _, params := filter.ParamsFilter(context.Background(), "SELECT ?", scanSecret); len(params) != 0 {
		t.Fatalf("LogMode result kept bound values: %v", params)
	}
}

// TestParameterizeRecorderHidesScanBoundValues covers GORM's Scan path, which
// logs the SQL built by the package-global recorder instead of the configured
// logger. It first proves the trigger interpolates under GORM's default
// recorder filter, then proves the package filter drops the value.
func TestParameterizeRecorderHidesScanBoundValues(t *testing.T) {
	original := logger.RecorderParamsFilter
	t.Cleanup(func() { logger.RecorderParamsFilter = original })

	logger.RecorderParamsFilter = func(_ context.Context, sql string, params ...any) (string, []any) {
		return sql, params
	}
	if leaked := captureScanLog(t); !strings.Contains(leaked, scanSecret) {
		t.Fatalf("expected the default recorder filter to interpolate, got: %s", leaked)
	}

	parameterizeRecorder()
	if filtered := captureScanLog(t); strings.Contains(filtered, scanSecret) {
		t.Fatalf("scan leaked bound value: %s", filtered)
	}
}

func captureScanLog(t *testing.T) string {
	t.Helper()

	var logOutput bytes.Buffer
	db := openTestDB(t, &logOutput)
	if err := db.Exec("CREATE TABLE samples (id INTEGER PRIMARY KEY, secret TEXT)").Error; err != nil {
		t.Fatalf("create table: %v", err)
	}
	logOutput.Reset()

	var dest []map[string]any
	_ = db.Raw("SELECT missing_column FROM samples WHERE secret = ?", scanSecret).Scan(&dest).Error

	return logOutput.String()
}

// TestNewParameterizesQueryLogging pins the wiring: every storage factory the
// services layer hands out must carry a logger that refuses to substitute bound
// values, and the recorder filter must be installed for the Scan path.
func TestNewParameterizesQueryLogging(t *testing.T) {
	services, err := New(Config{
		DSN: "sqlite://file:" + filepath.Join(t.TempDir(), "obot.db") + "?_journal=WAL&cache=shared&_busy_timeout=30000",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = services.DB.SQLDB.Close() })

	if _, ok := services.DB.DB.Logger.(gorm.ParamsFilter); !ok {
		t.Fatalf("storage logger %T does not parameterize bound query values", services.DB.DB.Logger)
	}
	if _, params := logger.RecorderParamsFilter(context.Background(), "SELECT ?", scanSecret); len(params) != 0 {
		t.Fatalf("recorder filter kept bound values: %v", params)
	}
}
