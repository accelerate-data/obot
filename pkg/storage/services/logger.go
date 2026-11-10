package services

import (
	"context"

	"gorm.io/gorm/logger"
)

type parameterizedLogger struct {
	logger.Interface
}

// newParameterizedLogger wraps a GORM logger so that bound query parameter
// values are replaced with placeholders in slow-query and error logs. The
// storage and gateway tables hold secrets that are encrypted at rest but appear
// in cleartext as bound parameters at query time.
func newParameterizedLogger(inner logger.Interface) logger.Interface {
	if inner == nil {
		inner = logger.Default
	}
	return parameterizedLogger{Interface: inner}
}

// ParamsFilter marks the logger so GORM leaves bound values out of traced SQL.
func (parameterizedLogger) ParamsFilter(_ context.Context, sql string, _ ...any) (string, []any) {
	return sql, nil
}

// LogMode re-wraps the result: the promoted LogMode returns the unwrapped
// logger, which would drop the filter for Debug() and any other LogMode caller.
func (l parameterizedLogger) LogMode(level logger.LogLevel) logger.Interface {
	return newParameterizedLogger(l.Interface.LogMode(level))
}

// stripRecorderParams drops bound values from the SQL logged by GORM's Scan
// path. Scan uses the package-global recorder rather than the configured
// logger, so it ignores a logger's own ParamsFilter.
func stripRecorderParams(_ context.Context, sql string, _ ...any) (string, []any) {
	return sql, nil
}

// parameterizeRecorder installs stripRecorderParams for GORM's recorder. It
// takes effect process-wide and only affects what is logged, never execution.
func parameterizeRecorder() {
	logger.RecorderParamsFilter = stripRecorderParams
}
