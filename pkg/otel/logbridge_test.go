package otel

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/contrib/bridges/otellogrus"
	"go.opentelemetry.io/otel/log/logtest"
	"go.opentelemetry.io/otel/trace"
)

// The bridge contract Init relies on: a logrus entry logged with a context
// whose span is sampled must surface as a log record carrying that span's
// trace id. Uses a private logrus instance wired exactly like Init wires the
// standard one, and the log API's test recorder in place of the provider.
func TestLogrusBridgeCarriesTraceContext(t *testing.T) {
	recorder := logtest.NewRecorder()
	log := logrus.New()
	log.AddHook(otellogrus.NewHook(
		"github.com/obot-platform/obot",
		otellogrus.WithLoggerProvider(recorder),
	))

	traceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	spanID := trace.SpanID{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x01, 0x02}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	}))

	log.WithContext(ctx).WithField("route", "/api/example").Info("http request completed")

	var found bool
	for _, records := range recorder.Result() {
		for _, rec := range records {
			got := trace.SpanContextFromContext(rec.Context)
			if got.TraceID() == traceID && got.SpanID() == spanID {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no log record carried the span's trace context; records: %+v", recorder.Result())
	}
}
