package logging

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
)

var (
	debugEnabled bool
	appLogger    *slog.Logger
)

func init() {
	debugEnabled = os.Getenv("DEBUG") == "true"

	level := slog.LevelInfo
	if debugEnabled {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch strings.ToLower(os.Getenv("LOG_FORMAT")) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	appLogger = slog.New(handler)
	slog.SetDefault(appLogger)

	// Route the stdlib log package through slog so `log.Printf` calls in
	// first- and third-party code land in the same sink with a consistent
	// format. Individual audit events should still use slog directly with
	// structured fields; this bridge is for the tail of un-migrated callers.
	log.SetFlags(0)
	log.SetOutput(slogBridge{})
}

// Debug logs at debug level with a printf-style message. Kept for back-compat;
// prefer slog.Debug / slog.Info / slog.Error with structured attributes in new code.
func Debug(format string, args ...any) {
	if !debugEnabled {
		return
	}
	appLogger.LogAttrs(context.Background(), slog.LevelDebug, fmt.Sprintf(format, args...))
}

// Logger returns the configured application logger.
func Logger() *slog.Logger { return appLogger }

// slogBridge implements io.Writer and forwards stdlib log output to slog.
type slogBridge struct{}

func (slogBridge) Write(b []byte) (int, error) {
	msg := strings.TrimRight(string(b), "\n")
	appLogger.Info(msg)
	return len(b), nil
}
