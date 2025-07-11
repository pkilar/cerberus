package logging

import (
	"log"
	"os"
)

var debugEnabled bool

func init() {
	debugEnabled = os.Getenv("DEBUG") == "true"
}

// Debug logs a message only if debug mode is enabled via DEBUG environment variable
func Debug(format string, args ...any) {
	if debugEnabled {
		log.Printf(format, args...)
	}
}
