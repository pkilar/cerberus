package vsockwatch

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file implements the auditd detection path described in
// docs/vsock-connect-detection.md §3 (Option A) / §4.2: an auditd rule
//
//	auditctl -a always,exit -F arch=b64 -S connect -k cerberus_vsock_watch
//
// (see packaging/audit-rules/61-cerberus-vsock.rules) logs every connect()
// syscall from every process, including the expected ssh-cert-api binary —
// deliberately not filtered by exe, since AuditWatcher needs to see and
// classify a connect() from that exact exe path too, in case it's running
// under the wrong uid or outside cerberus-api.service's cgroup (see
// Allowlist.Classify). That rule alone is noisy (it fires for ANY connect(),
// not just vsock ones), so this package tails the audit log, correlates each
// SYSCALL record with its paired SOCKADDR record (both share the same
// `msg=audit(timestamp:serial)` id), decodes the SOCKADDR's raw sockaddr_vm
// bytes, and only then narrows to (CID, port) == the enclave's. It is
// intentionally independent of the eBPF path in ebpf/loader.go: a different
// kernel facility, a different code path, so an attacker has to disable both
// to fully blind the system (§4.4).
//
// The real security decision is Allowlist.Classify below, applied to every
// parsed event — a misconfigured or absent auditctl rule degrades to "more
// log lines to parse" (or none at all), not "silently stops working".

// auditRecord is one parsed `type=... msg=audit(...): k=v k=v ...` line.
type auditRecord struct {
	recordType string
	msgID      string
	fields     map[string]string
}

// parseAuditLine parses a single audit log line. ok is false for lines that
// don't match the expected `type=X msg=audit(...):` shape (blank lines,
// continuation lines, or unrelated record types we don't care about).
func parseAuditLine(line string) (rec auditRecord, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || !strings.HasPrefix(line, "type=") {
		return auditRecord{}, false
	}

	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return auditRecord{}, false
	}
	recordType := strings.TrimPrefix(line[:sp], "type=")

	open := strings.Index(line, "audit(")
	if open < 0 {
		return auditRecord{}, false
	}
	open += len("audit(")
	closeParen := strings.IndexByte(line[open:], ')')
	if closeParen < 0 {
		return auditRecord{}, false
	}
	msgID := line[open : open+closeParen]

	rest := line[open+closeParen:]
	if idx := strings.IndexByte(rest, ':'); idx >= 0 {
		rest = rest[idx+1:]
	}

	return auditRecord{
		recordType: recordType,
		msgID:      msgID,
		fields:     splitAuditKV(rest),
	}, true
}

// splitAuditKV tokenizes the "key=value key2=\"quoted value\"" tail of an
// audit record. Quoted values may contain spaces; unquoted values may not
// (matching how auditd itself formats these lines).
func splitAuditKV(s string) map[string]string {
	fields := make(map[string]string)
	i := 0
	n := len(s)
	for i < n {
		for i < n && s[i] == ' ' {
			i++
		}
		start := i
		for i < n && s[i] != '=' && s[i] != ' ' {
			i++
		}
		if i >= n || s[i] != '=' {
			// No '=' found before the next space/EOL: not a key=value token,
			// skip to the next space.
			for i < n && s[i] != ' ' {
				i++
			}
			continue
		}
		key := s[start:i]
		i++ // skip '='
		if i < n && s[i] == '"' {
			i++
			valStart := i
			for i < n && s[i] != '"' {
				i++
			}
			fields[key] = s[valStart:i]
			if i < n {
				i++ // skip closing quote
			}
		} else {
			valStart := i
			for i < n && s[i] != ' ' {
				i++
			}
			fields[key] = s[valStart:i]
		}
	}
	return fields
}

// pendingKey pairs correlate SYSCALL and SOCKADDR records sharing a msgID.
type pending struct {
	fields    map[string]string
	saddrHex  string
	firstSeen time.Time
}

// correlator groups SYSCALL and SOCKADDR records by their shared msgID and
// emits a combined Event once both halves have arrived. Unpaired entries are
// swept after pendingTTL — a normal connect() always logs both record types
// back-to-back, so anything left unpaired that long is either a truncated
// tail (process restarted mid-stream) or a record we're not interested in
// (e.g. a SYSCALL for a different socket family never followed by a
// SOCKADDR at all is not possible for connect(), but defense in depth).
type correlator struct {
	mu          sync.Mutex
	pendingByID map[string]*pending
	pendingTTL  time.Duration
}

func newCorrelator() *correlator {
	return &correlator{pendingByID: make(map[string]*pending), pendingTTL: 10 * time.Second}
}

// feed processes one parsed record and returns a decoded Event when the
// SYSCALL+SOCKADDR pair for its msgID is complete.
func (c *correlator) feed(rec auditRecord) (Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.sweepLocked()

	p, ok := c.pendingByID[rec.msgID]
	if !ok {
		p = &pending{firstSeen: time.Now()}
		c.pendingByID[rec.msgID] = p
	}

	switch rec.recordType {
	case "SYSCALL":
		p.fields = rec.fields
	case "SOCKADDR":
		if saddr, ok := rec.fields["saddr"]; ok {
			p.saddrHex = saddr
		}
	default:
		return Event{}, false
	}

	if p.fields == nil || p.saddrHex == "" {
		return Event{}, false
	}
	delete(c.pendingByID, rec.msgID)

	raw, err := hex.DecodeString(p.saddrHex)
	if err != nil {
		return Event{}, false
	}
	addr, err := DecodeSockaddrVM(raw)
	if err != nil {
		return Event{}, false
	}

	return Event{
		Time:   time.Now(),
		PID:    parseUintField(p.fields["pid"]),
		UID:    parseUintField(p.fields["uid"]),
		GID:    parseUintField(p.fields["gid"]),
		Comm:   p.fields["comm"],
		Exe:    p.fields["exe"],
		Addr:   addr,
		Source: SourceAuditd,
	}, true
}

func (c *correlator) sweepLocked() {
	if len(c.pendingByID) == 0 {
		return
	}
	cutoff := time.Now().Add(-c.pendingTTL)
	for id, p := range c.pendingByID {
		if p.firstSeen.Before(cutoff) {
			delete(c.pendingByID, id)
		}
	}
}

func parseUintField(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

// AuditWatcher tails an auditd log file, correlates SYSCALL/SOCKADDR record
// pairs, classifies each connect() that targets the enclave, and ships an
// alert for anything that isn't Expected.
type AuditWatcher struct {
	// Path to the audit log, e.g. "/var/log/audit/audit.log".
	Path string
	// PollInterval controls how often the tailer checks for new data and for
	// log rotation (inode change). 500ms keeps alert latency well under the
	// "within seconds" goal without busy-looping.
	PollInterval time.Duration
	Allowlist    *Allowlist
	Shipper      Shipper
	// Blocker, if set, is invoked for Verdict.Blockworthy() events (the
	// opt-in reactive-kill response; see block.go). Nil disables blocking,
	// the default.
	Blocker Blocker
}

// Run tails Path from EOF (not from the beginning of an existing file — we
// only care about connects from now on) until ctx is canceled. It transparently
// follows log rotation: if the underlying inode changes (logrotate replacing
// the file), Run reopens Path. onReady, if non-nil, is called exactly once,
// immediately after Path is successfully opened and before Run starts
// polling — callers use this to signal process readiness (e.g. systemd's
// sd_notify READY=1, see cmd/cerberus-vsock-watch) only once this detector
// is actually watching, not merely once the process has started.
func (w *AuditWatcher) Run(ctx context.Context, onReady func()) error {
	interval := w.PollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	corr := newCorrelator()

	f, reader, err := openAtEnd(w.Path)
	if err != nil {
		return fmt.Errorf("vsockwatch: opening audit log %q: %w", w.Path, err)
	}
	if onReady != nil {
		onReady()
	}
	defer func() { _ = f.Close() }()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// pending holds a line fragment read without its trailing '\n' — the
	// tail of a write this poll tick caught mid-append. ReadString only
	// returns a non-nil error when it stops without finding the delimiter, so
	// on that path the bytes it did return must be carried over rather than
	// handled as a complete record; otherwise a record that straddles two
	// poll ticks is split, and its second half (which no longer starts with
	// "type=") is silently rejected by parseAuditLine on the next tick —
	// losing exactly the record that might have been alert-worthy.
	var pending strings.Builder

	// lastReopenErr de-dupes reopenIfRotated logging so a persistent failure
	// (permissions changed, path removed, disk issue) is reported instead of
	// spinning silently forever — indistinguishable from a healthy idle
	// watcher — while a merely transient one (e.g. logrotate mid-swap) isn't
	// logged on every tick.
	var lastReopenErr string

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for {
				line, readErr := reader.ReadString('\n')
				if readErr == nil {
					w.handleLine(ctx, corr, pending.String()+line)
					pending.Reset()
					continue
				}
				if line != "" {
					pending.WriteString(line)
				}
				break
			}

			rotated, newF, newReader, err := reopenIfRotated(w.Path, f)
			if err != nil {
				if msg := err.Error(); msg != lastReopenErr {
					slog.Warn("vsockwatch.audit.reopen_failed", "path", w.Path, "error", err)
					lastReopenErr = msg
				}
				continue
			}
			if lastReopenErr != "" {
				slog.Info("vsockwatch.audit.reopen_recovered", "path", w.Path)
				lastReopenErr = ""
			}
			if rotated {
				_ = f.Close()
				f, reader = newF, newReader
				// The old file is gone; any unterminated fragment from it
				// will never be completed.
				pending.Reset()
			}
		}
	}
}

func (w *AuditWatcher) handleLine(ctx context.Context, corr *correlator, line string) {
	rec, ok := parseAuditLine(line)
	if !ok {
		return
	}
	ev, ok := corr.feed(rec)
	if !ok {
		return
	}
	if !ev.Addr.IsEnclaveTarget() {
		return
	}
	cls := w.Allowlist.Classify(ev)
	if !cls.Verdict.Alertworthy() {
		return
	}
	// Blocker runs before Ship: an alert-delivery attempt (even an async,
	// non-blocking one) must never be able to delay the reactive kill, which
	// only has value if it happens promptly. See ship_async.go.
	if w.Blocker != nil && cls.Verdict.Blockworthy() {
		if err := w.Blocker.Block(ctx, ev); err != nil {
			slog.Error("vsockwatch.block.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
		} else {
			slog.Error("vsockwatch.block.killed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe)
		}
	}
	if w.Shipper != nil {
		if err := w.Shipper.Ship(ctx, NewAnomalyAlert(ev, cls)); err != nil {
			slog.Error("vsockwatch.ship.failed", "pid", ev.PID, "uid", ev.UID, "exe", ev.Exe, "error", err)
		}
	}
}

func openAtEnd(path string) (*os.File, *bufio.Reader, error) {
	// #nosec G304 -- path is AuditWatcher.Path, operator configuration (a
	// systemd EnvironmentFile or CLI flag), not untrusted input.
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, bufio.NewReader(f), nil
}

func reopenIfRotated(path string, current *os.File) (rotated bool, f *os.File, r *bufio.Reader, err error) {
	curInfo, err := current.Stat()
	if err != nil {
		return false, nil, nil, err
	}
	pathInfo, err := os.Stat(path)
	if err != nil {
		// Path missing momentarily during rotation: not fatal, caller retries.
		return false, nil, nil, err
	}
	if os.SameFile(curInfo, pathInfo) {
		return false, nil, nil, nil
	}
	// #nosec G304 -- path is AuditWatcher.Path, operator configuration (a
	// systemd EnvironmentFile or CLI flag), not untrusted input.
	newF, err := os.Open(path)
	if err != nil {
		return false, nil, nil, err
	}
	return true, newF, bufio.NewReader(newF), nil
}
