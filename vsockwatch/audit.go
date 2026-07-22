package vsockwatch

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// This file implements the auditd detection path described in
// docs/vsock-connect-detection.md §3 (Option A) / §4.2: an auditd rule
//
//	auditctl -a always,exit -F arch=b64 -S connect -F exe!=/usr/bin/ssh-cert-api -k cerberus_vsock_watch
//
// logs every connect() syscall from a process other than the expected
// ssh-cert-api binary. That rule alone is noisy (it fires for ANY connect(),
// not just vsock ones), so this package tails the audit log, correlates each
// SYSCALL record with its paired SOCKADDR record (both share the same
// `msg=audit(timestamp:serial)` id), decodes the SOCKADDR's raw sockaddr_vm
// bytes, and only then narrows to (CID, port) == the enclave's. It is
// intentionally independent of the eBPF path in ebpf/loader.go: a different
// kernel facility, a different code path, so an attacker has to disable both
// to fully blind the system (§4.4).
//
// Note the auditctl rule's `-F exe!=` pre-filter is a coarse noise reduction,
// not the actual security boundary — the real decision is Allowlist.Classify
// below, which is why this package still classifies every parsed event
// rather than trusting the rule's exe filter alone (defense in depth, and it
// means a misconfigured or absent auditctl rule degrades to "more log lines
// to parse", not "silently stops working").

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
}

// Run tails Path from EOF (not from the beginning of an existing file — we
// only care about connects from now on) until ctx is canceled. It transparently
// follows log rotation: if the underlying inode changes (logrotate replacing
// the file), Run reopens Path.
func (w *AuditWatcher) Run(ctx context.Context) error {
	interval := w.PollInterval
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	corr := newCorrelator()

	f, reader, err := openAtEnd(w.Path)
	if err != nil {
		return fmt.Errorf("vsockwatch: opening audit log %q: %w", w.Path, err)
	}
	defer f.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for {
				line, readErr := reader.ReadString('\n')
				if line != "" {
					w.handleLine(ctx, corr, line)
				}
				if readErr != nil {
					break
				}
			}

			rotated, newF, newReader, err := reopenIfRotated(w.Path, f)
			if err != nil {
				// Transient stat errors (e.g. logrotate mid-swap) are not
				// fatal; retry next tick rather than aborting the watcher.
				continue
			}
			if rotated {
				f.Close()
				f, reader = newF, newReader
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
	if w.Shipper != nil {
		_ = w.Shipper.Ship(ctx, NewAnomalyAlert(ev, cls))
	}
}

func openAtEnd(path string) (*os.File, *bufio.Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
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
	newF, err := os.Open(path)
	if err != nil {
		return false, nil, nil, err
	}
	return true, newF, bufio.NewReader(newF), nil
}
