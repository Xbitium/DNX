package main

// The router's first tests arrive with the retirement of the fixed address,
// because the retirement created the one behaviour worth pinning: what
// happens when yesterday's wire format shows up on today's network.

import (
	"encoding/binary"
	"strings"
	"testing"

	"dnx/internal/nspath"
)

// A 0xDF frame — the retired fixed address — must be refused BY NAME. An old
// sender is version skew, the ordinary condition of a protocol (defect 9),
// and "unrecognised marker" would send its operator hunting corruption when
// the truth is a one-line answer: your binary predates the migration.
func TestRetiredFixedFrameIsRefusedByName(t *testing.T) {
	frame := make([]byte, 35)
	frame[0] = retiredFixedMagic // a well-formed frame of the dead format
	_, _, _, err := decode(frame)
	if err == nil {
		t.Fatal("CRITICAL: a fixed-address frame was decoded after the format's retirement")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Fatalf("refused without saying why: %v — an operator cannot act on that", err)
	}

	// Genuinely unknown garbage stays a different answer: nobody's old
	// binary sent it, so nobody should be told to upgrade.
	garbage := []byte{0xAB, 0x01}
	if _, _, _, err := decode(garbage); err == nil || strings.Contains(err.Error(), "retired") {
		t.Fatalf("an unknown marker must be its own refusal, got: %v", err)
	}
}

// The surviving format still round-trips through encode and decode — the
// retirement removed a format, not the network.
func TestPathFrameSurvivesTheRetirement(t *testing.T) {
	p := nspath.Path{1, 1, 1, 2}
	payload := append([]byte{0xD8}, []byte("sealed")...)
	b := pathDest{path: p}.encode(2, payload)
	if b == nil {
		t.Fatal("encode failed")
	}
	dest, consumed, gotPayload, err := decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !dest.path.Equal(p) {
		t.Fatalf("path corrupted in transit: got %v want %v", dest.path, p)
	}
	if consumed != 2 {
		t.Fatalf("resolved-level counter corrupted: got %d want 2", consumed)
	}
	if string(gotPayload) != string(payload) {
		t.Fatal("payload corrupted in transit")
	}
	_ = binary.BigEndian // keep the import honest if the assertions above change
}
