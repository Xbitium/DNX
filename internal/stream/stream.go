// Package stream implements the DNX v0.2 reliable byte-stream layer.
//
// ------------------------------------------------------------------
// WHERE THIS SITS: inside an already-sealed session (internal/secure).
// There is NO crypto in this file — every frame handed to sendFn is
// encrypted by the session layer before it hits the wire, and every
// frame passed to OnFrame has already been authenticated and decrypted.
// This package worries only about reliability and ordering.
// ------------------------------------------------------------------
//
// WHY WE BUILD THIS RATHER THAN BORROW TCP: DNX carries TCP traffic over
// UDP (the substrate must be UDP for NAT traversal). Something has to put
// the "reliable, ordered" back. That something is this file.
//
// The design is deliberately TCP-shaped, because TCP's shape is correct
// and well understood:
//
//   - byte-offset sequence numbers (not packet counters), so segment
//     boundaries can change on retransmit
//   - cumulative ACK: "I have everything below N"
//   - RTO estimation per RFC 6298 (SRTT + RTTVAR), exponential backoff
//   - receiver-advertised window for flow control
//   - slow start + AIMD congestion control
//
// WHAT IT DELIBERATELY OMITS (and the docs must say so): selective ACK
// (SACK), fast retransmit on duplicate ACKs, path MTU discovery, and
// window scaling. Those are v0.3 concerns. Loss recovery here is
// timeout-driven, which is correct but slower than TCP on lossy paths.
package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Frame format (rides inside a sealed frame, so no auth fields needed here)
//
//	 0        1         5         9        11        13
//	+--------+---------+---------+--------+---------+---------+
//	| type   | seq u32 | ack u32 | wnd u16| len u16 | payload |
//	+--------+---------+---------+--------+---------+---------+
//
// seq = byte offset of the FIRST byte of payload in the sender's stream
// ack = next byte offset the sender expects to receive (cumulative)
// wnd = free space in the sender's receive buffer, for flow control
// ---------------------------------------------------------------------------

const (
	FrameData = 1
	FrameAck  = 2
	FrameFin  = 3
	FrameRst  = 4

	headerLen = 13

	// MaxSegment is the largest payload we put in one frame. Chosen to sit
	// comfortably under a 1500-byte Ethernet MTU after DNX routing header
	// (35B), sealed-frame overhead (9B header + 16B AEAD tag), UDP (8B) and
	// IP (20B). Conservative on purpose: fragmentation would be worse.
	MaxSegment = 1200

	// RecvBufMax bounds how much out-of-order + undelivered data we hold.
	// This is also what we advertise as our window.
	RecvBufMax = 256 * 1024
)

// Tunables for loss recovery and congestion control.
const (
	minRTO = 200 * time.Millisecond
	maxRTO = 10 * time.Second

	// initialCwnd in segments (RFC 6928 uses 10; we start smaller and
	// grow, since DNX paths include NAT-punched links of unknown quality).
	initialCwnd = 4 * MaxSegment

	maxRetries = 12 // give up on a segment after this many retransmits
)

var (
	ErrClosed = errors.New("stream closed")
	ErrReset  = errors.New("stream reset by peer")
)

// segment is one unacknowledged chunk sitting in the send buffer.
type segment struct {
	seq     uint32
	data    []byte
	sentAt  time.Time
	retries int
	// acked segments are dropped from the list entirely, so presence in the
	// list means "still outstanding".
}

// Stream is a reliable, ordered, bidirectional byte stream.
// It implements io.ReadWriteCloser so `dnx tunnel` can io.Copy a TCP
// connection straight through it.
type Stream struct {
	sendFn func([]byte) // hands a frame to the sealed session

	mu     sync.Mutex
	cond   *sync.Cond // signals: data arrived, window opened, or closed
	closed bool
	reset  bool
	err    error

	// ---- send side ----
	sndNext   uint32     // next byte offset we will assign
	sndUnack  uint32     // oldest byte we have not had ACKed
	sndQueue  []*segment // outstanding, ordered by seq
	peerWnd   uint32     // peer's advertised free buffer
	cwnd      uint32     // congestion window, in bytes
	ssthresh  uint32     // slow-start threshold
	finSent   bool

	// ---- receive side ----
	rcvNext  uint32            // next in-order byte we expect
	rcvOOO   map[uint32][]byte // out-of-order segments, keyed by seq
	rcvBuf   []byte            // in-order bytes ready for Read()
	finRecvd bool

	// ---- RTT estimation (RFC 6298) ----
	srtt    time.Duration
	rttvar  time.Duration
	rto     time.Duration
	haveRTT bool

	// ackPending marks that we owe the peer an ACK.
	ackPending bool

	// ---- persist timer (zero-window probe) ----
	// If the peer advertises a zero window and the ACK that later reopens
	// it is lost, both sides wait forever: the receiver believes it
	// announced space, the sender is waiting to be told. TCP breaks this
	// stalemate by probing a closed window periodically; so do we.
	lastProbe     time.Time
	probeInterval time.Duration
}

// New creates a stream. sendFn must deliver the frame to the peer's
// OnFrame — in production that means sealing it and writing to the UDP
// socket; in tests it can be a lossy virtual link.
func New(sendFn func([]byte)) *Stream {
	s := &Stream{
		sendFn:   sendFn,
		rcvOOO:   make(map[uint32][]byte),
		peerWnd:  RecvBufMax, // optimistic until the peer tells us otherwise
		cwnd:          initialCwnd,
		ssthresh:      RecvBufMax,
		rto:           minRTO * 3, // conservative before the first RTT sample
		probeInterval: minRTO,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// ---------------------------------------------------------------------------
// Frame encode / decode
// ---------------------------------------------------------------------------

func encodeFrame(typ byte, seq, ack uint32, wnd uint16, payload []byte) []byte {
	b := make([]byte, headerLen+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], seq)
	binary.BigEndian.PutUint32(b[5:], ack)
	binary.BigEndian.PutUint16(b[9:], wnd)
	binary.BigEndian.PutUint16(b[11:], uint16(len(payload)))
	copy(b[headerLen:], payload)
	return b
}

type frame struct {
	typ     byte
	seq     uint32
	ack     uint32
	wnd     uint16
	payload []byte
}

func decodeFrame(b []byte) (*frame, error) {
	if len(b) < headerLen {
		return nil, fmt.Errorf("stream frame too short: %d bytes", len(b))
	}
	n := binary.BigEndian.Uint16(b[11:])
	if int(n) > len(b)-headerLen {
		return nil, fmt.Errorf("stream frame length %d exceeds buffer", n)
	}
	return &frame{
		typ:     b[0],
		seq:     binary.BigEndian.Uint32(b[1:]),
		ack:     binary.BigEndian.Uint32(b[5:]),
		wnd:     binary.BigEndian.Uint16(b[9:]),
		payload: b[headerLen : headerLen+int(n)],
	}, nil
}

// ---------------------------------------------------------------------------
// Public API: io.ReadWriteCloser
// ---------------------------------------------------------------------------

// Write queues bytes for reliable delivery. It blocks while the send
// window is full — that back-pressure is what makes flow control real.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		s.mu.Lock()
		for {
			if s.closed || s.reset {
				err := s.err
				if err == nil {
					err = ErrClosed
				}
				s.mu.Unlock()
				return written, err
			}
			if s.windowAvailable() > 0 {
				break
			}
			s.cond.Wait() // window full: sleep until an ACK frees space
		}

		// Take as much as window and segment size allow.
		n := int(s.windowAvailable())
		if n > len(p) {
			n = len(p)
		}
		if n > MaxSegment {
			n = MaxSegment
		}

		seg := &segment{
			seq:    s.sndNext,
			data:   append([]byte(nil), p[:n]...),
			sentAt: time.Now(),
		}
		s.sndNext += uint32(n)
		s.sndQueue = append(s.sndQueue, seg)

		f := encodeFrame(FrameData, seg.seq, s.rcvNext, s.advertiseWindow(), seg.data)
		s.ackPending = false
		s.mu.Unlock()

		s.sendFn(f)

		p = p[n:]
		written += n
	}
	return written, nil
}

// Read returns in-order bytes, blocking until some are available.
// Returns io.EOF once the peer has FINed and all data is drained.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if len(s.rcvBuf) > 0 {
			n := copy(p, s.rcvBuf)
			s.rcvBuf = s.rcvBuf[n:]
			// Draining the buffer opens our window; tell the peer.
			s.ackPending = true
			s.mu.Unlock()
			s.sendAck()
			s.mu.Lock()
			return n, nil
		}
		if s.reset {
			return 0, ErrReset
		}
		if s.finRecvd {
			return 0, io.EOF
		}
		if s.closed {
			return 0, ErrClosed
		}
		s.cond.Wait()
	}
}

// Close sends FIN and stops accepting writes. Reads may still drain.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sendFin := !s.finSent
	s.finSent = true
	seq := s.sndNext
	ack := s.rcvNext
	wnd := s.advertiseWindow()
	s.cond.Broadcast()
	s.mu.Unlock()

	if sendFin {
		s.sendFn(encodeFrame(FrameFin, seq, ack, wnd, nil))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Inbound frames
// ---------------------------------------------------------------------------

// OnFrame processes one decrypted frame from the peer.
func (s *Stream) OnFrame(b []byte) {
	f, err := decodeFrame(b)
	if err != nil {
		return // malformed: drop. The sealed layer already proved authenticity,
		// so this means a bug, not an attack.
	}

	s.mu.Lock()

	// Every frame carries the peer's window and cumulative ACK.
	s.peerWnd = uint32(f.wnd)
	s.processAck(f.ack)

	switch f.typ {
	case FrameRst:
		s.reset = true
		s.err = ErrReset
		s.cond.Broadcast()
		s.mu.Unlock()
		return

	case FrameFin:
		// Peer will send no more data. Only honor it once we have all
		// bytes before it — otherwise a FIN could jump a gap.
		if f.seq == s.rcvNext {
			s.finRecvd = true
		} else {
			// Hold the FIN implicitly: record it as an empty OOO segment
			// so it lands when the gap fills.
			s.rcvOOO[f.seq] = []byte{}
		}
		s.cond.Broadcast()
		s.mu.Unlock()
		s.sendAck()
		return

	case FrameData:
		if len(f.payload) > 0 {
			s.acceptData(f.seq, f.payload)
		}
		s.cond.Broadcast()
		s.mu.Unlock()
		s.sendAck() // ACK immediately: simple, correct, slightly chatty
		return

	default: // FrameAck
		s.cond.Broadcast()
		s.mu.Unlock()
		return
	}
}

// acceptData places a segment in order, or parks it if it arrived early.
// Caller holds the lock.
func (s *Stream) acceptData(seq uint32, data []byte) {
	// Already delivered? Duplicate — ignore, but still ACK (done by caller).
	if seqLE(seq+uint32(len(data)), s.rcvNext) {
		return
	}

	// Partial overlap: trim what we already have.
	if seqLT(seq, s.rcvNext) {
		trim := s.rcvNext - seq
		if int(trim) < len(data) {
			data = data[trim:]
			seq = s.rcvNext
		} else {
			return
		}
	}

	// Buffer-full guard: never let a peer exhaust memory.
	if len(s.rcvBuf)+len(data) > RecvBufMax {
		return // drop; our advertised window told them not to do this
	}

	if seq == s.rcvNext {
		s.rcvBuf = append(s.rcvBuf, data...)
		s.rcvNext += uint32(len(data))
		s.drainOOO()
	} else {
		// Out of order — park it. (Reordering is normal on the internet.)
		if _, dup := s.rcvOOO[seq]; !dup {
			s.rcvOOO[seq] = append([]byte(nil), data...)
		}
	}
}

// drainOOO moves parked segments into the in-order buffer once the gap
// before them is filled. Caller holds the lock.
func (s *Stream) drainOOO() {
	for {
		data, ok := s.rcvOOO[s.rcvNext]
		if !ok {
			return
		}
		delete(s.rcvOOO, s.rcvNext)
		if len(data) == 0 {
			// This was a parked FIN.
			s.finRecvd = true
			return
		}
		s.rcvBuf = append(s.rcvBuf, data...)
		s.rcvNext += uint32(len(data))
	}
}

// processAck retires acknowledged segments and updates RTT + congestion
// window. Caller holds the lock.
func (s *Stream) processAck(ack uint32) {
	if seqLE(ack, s.sndUnack) {
		return // old or duplicate ACK; no new information
	}

	now := time.Now()
	acked := uint32(0)
	kept := s.sndQueue[:0]
	for _, seg := range s.sndQueue {
		end := seg.seq + uint32(len(seg.data))
		if seqLE(end, ack) {
			acked += uint32(len(seg.data))
			// RTT sample only from segments never retransmitted
			// (Karn's algorithm — a retransmitted segment's RTT is ambiguous).
			if seg.retries == 0 {
				s.updateRTT(now.Sub(seg.sentAt))
			}
		} else {
			kept = append(kept, seg)
		}
	}
	s.sndQueue = kept
	s.sndUnack = ack

	// ---- congestion control: slow start, then AIMD ----
	if acked > 0 {
		if s.cwnd < s.ssthresh {
			s.cwnd += acked // slow start: exponential
		} else {
			// congestion avoidance: roughly +1 segment per RTT
			s.cwnd += MaxSegment * acked / s.cwnd
		}
		if s.cwnd > RecvBufMax {
			s.cwnd = RecvBufMax
		}
	}

	s.cond.Broadcast() // Write() may be waiting on window space
}

// updateRTT implements RFC 6298's SRTT/RTTVAR smoothing.
// Caller holds the lock.
func (s *Stream) updateRTT(sample time.Duration) {
	if !s.haveRTT {
		s.srtt = sample
		s.rttvar = sample / 2
		s.haveRTT = true
	} else {
		d := s.srtt - sample
		if d < 0 {
			d = -d
		}
		s.rttvar = (3*s.rttvar + d) / 4
		s.srtt = (7*s.srtt + sample) / 8
	}
	s.rto = s.srtt + 4*s.rttvar
	if s.rto < minRTO {
		s.rto = minRTO
	}
	if s.rto > maxRTO {
		s.rto = maxRTO
	}
}

// ---------------------------------------------------------------------------
// Timers
// ---------------------------------------------------------------------------

// Tick drives retransmission. Call it periodically (every ~50ms in
// production). Returns false once the stream is dead and can be reaped.
func (s *Stream) Tick() bool {
	s.mu.Lock()
	if s.reset {
		s.mu.Unlock()
		return false
	}

	now := time.Now()
	var toSend [][]byte
	lost := false

	for _, seg := range s.sndQueue {
		if now.Sub(seg.sentAt) < s.rto {
			continue
		}
		if seg.retries >= maxRetries {
			s.reset = true
			s.err = fmt.Errorf("peer unreachable: segment at %d unacknowledged after %d retries", seg.seq, seg.retries)
			s.cond.Broadcast()
			s.mu.Unlock()
			return false
		}
		seg.retries++
		seg.sentAt = now
		lost = true
		toSend = append(toSend, encodeFrame(FrameData, seg.seq, s.rcvNext, s.advertiseWindow(), seg.data))
	}

	if lost {
		// Loss signal: multiplicative decrease, then exponential RTO backoff.
		s.ssthresh = s.cwnd / 2
		if s.ssthresh < 2*MaxSegment {
			s.ssthresh = 2 * MaxSegment
		}
		s.cwnd = initialCwnd
		s.rto *= 2
		if s.rto > maxRTO {
			s.rto = maxRTO
		}
	}

	// ---- persist timer: probe a closed peer window ----
	// A zero-length DATA frame is a legal probe: the peer ignores the empty
	// payload but always answers a DATA frame with an ACK, and every ACK
	// carries the peer's current window. That reply is what un-sticks us.
	var probe []byte
	if s.peerWnd == 0 && !s.closed {
		if now.Sub(s.lastProbe) >= s.probeInterval {
			s.lastProbe = now
			s.probeInterval *= 2 // back off, so a genuinely idle peer isn't spammed
			if s.probeInterval > maxRTO {
				s.probeInterval = maxRTO
			}
			probe = encodeFrame(FrameData, s.sndNext, s.rcvNext, s.advertiseWindow(), nil)
		}
	} else {
		s.probeInterval = minRTO // window is open again: reset the backoff
	}

	needAck := s.ackPending
	ackFrame := encodeFrame(FrameAck, s.sndNext, s.rcvNext, s.advertiseWindow(), nil)
	s.ackPending = false
	s.mu.Unlock()

	for _, f := range toSend {
		s.sendFn(f)
	}
	if probe != nil {
		s.sendFn(probe)
	}
	if needAck {
		s.sendFn(ackFrame)
	}
	return true
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// windowAvailable is how many more bytes we may put in flight.
// Caller holds the lock.
func (s *Stream) windowAvailable() uint32 {
	inFlight := s.sndNext - s.sndUnack
	limit := s.cwnd
	if s.peerWnd < limit {
		limit = s.peerWnd // never overrun the receiver
	}
	if inFlight >= limit {
		return 0
	}
	return limit - inFlight
}

// advertiseWindow reports our free receive space. Caller holds the lock.
func (s *Stream) advertiseWindow() uint16 {
	free := RecvBufMax - len(s.rcvBuf)
	if free < 0 {
		free = 0
	}
	if free > 65535 {
		free = 65535 // no window scaling in v0.2 — documented limit
	}
	return uint16(free)
}

func (s *Stream) sendAck() {
	s.mu.Lock()
	f := encodeFrame(FrameAck, s.sndNext, s.rcvNext, s.advertiseWindow(), nil)
	s.ackPending = false
	s.mu.Unlock()
	s.sendFn(f)
}

// Stats exposes internals for the dashboard and tests.
func (s *Stream) Stats() (inFlight, cwnd uint32, rto time.Duration, outstanding int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sndNext - s.sndUnack, s.cwnd, s.rto, len(s.sndQueue)
}

// ---- serial-number arithmetic (RFC 1982), so 32-bit wraparound is safe ----

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
