package stream

import (
	"bytes"
	"io"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Virtual link: a deliberately hostile network between two streams.
//
// The whole point of this harness is that the internet drops, reorders and
// duplicates packets, and a reliability layer is only real if it survives
// that. Everything is seeded, so a failure is reproducible.
// ---------------------------------------------------------------------------

type link struct {
	mu sync.Mutex
	rn *rand.Rand

	dropRate    float64 // fraction of frames vanished
	dupRate     float64 // fraction delivered twice
	reorderRate float64 // fraction held back and delivered late

	held [][]byte // frames parked for reordering
	dst  func([]byte)

	delivered int
	dropped   int
	reordered int // frames that were held and delivered late
}

// deliver is the single exit point toward the peer, so every frame that
// actually crosses the link is counted exactly once. (An earlier version
// counted only the fast path, which silently undercounted reordered
// frames and made the reordering test look weaker than it was.)
func (l *link) deliver(b []byte) {
	l.mu.Lock()
	l.delivered++
	l.mu.Unlock()
	l.dst(b)
}

func newLink(seed int64) *link {
	return &link{rn: rand.New(rand.NewSource(seed))}
}

// send pushes a frame through the impairments toward dst.
func (l *link) send(b []byte) {
	cp := append([]byte(nil), b...)

	l.mu.Lock()
	// Release anything previously held (delivers it *after* later frames —
	// that is exactly what reordering looks like).
	var release [][]byte
	if len(l.held) > 0 && l.rn.Float64() < 0.5 {
		release = l.held
		l.held = nil
	}

	if l.rn.Float64() < l.dropRate {
		l.dropped++
		l.mu.Unlock()
		l.releaseAll(release)
		return
	}

	if l.rn.Float64() < l.reorderRate {
		l.held = append(l.held, cp)
		l.reordered++
		l.mu.Unlock()
		l.releaseAll(release)
		return
	}

	dup := l.rn.Float64() < l.dupRate
	l.mu.Unlock()

	l.releaseAll(release)
	l.deliver(cp)
	if dup {
		l.deliver(append([]byte(nil), cp...))
	}
}

// releaseAll delivers previously-held frames (late, hence out of order).
func (l *link) releaseAll(held [][]byte) {
	for _, h := range held {
		l.deliver(h)
	}
}

// flush delivers anything still parked (end of test).
func (l *link) flush() {
	l.mu.Lock()
	held := l.held
	l.held = nil
	l.mu.Unlock()
	l.releaseAll(held)
}

// pair wires two streams together through two impaired links.
type pair struct {
	a, b       *Stream
	linkAB     *link
	linkBA     *link
	stopTicker chan struct{}
	wg         sync.WaitGroup
}

func newPair(t *testing.T, seed int64, drop, dup, reorder float64) *pair {
	t.Helper()
	p := &pair{
		linkAB:     newLink(seed),
		linkBA:     newLink(seed + 1),
		stopTicker: make(chan struct{}),
	}
	for _, l := range []*link{p.linkAB, p.linkBA} {
		l.dropRate, l.dupRate, l.reorderRate = drop, dup, reorder
	}

	p.a = New(func(b []byte) { p.linkAB.send(b) })
	p.b = New(func(b []byte) { p.linkBA.send(b) })

	p.linkAB.dst = func(b []byte) { p.b.OnFrame(b) }
	p.linkBA.dst = func(b []byte) { p.a.OnFrame(b) }

	// Drive retransmission timers, as production would.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		tk := time.NewTicker(10 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-p.stopTicker:
				return
			case <-tk.C:
				p.a.Tick()
				p.b.Tick()
				p.linkAB.flush()
				p.linkBA.flush()
			}
		}
	}()
	return p
}

func (p *pair) stop() {
	close(p.stopTicker)
	p.wg.Wait()
}

// transfer sends payload from `from` to `to` and returns what arrived.
func transfer(t *testing.T, p *pair, from, to *Stream, payload []byte, timeout time.Duration) []byte {
	t.Helper()

	done := make(chan []byte, 1)
	go func() {
		var got bytes.Buffer
		buf := make([]byte, 4096)
		for got.Len() < len(payload) {
			n, err := to.Read(buf)
			if n > 0 {
				got.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- got.Bytes()
	}()

	go func() {
		if _, err := from.Write(payload); err != nil {
			t.Errorf("write failed: %v", err)
		}
	}()

	select {
	case got := <-done:
		return got
	case <-time.After(timeout):
		inFlight, cwnd, rto, outstanding := from.Stats()
		t.Fatalf("transfer timed out after %v (inflight=%d cwnd=%d rto=%v outstanding=%d)",
			timeout, inFlight, cwnd, rto, outstanding)
		return nil
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestPerfectLink is the baseline: no impairments, data must arrive intact.
func TestPerfectLink(t *testing.T) {
	p := newPair(t, 1, 0, 0, 0)
	defer p.stop()

	payload := []byte("DNX streams: reliable, ordered, and encrypted underneath.")
	got := transfer(t, p, p.a, p.b, payload, 5*time.Second)

	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch:\n got %q\nwant %q", got, payload)
	}
}

// TestMultiSegment forces the data across many frames, exercising
// sequencing and the send window.
func TestMultiSegment(t *testing.T) {
	p := newPair(t, 2, 0, 0, 0)
	defer p.stop()

	payload := make([]byte, 64*1024) // ~55 segments
	rand.New(rand.NewSource(99)).Read(payload)

	got := transfer(t, p, p.a, p.b, payload, 20*time.Second)

	if len(got) != len(payload) {
		t.Fatalf("length mismatch: got %d want %d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("CRITICAL: multi-segment payload corrupted")
	}
}

// TestPacketLoss is the one that matters: 20% of frames vanish and the
// stream must still deliver every byte, in order.
func TestPacketLoss(t *testing.T) {
	p := newPair(t, 3, 0.20, 0, 0)
	defer p.stop()

	payload := make([]byte, 16*1024)
	rand.New(rand.NewSource(7)).Read(payload)

	got := transfer(t, p, p.a, p.b, payload, 60*time.Second)

	if !bytes.Equal(got, payload) {
		t.Fatalf("CRITICAL: data lost or corrupted under 20%% packet loss (got %d of %d bytes)",
			len(got), len(payload))
	}
	t.Logf("survived %d dropped frames", p.linkAB.dropped+p.linkBA.dropped)
}

// TestReordering: frames arrive out of order and must still be
// reassembled correctly.
func TestReordering(t *testing.T) {
	p := newPair(t, 4, 0, 0, 0.30)
	defer p.stop()

	payload := make([]byte, 32*1024)
	rand.New(rand.NewSource(11)).Read(payload)

	got := transfer(t, p, p.a, p.b, payload, 30*time.Second)

	if !bytes.Equal(got, payload) {
		t.Fatal("CRITICAL: reordering corrupted the stream")
	}
}

// TestDuplication: duplicate frames must never produce duplicate bytes.
// (A naive implementation appends the payload twice — this catches that.)
func TestDuplication(t *testing.T) {
	p := newPair(t, 5, 0, 0.35, 0)
	defer p.stop()

	payload := make([]byte, 32*1024)
	rand.New(rand.NewSource(13)).Read(payload)

	got := transfer(t, p, p.a, p.b, payload, 30*time.Second)

	if len(got) != len(payload) {
		t.Fatalf("CRITICAL: duplicate frames changed stream length: got %d want %d",
			len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("CRITICAL: duplication corrupted the stream")
	}
}

// TestHostileNetwork combines everything at once — the realistic
// bad-path case.
func TestHostileNetwork(t *testing.T) {
	p := newPair(t, 6, 0.15, 0.15, 0.20)
	defer p.stop()

	payload := make([]byte, 16*1024)
	rand.New(rand.NewSource(17)).Read(payload)

	got := transfer(t, p, p.a, p.b, payload, 90*time.Second)

	if !bytes.Equal(got, payload) {
		t.Fatalf("CRITICAL: stream failed under combined loss+dup+reorder (got %d of %d)",
			len(got), len(payload))
	}
}

// TestBidirectional: both directions at once, since a tunnel is duplex.
func TestBidirectional(t *testing.T) {
	p := newPair(t, 7, 0.05, 0, 0.10)
	defer p.stop()

	aToB := make([]byte, 8*1024)
	bToA := make([]byte, 8*1024)
	rand.New(rand.NewSource(19)).Read(aToB)
	rand.New(rand.NewSource(23)).Read(bToA)

	var wg sync.WaitGroup
	var gotB, gotA []byte

	wg.Add(2)
	go func() { defer wg.Done(); gotB = transfer(t, p, p.a, p.b, aToB, 60*time.Second) }()
	go func() { defer wg.Done(); gotA = transfer(t, p, p.b, p.a, bToA, 60*time.Second) }()
	wg.Wait()

	if !bytes.Equal(gotB, aToB) {
		t.Fatal("CRITICAL: A->B direction corrupted")
	}
	if !bytes.Equal(gotA, bToA) {
		t.Fatal("CRITICAL: B->A direction corrupted")
	}
}

// TestFinAndEOF: Close() must produce a clean io.EOF at the reader, which
// is what lets io.Copy terminate normally in `dnx tunnel`.
func TestFinAndEOF(t *testing.T) {
	p := newPair(t, 8, 0, 0, 0)
	defer p.stop()

	payload := []byte("final transmission")

	go func() {
		p.a.Write(payload)
		time.Sleep(100 * time.Millisecond)
		p.a.Close()
	}()

	var got bytes.Buffer
	buf := make([]byte, 256)
	deadline := time.After(10 * time.Second)
	for {
		type res struct {
			n   int
			err error
		}
		ch := make(chan res, 1)
		go func() { n, err := p.b.Read(buf); ch <- res{n, err} }()

		select {
		case r := <-ch:
			if r.n > 0 {
				got.Write(buf[:r.n])
			}
			if r.err == io.EOF {
				if !bytes.Equal(got.Bytes(), payload) {
					t.Fatalf("data before EOF wrong: got %q want %q", got.Bytes(), payload)
				}
				return // clean EOF — exactly what we want
			}
			if r.err != nil {
				t.Fatalf("unexpected error: %v", r.err)
			}
		case <-deadline:
			t.Fatal("never received EOF after peer Close()")
		}
	}
}

// TestFlowControl: a receiver that never reads must not cause the sender
// to buffer without bound — the advertised window has to stop it.
func TestFlowControl(t *testing.T) {
	p := newPair(t, 9, 0, 0, 0)
	defer p.stop()

	// b never calls Read(), so its buffer fills and its window closes.
	writeDone := make(chan int, 1)
	go func() {
		total := 0
		buf := make([]byte, 4096)
		for i := 0; i < 200; i++ { // 800KB, far beyond RecvBufMax
			n, err := p.a.Write(buf)
			total += n
			if err != nil {
				break
			}
		}
		writeDone <- total
	}()

	select {
	case n := <-writeDone:
		t.Fatalf("writer completed %d bytes with no reader — flow control failed to block", n)
	case <-time.After(3 * time.Second):
		// Correct: the writer is blocked on a closed window.
		inFlight, _, _, _ := p.a.Stats()
		if inFlight > RecvBufMax {
			t.Fatalf("in-flight %d exceeds receiver buffer %d", inFlight, RecvBufMax)
		}
		t.Logf("writer correctly blocked with %d bytes in flight (limit %d)", inFlight, RecvBufMax)
	}
}

// TestSeqWraparound checks the serial-number comparisons hold across the
// 32-bit boundary — the classic bug that only shows up after 4GB.
func TestSeqWraparound(t *testing.T) {
	cases := []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true},
		{2, 1, false},
		{0xFFFFFFFF, 0, true},        // wraps forward
		{0, 0xFFFFFFFF, false},       // does not wrap backward
		{0xFFFFFF00, 0x00000100, true},
		{5, 5, false},
	}
	for _, c := range cases {
		if got := seqLT(c.a, c.b); got != c.want {
			t.Errorf("seqLT(%d,%d) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestDeadPeer: if the peer vanishes entirely, the stream must give up
// rather than retransmit forever.
func TestDeadPeer(t *testing.T) {
	p := newPair(t, 10, 1.0, 0, 0) // 100% loss: nothing gets through
	defer p.stop()

	go p.a.Write([]byte("into the void"))

	deadline := time.After(120 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("stream never gave up on a dead peer")
		case <-time.After(200 * time.Millisecond):
			if !p.a.Tick() {
				return // correctly declared the peer unreachable
			}
		}
	}
}
