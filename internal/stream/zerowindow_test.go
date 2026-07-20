package stream

import (
	"sync"
	"testing"
	"time"
)

// TestZeroWindowDeadlock is the classic reliable-transport trap.
//
// Sequence:
//  1. Receiver stops reading, its buffer fills, it advertises window = 0.
//  2. Sender parks, waiting for the window to open.
//  3. Receiver's app finally reads, freeing space, and sends an ACK
//     announcing the new window.
//  4. **That ACK is lost.**
//
// Without a persist timer, both sides now wait forever: the receiver
// believes it announced space; the sender is waiting to be told. TCP
// breaks the stalemate by probing a closed window periodically.
//
// The assertion is *forward progress* — that the receiver's in-order byte
// count advances after the window reopens. It is deliberately NOT "the
// whole write completes": with a receiver that drains only part of the
// stream, blocking again afterwards is correct flow control, not failure.
func TestZeroWindowDeadlock(t *testing.T) {
	var mu sync.Mutex
	dropReverse := false // when true, B->A frames (including ACKs) are lost

	var a, b *Stream
	a = New(func(f []byte) { b.OnFrame(append([]byte(nil), f...)) })
	b = New(func(f []byte) {
		mu.Lock()
		dropped := dropReverse
		mu.Unlock()
		if dropped {
			return // simulate the lost window-update ACK
		}
		a.OnFrame(append([]byte(nil), f...))
	})

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		tk := time.NewTicker(20 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				a.Tick()
				b.Tick()
			}
		}
	}()

	// ---- 1 & 2: fill the receiver until the sender blocks ----
	writerStopped := make(chan struct{})
	go func() {
		buf := make([]byte, 8192)
		for i := 0; i < 200; i++ { // far more than the receiver will drain
			if _, err := a.Write(buf); err != nil {
				break
			}
		}
		close(writerStopped)
	}()

	select {
	case <-writerStopped:
		t.Fatal("sender never blocked — receiver window failed to close")
	case <-time.After(2 * time.Second):
	}

	b.mu.Lock()
	beforeDrain := b.rcvNext
	b.mu.Unlock()
	t.Logf("sender blocked; receiver holds %d bytes and advertises a closed window", beforeDrain)

	// ---- 3 & 4: receiver drains, but its window-update ACKs are lost ----
	mu.Lock()
	dropReverse = true
	mu.Unlock()

	drained := 0
	buf := make([]byte, 32*1024)
	for drained < 128*1024 {
		n, err := b.Read(buf)
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		drained += n
	}
	t.Logf("receiver drained %d bytes while every window-update ACK was lost", drained)

	// Reverse path restored. The window is open, but the sender was never
	// told. Only a window probe can discover that.
	mu.Lock()
	dropReverse = false
	mu.Unlock()

	// ---- the assertion: does data start moving again? ----
	deadline := time.After(20 * time.Second)
	for {
		select {
		case <-deadline:
			a.mu.Lock()
			pw, inFlight := a.peerWnd, a.sndNext-a.sndUnack
			a.mu.Unlock()
			t.Fatalf("DEADLOCK: no progress past %d bytes after the window reopened "+
				"(sender sees peerWnd=%d inFlight=%d) — zero-window probe missing or broken",
				beforeDrain, pw, inFlight)
		case <-time.After(200 * time.Millisecond):
			b.mu.Lock()
			now := b.rcvNext
			b.mu.Unlock()
			if now > beforeDrain {
				t.Logf("recovered: receiver advanced %d -> %d bytes after a probe reopened the window",
					beforeDrain, now)
				return
			}
		}
	}
}
