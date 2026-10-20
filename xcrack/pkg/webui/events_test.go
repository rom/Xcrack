package webui

import (
	"testing"
	"time"
)

func TestHubNotify(t *testing.T) {
	h := newHub()
	ch, cancel := h.subscribe()

	h.notify()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscriber did not receive a notify")
	}

	// A second notify with no intervening read coalesces into the buffered slot
	// (non-blocking), leaving exactly one pending signal.
	h.notify()
	h.notify()
	select {
	case <-ch:
	default:
		t.Fatal("coalesced notify left nothing pending")
	}
	select {
	case <-ch:
		t.Fatal("coalesced notify delivered more than one signal")
	default:
	}

	// After cancel, a notify must not panic (and the subscriber is gone).
	cancel()
	h.notify()
}
