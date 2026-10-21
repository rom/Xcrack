package webui

import (
	"net/http"
	"sync"
	"time"
)

// A server-wide "something changed" nudge so the History, Statistics and
// Recovered lists update live instead of only on a manual refresh or tab
// switch. It deliberately carries no job data — each nudge just tells the SPA to
// re-fetch whatever list it is showing, and those fetches are already filtered
// to the requesting user, so the stream leaks nothing about other users' jobs.
// (The per-job /jobs/{id}/events stream, which carries live progress/log/found,
// is separate.)

// hub fans a contentless signal out to every connected list-watcher.
type hub struct {
	mu   sync.Mutex
	subs map[int]chan struct{}
	next int
}

func newHub() *hub { return &hub{subs: map[int]chan struct{}{}} }

func (h *hub) subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	id := h.next
	h.next++
	h.subs[id] = ch
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

// notify wakes every watcher without blocking: a watcher whose buffer is already
// full will coalesce this nudge into the pending one.
func (h *hub) notify() {
	if h == nil {
		return
	}
	h.mu.Lock()
	for _, ch := range h.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	h.mu.Unlock()
}

// handleListEvents streams list-changed nudges as Server-Sent Events until the
// client disconnects.
func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, cancel := s.mgr.hub.subscribe()
	defer cancel()
	// An initial nudge lets a just-connected client sync immediately.
	_, _ = w.Write([]byte("event: changed\ndata: {}\n\n"))
	flusher.Flush()

	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-ch:
			_, _ = w.Write([]byte("event: changed\ndata: {}\n\n"))
			flusher.Flush()
		case <-keepalive.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
