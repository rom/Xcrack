package webui

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newAuthTestServer builds an auth-enabled server with no real OIDC provider
// (Issuer empty), so tests can inject sessions directly and exercise the
// middleware + ownership rules without an identity provider.
func newAuthTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	srv, err := NewServer(Config{WorkDir: t.TempDir(), ExposeSecrets: true, Auth: AuthConfig{Enabled: true}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(func() { ts.Close(); srv.Close() })
	return ts, srv
}

func cookieFor(t *testing.T, srv *Server, u user) *http.Cookie {
	t.Helper()
	id, err := srv.auth.newSession(u)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: sessionCookie, Value: id}
}

func authedReq(t *testing.T, method, url string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func listHasJob(t *testing.T, ts *httptest.Server, cookie *http.Cookie, id string) bool {
	t.Helper()
	resp := authedReq(t, http.MethodGet, ts.URL+"/api/v1/jobs", cookie)
	defer resp.Body.Close()
	var out struct {
		Jobs []struct {
			ID string `json:"id"`
		} `json:"jobs"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	for _, j := range out.Jobs {
		if j.ID == id {
			return true
		}
	}
	return false
}

// createJobAs submits a tiny job as the given user and waits for it to finish.
func createJobAs(t *testing.T, ts *httptest.Server, cookie *http.Cookie) string {
	t.Helper()
	spec := `{"candidates":{"use_default_list":false,"passwords":["a","b"]}}`
	body, ct := buildJobRequest(t, spec, map[string][]byte{"x.bin": []byte("hello")}, nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/jobs", body)
	req.Header.Set("Content-Type", ct)
	req.AddCookie(cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create job: %d %s", resp.StatusCode, b)
	}
	var created struct {
		ID string `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	resp.Body.Close()
	if created.ID == "" {
		t.Fatal("no job id")
	}
	for i := 0; i < 250; i++ {
		r := authedReq(t, http.MethodGet, ts.URL+"/api/v1/jobs/"+created.ID, cookie)
		var v struct {
			State string `json:"state"`
		}
		json.NewDecoder(r.Body).Decode(&v)
		r.Body.Close()
		switch v.State {
		case "done", "error", "canceled":
			return created.ID
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not reach a terminal state")
	return ""
}

// TestMeReportsAuthDisabled confirms the single-user default: auth off, every
// request is implicitly signed in.
func TestMeReportsAuthDisabled(t *testing.T) {
	ts := newTestServer(t)
	me := getJSON(t, ts.URL+"/api/v1/me")
	if me["auth_enabled"] != false || me["authenticated"] != true {
		t.Fatalf("auth-disabled /me = %v, want auth_enabled=false authenticated=true", me)
	}
}

// TestAuthRequiresSession checks the middleware: a data endpoint is 401 without a
// session, and /me reports not-authenticated (but is itself reachable).
func TestAuthRequiresSession(t *testing.T) {
	ts, _ := newAuthTestServer(t)
	resp := authedReq(t, http.MethodGet, ts.URL+"/api/v1/jobs", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /jobs = %d, want 401", resp.StatusCode)
	}
	me := getJSON(t, ts.URL+"/api/v1/me")
	if me["auth_enabled"] != true || me["authenticated"] != false {
		t.Fatalf("unauthenticated /me = %v, want auth_enabled=true authenticated=false", me)
	}
}

// TestJobOwnershipIsolation checks that a job is visible only to its owner and to
// an admin, and that a non-owner cannot read or delete it (404, hiding it).
func TestJobOwnershipIsolation(t *testing.T) {
	ts, srv := newAuthTestServer(t)
	alice := cookieFor(t, srv, user{Subject: "alice"})
	bob := cookieFor(t, srv, user{Subject: "bob"})
	admin := cookieFor(t, srv, user{Subject: "root", Admin: true})

	id := createJobAs(t, ts, alice)

	if !listHasJob(t, ts, alice, id) {
		t.Fatal("owner should see their own job in the list")
	}
	if listHasJob(t, ts, bob, id) {
		t.Fatal("a non-owner must not see another user's job")
	}
	if !listHasJob(t, ts, admin, id) {
		t.Fatal("an admin should see every user's job")
	}

	aliceGet := authedReq(t, http.MethodGet, ts.URL+"/api/v1/jobs/"+id, alice)
	aliceGet.Body.Close()
	if aliceGet.StatusCode != http.StatusOK {
		t.Fatalf("owner GET = %d, want 200", aliceGet.StatusCode)
	}
	bobGet := authedReq(t, http.MethodGet, ts.URL+"/api/v1/jobs/"+id, bob)
	bobGet.Body.Close()
	if bobGet.StatusCode != http.StatusNotFound {
		t.Fatalf("non-owner GET = %d, want 404", bobGet.StatusCode)
	}
	bobDel := authedReq(t, http.MethodDelete, ts.URL+"/api/v1/jobs/"+id, bob)
	bobDel.Body.Close()
	if bobDel.StatusCode != http.StatusNotFound {
		t.Fatalf("non-owner DELETE = %d, want 404", bobDel.StatusCode)
	}
	// The job still exists for its owner after Bob's rejected delete.
	if !listHasJob(t, ts, alice, id) {
		t.Fatal("job should survive a rejected non-owner delete")
	}
}
