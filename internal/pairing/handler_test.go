package pairing

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A caller-supplied code and peer name: RunSink (unchanged wire format)
// pairs against NewHandler and both sides derive the same key.
func TestNewHandlerPairsWithRunSink(t *testing.T) {
	code, err := NewCode()
	if err != nil {
		t.Fatal(err)
	}
	var stored *HandshakeResult
	var storedPeer string
	h := NewHandler(HandlerConfig{
		LocalHostname: "laptop.test",
		Authorize: func(r *http.Request, req *SinkRequest) (Code, string, error) {
			if !Code(req.Code).Equal(code) {
				return "", "", &PairError{Status: http.StatusUnauthorized, Msg: "invalid pairing code"}
			}
			return code, "grokbot", nil
		},
		Complete: func(peer string, c Code, res *HandshakeResult) error {
			storedPeer, stored = peer, res
			return nil
		},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	res, err := RunSink(context.Background(), srv.URL+"/pair", code, "grok-bot-host")
	if err != nil {
		t.Fatalf("RunSink: %v", err)
	}
	if stored == nil || storedPeer != "grokbot" {
		t.Fatalf("Complete not called with the caller's peer name: %q", storedPeer)
	}
	if !bytes.Equal(res.Key, stored.Key) || res.Fingerprint != stored.Fingerprint {
		t.Fatal("sink and source derived different keys")
	}
	if stored.RemotePeer != "grok-bot-host" || res.RemotePeer != "laptop.test" {
		t.Fatalf("hostnames: source saw %q, sink saw %q", stored.RemotePeer, res.RemotePeer)
	}
}

func TestNewHandlerRefusalsAndLimits(t *testing.T) {
	h := NewHandler(HandlerConfig{
		LocalHostname: "laptop.test",
		Authorize: func(r *http.Request, req *SinkRequest) (Code, string, error) {
			return "", "", &PairError{Status: http.StatusForbidden, Msg: "wrong machine"}
		},
		Complete: func(string, Code, *HandshakeResult) error { t.Fatal("must not complete"); return nil },
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, err := RunSink(context.Background(), srv.URL+"/pair", Code("ABCD-EFGH-IJKL"), "x")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "wrong machine") {
		t.Fatalf("refusal status not passed through: %v", err)
	}

	big := bytes.Repeat([]byte("a"), 20*1024)
	resp, err := http.Post(srv.URL+"/pair", "application/json", bytes.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", resp.StatusCode)
	}

	var last int
	for range AttemptLimit + 1 {
		resp, err := http.Post(srv.URL+"/pair", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("status after %d attempts = %d, want 429", AttemptLimit+1, last)
	}
}
