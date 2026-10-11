// Package pairing implements the source-sink pairing handshake.
//
// The flow: source generates an X25519 ephemeral keypair plus a short
// human-typable pairing code, starts an HTTP listener, and prints the code
// to the user. The user runs the sink-side command with that code on the
// other machine. Sink generates its own X25519 keypair, POSTs its public
// key (and the pairing code) to the source's pairing endpoint. Source
// verifies the code, replies with its public key. Both sides compute the
// X25519 shared secret and run HKDF-SHA256 over (shared_secret, salt=code,
// info="agentcookie-pair-v1") to derive the final 32-byte symmetric key.
//
// The pairing code in the HKDF salt is the MITM defense: an attacker who
// intercepts the TLS-or-not channel without knowing the code gets a
// different derived key, and the next encrypted message fails its AEAD
// tag check. Tailscale already gives us a confidential channel; this is
// defense in depth.
package pairing

import (
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"strings"
	"time"

	"github.com/mvanhorn/agentcookie/internal/cli/httpserver"
)

const (
	// ProtocolVersion is bumped on incompatible wire-format changes.
	ProtocolVersion = 1
	// CodeLength is how many base32 characters the pairing code uses.
	// v0.12 bumped from 8 (40 bits) to 12 (64 bits). The wizard install
	// auto-pastes the code; the four extra characters add no UX cost.
	CodeLength = 12
	// HKDFInfo is mixed into every derived key. Bump on protocol revisions.
	HKDFInfo = "agentcookie-pair-v1"
	// PairTimeout caps how long the source side listens for a sink.
	PairTimeout = 10 * time.Minute
)

// Code is the short human-typable pairing token. Display format is "XXXX-XXXX-XXXX".
type Code string

// NewCode returns a fresh random code.
func NewCode() (Code, error) {
	enc := base32.StdEncoding
	raw := make([]byte, 8) // 64 bits -> 13 base32 chars; we use the first 12
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	s := strings.TrimRight(enc.EncodeToString(raw), "=")
	if len(s) < CodeLength {
		return "", fmt.Errorf("code too short: %d", len(s))
	}
	s = s[:CodeLength]
	return Code(s[:4] + "-" + s[4:8] + "-" + s[8:]), nil
}

// Normalize returns the canonical form of c (uppercase, hyphen-separated 4-char groups).
func (c Code) Normalize() Code {
	s := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(string(c), "-", ""), " ", ""))
	if len(s) != CodeLength {
		return c
	}
	return Code(s[:4] + "-" + s[4:8] + "-" + s[8:])
}

// String renders the code in the canonical form.
func (c Code) String() string { return string(c.Normalize()) }

// Equal compares codes in constant time.
func (c Code) Equal(other Code) bool {
	a, b := []byte(c.Normalize()), []byte(other.Normalize())
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// SinkRequest is the JSON body the sink POSTs to the source's /pair endpoint.
type SinkRequest struct {
	ProtocolVersion int    `json:"protocol_version"`
	Code            string `json:"code"`
	SinkPublicKey   []byte `json:"sink_public_key"`
	SinkHostname    string `json:"sink_hostname"`
}

// SourceResponse is the JSON the source replies with on a successful handshake.
type SourceResponse struct {
	ProtocolVersion int    `json:"protocol_version"`
	SourcePublicKey []byte `json:"source_public_key"`
	SourceHostname  string `json:"source_hostname"`
	Fingerprint     string `json:"fingerprint"`
}

// HandshakeResult carries the derived state both sides write to disk.
type HandshakeResult struct {
	Key         []byte
	Fingerprint string
	LocalRole   string // "source" or "sink"
	RemotePeer  string // the OTHER side's hostname
	PairedAt    time.Time
}

// DeriveKey runs HKDF over the X25519 shared secret salted with the code.
func DeriveKey(sharedSecret []byte, code Code) ([]byte, string, error) {
	key, err := hkdf.Key(sha256.New, sharedSecret, []byte(code.Normalize()), HKDFInfo, 32)
	if err != nil {
		return nil, "", fmt.Errorf("hkdf: %w", err)
	}
	// Fingerprint = short hex hash of the derived key, for human comparison.
	sum := sha256.Sum256(key)
	fp := hex.EncodeToString(sum[:4])
	return key, fp, nil
}

// PairError is a /pair refusal with the HTTP status to answer with.
type PairError struct {
	Status int
	Msg    string
}

func (e *PairError) Error() string { return e.Msg }

// HandlerConfig configures NewHandler. Serving is separate from code
// minting: the caller decides which presented code is valid and which peer
// name the key is filed under.
type HandlerConfig struct {
	// LocalHostname is announced to the sink in SourceResponse.
	LocalHostname string
	// Authorize checks the presented code (and anything else about the
	// caller) and returns the code the key is derived with plus the peer
	// name. Return a *PairError to refuse with its status; any other
	// error answers 401.
	Authorize func(r *http.Request, req *SinkRequest) (Code, string, error)
	// Complete runs after a successful exchange and before the response
	// is written, so a key that cannot be stored never reads as paired on
	// the sink. A *PairError answers with its status; other errors 500.
	Complete func(peer string, code Code, res *HandshakeResult) error
}

// NewHandler serves the source side of POST /pair: the per-IP attempt
// limiter, the 16 KB body cap (413 when exceeded), protocol version check,
// X25519 exchange with a fresh ephemeral key, and HKDF derivation. The wire
// format is the one RunSink speaks.
func NewHandler(cfg HandlerConfig) http.Handler {
	limiter := newRateLimiter()
	curve := ecdh.X25519()
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(rw, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if !limiter.allow(clientIP(r)) {
			http.Error(rw, "too many pairing attempts", http.StatusTooManyRequests)
			return
		}
		httpserver.LimitedReader(r, httpserver.Defaults(httpserver.Pair).MaxBodyBytes)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			if _, tooBig := errors.AsType[*http.MaxBytesError](err); tooBig {
				http.Error(rw, "pairing request too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(rw, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var req SinkRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(rw, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.ProtocolVersion != ProtocolVersion {
			http.Error(rw, fmt.Sprintf("protocol mismatch: sink=%d source=%d", req.ProtocolVersion, ProtocolVersion), http.StatusBadRequest)
			return
		}
		code, peer, err := cfg.Authorize(r, &req)
		if err != nil {
			writePairError(rw, err, http.StatusUnauthorized)
			return
		}
		sinkPub, err := curve.NewPublicKey(req.SinkPublicKey)
		if err != nil {
			http.Error(rw, "bad sink public key: "+err.Error(), http.StatusBadRequest)
			return
		}
		priv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			http.Error(rw, "gen ephemeral key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		shared, err := priv.ECDH(sinkPub)
		if err != nil {
			http.Error(rw, "ecdh: "+err.Error(), http.StatusInternalServerError)
			return
		}
		key, fp, err := DeriveKey(shared, code)
		if err != nil {
			http.Error(rw, "derive: "+err.Error(), http.StatusInternalServerError)
			return
		}
		res := &HandshakeResult{
			Key:         key,
			Fingerprint: fp,
			LocalRole:   "source",
			RemotePeer:  req.SinkHostname,
			PairedAt:    time.Now(),
		}
		if err := cfg.Complete(peer, code, res); err != nil {
			writePairError(rw, err, http.StatusInternalServerError)
			return
		}
		respBody, _ := json.Marshal(SourceResponse{
			ProtocolVersion: ProtocolVersion,
			SourcePublicKey: priv.PublicKey().Bytes(),
			SourceHostname:  cfg.LocalHostname,
			Fingerprint:     fp,
		})
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write(respBody)
	})
}

func writePairError(rw http.ResponseWriter, err error, fallback int) {
	if pe, ok := errors.AsType[*PairError](err); ok {
		http.Error(rw, pe.Msg, pe.Status)
		return
	}
	http.Error(rw, err.Error(), fallback)
}

// RunSource starts the source-side listener, prints the code, waits for the
// sink to connect. Returns the derived key + peer info on success.
func RunSource(ctx context.Context, listenAddr, localHostname string, w io.Writer) (*HandshakeResult, Code, error) {
	code, err := NewCode()
	if err != nil {
		return nil, "", err
	}

	resultCh := make(chan *HandshakeResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.Handle("/pair", NewHandler(HandlerConfig{
		LocalHostname: localHostname,
		Authorize: func(r *http.Request, req *SinkRequest) (Code, string, error) {
			if !Code(req.Code).Equal(code) {
				return "", "", &PairError{Status: http.StatusUnauthorized, Msg: "invalid pairing code"}
			}
			return code, req.SinkHostname, nil
		},
		Complete: func(_ string, _ Code, res *HandshakeResult) error {
			select {
			case resultCh <- res:
			default:
			}
			return nil
		},
	}))

	srv := httpserver.Configure(&http.Server{Addr: listenAddr, Handler: mux}, httpserver.Pair)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, "", fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	defer ln.Close()

	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("pair server: %w", err)
		}
	}()

	fmt.Fprintln(w, "agentcookie pair (source side)")
	fmt.Fprintln(w, "  pairing code:", code)
	fmt.Fprintln(w, "  source hostname:", localHostname)
	fmt.Fprintln(w, "  listening on:", listenAddr)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Run this on the sink machine within", PairTimeout)
	fmt.Fprintf(w, "    agentcookie pair --as sink --peer %s --pair-url http://%s/pair --code %s\n", localHostname, listenAddr, code)
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Waiting for sink...")

	pairCtx, cancel := context.WithTimeout(ctx, PairTimeout)
	defer cancel()
	select {
	case <-pairCtx.Done():
		_ = srv.Shutdown(context.Background())
		if errors.Is(pairCtx.Err(), context.DeadlineExceeded) {
			return nil, code, fmt.Errorf("pairing timed out after %s without a sink connection", PairTimeout)
		}
		return nil, code, pairCtx.Err()
	case err := <-errCh:
		return nil, code, err
	case res := <-resultCh:
		_ = srv.Shutdown(context.Background())
		return res, code, nil
	}
}

// RunSink performs the sink-side handshake: connect to source's pairing URL,
// send our public key + the code, receive source's public key, derive the
// shared key.
func RunSink(ctx context.Context, sourcePairURL string, providedCode Code, localHostname string) (*HandshakeResult, error) {
	return RunSinkWithClient(ctx, httpserver.Client(httpserver.PairClient), sourcePairURL, providedCode, localHostname)
}

// RunSinkWithClient is RunSink over a caller-supplied HTTP client, for a
// sink that reaches the source only through a configured proxy.
func RunSinkWithClient(ctx context.Context, client *http.Client, sourcePairURL string, providedCode Code, localHostname string) (*HandshakeResult, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen ephemeral key: %w", err)
	}
	reqBody := SinkRequest{
		ProtocolVersion: ProtocolVersion,
		Code:            string(providedCode.Normalize()),
		SinkPublicKey:   priv.PublicKey().Bytes(),
		SinkHostname:    localHostname,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, "POST", sourcePairURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", sourcePairURL, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned %d: %s", resp.StatusCode, string(respBody))
	}
	var srcResp SourceResponse
	if err := json.Unmarshal(respBody, &srcResp); err != nil {
		return nil, fmt.Errorf("decode source response: %w", err)
	}
	if srcResp.ProtocolVersion != ProtocolVersion {
		return nil, fmt.Errorf("protocol mismatch: source=%d sink=%d", srcResp.ProtocolVersion, ProtocolVersion)
	}
	srcPub, err := curve.NewPublicKey(srcResp.SourcePublicKey)
	if err != nil {
		return nil, fmt.Errorf("bad source public key: %w", err)
	}
	shared, err := priv.ECDH(srcPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	key, fp, err := DeriveKey(shared, providedCode)
	if err != nil {
		return nil, err
	}
	if fp != srcResp.Fingerprint {
		return nil, fmt.Errorf("fingerprint mismatch (man-in-the-middle?): local=%s source=%s", fp, srcResp.Fingerprint)
	}
	return &HandshakeResult{
		Key:         key,
		Fingerprint: fp,
		LocalRole:   "sink",
		RemotePeer:  srcResp.SourceHostname,
		PairedAt:    time.Now(),
	}, nil
}

// LocalHostname returns os.Hostname or a fallback if that errors.
func LocalHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown-host"
	}
	return h
}
