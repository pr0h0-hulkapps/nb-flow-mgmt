// Package flowtoken implements the HMAC bearer-token scheme shared between the
// patched NetBird management server (which mints tokens in ExtendNetBirdConfig)
// and the flow receiver (which verifies them on each gRPC stream).
//
// This is the CANONICAL copy. The receiver carries a byte-identical copy at
// receiver/internal/token/token.go — keep the two in sync.
//
// Wire format (what the agent sends, unchanged NetBird behaviour):
//
//	authorization: Bearer <signature>.<payload>
//
//	payload   = base64url( json(Claims) )           // no padding, URL alphabet
//	signature = base64url( HMAC-SHA256(secret, payload) )
//
// base64url has no '.' in its alphabet, so splitting the token on the first
// '.' is unambiguous.
package flowtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Claims is the JSON payload carried inside the token. It binds a token to a
// peer/account and bounds its lifetime. The management server re-mints on every
// sync, so a short TTL is fine and limits replay.
type Claims struct {
	Peer    string `json:"peer"`    // WireGuard public key (base64) of the emitting peer
	Account string `json:"account"` // NetBird account ID
	Exp     int64  `json:"exp"`     // expiry, unix seconds
}

var (
	// ErrMalformed means the token was not "<sig>.<payload>".
	ErrMalformed = errors.New("malformed flow token")
	// ErrBadSignature means the HMAC did not verify.
	ErrBadSignature = errors.New("invalid flow token signature")
	// ErrExpired means the token's exp is in the past.
	ErrExpired = errors.New("flow token expired")
)

var enc = base64.RawURLEncoding

// Mint builds the (payload, signature) pair for a peer. The management module
// calls this and places the results in FlowConfig.TokenPayload /
// FlowConfig.TokenSignature.
func Mint(secret []byte, c Claims) (payload string, signature string, err error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return "", "", fmt.Errorf("marshal claims: %w", err)
	}
	payload = enc.EncodeToString(raw)
	signature = sign(secret, payload)
	return payload, signature, nil
}

// MintWithTTL is a convenience wrapper that sets Exp = now + ttl.
func MintWithTTL(secret []byte, peer, account string, now time.Time, ttl time.Duration) (string, string, error) {
	return Mint(secret, Claims{Peer: peer, Account: account, Exp: now.Add(ttl).Unix()})
}

// VerifyBearer takes the raw metadata value (with or without the "Bearer "
// prefix), verifies the signature against secret, checks expiry against now,
// and returns the decoded claims.
func VerifyBearer(secret []byte, bearer string, now time.Time) (*Claims, error) {
	bearer = strings.TrimSpace(bearer)
	bearer = strings.TrimPrefix(bearer, "Bearer ")
	bearer = strings.TrimPrefix(bearer, "bearer ")

	sig, payload, ok := strings.Cut(bearer, ".")
	if !ok || sig == "" || payload == "" {
		return nil, ErrMalformed
	}

	expected := sign(secret, payload)
	// constant-time compare over equal-length base64 strings
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, ErrBadSignature
	}

	raw, err := enc.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %v", ErrMalformed, err)
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%w: unmarshal claims: %v", ErrMalformed, err)
	}
	if c.Exp != 0 && now.Unix() > c.Exp {
		return nil, ErrExpired
	}
	return &c, nil
}

func sign(secret []byte, payload string) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(payload))
	return enc.EncodeToString(m.Sum(nil))
}
