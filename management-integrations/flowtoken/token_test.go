package flowtoken

import (
	"fmt"
	"testing"
	"time"
)

var secret = []byte("test-secret-key")

func TestMintVerifyRoundTrip(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	payload, sig, err := MintWithTTL(secret, "peerPubKey", "acct-1", now, time.Hour)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	bearer := fmt.Sprintf("Bearer %s.%s", sig, payload)
	claims, err := VerifyBearer(secret, bearer, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Peer != "peerPubKey" || claims.Account != "acct-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestTamperedRejected(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	payload, sig, _ := MintWithTTL(secret, "p", "a", now, time.Hour)
	bad := "AAAA" + sig[4:]
	if _, err := VerifyBearer(secret, bad+"."+payload, now); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestExpiredRejected(t *testing.T) {
	now := time.Unix(5_000_000, 0)
	payload, sig, _ := MintWithTTL(secret, "p", "a", now, time.Minute)
	if _, err := VerifyBearer(secret, sig+"."+payload, now.Add(2*time.Minute)); err != ErrExpired {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

// TestGoldenVector MUST match receiver/internal/token/token_test.go exactly.
// These two assertions are the contract that keeps the management server's
// minting and the receiver's verification on the same wire format.
func TestGoldenVector(t *testing.T) {
	const (
		goldSecret = "golden-secret"
		goldPay    = "eyJwZWVyIjoicGVlclgiLCJhY2NvdW50IjoiYWNjdFkiLCJleHAiOjE3MDAwMDAwMDB9"
		goldSig    = "1jqjCEQs7Se1oIragjjAZG6g-tgkYMFfnqY2ixWDwIA"
	)
	p, s, err := Mint([]byte(goldSecret), Claims{Peer: "peerX", Account: "acctY", Exp: 1700000000})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if p != goldPay || s != goldSig {
		t.Fatalf("golden drift vs receiver:\n got payload=%s sig=%s\nwant payload=%s sig=%s", p, s, goldPay, goldSig)
	}
}
