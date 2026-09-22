package platform

import (
	"bytes"
	"testing"
)

func TestTraceRequestPayloadRoundTripEncrypted(t *testing.T) {
	security := &Security{masterKey: bytes.Repeat([]byte{0x42}, 32)}
	requestID := "11111111-2222-4333-8444-555555555555"
	body := []byte(`{"model":"example","input":"private-user-request-SENTINEL","messages":[{"role":"user","content":"full text"}]}`)

	ciphertext, err := sealTraceRequestPayload(security, requestID, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("request payload ciphertext is empty")
	}
	if bytes.Contains(ciphertext, []byte("private-user-request-SENTINEL")) {
		t.Fatal("plaintext request leaked into stored ciphertext")
	}

	plaintext, err := openTraceRequestPayload(security, requestID, ciphertext, int64(len(body)+1024))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, body) {
		t.Fatalf("round trip mismatch: got %q", plaintext)
	}

	if _, err := openTraceRequestPayload(security, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", ciphertext, int64(len(body)+1024)); err == nil {
		t.Fatal("ciphertext decrypted with the wrong request ID/AAD")
	}
}

func TestTraceRequestPayloadHonorsMaximum(t *testing.T) {
	security := &Security{masterKey: bytes.Repeat([]byte{0x24}, 32)}
	requestID := "aaaaaaaa-bbbb-4ccc-8ddd-111111111111"
	body := bytes.Repeat([]byte("x"), 8192)

	ciphertext, err := sealTraceRequestPayload(security, requestID, body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openTraceRequestPayload(security, requestID, ciphertext, 1024); err == nil {
		t.Fatal("oversized restored payload was not rejected")
	}
}
