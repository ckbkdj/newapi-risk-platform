package platform

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

const inputCaptureBlockBytes = 64 * 1024
const inputCaptureMaximumBytes = 256 * 1024 * 1024

// Only this envelope's ciphertext is persisted. Identifying fields and expiry
// are authenticated as AAD so ciphertext cannot be swapped between requests.
type traceInputRecord struct {
	ID          string `json:"id"`
	RequestID   string `json:"request_id"`
	RouteSlug   string `json:"route_slug"`
	StartedAt   string `json:"started_at"`
	ExpiresUnix int64  `json:"expires_unix"`
	BodyBytes   int64  `json:"body_bytes"`
}

func newTraceInputID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func traceInputAEAD(master []byte) (cipher.AEAD, error) {
	if len(master) != 32 {
		return nil, errors.New("invalid input archive key")
	}
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte("newapi-risk/trace-input/gzip-aes256gcm/v1"))
	block, err := aes.NewCipher(mac.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealTraceInput(master []byte, record traceInputRecord, parts [][]byte) ([]byte, error) {
	if record.BodyBytes < 0 || record.BodyBytes > inputCaptureMaximumBytes {
		return nil, errors.New("invalid input size")
	}
	aead, err := traceInputAEAD(master)
	if err != nil {
		return nil, err
	}
	aad, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	var compressed bytes.Buffer
	zipper, _ := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	var size int64
	for _, part := range parts {
		size += int64(len(part))
		if size > record.BodyBytes {
			_ = zipper.Close()
			return nil, errors.New("input size mismatch")
		}
		if _, err := zipper.Write(part); err != nil {
			_ = zipper.Close()
			return nil, err
		}
	}
	if err := zipper.Close(); err != nil {
		return nil, err
	}
	if size != record.BodyBytes {
		return nil, errors.New("input size mismatch")
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, compressed.Bytes(), aad), nil
}

func openTraceInput(master []byte, record traceInputRecord, sealed []byte) ([]byte, error) {
	if record.BodyBytes < 0 || record.BodyBytes > inputCaptureMaximumBytes {
		return nil, errors.New("invalid input size")
	}
	aead, err := traceInputAEAD(master)
	if err != nil {
		return nil, err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() || len(sealed) > inputCaptureMaximumBytes+1024*1024 {
		return nil, errors.New("invalid archive envelope")
	}
	aad, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	compressed, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], aad)
	if err != nil {
		return nil, errors.New("input archive authentication failed")
	}
	zipper, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, errors.New("invalid input compression")
	}
	defer zipper.Close()
	// A verified byte count still has a hard upper bound. Never expand a gzip
	// bomb or silently return a prefix and describe it as a complete request.
	body, err := io.ReadAll(io.LimitReader(zipper, record.BodyBytes+1))
	if err != nil || int64(len(body)) != record.BodyBytes {
		return nil, errors.New("input archive length mismatch")
	}
	var extra [1]byte
	if n, err := zipper.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, errors.New("input archive trailing data")
	}
	return body, nil
}

// Four charged bytes per allocated block cover capture storage, compression
// growth and ciphertext during a worker handoff. The gateway's pre-existing
// request buffer is separate; capture can never hold an unlimited queue.
type traceInputByteBudget struct {
	limit int64
	used  atomic.Int64
}

func (b *traceInputByteBudget) take(n int64) bool {
	for {
		used := b.used.Load()
		if n < 0 || used > b.limit-n {
			return false
		}
		if b.used.CompareAndSwap(used, used+n) {
			return true
		}
	}
}

type traceInputBody struct {
	io.ReadCloser
	budget     *traceInputByteBudget
	limit      int64
	parts      [][]byte
	size       int64
	charged    int64
	finished   bool
	failed     bool
	onComplete func([][]byte, int64, int64)
	onFailure  func(string)
}

func (b *traceInputBody) discard(code string) {
	if b.finished || b.failed {
		return
	}
	b.failed = true
	b.parts = nil
	b.budget.used.Add(-b.charged)
	b.charged = 0
	if b.onFailure != nil {
		b.onFailure(code)
	}
}
func (b *traceInputBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if !b.finished && !b.failed && n > 0 {
		if int64(n) > b.limit-b.size {
			b.discard("capture_size_limit")
		} else {
			data := p[:n]
			for len(data) > 0 {
				if len(b.parts) == 0 || len(b.parts[len(b.parts)-1]) == inputCaptureBlockBytes {
					charge := int64(4 * inputCaptureBlockBytes)
					if !b.budget.take(charge) {
						b.discard("capture_memory_limit")
						break
					}
					b.charged += charge
					b.parts = append(b.parts, make([]byte, 0, inputCaptureBlockBytes))
				}
				i := len(b.parts) - 1
				count := min(len(data), cap(b.parts[i])-len(b.parts[i]))
				b.parts[i] = append(b.parts[i], data[:count]...)
				b.size += int64(count)
				data = data[count:]
			}
		}
	}
	if !b.finished && !b.failed && err == io.EOF {
		b.finished = true
		if b.onComplete != nil {
			b.onComplete(b.parts, b.size, b.charged)
		} else {
			b.budget.used.Add(-b.charged)
		}
		b.parts, b.charged = nil, 0
	} else if err != nil && err != io.EOF {
		b.discard("request_read_incomplete")
	}
	return n, err
}
func (b *traceInputBody) Close() error {
	// The base gateway does not read unauthenticated/overloaded requests. Do not
	// archive a partial body or read the rest just to produce an archive.
	if !b.finished && !b.failed && b.size > 0 {
		b.discard("request_not_fully_read")
	}
	return b.ReadCloser.Close()
}

func traceInputExpired(record traceInputRecord, now time.Time, days int) bool {
	started, err := time.Parse(time.RFC3339Nano, record.StartedAt)
	return err != nil || record.ExpiresUnix <= now.Unix() || started.Before(now.Add(-time.Duration(days)*24*time.Hour))
}
