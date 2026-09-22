package platform

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

const traceRequestPayloadScopePrefix = "trace-request-payload-v1:"

func sealTraceRequestPayload(security *Security, requestID string, body []byte) ([]byte, error) {
	if security == nil || requestID == "" || len(body) == 0 {
		return nil, nil
	}
	var compressed bytes.Buffer
	writer, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(body); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	packed := append([]byte{1}, compressed.Bytes()...)
	return security.Encrypt(traceRequestPayloadScopePrefix+requestID, packed)
}

func openTraceRequestPayload(security *Security, requestID string, ciphertext []byte, maximum int64) ([]byte, error) {
	if security == nil || requestID == "" || len(ciphertext) == 0 {
		return nil, nil
	}
	packed, err := security.Decrypt(traceRequestPayloadScopePrefix+requestID, ciphertext)
	if err != nil {
		return nil, err
	}
	if len(packed) < 2 || packed[0] != 1 {
		return nil, errors.New("unsupported trace request payload format")
	}
	reader, err := gzip.NewReader(bytes.NewReader(packed[1:]))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	if maximum <= 0 {
		maximum = 64 * 1024 * 1024
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maximum {
		return nil, errors.New("trace request payload exceeds configured request ceiling")
	}
	return payload, nil
}
