ALTER TABLE request_traces
    ADD COLUMN IF NOT EXISTS request_payload_ciphertext BYTEA;
