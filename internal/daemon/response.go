package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Private IPC framing avoids encoding, validating and copying the entire JSON
// payload a second time inside a JSON envelope. Public CLI/HTTP JSON is unchanged.
// 128 MiB accommodates a full production jail of maximal-length IPv6 addresses.
const maxResponseBytes = 128 << 20

type responseHeader struct {
	Version     int  `json:"version"`
	Length      int  `json:"length"`
	Error       bool `json:"error,omitempty"`
	ErrorLength int  `json:"error_length,omitempty"`
}

func writeResponse(w io.Writer, r Response) error {
	if len(r.Data) > maxResponseBytes {
		return fmt.Errorf("response exceeds IPC limit")
	}
	var errorPayload []byte
	if r.Error != "" {
		r.Data = nil
		var err error
		errorPayload, err = json.Marshal(r.Error)
		if err != nil {
			return err
		}
		if len(errorPayload) > maxResponseBytes {
			return fmt.Errorf("response exceeds IPC limit")
		}
	}
	if err := json.NewEncoder(w).Encode(responseHeader{Version: 1, Length: len(r.Data), Error: len(errorPayload) != 0, ErrorLength: len(errorPayload)}); err != nil {
		return err
	}
	payload := r.Data
	if len(errorPayload) > 0 {
		payload = errorPayload
	}
	_, err := io.Copy(w, bytes.NewReader(payload))
	return err
}

func readResponse(r io.Reader) (json.RawMessage, error) {
	br := bufio.NewReader(r)
	header, err := br.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	var h responseHeader
	decoder := json.NewDecoder(bytes.NewReader(header))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&h); err != nil {
		return nil, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("invalid IPC response header")
	}
	if h.Version != 1 || h.Length < 0 || h.Length > maxResponseBytes || h.ErrorLength < 0 || h.ErrorLength > maxResponseBytes || h.Error && h.Length != 0 || h.Error != (h.ErrorLength != 0) {
		return nil, fmt.Errorf("invalid IPC response header (restart daemon after upgrading)")
	}
	if h.Error {
		payload := make([]byte, h.ErrorLength)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, err
		}
		var message string
		if err := json.Unmarshal(payload, &message); err != nil {
			return nil, fmt.Errorf("invalid IPC error payload: %w", err)
		}
		return nil, errors.New(message)
	}
	data := make(json.RawMessage, h.Length)
	_, err = io.ReadFull(br, data)
	return data, err
}
