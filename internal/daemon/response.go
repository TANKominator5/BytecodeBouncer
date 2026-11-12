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
	Version int    `json:"version"`
	Length  int    `json:"length"`
	Error   string `json:"error,omitempty"`
}

func writeResponse(w io.Writer, r Response) error {
	if len(r.Data) > maxResponseBytes {
		return fmt.Errorf("response exceeds IPC limit")
	}
	if r.Error != "" {
		r.Data = nil
	}
	if err := json.NewEncoder(w).Encode(responseHeader{Version: 1, Length: len(r.Data), Error: r.Error}); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(r.Data))
	return err
}

func readResponse(r io.Reader) (json.RawMessage, error) {
	br := bufio.NewReader(r)
	header, err := br.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	var h responseHeader
	if err := json.Unmarshal(header, &h); err != nil {
		return nil, err
	}
	if h.Version != 1 || h.Length < 0 || h.Length > maxResponseBytes || h.Error != "" && h.Length != 0 {
		return nil, fmt.Errorf("invalid IPC response header (restart daemon after upgrading)")
	}
	if h.Error != "" {
		return nil, errors.New(h.Error)
	}
	data := make(json.RawMessage, h.Length)
	_, err = io.ReadFull(br, data)
	return data, err
}
