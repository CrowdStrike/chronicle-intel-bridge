// This is free and unencumbered software released into the public domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a compiled
// binary, for any purpose, commercial or non-commercial, and by any
// means.
//
// In jurisdictions that recognize copyright laws, the author or authors
// of this software dedicate any and all copyright interest in the
// software to the public domain. We make this dedication for the benefit
// of the public at large and to the detriment of our heirs and
// successors. We intend this dedication to be an overt act of
// relinquishment in perpetuity of all present and future rights to this
// software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <https://unlicense.org>

// Package state persists the last delivered Falcon marker so CCIB can resume
// gaplessly across restarts. Writes are atomic (temp file + rename) so a crash
// mid-write never corrupts the stored cursor.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Store reads and writes the resume marker at a fixed file path.
type Store struct {
	path string
}

// persisted is the on-disk JSON shape, matching the original Python service.
type persisted struct {
	LastMarker string `json:"last_marker"`
}

// New returns a Store backed by the file at path.
func New(path string) *Store {
	return &Store{path: path}
}

// Load returns the saved marker. A missing state file is the normal
// first-run case and yields ("", nil), so startup falls back to the initial
// lookback window. A file that exists but cannot be read or parsed yields a
// non-nil error so the caller can distinguish corruption from a fresh start
// and avoid silently restarting a full backfill. An empty stored marker is
// reported as ("", nil).
func (s *Store) Load() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("state: reading %s: %w", s.path, err)
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return "", fmt.Errorf("state: parsing %s: %w", s.path, err)
	}
	return p.LastMarker, nil
}

// Save atomically writes marker to the state file, creating the parent
// directory if needed. It writes a temporary file in the target directory and
// renames it into place, so the destination is never left partially written.
func (s *Store) Save(marker string) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("state: creating directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "state-*.tmp")
	if err != nil {
		return fmt.Errorf("state: creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	data, err := json.Marshal(persisted{LastMarker: marker})
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("state: marshaling: %w", err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return fmt.Errorf("state: writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("state: closing temp file: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("state: renaming temp file: %w", err)
	}
	return nil
}
