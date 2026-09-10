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

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFile(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "nope.json"))
	marker, err := s.Load()
	if err != nil {
		t.Errorf("Load() error = %v; want nil for missing file", err)
	}
	if marker != "" {
		t.Errorf("Load() = %q; want empty for missing file", marker)
	}
}

func TestSaveThenLoad(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "state.json"))
	if err := s.Save("marker-123"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	marker, err := s.Load()
	if err != nil || marker != "marker-123" {
		t.Errorf("Load() = %q, %v; want marker-123, nil", marker, err)
	}
}

func TestSaveCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "deep", "state.json")
	s := New(path)
	if err := s.Save("m"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state file not created: %v", err)
	}
}

func TestSaveOverwrites(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), "state.json"))
	if err := s.Save("first"); err != nil {
		t.Fatalf("Save first: %v", err)
	}
	if err := s.Save("second"); err != nil {
		t.Fatalf("Save second: %v", err)
	}
	marker, err := s.Load()
	if err != nil || marker != "second" {
		t.Errorf("Load() = %q, %v; want second, nil", marker, err)
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "state.json"))
	if err := s.Save("m"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one file (state.json), got %d entries", len(entries))
	}
}

func TestLoadCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seeding corrupt file: %v", err)
	}
	s := New(path)
	marker, err := s.Load()
	if err == nil {
		t.Error("Load() error = nil for corrupt file; want a non-nil error")
	}
	if marker != "" {
		t.Errorf("Load() = %q; want empty for corrupt file", marker)
	}
}

func TestLoadEmptyMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{"last_marker":""}`), 0o600); err != nil {
		t.Fatalf("seeding empty-marker file: %v", err)
	}
	s := New(path)
	marker, err := s.Load()
	if err != nil {
		t.Errorf("Load() error = %v; want nil for a valid empty marker", err)
	}
	if marker != "" {
		t.Errorf("Load() = %q; want empty", marker)
	}
}
