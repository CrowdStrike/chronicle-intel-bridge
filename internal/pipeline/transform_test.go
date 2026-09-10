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

package pipeline

import (
	"testing"

	"github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"
)

func TestTransformRemovesMarker(t *testing.T) {
	ind := indicator.Indicator{
		"_marker":   "abc123",
		"id":        "ind-1",
		"indicator": "1.2.3.4",
		"labels":    []any{},
		"relations": []any{},
	}
	transform(ind)
	if _, ok := ind["_marker"]; ok {
		t.Error("_marker should be removed")
	}
}

func TestTransformStripsLabelLastValidOn(t *testing.T) {
	ind := indicator.Indicator{
		"_marker": "abc123",
		"id":      "ind-1",
		"labels":  []any{map[string]any{"name": "malware", "last_valid_on": 1700000000.0}},
	}
	transform(ind)
	labels, ok := ind["labels"].([]any)
	if !ok || len(labels) == 0 {
		t.Fatal("labels should be a non-empty slice")
	}
	label, ok := labels[0].(map[string]any)
	if !ok {
		t.Fatal("label should be an object")
	}
	if _, ok := label["last_valid_on"]; ok {
		t.Error("label last_valid_on should be removed")
	}
	if _, ok := label["name"]; !ok {
		t.Error("label name should be preserved")
	}
}

func TestTransformStripsRelationLastValidDate(t *testing.T) {
	ind := indicator.Indicator{
		"_marker":   "abc123",
		"id":        "ind-1",
		"relations": []any{map[string]any{"id": "rel-1", "type": "parent", "last_valid_date": 1700000000.0}},
	}
	transform(ind)
	relations, ok := ind["relations"].([]any)
	if !ok || len(relations) == 0 {
		t.Fatal("relations should be a non-empty slice")
	}
	rel, ok := relations[0].(map[string]any)
	if !ok {
		t.Fatal("relation should be an object")
	}
	if _, ok := rel["last_valid_date"]; ok {
		t.Error("relation last_valid_date should be removed")
	}
	if _, ok := rel["type"]; !ok {
		t.Error("relation type should be preserved")
	}
}

// TestTransformNoPanicWhenFieldsAbsent covers the gap the Python version had:
// dict.pop on a missing key raised KeyError and killed the reader thread. The
// Go transform must tolerate indicators that lack any of the volatile fields.
func TestTransformNoPanicWhenFieldsAbsent(t *testing.T) {
	cases := []struct {
		name string
		ind  indicator.Indicator
	}{
		{"empty", indicator.Indicator{}},
		{"no marker", indicator.Indicator{"id": "ind-1", "indicator": "1.2.3.4"}},
		{"labels missing timestamp", indicator.Indicator{
			"labels": []any{map[string]any{"name": "malware"}},
		}},
		{"relations missing timestamp", indicator.Indicator{
			"relations": []any{map[string]any{"id": "rel-1"}},
		}},
		{"labels not an array", indicator.Indicator{"labels": "unexpected"}},
		{"label not an object", indicator.Indicator{"labels": []any{"unexpected"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here fails the test via the testing framework.
			transform(tc.ind)
		})
	}
}
