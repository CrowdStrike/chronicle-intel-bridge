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

// Package pipeline wires the Falcon reader and Chronicle writer together: it
// fetches indicator batches, deduplicates and reshapes them, and delivers them
// to Chronicle. The resume position advances only over data that was fully
// delivered: on a delivery failure the reader holds its cursor and the writer
// holds the persisted marker at the last delivered batch, so the undelivered
// window is re-fetched rather than skipped.
package pipeline

import "github.com/crowdstrike/chronicle-intel-bridge/internal/indicator"

// Batch is a set of indicators to deliver together, tagged with the Falcon
// marker that follows them. The marker is persisted only after every indicator
// in the batch has been accepted by Chronicle, and only if no earlier batch in
// the same cycle failed, so neither the persisted marker nor the in-memory
// cursor ever advances past undelivered data.
//
// A batch with a non-nil flush is a control sentinel, not data: the reader
// sends it at the end of a cycle to drain the writer and learn the resume
// position before choosing the next cursor. A sentinel carries no indicators.
type Batch struct {
	Indicators []indicator.Indicator
	Marker     string
	flush      chan deliveryReport
}

// deliveryReport is the writer's answer to a flush sentinel: the marker of the
// last batch fully delivered before any failure in the cycle, and whether a
// delivery failed. The reader uses it to hold the cursor back on failure so the
// undelivered window is re-fetched on the next cycle.
type deliveryReport struct {
	committed string
	failed    bool
}

// transform reshapes an indicator into the form forwarded to Chronicle by
// removing the volatile fields Chronicle should never receive: the pagination
// marker and the per-label/per-relation validity timestamps. It mutates ind in
// place. Missing fields are skipped rather than treated as errors, so a
// malformed indicator cannot crash the reader.
func transform(ind indicator.Indicator) {
	delete(ind, "_marker")
	for _, label := range indicator.Objects(ind["labels"]) {
		delete(label, "last_valid_on")
	}
	for _, rel := range indicator.Objects(ind["relations"]) {
		delete(rel, "last_valid_date")
	}
}
