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

// Package indicator defines the CCIB representation of a CrowdStrike Falcon
// intelligence indicator.
package indicator

// Indicator is a single Falcon intelligence indicator, kept as a decoded JSON
// object. CCIB forwards the whole object to Chronicle verbatim and only removes
// a few volatile fields for deduplication, so an open map is the faithful,
// lossless representation. It is a defined type rather than an alias so that
// values flowing through the pipeline carry the indicator's identity.
type Indicator map[string]any

// Objects returns the elements of v that are JSON objects, ignoring any
// non-object entries and a v that is not a slice. Falcon nests labels and
// relations as arrays of objects; callers use this to walk them without
// panicking on unexpected shapes.
func Objects(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	objs := make([]map[string]any, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			objs = append(objs, m)
		}
	}
	return objs
}
