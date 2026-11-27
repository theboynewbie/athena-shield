package cache

import (
	"bytes"
	"net/http"
	"testing"
)

func TestEdgeCacheLRUBoundedBytes(t *testing.T) {
	// Cap at 1500 bytes; each 250-byte body + metadata is ~512 bytes, so max 2 entries fit
	ec := NewEdgeCache(1500)
	hdr := http.Header{"Content-Type": {"text/html; charset=utf-8"}}

	bodyA := bytes.Repeat([]byte("A"), 250)
	bodyB := bytes.Repeat([]byte("B"), 250)
	bodyC := bytes.Repeat([]byte("C"), 250)

	ec.Set("kA", http.StatusOK, hdr, bodyA, false)
	ec.Set("kB", http.StatusOK, hdr, bodyB, false)

	// Access kA to promote it to MRU; kB becomes LRU
	if _, ok := ec.Get("kA"); !ok {
		t.Fatalf("expected kA in cache")
	}

	// Inserting kC should evict kB (LRU) while keeping kA
	ec.Set("kC", http.StatusOK, hdr, bodyC, false)

	entries, totalBytes := ec.Stats()
	if totalBytes > 1500 {
		t.Fatalf("totalBytes %d exceeded cap 1500", totalBytes)
	}
	if entries > 2 {
		t.Fatalf("expected at most 2 entries, got %d", entries)
	}
	if _, ok := ec.Get("kB"); ok {
		t.Fatalf("expected kB (LRU) to be evicted")
	}
	if _, ok := ec.Get("kA"); !ok {
		t.Fatalf("expected kA (MRU) to remain cached")
	}
	if _, ok := ec.Get("kC"); !ok {
		t.Fatalf("expected kC to be cached")
	}

	// Oversized item > maxBytes should be skipped cleanly
	ec.Set("kBig", http.StatusOK, hdr, bytes.Repeat([]byte("X"), 2000), false)
	if _, ok := ec.Get("kBig"); ok {
		t.Fatalf("expected oversized item to be skipped")
	}

	purged := ec.PurgeAll()
	if purged == 0 {
		t.Fatalf("expected PurgeAll to report purged entries")
	}
	entries, totalBytes = ec.Stats()
	if entries != 0 || totalBytes != 0 {
		t.Fatalf("expected 0 entries and 0 bytes after PurgeAll, got (%d, %d)", entries, totalBytes)
	}
}
