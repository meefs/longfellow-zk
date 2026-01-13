package zk

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestLoadVICAL(t *testing.T) {
	// Load real test data
	cborData, err := os.ReadFile("../vical.cbor")
	if err != nil {
		t.Fatalf("Failed to read vical.cbor: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.Write(cborData)
	}))
	defer ts.Close()

	err = LoadVICAL(ts.URL)
	if err != nil {
		t.Fatalf("LoadVICAL failed: %v", err)
	}
}
