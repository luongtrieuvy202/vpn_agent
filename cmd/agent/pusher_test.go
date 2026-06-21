package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestPushUsageWithRetry(t *testing.T) {
	// Success on first try
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer okSrv.Close()
	if !pushUsageWithRetry(okSrv.URL, []byte(`{}`)) {
		t.Error("expected success on 200")
	}

	// 4xx must NOT retry (bad key/server id won't fix itself)
	var calls int32
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer badSrv.Close()
	if pushUsageWithRetry(badSrv.URL, []byte(`{}`)) {
		t.Error("expected failure on 401")
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Errorf("4xx should not retry; got %d calls", n)
	}
}
