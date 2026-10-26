package audit

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpx "github.com/etamong-playground/httpx-go"
)

func TestAccessOptionsExcludeRawRequestValuesAndPreserveCorrelation(t *testing.T) {
	var output bytes.Buffer
	resetForTest(&output)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /items/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("id") != "private-path-marker" || r.URL.Query().Get("token") != "private-query-marker" || r.Header.Get("X-Forwarded-Email") != "private-user-marker@example.test" {
			t.Error("logging changed the handler request")
		}
		(&httpx.Responder{App: "example", Log: httpx.NewLogger(&output)}).Fail(w, r, http.StatusConflict, "Please retry.", nil)
	})
	options := AccessLogOptions{
		Route: func(r *http.Request) string {
			if r.Pattern != "" {
				return r.Pattern
			}
			return "unmatched"
		},
		ClientIP: func(*http.Request) string { return "" },
		User:     func(*http.Request) string { return "" },
	}
	handler := httpx.RequestID(AccessLogMiddlewareWithOptions(mux, options))
	request := httptest.NewRequest("GET", "/items/private-path-marker?token=private-query-marker", nil)
	request.Header.Set("X-Forwarded-Email", "private-user-marker@example.test")
	request.Header.Set("X-Forwarded-For", "192.0.2.189")
	request.RemoteAddr = "198.51.100.78:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatal(response.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body["error"] != "Please retry." || body["ref"] != response.Header().Get("X-Request-Id") {
		t.Fatal("response contract", response.Body.String(), err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected error and access records, got %s", output.String())
	}
	var access map[string]any
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["ref"] != body["ref"] {
			t.Fatal("correlation mismatch", record)
		}
		if record["kind"] == "access" {
			access = record
		}
	}
	if access == nil || access["path"] != "GET /items/{id}" || access["status"] != float64(http.StatusConflict) || access["ip"] != "" {
		t.Fatal("access fields", access)
	}
	for _, marker := range []string{"private-path-marker", "private-query-marker", "private-user-marker", "192.0.2.189", "198.51.100.78"} {
		if strings.Contains(output.String(), marker) {
			t.Fatalf("retained raw request marker %q", marker)
		}
	}
	output.Reset()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/unknown-private-marker?token=private-query-marker", nil))
	var unmatched map[string]any
	if err := json.Unmarshal(output.Bytes(), &unmatched); err != nil || unmatched["path"] != "unmatched" || unmatched["status"] != float64(404) {
		t.Fatal("unmatched route", output.String(), err)
	}
}

func TestAccessOptionsEmptyRouteNeverFallsBack(t *testing.T) {
	var output bytes.Buffer
	resetForTest(&output)
	handler := AccessLogMiddlewareWithOptions(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }), AccessLogOptions{Route: func(*http.Request) string { return "" }})
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/private-path", nil))
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil || record["path"] != "" {
		t.Fatal(output.String(), err)
	}
}

func TestAccessOptionsRemainLocalAndKeepHealthExclusion(t *testing.T) {
	var output bytes.Buffer
	resetForTest(&output)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("unchanged")) })
	hidden := AccessLogMiddlewareWithOptions(next, AccessLogOptions{ClientIP: func(*http.Request) string { return "" }, User: func(*http.Request) string { return "" }})
	normal := AccessLogMiddleware(next)
	for _, handler := range []http.Handler{hidden, normal} {
		request := httptest.NewRequest("GET", "/example", nil)
		request.Header.Set("X-Forwarded-For", "192.0.2.44")
		request.Header.Set("X-Forwarded-User", "fixture-user")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != 200 || response.Body.String() != "unchanged" {
			t.Fatal("handler behavior changed")
		}
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatal(output.String())
	}
	var omitted, legacy map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &omitted); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &legacy); err != nil {
		t.Fatal(err)
	}
	if omitted["ip"] != "" || omitted["user"] != nil || legacy["ip"] != "192.0.2.44" || legacy["user"] != "fixture-user" {
		t.Fatal(omitted, legacy)
	}
	output.Reset()
	hidden.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/healthz", nil))
	if output.Len() != 0 {
		t.Fatal("health probe was logged", output.String())
	}
}
