package auth

import (
	"net/http"
	"testing"
)

func TestEmptyAuthHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "")

	_, err := GetAPIKey(headers)

	// We expect this error to be ErrNoAuthHeaderIncluded
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestMalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "123")

	_, err := GetAPIKey(headers)

	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header', got %v", err)
	}

	headers.Set("Authorization", "ApiKeyy 123")

	_, err = GetAPIKey(headers)

	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header', got %v", err)
	}
}

func TestCorrectHeader(t *testing.T) {
	headers := http.Header{}
	headers.Add("Authorization", "ApiKey 123")
	want := "123"

	got, err := GetAPIKey(headers)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("expected '123', got %v", got)
	}
}
