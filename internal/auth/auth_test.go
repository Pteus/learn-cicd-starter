package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError error
	}{
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - missing token",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name: "valid header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey:   "abc123",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("got key %q, want %q", gotKey, tt.wantKey)
			}

			if (err == nil) != (tt.wantError == nil) {
				t.Errorf("got error %v, want %v", err, tt.wantError)
			} else if err != nil && tt.wantError != nil {
				if err.Error() != tt.wantError.Error() {
					t.Errorf("got error %q, want %q", err.Error(), tt.wantError.Error())
				}
			}
		})
	}
}
