package basicauthtotp

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddytest"
)

func TestUnmarshalCaddyfile_TOTPCodeLength(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name: "valid 6 digits",
			input: `
			basic_auth_totp {
				totp_code_length 6
			}`,
			wantLen: 6,
		},
		{
			name: "valid 8 digits",
			input: `
			basic_auth_totp {
				totp_code_length 8
			}`,
			wantLen: 8,
		},
		{
			name: "invalid argument",
			input: `
			basic_auth_totp {
				totp_code_length abc
			}`,
			wantErr: true,
		},
		{
			name: "missing argument",
			input: `
			basic_auth_totp {
				totp_code_length
			}`,
			wantErr: true,
		},
		{
			name: "missing value",
			input: `
			basic_auth_totp {
			}`,
			wantLen: 0, // default, not set
		},
		{
			name: "invalid 7 digits",
			input: `
			basic_auth_totp {
				totp_code_length 7
			}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := caddyfile.NewTestDispenser(tt.input)
			var m BasicAuthTOTP
			err := m.UnmarshalCaddyfile(d)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if m.TOTPCodeLength != tt.wantLen {
				t.Errorf("got TOTPCodeLength=%d, want %d", m.TOTPCodeLength, tt.wantLen)
			}
		})
	}
}

func TestCaddyfileBasicAuthTOTP(t *testing.T) {
	config := `
	{
		skip_install_trust
		admin localhost:2999
		http_port 8080
	}
		:8080 {
		handle /protected/* {
			basic_auth {
				test "$2a$14$wn.TvPHrBIDCt4og7KQJoejbQFm5DMomYARgbwIy6XaGOYKh996g2"
			}

			basic_auth_totp {
				secrets_file_path 2fa-secrets-example.json
				cookie_path /protected/
				sign_key "1TBE4uljAfnRW0kxiy5JrZbpsnoZ8Ho3eDQwbfW3asI="
				session_inactivity_timeout 10m
			}

			respond "hello {http.auth.user.id}"
		}

		handle * {
			respond "unprotected content"
		}
	}
`
	tester := caddytest.NewTester(t)
	tester.InitServer(config, "caddyfile")

	// Unprotected endpoint
	req, err := http.NewRequest("GET", "http://localhost:8080/", nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	resp := tester.AssertResponseCode(req, 200)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "unprotected content") {
		t.Errorf("Expected unprotected content, got: %s", string(body))
	}

	// Protected endpoint, no auth
	req, err = http.NewRequest("GET", "http://localhost:8080/protected/", nil)
	if err != nil {
		t.Fatalf("Failed to create GET request: %v", err)
	}
	tester.AssertResponseCode(req, 401)

	// Protected endpoint, with basic auth, should get 2FA form (status 200, HTML form)
	req.SetBasicAuth("test", "test")
	resp = tester.AssertResponseCode(req, 200)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "2FA Authentication Required") {
		t.Errorf("Expected 2FA form, got: %s", string(body))
	}
}
