// Copyright 2024 Steffen Busch

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package basicauthtotp

import (
	"fmt"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Initialize the module by registering it with Caddy
func init() {
	caddy.RegisterModule(BasicAuthTOTP{})
	httpcaddyfile.RegisterHandlerDirective("basic_auth_totp", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("basic_auth_totp", "after", "basic_auth")
}

// parseCaddyfile parses the Caddyfile configuration
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m = new(BasicAuthTOTP)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// UnmarshalCaddyfile parses the configuration from the Caddyfile.
func (m *BasicAuthTOTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "session_inactivity_timeout":
				var inactivityTimeoutStr string
				if !d.Args(&inactivityTimeoutStr) {
					return d.ArgErr()
				}
				duration, err := time.ParseDuration(inactivityTimeoutStr)
				if err != nil {
					return fmt.Errorf("invalid session_inactivity_timeout duration: %s", err)
				}
				m.SessionInactivityTimeout = duration
			case "secrets_file_path":
				var filePath string
				if !d.Args(&filePath) {
					return d.ArgErr()
				}
				m.SecretsFilePath = filePath
			case "cookie_name":
				var cookieName string
				if !d.Args(&cookieName) {
					return d.ArgErr()
				}
				m.CookieName = cookieName
			case "cookie_path":
				var cookiePath string
				if !d.Args(&cookiePath) {
					return d.ArgErr()
				}
				m.CookiePath = cookiePath
			case "logout_session_path":
				var logoutPath string
				if !d.Args(&logoutPath) {
					return d.ArgErr()
				}
				m.LogoutSessionPath = logoutPath
			case "logout_redirect_url":
				var redirectURL string
				if !d.Args(&redirectURL) {
					return d.ArgErr()
				}
				m.LogoutRedirectURL = redirectURL
			default:
				return d.Errf("unrecognized parameter: %s", d.Val())
			}
		}
	}

	return nil
}
