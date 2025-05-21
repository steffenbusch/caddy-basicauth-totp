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
	"strconv"
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
			param := d.Val()
			var arg string
			if !d.Args(&arg) {
				return d.ArgErr()
			}
			switch param {
			case "session_inactivity_timeout":
				duration, err := time.ParseDuration(arg)
				if err != nil {
					return fmt.Errorf("invalid session_inactivity_timeout duration: %s", err)
				}
				m.SessionInactivityTimeout = duration
			case "secrets_file_path":
				m.SecretsFilePath = arg
			case "cookie_name":
				m.CookieName = arg
			case "cookie_path":
				m.CookiePath = arg
			case "form_template":
				m.FormTemplateFile = arg
			case "sign_key":
				m.SignKey = arg
			case "totp_code_length":
				length, err := strconv.Atoi(arg)
				if err != nil {
					return d.Errf("invalid totp_code_length: must be an integer")
				}
				if !isValidTOTPCodeLength(length) {
					return d.Errf("invalid totp_code_length: eiher 6 or 8 digits are allowed")
				}
				m.TOTPCodeLength = length
			case "logout_session_path":
			case "logout_redirect_url":
				return d.Errf("logout support was dropped. Remove subdirective %s", param)
			default:
				return d.Errf("unknown subdirective: %s", param)
			}
		}
	}
	return nil
}
