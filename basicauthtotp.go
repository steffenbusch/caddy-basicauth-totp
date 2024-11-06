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
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pquerna/otp/totp"
)

// BasicAuthTOTP is a Caddy module that enhances Caddy's `basic_auth` directive by adding
// Time-based One-Time Password (TOTP) two-factor authentication (2FA). This module supplements
// `basic_auth` and does not replace it; therefore, `basic_auth` must be configured and active
// for BasicAuthTOTP to function correctly. Together, these two directives provide an additional
// security layer for sensitive routes by requiring both standard credentials and a valid TOTP
// code from a compatible authenticator app.
//
// This module is suitable for scenarios where extra security is necessary but may not be
// intended for production environments without additional testing, as it is in an experimental phase.
//
// Key features include:
//   - Session-based TOTP authentication with configurable inactivity timeouts.
//   - IP binding for session validation, requiring re-authentication if the user's IP changes.
//   - Customizable session cookie options, including name and path scope.
//
// Configuration options in BasicAuthTOTP provide flexibility in securing routes, managing
// session behavior, and allowing users to log out via a dedicated logout path. Secrets are
// loaded from a specified JSON file that maps usernames to TOTP secrets.
//
// Example use case:
// BasicAuthTOTP is ideal for protecting sensitive or restricted resources by requiring an
// additional TOTP code, making it a good fit for applications where higher assurance of
// identity is required.
type BasicAuthTOTP struct {
	// SessionInactivityTimeout defines the maximum allowed period of inactivity before
	// a 2FA session expires and requires re-authentication. Default is 60 minutes.
	SessionInactivityTimeout time.Duration `json:"session_inactivity_timeout,omitempty"`

	// SecretsFilePath specifies the path to the JSON file containing TOTP secrets for each user.
	// This file should contain usernames and their corresponding TOTP secrets.
	SecretsFilePath string `json:"secrets_file_path,omitempty"`

	// CookieName defines the name of the cookie used to store the session token for 2FA.
	// Default is `basicauthtotp_session`.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath specifies the path scope of the session cookie.
	// This restricts where the cookie is sent on the server. Default is `/`.
	CookiePath string `json:"cookie_path,omitempty"`

	// LogoutSessionPath defines the URL path that triggers a session logout.
	// When this path is accessed, the 2FA session will be terminated and the cookie will be removed.
	// Default is `/logout-session`.
	LogoutSessionPath string `json:"logout_path,omitempty"`

	// LogoutRedirectURL specifies the URL to redirect the user to after they log out of their 2FA session.
	// This can be a landing page or login page where the user can re-authenticate. Default is `/`.
	LogoutRedirectURL string `json:"logout_redirect_url,omitempty"`

	// loadedSecrets holds the map of user secrets, loaded from the SecretsFilePath JSON file.
	// This map is populated when the file is read and accessed when validating TOTP codes.
	loadedSecrets map[string]string

	// secretsLoadMutex is used to synchronize access to the loadedSecrets map.
	// This prevents race conditions when loading or accessing user secrets.
	secretsLoadMutex *sync.Mutex

	// logger provides structured logging for the module.
	// It's initialized in the Provision method and used throughout the module for debug information.
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (BasicAuthTOTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.basicauthtotp",
		New: func() caddy.Module { return new(BasicAuthTOTP) },
	}
}

// Provision sets up the module, initializes the logger, and applies default values.
func (m *BasicAuthTOTP) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()

	// Initialize the mutex if it's nil
	if m.secretsLoadMutex == nil {
		m.secretsLoadMutex = &sync.Mutex{}
	}

	// Set default values if not provided
	if m.CookieName == "" {
		m.CookieName = "basicauthtotp_session"
	}
	if m.CookiePath == "" {
		m.CookiePath = "/"
	}
	if m.SessionInactivityTimeout == 0 {
		m.SessionInactivityTimeout = 60 * time.Minute // Default inactivity timeout
	}
	if m.LogoutSessionPath == "" {
		m.LogoutSessionPath = "/logout-session"
	}
	if m.LogoutRedirectURL == "" {
		m.LogoutRedirectURL = "/"
	}

	// Log the chosen configuration values
	m.logger.Info("BasicAuthTOTP plugin configured",
		zap.Duration("SessionInactivityTimeout", m.SessionInactivityTimeout),
		zap.String("SecretsFilePath", m.SecretsFilePath),
		zap.String("CookieName", m.CookieName),
		zap.String("CookiePath", m.CookiePath),
		zap.String("LogoutSessionPath", m.LogoutSessionPath),
		zap.String("LogoutRedirectURL", m.LogoutRedirectURL),
	)

	return nil
}

// Validate ensures the configuration is correct.
func (m *BasicAuthTOTP) Validate() error {
	if m.SessionInactivityTimeout <= 0 {
		return fmt.Errorf("SessionInactivityTimeout must be a positive duration")
	}
	return nil
}

// ServeHTTP handles incoming HTTP requests and checks for IP changes.
func (m *BasicAuthTOTP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	username, _, ok := r.BasicAuth()
	if !ok || username == "" {
		return next.ServeHTTP(w, r)
	}

	// TODO: The r.URL.Path might not have the expected/configured value of LogoutSessionPath
	// due to `handle_path`. Maybe we should check for {http.request.orig_uri.path} here?
	// Handle logout session if the path matches the configured logout path.
	if r.URL.Path == m.LogoutSessionPath {
		cookie, err := r.Cookie(m.CookieName)
		if err == nil {
			m.deleteSession(w, cookie.Value)
		}
		// Redirect to the configured logout URL, or fallback to "/"
		http.Redirect(w, r, m.LogoutRedirectURL, http.StatusSeeOther)
		return nil
	}

	// Validate session and check IP consistency
	clientIP := getClientIP(r.Context())
	if m.hasValidSession(r, username, clientIP) {
		return next.ServeHTTP(w, r)
	}

	if r.Method != http.MethodPost {
		show2FAForm(w, "")
		return nil
	}

	// Parse TOTP code from POST data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return nil
	}

	totpCode := r.FormValue("totp_code")
	// Check if the TOTP code is missing; if so, log and prompt for 2FA again.
	if totpCode == "" {
		m.logger.Warn("Missing TOTP code in POST",
			zap.String("username", username),
			zap.String("client_ip", clientIP),
		)
		show2FAForm(w, "")
		return nil
	}

	// Attempt to retrieve the TOTP secret for the user.
	// If an error occurs while fetching the secret (e.g., if no TOTP secret is set for the user),
	// log it and show an error message.
	secret, err := m.getSecretForUser(username)
	if err != nil {
		m.logger.Warn("Failed to retrieve TOTP secret for user",
			zap.String("username", username),
			zap.String("client_ip", clientIP),
			zap.Error(err),
		)
		show2FAForm(w, "Authentication error. Please contact support.")
		return nil
	}

	// Validate the TOTP code with the user's secret.
	// If validation fails, log an invalid TOTP attempt for monitoring tools like fail2ban.
	if !totp.Validate(totpCode, secret) {
		m.logger.Warn("Invalid TOTP attempt",
			zap.String("username", username),
			zap.String("client_ip", clientIP),
		)
		show2FAForm(w, "Invalid TOTP code. Please try again.")
		return nil
	}

	// Create session on successful TOTP validation.
	m.createSession(w, username, clientIP)

	// Access the replacer from the request context to retrieve Caddy's original URI placeholder.
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Retrieve the unmodified original request URI (e.g., full path before handle_path stripped it).
	// Fallback to the current request URI if the original is unavailable.
	redirectURL := repl.ReplaceAll("{http.request.orig_uri}", r.URL.RequestURI())

	// Log the final redirect decision for debugging purposes.
	m.logger.Debug("Session ok, redirecting",
		zap.String("redirect_url", redirectURL),
		zap.String("current_request_uri", r.URL.RequestURI()),
	)

	// Redirect the client to the original requested URL.
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	return ""
}

// show2FAForm displays a styled 2FA form with an optional error message.
// This function is defined in a separate file to modularize HTML rendering.

// Interface guards to ensure BasicAuthTOTP implements the necessary interfaces.
var (
	_ caddy.Module                = (*BasicAuthTOTP)(nil)
	_ caddy.Provisioner           = (*BasicAuthTOTP)(nil)
	_ caddy.Validator             = (*BasicAuthTOTP)(nil)
	_ caddyhttp.MiddlewareHandler = (*BasicAuthTOTP)(nil)
)
