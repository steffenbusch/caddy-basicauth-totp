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
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"net"
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
//   - JWT(JSON Web Token)-session-based TOTP authentication with configurable inactivity timeouts.
//   - IP binding for session validation, requiring re-authentication if the user's IP changes.
//   - Customizable session cookie options, including name and path scope.
//
// Instead of server-side session management, this module uses JWTs stored in cookies to manage
// sessions. This approach simplifies session handling and no sessions are lost when
// Caddy is reloaded or restarted.
// However, this approach is less secure than server-side session management, as JWTs are
// not invalidated or blacklisted and no logout is provided. To mitigate risks, the module uses IP binding
// to ensure that the JWT is only valid for the client IP address that created it.
// If the client IP changes, the JWT cookie is removed and the user must re-authenticate.
//
// Configuration options in BasicAuthTOTP provide flexibility in securing routes, and
// managing session inactivity timeout. Secrets are loaded from a specified JSON file that maps
// usernames to TOTP secrets.
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
	// Default is `batotp_sess`.
	CookieName string `json:"cookie_name,omitempty"`

	// CookiePath specifies the path scope of the session cookie.
	// This restricts where the cookie is sent on the server. Default is `/`.
	CookiePath string `json:"cookie_path,omitempty"`

	// Filename of the custom template to use instead of the embedded default template.
	FormTemplateFile string `json:"form_template,omitempty"`

	// template is the parsed HTML template used to render the 2FA form.
	formTemplate *template.Template

	// SignKey is the base64 encoded secret key used to sign the JWTs.
	SignKey string `json:"sign_key,omitempty"`

	// signKeyBytes is the base64 decoded secret key used to sign the JWTs.
	signKeyBytes []byte

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
		m.CookieName = "batotp_sess"
	}
	if m.CookiePath == "" {
		m.CookiePath = "/"
	}
	if m.SessionInactivityTimeout == 0 {
		m.SessionInactivityTimeout = 60 * time.Minute // Default inactivity timeout
	}

	var err error
	m.signKeyBytes, err = base64.StdEncoding.DecodeString(m.SignKey)
	if err != nil {
		m.logger.Error("Failed to decode sign key", zap.Error(err))
		return err
	}

	// Provision the HTML template
	if err = m.provisionTemplate(); err != nil {
		return err
	}

	// Log the chosen configuration values
	m.logger.Info("BasicAuthTOTP plugin configured",
		zap.Duration("SessionInactivityTimeout", m.SessionInactivityTimeout),
		zap.String("SecretsFilePath", m.SecretsFilePath),
		zap.String("CookieName", m.CookieName),
		zap.String("CookiePath", m.CookiePath),
		zap.String("TemplateFile", m.FormTemplateFile),
		// SignKey is omitted from the log output for security reasons.
	)
	return nil
}

// Validate ensures the configuration is correct.
func (m *BasicAuthTOTP) Validate() error {
	if m.SessionInactivityTimeout <= 0 {
		return fmt.Errorf("SessionInactivityTimeout must be a positive duration")
	}

	// Check if the base64 encoded sign key is set
	if m.SignKey == "" {
		return fmt.Errorf("SignKey must be defined")
	}

	// Check if the base64 decoded sign key has an appropriate length
	if len(m.signKeyBytes) < 32 { // 32 bytes is commonly recommended as a minimum for security
		return fmt.Errorf("decoded sign key must be at least 32 bytes long, check the base64 encoded sign key")
	}

	return nil
}

// ServeHTTP handles incoming HTTP requests and checks for IP changes.
func (m *BasicAuthTOTP) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	username, _, ok := r.BasicAuth()
	if !ok || username == "" {
		return next.ServeHTTP(w, r)
	}

	// Access the replacer from the request context to retrieve the requests original URI / path placeholders.
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return caddyhttp.Error(http.StatusInternalServerError, nil)
	}

	// Retrieve the client IP address from the Caddy context.
	clientIP := getClientIP(r.Context(), r.RemoteAddr)

	// Validate session and check IP consistency
	if m.hasValidJWTCookie(w, r, username, clientIP) {
		return next.ServeHTTP(w, r)
	}

	// Initialize FormData with the html escaped username
	username = html.EscapeString(username)
	formData := FormData{
		Username: username,
	}

	if r.Method != http.MethodPost {
		m.show2FAForm(w, formData)
		return nil
	}

	// Parse TOTP code from POST data.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return nil
	}

	// Create logger with common fields
	logger := m.logger.With(
		zap.String("username", username),
		zap.String("client_ip", clientIP),
	)

	totpCode := r.FormValue("totp_code")
	// Check if the TOTP code is missing; if so, log and prompt for 2FA again.
	if totpCode == "" {
		logger.Warn("Missing TOTP code in POST")
		m.show2FAForm(w, formData)
		return nil
	}

	// Attempt to retrieve the TOTP secret for the user.
	// If an error occurs while fetching the secret (e.g., if no TOTP secret is set for the user),
	// log it and show an error message.
	secret, err := m.getSecretForUser(username)
	if err != nil {
		logger.Warn("Failed to retrieve TOTP secret", zap.Error(err))
		formData.ErrorMessage = "Authentication error. Please contact support."
		m.show2FAForm(w, formData)
		return nil
	}

	// Validate the TOTP code with the user's secret.
	// If validation fails, log an invalid TOTP attempt for monitoring tools like fail2ban.
	if !totp.Validate(totpCode, secret) {
		logger.Warn("Invalid TOTP attempt")
		formData.ErrorMessage = "Invalid TOTP code. Please try again."
		m.show2FAForm(w, formData)
		return nil
	}

	// Create a new JWT session cookie for the user on successful TOTP validation.
	m.createOrUpdateJWTCookie(w, username, clientIP)

	// Retrieve the unmodified request's original URI (e.g., full path before handle_path stripped it).
	// Fallback to the current request URI if the request's original URI is unavailable.
	redirectURL := repl.ReplaceAll("{http.request.orig_uri}", r.URL.RequestURI())

	// Log the final redirect decision for debugging purposes.
	logger.Debug("Session ok, redirecting",
		zap.String("redirect_url", redirectURL),
		zap.String("current_request_uri", r.URL.RequestURI()),
	)

	// Redirect the client to the original requested URL.
	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

// getClientIP retrieves the client IP address directly from the Caddy context.
func getClientIP(ctx context.Context, remoteAddr string) string {
	clientIP, ok := ctx.Value(caddyhttp.VarsCtxKey).(map[string]any)["client_ip"]
	if ok {
		if ip, valid := clientIP.(string); valid {
			return ip
		}
	}
	// If the client IP is empty, extract it from the request's RemoteAddr.
	var err error
	clientIP, _, err = net.SplitHostPort(remoteAddr)
	if err != nil {
		// Use the complete RemoteAddr string as a last resort.
		clientIP = remoteAddr
	}
	return clientIP.(string)
}

// Interface guards to ensure BasicAuthTOTP implements the necessary interfaces.
var (
	_ caddy.Module                = (*BasicAuthTOTP)(nil)
	_ caddy.Provisioner           = (*BasicAuthTOTP)(nil)
	_ caddy.Validator             = (*BasicAuthTOTP)(nil)
	_ caddyhttp.MiddlewareHandler = (*BasicAuthTOTP)(nil)
)
