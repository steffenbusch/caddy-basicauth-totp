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
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"html/template"
	"net/http"

	"go.uber.org/zap"
)

// default2FAFormHTML contains the default HTML content for the 2FA form.
// By default, its value is an embedded document. To configure a custom
// HTML form, set Caddyfile directive `template_file` to the path of
// an external HTML file.
//
//go:embed default-2fa-form.html
var default2FAFormHTML string

// FormData holds the data to be passed to the 2FA form template
type FormData struct {
	Nonce        string
	ErrorMessage string
	Username     string
}

// generateNonce generates a random base64 nonce
func generateNonce() (string, error) {
	nonceBytes := make([]byte, 18) // 18 bytes (144 bits) avoids `==` padding in base64
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(nonceBytes), nil
}

// provisionTemplate sets up the HTML template for the 2FA form.
func (m *BasicAuthTOTP) provisionTemplate() error {
	var err error
	// Load the external custom HTML template if set
	if m.TemplateFile != "" {
		m.Template, err = template.ParseFiles(m.TemplateFile)
		if err != nil {
			m.logger.Warn("failed to load custom 2FA form template, using default",
				zap.String("template_path", m.TemplateFile),
				zap.Error(err))
		}
	}

	// Use the default HTML template if no custom template is set
	// or if there was an error loading the custom template
	if m.TemplateFile == "" || err != nil {
		// Parse the embedded HTML content
		m.Template, err = template.New("2fa_form").Parse(default2FAFormHTML)
		if err != nil {
			m.logger.Error("failed to parse default 2FA form template",
				zap.Error(err))
			return err
		}
	}
	return nil
}

// show2FAForm displays a styled 2FA form with an error message if provided.
// It generates a nonce for the Content-Security-Policy and uses either a custom
// or default HTML template to render the form.
func (m *BasicAuthTOTP) show2FAForm(w http.ResponseWriter, formData FormData) {
	// Generate a nonce for this request
	nonce, err := generateNonce()
	if err != nil {
		m.logger.Error("failed to generate nonce for 2FA form",
			zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Update the nonce in the data struct
	formData.Nonce = nonce

	// Set the Content-Type and Content-Security-Policy headers with nonce
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'nonce-"+nonce+"'; form-action 'self';")
	w.WriteHeader(http.StatusOK)

	// Execute the template and write the output to the response
	if err := m.Template.Execute(w, formData); err != nil {
		m.logger.Error("failed to execute 2FA form template",
			zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}
