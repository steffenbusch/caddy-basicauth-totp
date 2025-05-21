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
	"encoding/json"
	"fmt"
	"os"
)

// userSecretEntry represents a single user's TOTP secret and optional code length.
type userSecretEntry struct {
	Username   string `json:"username"`
	Secret     string `json:"secret"`
	CodeLength int    `json:"code_length,omitempty"`
}

// secretsFileFormat represents the structure of the secrets JSON file.
type secretsFileFormat struct {
	Users []userSecretEntry `json:"users"`
}

// loadSecretsFile loads the secrets file and populates loadedUserSecrets.
func (m *BasicAuthTOTP) loadSecretsFile() error {
	data, err := os.ReadFile(m.SecretsFilePath)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}
	var secrets secretsFileFormat
	if err := json.Unmarshal(data, &secrets); err != nil {
		return fmt.Errorf("failed to unmarshal secrets file: %w", err)
	}
	m.loadedUserSecrets = make(map[string]userSecretEntry)
	for _, entry := range secrets.Users {
		m.loadedUserSecrets[entry.Username] = entry
	}
	return nil
}

// getSecretForUser returns the TOTP secret and code length for a user.
func (m *BasicAuthTOTP) getSecretForUser(username string) (secret string, codeLength int, err error) {
	m.secretsLoadMutex.Lock()
	defer m.secretsLoadMutex.Unlock()
	if m.loadedUserSecrets == nil {
		// Load secrets from file
		if err := m.loadSecretsFile(); err != nil {
			return "", 0, err
		}
	}
	entry, ok := m.loadedUserSecrets[username]
	if !ok {
		return "", 0, fmt.Errorf("no TOTP secret found for user %s", username)
	}
	secret = entry.Secret
	if secret == "" {
		return "", 0, fmt.Errorf("TOTP secret for user %s is empty", username)
	}
	if entry.CodeLength > 0 {
		codeLength = entry.CodeLength
	} else {
		codeLength = m.TOTPCodeLength
	}
	return secret, codeLength, nil
}
