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

	"go.uber.org/zap"
)

// UserSecret and UsersFile define structures for handling TOTP secrets.
type UserSecret struct {
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

type UsersFile struct {
	Users []UserSecret `json:"users"`
}

// loadSecrets loads secrets from the specified JSON file.
func (m *BasicAuthTOTP) loadSecrets() error {
	m.secretsLoadMutex.Lock()
	defer m.secretsLoadMutex.Unlock()

	if m.loadedSecrets != nil {
		return nil // Secrets are already loaded
	}

	file, err := os.Open(m.SecretsFilePath)
	if err != nil {
		m.logger.Error("could not open secrets file", zap.String("file", m.SecretsFilePath), zap.Error(err))
		return fmt.Errorf("could not open secrets file: %v", err)
	}
	defer file.Close()

	var usersFile UsersFile
	if err := json.NewDecoder(file).Decode(&usersFile); err != nil {
		m.logger.Error("could not decode secrets file", zap.String("file", m.SecretsFilePath), zap.Error(err))
		return fmt.Errorf("could not decode secrets file: %v", err)
	}

	m.loadedSecrets = make(map[string]string)
	for _, user := range usersFile.Users {
		m.loadedSecrets[user.Username] = user.Secret
	}
	return nil
}

// getSecretForUser retrieves the user's TOTP secret from the loaded secrets map.
func (m *BasicAuthTOTP) getSecretForUser(username string) (string, error) {
	if err := m.loadSecrets(); err != nil {
		return "", err
	}
	secret, exists := m.loadedSecrets[username]
	if !exists {
		return "", fmt.Errorf("no TOTP secret found for user %s", username)
	}
	return secret, nil
}
