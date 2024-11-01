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
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// session represents a 2FA session with expiration and client IP tracking.
type session struct {
	username string
	expires  time.Time
	clientIP string
}

var sessionStore = make(map[string]session)
var mu sync.RWMutex

// createSession generates a new session with a specified client IP and logs the details.
func (m *BasicAuthTOTP) createSession(w http.ResponseWriter, username, clientIP string) {
	token := uuid.NewString()
	mu.Lock()
	defer mu.Unlock()

	expiration := time.Now().Add(m.SessionInactivityTimeout)
	sessionStore[token] = session{username: username, expires: expiration, clientIP: clientIP}

	m.logger.Debug("Created new session",
		zap.String("username", username),
		zap.String("client_ip", clientIP),
		zap.String("token", token),
		zap.Time("expires", expiration),
	)

	cookie := &http.Cookie{
		Name:     m.CookieName,
		Value:    token,
		Path:     m.CookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
}

// deleteSession removes the session from the store and clears the cookie.
func (m *BasicAuthTOTP) deleteSession(w http.ResponseWriter, token string) {
	mu.Lock()
	delete(sessionStore, token)
	mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     m.CookieName,
		Value:    "",
		Path:     m.CookiePath,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// hasValidSession checks if there is a valid session with a matching client IP.
// It extends the session expiration if less than 50% of the inactivity timeout remains.
func (m *BasicAuthTOTP) hasValidSession(r *http.Request, username, clientIP string) bool {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return false
	}

	mu.RLock()
	sess, exists := sessionStore[cookie.Value]
	mu.RUnlock()

	if !exists || sess.username != username || time.Now().After(sess.expires) || sess.clientIP != clientIP {
		return false
	}

	// Extend session if less than 50% of inactivity timeout remains
	threshold := m.SessionInactivityTimeout / 2
	if time.Until(sess.expires) < threshold {
		mu.Lock()
		sess.expires = time.Now().Add(m.SessionInactivityTimeout)
		sessionStore[cookie.Value] = sess
		mu.Unlock()

		m.logger.Debug("Extended session due to activity",
			zap.String("username", username),
			zap.String("client_ip", clientIP),
			zap.String("token", cookie.Value),
			zap.Time("new_expires", sess.expires),
		)
	}

	return true
}
