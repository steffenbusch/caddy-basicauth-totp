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
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// createOrUpdateJWTCookie generates a new JWT with a specified client IP or updates an existing one, and logs the details.
func (m *BasicAuthTOTP) createOrUpdateJWTCookie(w http.ResponseWriter, username, clientIP string) {
	expiration := time.Now().Add(m.SessionInactivityTimeout)
	claims := jwt.MapClaims{
		"username": username,
		"clientIP": clientIP,
		"exp":      expiration.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(m.SignKey))
	if err != nil {
		m.logger.Error("Failed to sign JWT", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	m.logger.Debug("Created or updated session",
		zap.String("username", username),
		zap.String("client_ip", clientIP),
		zap.String("token", signedToken),
		zap.Time("expires", expiration),
	)

	cookie := &http.Cookie{
		Name:     m.CookieName,
		Value:    signedToken,
		Path:     m.CookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, cookie)
}

// deleteJWTCookie clears the JWT cookie.
func (m *BasicAuthTOTP) deleteJWTCookie(w http.ResponseWriter) {
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

// hasValidJWTCookie checks if there is a valid JWT with a matching client IP.
func (m *BasicAuthTOTP) hasValidJWTCookie(w http.ResponseWriter, r *http.Request, username, clientIP string) bool {
	cookie, err := r.Cookie(m.CookieName)
	if err != nil {
		return false
	}

	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.SignKey), nil
	})
	if err != nil {
		m.logger.Error("Failed to parse JWT", zap.Error(err))
		return false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["username"] != username || claims["clientIP"] != clientIP {
			m.logger.Warn("JWT does not match username or client IP",
				zap.String("username", username),
				zap.String("client_ip", clientIP),
				zap.String("token_username", claims["username"].(string)),
				zap.String("token_client_ip", claims["clientIP"].(string)),
			)
			return false
		}

		expiration := time.Unix(int64(claims["exp"].(float64)), 0)
		if time.Now().After(expiration) {
			m.logger.Debug("JWT has expired", zap.Time("expiration", expiration))
			return false
		}

		// Extend session if less than 50% of inactivity timeout remains
		threshold := m.SessionInactivityTimeout / 2
		if time.Until(expiration) < threshold {
			m.logger.Debug("Extending session",
				zap.String("username", username),
				zap.String("client_ip", clientIP),
				zap.Time("expiration", expiration),
			)
			m.createOrUpdateJWTCookie(w, username, clientIP)
		}

		return true
	}

	return false
}
