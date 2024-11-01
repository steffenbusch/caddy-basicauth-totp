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
)

// show2FAForm displays a styled 2FA form with a custom error message if provided.
func show2FAForm(w http.ResponseWriter, errorMessage string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)

	// Set the error message HTML if an error message is provided
	errorMessageHTML := ""
	if errorMessage != "" {
		errorMessageHTML = `<p class="error-message">` + errorMessage + `</p>`
	}

	formHTML := `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>2FA Authentication</title>
            <style>
				body {
					font-family: Arial, sans-serif;
					display: flex;
					align-items: center;
					justify-content: center;
					height: 100vh;
					margin: 0;
					background-color: #f4f4f9;
				}
				.container {
					text-align: center;
					width: 100%;
					max-width: 400px;
					background-color: #ffffff;
					padding: 20px;
					border-radius: 8px;
					box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
					box-sizing: border-box;
					min-height: 280px;
				}
				h1 {
					font-size: 1.6em;
					color: #333;
					margin-bottom: 0.8em;
				}
				p {
					font-size: 1em;
					color: #555;
					margin-bottom: 1em;
				}
				label {
					display: block;
					font-size: 0.9em;
					color: #333;
					margin-bottom: 0.5em;
				}
				input[type="text"] {
					width: 100%;
					padding: 10px;
					margin-bottom: 1em;
					font-size: 1em;
					border: 1px solid #ccc;
					border-radius: 4px;
					box-sizing: border-box;
				}
				button {
					background-color: #4CAF50;
					color: white;
					padding: 10px 20px;
					font-size: 1em;
					border: none;
					border-radius: 4px;
					cursor: pointer;
				}
				button:hover {
					background-color: #45a049;
				}
				.error-message {
					color: #d9534f;
					font-size: 0.9em;
					margin-top: 1em;
				}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>2FA Authentication Required</h1>
                <p>Please enter your 2FA code to continue.</p>
                <form method="POST" action="">
                    <label for="totp_code">2FA Code:</label>
                    <input type="text" id="totp_code" name="totp_code" size="30" maxlength="6" required autofocus>
                    <button type="submit">Submit</button>
                </form>
                ` + errorMessageHTML + `
            </div>
        </body>
        </html>`

	w.Write([]byte(formHTML))
}
