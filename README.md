# BasicAuthTOTP Caddy Plugin

The **BasicAuthTOTP** plugin for [Caddy](https://caddyserver.com) enhances Caddy's basic authentication with Time-based One-Time Password (TOTP) two-factor authentication (2FA). This plugin is designed for use with Caddy's basic authentication, adding an extra layer of security for web applications and services hosted with Caddy.

> [!TIP]
> For more extensive authentication, authorization, and accounting requirements, consider using [AuthCrunch / caddy-security](https://github.com/greenpau/caddy-security). AuthCrunch provides a comprehensive AAA solution, supporting Form-Based, Basic, Local, LDAP, OpenID Connect, OAuth 2.0 (e.g., GitHub, Google, Facebook), SAML Authentication, and 2FA/MFA (including app-based authenticators and Yubico). It also offers authorization with JWT/PASETO tokens, making it ideal for more complex or larger-scale environments.

**BasicAuthTOTP** is best suited for smaller, perhaps internal user groups who require added security for specific endpoints but do not need a full-featured authentication, and authorization solution. It requires users to authenticate with both a valid TOTP code and basic auth credentials, making it suitable for lightweight, targeted protection of sensitive resources.

## Features

This plugin introduces additional authentication steps within Caddy configurations:

- **TOTP Authentication**: Requires users to enter a valid TOTP code in addition to basic auth credentials.
- **Session Management**: Allows configurable inactivity-based session expiration and IP-based session validation to prevent session hijacking.
- **Logout Support**: Provides a custom logout endpoint that clears the 2FA session, enabling users to securely log out of the 2FA session. **Note:** This does not log the user out of Basic Authentication, as Basic Auth sessions are managed separately by the browser and are not affected by the 2FA logout.

### Authentication Flow

When accessing a protected route, users will first be prompted to enter their Basic Authentication credentials. After successfully completing Basic Authentication, they will see a 2FA prompt to enter their TOTP code, as shown below:

<p align="center">
  <img src="assets/totp-input-screen.png" alt="TOTP 2FA Input Screen">
</p>

## Disclaimer

**Experimental Module**: This plugin is currently in an experimental phase and is primarily developed to meet specific, personal requirements. While contributions and suggestions are welcome, please be aware that this module may lack certain features or robustness expected in production environments.

> [!Important]
> Due to its experimental nature, this plugin is **not yet intended for use in production or mission-critical systems**. Use it at your own risk. The author assumes no responsibility for potential security risks, stability issues, or data loss that may arise from its use in such environments.

## Building

To build Caddy with this module, use xcaddy:

```bash
$ xcaddy build --with github.com/steffenbusch/caddy-basicauth-totp
```

## Caddyfile Config

By default, the `basic_auth_totp` directive is ordered after `basic_auth` in the Caddyfile. This enables seamless integration with Caddy's existing basic authentication system. Below is an example configuration, followed by detailed explanations of each configuration option.

```caddyfile
:8080 {
    handle /top-secret/* {
        basic_auth {
            user hashed_password
        }

        basic_auth_totp {
            session_inactivity_timeout 2h
            secrets_file_path /path/to/2fa-secrets.json
            cookie_name basicauthtotp_session
            cookie_path /top-secret
            logout_path /top-secret/logout
            logout_redirect_url /
        }

        respond "Welcome, you have passed basic and TOTP authentication!"
    }
}
```

### Configuration Options

- **`session_inactivity_timeout`**: Sets the maximum period of inactivity allowed before a session expires, requiring re-authentication. Default is `60m`.
  - *Usage Tip*: A shorter inactivity timeout improves security by prompting for re-authentication if users are inactive, while a longer timeout enhances convenience for active users.

- **`secrets_file_path`**: Specifies the path to a JSON file containing TOTP secrets for each user, required for validating TOTP codes.

  - Example JSON structure:

  ```json
    {
    "users": [
      {
        "username": "user1",
        "secret": "F2MV5KORBGRG5GTEUKHKF3YJYXJPC45PS7YHVV4GFIIWEYQE"
      },
      {
        "username": "user2",
        "secret": "BABC3SA2W523ZMLXH73IN46FBWJPEKLLPPL53AO44LWFIS5T"
      }
    ]
  }
  ```

  Each user should have a unique TOTP secret, formatted in **Base32** without padding (`=`). This key will later be used by a TOTP-compatible app (such as Google Authenticator or Authy) to generate time-based one-time passwords.

- **`cookie_name`**: Defines a custom name for the session cookie that stores the 2FA token. Default is `basicauthtotp_session`.

- **`cookie_path`**: Sets the path scope of the session cookie, defining where it will be sent on the server. Default is `/`.
  - *Usage Tip*: Ensure this aligns with the URL path protected by `basic_auth`, as the cookie will only be sent to matching paths.

- **`logout_path`**: Defines the URL path for logging out and clearing the 2FA session. Default is `/logout-session`.
  - *Usage Tip*: If your protected path is within a specific route (e.g., `/top-secret/*`), ensure that the `logout_path` is nested under the same route (e.g., `/top-secret/logout`). This allows the `handle` directive to correctly route the logout requests to `basic_auth_totp`.

- **`logout_redirect_url`**: Specifies the URL to redirect users to after logging out. Default is `/`.

### Session Management Explanation

The session is managed with an inactivity-based expiration. Once a user authenticates with a TOTP code, a session is created with an inactivity timeout (`session_inactivity_timeout`). Each valid request within this timeout period extends the session expiration by the specified inactivity duration, but only if less than 50% of the timeout remains. This reduces the frequency of session updates, optimizing performance by minimizing lock contention.

#### Generating a TOTP-compatible Secret

To create a secure, random key in the correct format, you can use the following command:

```bash
openssl rand 30 | base32 | tr --delete '='
```

**Explanation of the command:**

- **`openssl rand 30`**: Generates 30 random bytes.
- **`| base32`**: Converts the random bytes to Base32 format.
- **`| tr --delete '='`**: Removes any `=` padding characters, which are not needed in TOTP format.

This Base32 key can then be stored in `secrets_file_path` and will be used by the TOTP library to generate one-time passwords.

#### Setting Up the Secret in a 2FA App

If you want to set up the secret directly in a 2FA app, you can also generate a QR code that includes the Base32 secret. A useful tool for this is the [2FA QR Code Generator](https://stefansundin.github.io/2fa-qr/), where you can input the Base32 key to create a scannable QR code for the app.

### Example: Custom Logout Path

The following configuration sets up a custom logout endpoint at `/logout` that, when accessed, will clear the user's 2FA session and redirect them to the root URL (`/`):

```caddyfile
:8080 {
    basic_auth {
        user hashed_password
    }

    basic_auth_totp {
        session_inactivity_timeout 30m
        secrets_file_path /path/to/2fa-secrets.json
        logout_path /logout
        logout_redirect_url /
    }
}
```

## Security Considerations

- **TOTP Secret Management**: Ensure that the `secrets_file_path` is secure and not accessible via the web server. This file contains sensitive user secrets and should be protected from unauthorized access.
- **Inactivity Timeout**: Choose an appropriate `session_inactivity_timeout` that balances usability and security. Shorter timeouts enhance security but may inconvenience users by requiring frequent re-authentication.
- **Session Renewal Optimization**: To optimize performance, sessions are only extended when less than 50% of the inactivity timeout remains. This approach reduces the frequency of session updates and improves handling of concurrent access.
- **IP Binding**: Sessions are automatically bound to the client’s IP address, providing an additional layer of security against session hijacking. This setting cannot be disabled. By default, the session is tied to the client’s IP address, meaning that if a user’s IP address changes (e.g., due to network switching), they will be required to re-authenticate with a TOTP code. This feature enhances security by ensuring that each session is restricted to a specific client IP.
- **Cookie Security**: The session cookie is set with `HttpOnly`, `Secure`, and `SameSite=Lax` attributes. These settings help prevent attacks, but `SameSite` is not currently configurable.
- **Brute-Force Attack Prevention and Logging**: To help prevent brute-force attempts on TOTP codes, the plugin logs each invalid TOTP attempt with the username and client IP, such as:

    `2024/11/01 08:08:36.099 WARN    http.handlers.basicauth2fa      Invalid TOTP attempt    {"username": "user1", "client_ip": "4.8.15.16"}`

    This log entry provides crucial information for security monitoring and can be used with `fail2ban` or similar tools to block repeated failed attempts.
- **TOTP Validation Settings**: The plugin uses TOTP validation settings compatible with Google Authenticator, including:
  - 6-digit codes,
  - A 30-second code validity period,
  - A skew allowance of one period (±30 seconds) for clock drift,
  - SHA-1 as the HMAC algorithm.

  These settings are applied by default in the `Validate` function to maintain compatibility with most authenticator apps while ensuring secure TOTP verification.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Caddy](https://caddyserver.com) for providing a powerful and extensible web server.
- [pquerna/otp](https://github.com/pquerna/otp) for TOTP functionality, used under the Apache License 2.0.
