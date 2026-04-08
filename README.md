# go-oauth-pkce-demo

A small Go CLI for learning OAuth 2.0 Authorization Code flow with PKCE, local callbacks, refresh tokens, and token persistence.

It is intentionally provider-agnostic. You can point it at any OAuth provider that supports PKCE and a loopback redirect URI. That makes it useful for understanding the same moving pieces that tools like OpenClaw document for their Codex-style login flow, without baking in private provider assumptions.

## What the demo shows

- Generate a `state` value to prevent callback forgery.
- Generate a PKCE `code_verifier` and `code_challenge`.
- Open the browser to the provider's authorize endpoint.
- Listen on `127.0.0.1` for the redirect callback.
- Exchange the authorization code for access and refresh tokens.
- Persist tokens to disk.
- Auto-refresh access tokens before they expire.
- Reuse rotated refresh tokens when the provider returns a new one.

## Project layout

- `cmd/pkcedemo/main.go` - CLI entry point.
- `internal/oauth/pkce.go` - PKCE state, verifier, and challenge helpers.
- `internal/oauth/local_callback.go` - local loopback callback server.
- `internal/oauth/client.go` - authorize URL building, code exchange, refresh, and protected-resource calls.
- `internal/oauth/store.go` - JSON token store.
- `internal/oauth/manager.go` - token validity checks and automatic refresh.

## Environment variables

Copy `.env.example` and set the values for your provider.

```powershell
$env:OAUTH_CLIENT_ID = "your-client-id"
$env:OAUTH_AUTHORIZE_URL = "https://example.com/oauth/authorize"
$env:OAUTH_TOKEN_URL = "https://example.com/oauth/token"
$env:OAUTH_REDIRECT_URL = "http://127.0.0.1:1455/callback"
$env:OAUTH_SCOPES = "openid,profile,offline_access"
$env:OAUTH_RESOURCE_URL = "https://example.com/api/me"
$env:TOKEN_STORE_PATH = ".demo-token.json"
```

Required:

- `OAUTH_CLIENT_ID`
- `OAUTH_AUTHORIZE_URL`
- `OAUTH_TOKEN_URL`

Optional:

- `OAUTH_REDIRECT_URL` - defaults to `http://127.0.0.1:1455/callback`
- `OAUTH_SCOPES` - defaults to `openid,profile,offline_access`
- `OAUTH_RESOURCE_URL` - used by `call`
- `TOKEN_STORE_PATH` - defaults to `.demo-token.json`

## Run the demo

Build it:

```powershell
go build -o .\bin\pkcedemo.exe .\cmd\pkcedemo
```

Start login:

```powershell
.\bin\pkcedemo.exe login
```

Print a valid access token. If the current token is close to expiry, the CLI refreshes it first:

```powershell
.\bin\pkcedemo.exe token
```

Force a refresh-token grant:

```powershell
.\bin\pkcedemo.exe refresh
```

Call a protected resource URL with the stored bearer token:

```powershell
.\bin\pkcedemo.exe call
```

## How automatic refresh works

`TokenSource.ValidToken` loads the stored token and checks whether it expires within a small safety window. If the token is still fresh enough, it is returned as-is. Otherwise, the CLI:

1. uses the stored `refresh_token`
2. requests a new access token from the token endpoint
3. saves the refreshed token payload back to disk
4. keeps the previous refresh token only when the provider omits a new one

That last step matters because many providers rotate refresh tokens.

## Mapping this to OAuth concepts

- `state` answers: "Is this callback for the login request I started?"
- `code_verifier` answers: "Is the client redeeming this code the same client that initiated the login?"
- `access_token` answers: "Can I access the protected resource right now?"
- `refresh_token` answers: "Can I silently renew access without asking the user to log in again?"

## Notes about OpenAI / Codex-style learning

This repo is for learning the protocol shape: Authorization Code flow, PKCE, local loopback redirect, token storage, and refresh.

If you want to experiment with a specific provider, only use endpoints and client credentials that the provider has officially granted you to use. The demo is generic on purpose.
