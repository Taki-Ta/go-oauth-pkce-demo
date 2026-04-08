package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type TokenSet struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry"`
	AccountID    string    `json:"account_id,omitempty"`
}

type Client struct {
	httpClient *http.Client
	config     Config
}

func NewClient(cfg Config) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 20 * time.Second},
		config:     cfg,
	}
}

func (c *Client) AuthorizeURL(state, challenge string) (string, error) {
	parsed, err := url.Parse(c.config.AuthorizeURL)
	if err != nil {
		return "", fmt.Errorf("parse authorize URL: %w", err)
	}

	query := parsed.Query()
	query.Set("response_type", "code")
	query.Set("client_id", c.config.ClientID)
	query.Set("redirect_uri", c.config.RedirectURL)
	query.Set("scope", strings.Join(c.config.Scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (c *Client) OpenBrowser(authURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL)
	case "darwin":
		cmd = exec.Command("open", authURL)
	default:
		cmd = exec.Command("xdg-open", authURL)
	}
	return cmd.Start()
}

func (c *Client) ExchangeCode(ctx context.Context, code, verifier string) (*TokenSet, error) {
	values := url.Values{}
	values.Set("grant_type", "authorization_code")
	values.Set("client_id", c.config.ClientID)
	values.Set("code", code)
	values.Set("redirect_uri", c.config.RedirectURL)
	values.Set("code_verifier", verifier)
	return c.exchangeToken(ctx, values)
}

func (c *Client) Refresh(ctx context.Context, refreshToken string) (*TokenSet, error) {
	values := url.Values{}
	values.Set("grant_type", "refresh_token")
	values.Set("client_id", c.config.ClientID)
	values.Set("refresh_token", refreshToken)
	return c.exchangeToken(ctx, values)
}

func (c *Client) exchangeToken(ctx context.Context, values url.Values) (*TokenSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, bytes.TrimSpace(body))
	}

	var raw struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, fmt.Errorf("token response did not include access_token")
	}

	expiry := time.Now().Add(time.Hour)
	if raw.ExpiresIn > 0 {
		expiry = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}

	tokenSet := &TokenSet{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		TokenType:    defaultTokenType(raw.TokenType),
		Scope:        raw.Scope,
		Expiry:       expiry,
	}

	if accountID := extractJWTSubject(raw.IDToken); accountID != "" {
		tokenSet.AccountID = accountID
	}

	return tokenSet, nil
}

func (c *Client) CallResource(ctx context.Context, accessToken string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.config.ResourceURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func defaultTokenType(value string) string {
	if value == "" {
		return "Bearer"
	}
	return value
}

func extractJWTSubject(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Subject
}
