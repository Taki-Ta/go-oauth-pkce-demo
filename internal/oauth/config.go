package oauth

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	ClientID     string
	AuthorizeURL string
	TokenURL     string
	RedirectURL  string
	Scopes       []string
	ResourceURL  string
	StorePath    string
}

func LoadConfig() (Config, error) {
	cfg := Config{
		ClientID:     strings.TrimSpace(os.Getenv("OAUTH_CLIENT_ID")),
		AuthorizeURL: strings.TrimSpace(os.Getenv("OAUTH_AUTHORIZE_URL")),
		TokenURL:     strings.TrimSpace(os.Getenv("OAUTH_TOKEN_URL")),
		RedirectURL:  defaultString(strings.TrimSpace(os.Getenv("OAUTH_REDIRECT_URL")), "http://127.0.0.1:1455/callback"),
		ResourceURL:  strings.TrimSpace(os.Getenv("OAUTH_RESOURCE_URL")),
		StorePath:    defaultString(strings.TrimSpace(os.Getenv("TOKEN_STORE_PATH")), ".demo-token.json"),
	}

	rawScopes := defaultString(strings.TrimSpace(os.Getenv("OAUTH_SCOPES")), "openid,profile,offline_access")
	cfg.Scopes = splitScopes(rawScopes)

	var missing []string
	if cfg.ClientID == "" {
		missing = append(missing, "OAUTH_CLIENT_ID")
	}
	if cfg.AuthorizeURL == "" {
		missing = append(missing, "OAUTH_AUTHORIZE_URL")
	}
	if cfg.TokenURL == "" {
		missing = append(missing, "OAUTH_TOKEN_URL")
	}
	if cfg.RedirectURL == "" {
		missing = append(missing, "OAUTH_REDIRECT_URL")
	}

	if len(missing) > 0 {
		return Config{}, errors.New("missing required environment variables: " + strings.Join(missing, ", "))
	}

	return cfg, nil
}

func (c Config) ValidateForResourceCall() error {
	if c.ResourceURL == "" {
		return fmt.Errorf("OAUTH_RESOURCE_URL is required for the call command")
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func splitScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' '
	})

	scopes := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field != "" {
			scopes = append(scopes, field)
		}
	}
	return scopes
}
