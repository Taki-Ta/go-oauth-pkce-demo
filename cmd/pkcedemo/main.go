package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Taki-Ta/go-oauth-pkce-demo/internal/oauth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cfg, err := oauth.LoadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}

	client := oauth.NewClient(cfg)
	store := oauth.NewFileStore(cfg.StorePath)
	tokens := oauth.NewTokenSource(store, client)

	var runErr error
	switch os.Args[1] {
	case "login":
		runErr = runLogin(ctx, cfg, client, store)
	case "token":
		runErr = runToken(ctx, tokens)
	case "refresh":
		runErr = runRefresh(ctx, tokens)
	case "call":
		runErr = runCall(ctx, cfg, client, tokens)
	case "help", "-h", "--help":
		usage()
		return
	default:
		runErr = fmt.Errorf("unknown command %q", os.Args[1])
	}

	if runErr != nil {
		if errors.Is(runErr, flag.ErrHelp) {
			usage()
			return
		}
		fmt.Fprintln(os.Stderr, "error:", runErr)
		os.Exit(1)
	}
}

func runLogin(ctx context.Context, cfg oauth.Config, client *oauth.Client, store *oauth.FileStore) error {
	state, err := oauth.NewState()
	if err != nil {
		return fmt.Errorf("generate state: %w", err)
	}
	verifier, challenge, err := oauth.NewPKCE()
	if err != nil {
		return fmt.Errorf("generate PKCE pair: %w", err)
	}

	authURL, err := client.AuthorizeURL(state, challenge)
	if err != nil {
		return err
	}

	fmt.Println("Open this URL in your browser if it does not open automatically:")
	fmt.Println(authURL)
	fmt.Println()

	if err := client.OpenBrowser(authURL); err != nil {
		fmt.Println("Could not open the browser automatically:", err)
	}

	callback, err := oauth.WaitForCallback(ctx, cfg.RedirectURL)
	if err != nil {
		return err
	}
	if callback.Error != "" {
		return fmt.Errorf("authorization failed: %s", callback.Error)
	}
	if callback.State != state {
		return fmt.Errorf("state mismatch: expected %q got %q", state, callback.State)
	}
	if callback.Code == "" {
		return fmt.Errorf("callback did not include an authorization code")
	}

	token, err := client.ExchangeCode(ctx, callback.Code, verifier)
	if err != nil {
		return err
	}
	if err := store.Save(ctx, token); err != nil {
		return err
	}

	fmt.Printf("Login complete. Token stored in %s\n", cfg.StorePath)
	if token.AccountID != "" {
		fmt.Printf("Account ID (from id_token sub): %s\n", token.AccountID)
	}
	fmt.Printf("Expires at: %s\n", token.Expiry.Format(time.RFC3339))
	return nil
}

func runToken(ctx context.Context, tokens *oauth.TokenSource) error {
	token, err := tokens.ValidToken(ctx)
	if err != nil {
		return err
	}

	fmt.Println(token.AccessToken)
	fmt.Printf("\nExpires at: %s\n", token.Expiry.Format(time.RFC3339))
	if token.AccountID != "" {
		fmt.Printf("Account ID: %s\n", token.AccountID)
	}
	return nil
}

func runRefresh(ctx context.Context, tokens *oauth.TokenSource) error {
	token, err := tokens.ForceRefresh(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Refresh succeeded. New expiry: %s\n", token.Expiry.Format(time.RFC3339))
	if token.AccountID != "" {
		fmt.Printf("Account ID: %s\n", token.AccountID)
	}
	return nil
}

func runCall(ctx context.Context, cfg oauth.Config, client *oauth.Client, tokens *oauth.TokenSource) error {
	if err := cfg.ValidateForResourceCall(); err != nil {
		return err
	}

	token, err := tokens.ValidToken(ctx)
	if err != nil {
		return err
	}

	body, status, err := client.CallResource(ctx, token.AccessToken)
	if err != nil {
		return err
	}

	fmt.Printf("HTTP %d\n", status)
	fmt.Println(string(body))
	return nil
}

func usage() {
	fmt.Println(`pkcedemo demonstrates OAuth 2.0 Authorization Code + PKCE.

Usage:
  pkcedemo login    Start browser login and store tokens
  pkcedemo token    Print the current access token, auto-refreshing if needed
  pkcedemo refresh  Force a refresh-token grant and update the store
  pkcedemo call     Call OAUTH_RESOURCE_URL with a Bearer token

Required environment variables:
  OAUTH_CLIENT_ID
  OAUTH_AUTHORIZE_URL
  OAUTH_TOKEN_URL

Optional environment variables:
  OAUTH_REDIRECT_URL   default: http://127.0.0.1:1455/callback
  OAUTH_SCOPES         default: openid,profile,offline_access
  OAUTH_RESOURCE_URL   used by the call command
  TOKEN_STORE_PATH     default: .demo-token.json`)
}
