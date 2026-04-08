package oauth

import (
	"context"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
)

type CallbackResult struct {
	Code  string
	State string
	Error string
}

func WaitForCallback(ctx context.Context, redirectURL string) (*CallbackResult, error) {
	parsed, err := url.Parse(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("parse redirect URL: %w", err)
	}

	listener, err := net.Listen("tcp", parsed.Host)
	if err != nil {
		return nil, fmt.Errorf("listen on redirect host %q: %w", parsed.Host, err)
	}
	defer listener.Close()

	resultCh := make(chan *CallbackResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}
	defer srv.Close()

	mux.HandleFunc(parsed.Path, func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		result := &CallbackResult{
			Code:  query.Get("code"),
			State: query.Get("state"),
			Error: query.Get("error"),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if result.Error != "" {
			_, _ = fmt.Fprintf(w, "<h1>OAuth error</h1><p>%s</p>", html.EscapeString(result.Error))
		} else {
			_, _ = fmt.Fprint(w, "<h1>Login complete</h1><p>You can return to the terminal.</p>")
		}

		select {
		case resultCh <- result:
		default:
		}
	})

	go func() {
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
