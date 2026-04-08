package oauth

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type TokenSource struct {
	mu     sync.Mutex
	store  *FileStore
	client *Client
	skew   time.Duration
}

func NewTokenSource(store *FileStore, client *Client) *TokenSource {
	return &TokenSource{
		store:  store,
		client: client,
		skew:   2 * time.Minute,
	}
}

func (s *TokenSource) ValidToken(ctx context.Context) (*TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}

	if time.Until(token.Expiry) > s.skew {
		return token, nil
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("access token is expiring and no refresh token is stored; run login again")
	}

	refreshed, err := s.client.Refresh(ctx, token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	// Some providers rotate refresh tokens; keep the previous one only when the
	// new response omits it.
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	if refreshed.AccountID == "" {
		refreshed.AccountID = token.AccountID
	}

	if err := s.store.Save(ctx, refreshed); err != nil {
		return nil, fmt.Errorf("persist refreshed token: %w", err)
	}

	return refreshed, nil
}

func (s *TokenSource) ForceRefresh(ctx context.Context) (*TokenSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, err := s.store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token stored; run login again")
	}

	refreshed, err := s.client.Refresh(ctx, token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}
	if refreshed.RefreshToken == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	if refreshed.AccountID == "" {
		refreshed.AccountID = token.AccountID
	}

	if err := s.store.Save(ctx, refreshed); err != nil {
		return nil, fmt.Errorf("persist refreshed token: %w", err)
	}
	return refreshed, nil
}
