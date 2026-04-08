package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

type FileStore struct {
	path string
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) Load(ctx context.Context) (*TokenSet, error) {
	_ = ctx

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("token store %q not found; run the login command first", s.path)
		}
		return nil, err
	}

	var token TokenSet
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("decode token store: %w", err)
	}
	if token.AccessToken == "" {
		return nil, fmt.Errorf("token store %q does not contain an access token", s.path)
	}
	return &token, nil
}

func (s *FileStore) Save(ctx context.Context, token *TokenSet) error {
	_ = ctx

	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(s.path, data, 0o600)
}
