package jwt

import (
	"context"
	"strings"

	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/res.zgo"
)

// GetBearerToken 获取用户令牌
func GetBearerToken(ctx context.Context) (string, error) {
	if c, ok := ctx.(res.Context); ok {
		prefix := "Bearer "
		if auth := c.GetHeader("Authorization"); auth != "" && strings.HasPrefix(auth, prefix) {
			return auth[len(prefix):], nil
		}
	}
	return "", auth.ErrNoneToken
}

// GetFormToken 获取用户令牌
func GetFormToken(ctx context.Context) (string, error) {
	if c, ok := ctx.(res.Context); ok {
		if auth := c.GetRequest().Form.Get("token"); auth != "" {
			return auth, nil
		}
	}
	return "", auth.ErrNoneToken
}

// GetCookieToken 获取用户令牌
func GetCookieToken(ctx context.Context) (string, error) {
	if c, ok := ctx.(res.Context); ok {
		if auth, err := c.GetRequest().Cookie("authorization"); err == nil && auth != nil && auth.Value != "" {
			return auth.Value, nil
		}
	}
	return "", auth.ErrNoneToken
}
