package jwt

/*
 为什么使用反向验证(只记录登出的用户, 因为我们确信点击登出的操作比点击登陆的操作要少的多的多)
*/
import (
	"context"
	"errors"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/crypto.zgo"
	"github.com/suisrc/logger.zgo"
	"github.com/suisrc/res.zgo"
)

type options struct {
	tokenType        string                                                                                 // 令牌类型,传递给TokenInfo
	expired          int                                                                                    // 访问令牌间隔
	refresh          int                                                                                    // 刷新令牌间隔
	signingMethod    jwt.SigningMethod                                                                      // 签名方法
	signingSecret    interface{}                                                                            // 公用签名密钥
	signingFunc      func(context.Context, *UserClaims, jwt.SigningMethod, interface{}) (string, error)     // JWT构建令牌
	claimsFunc       func(context.Context, *UserClaims) (refresh int, err error)                            // 处理令牌载体, 对载体的内容进行处理
	keyFunc          func(context.Context, *jwt.Token, jwt.SigningMethod, interface{}) (interface{}, error) // JWT中获取密钥, 该内容可以忽略默认的signingMethod和signingSecret
	parseClaimsFunc  func(context.Context, string) (*UserClaims, error)                                     // 解析令牌
	parseRefreshFunc func(context.Context, string) (*UserClaims, error)                                     // 解析刷新令牌
	tokenFunc        func(context.Context) (string, error)                                                  // 获取令牌
	updateFunc       func(context.Context) error                                                            // 更新Auther
}

// Option 定义参数项
type Option func(*options)

// SetSigningMethod 设定签名方式
func SetSigningMethod(method jwt.SigningMethod) Option {
	return func(o *options) {
		o.signingMethod = method
	}
}

// SetSigningSecret 设定签名方式
func SetSigningSecret(secret string) Option {
	return func(o *options) {
		o.signingSecret = []byte(secret)
	}
}

// SetExpired 设定令牌过期时长(单位秒，默认2小时)
func SetExpired(expired int) Option {
	return func(o *options) {
		o.expired = expired
	}
}

// SetRefresh 设定令牌过期时长(单位秒，默认7天)
func SetRefresh(refresh int) Option {
	return func(o *options) {
		o.refresh = refresh
	}
}

// SetKeyFunc 设定签名key
func SetKeyFunc(f func(context.Context, *jwt.Token, jwt.SigningMethod, interface{}) (interface{}, error)) Option {
	return func(o *options) {
		o.keyFunc = f
	}
}

// SetNewClaims 设定声明内容
func SetNewClaims(f func(context.Context, *UserClaims, jwt.SigningMethod, interface{}) (string, error)) Option {
	return func(o *options) {
		o.signingFunc = f
	}
}

// SetTokenFunc 设定令牌Token
func SetTokenFunc(f func(context.Context) (string, error)) Option {
	return func(o *options) {
		o.tokenFunc = f
	}
}

// SetParseClaimsFunc 设定解析令牌方法
func SetParseClaimsFunc(f func(context.Context, string) (*UserClaims, error)) Option {
	return func(o *options) {
		o.parseClaimsFunc = f
	}
}

// SetParseRefreshFunc 设定解析刷新令牌方法
func SetParseRefreshFunc(f func(context.Context, string) (*UserClaims, error)) Option {
	return func(o *options) {
		o.parseRefreshFunc = f
	}
}

// SetUpdateFunc 设定刷新者
func SetUpdateFunc(f func(context.Context) error) Option {
	return func(o *options) {
		o.updateFunc = f
	}
}

// SetFixClaimsFunc 设定修复载体的方法
func SetFixClaimsFunc(f func(context.Context, *UserClaims) (int, error)) Option {
	return func(o *options) {
		o.claimsFunc = f
	}
}

//===================================================
// 分割线
//===================================================

// New 创建认证实例
func New(store res.Storer, opts ...Option) *Auther {
	a := &Auther{
		store: store,
	}
	o := options{
		tokenType:        "JWT",
		expired:          2 * 3600,
		refresh:          7 * 24 * 3600,
		signingMethod:    jwt.SigningMethodHS512,
		signingFunc:      NewWithClaims,
		keyFunc:          KeyFuncCallback,
		tokenFunc:        GetBearerToken,
		parseClaimsFunc:  a.parseTokenClaims,
		parseRefreshFunc: a.parseRefreshClaims,
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.signingSecret == nil {
		secret := crypto.UUID(32)
		o.signingSecret = []byte(secret) // 默认随机生成
		logger.Infof(nil, "new random signing secret: %s", secret)
	}
	a.opts = &o

	return a
}

// Release 释放资源
func (a *Auther) Release() error {
	return a.callStore(func(store res.Storer) error {
		return store.Close()
	})
}

//===================================================
// 分割线
//===================================================

var _ auth.Auther = &Auther{}

// Auther jwt认证
type Auther struct {
	opts  *options
	store res.Storer
}

// GetUserInfo 获取用户
func (a *Auther) GetUserInfo(c context.Context, tkn string) (auth.UserInfo, error) {
	if tkn == "" {
		var err error // 没有给定令牌， 使用当前用户访问令牌
		if tkn, err = a.opts.tokenFunc(c); err != nil {
			return nil, err
		}
	}
	claims, err := a.opts.parseClaimsFunc(c, tkn)
	if err != nil {
		// var e *jwt.ValidationError
		// if errors.As(err, &e) {
		if erx, b := err.(*jwt.ValidationError); b {
			if erx.Errors&jwt.ValidationErrorExpired > 0 {
				return nil, auth.ErrExpiredToken // 令牌本身过期
			}
			return nil, auth.ErrInvalidToken
		}
		return nil, err
	}

	err = a.callStore(func(store res.Storer) error {
		// 反向验证该用户是否已经登出
		if exists, err := store.Check(c, "token:"+claims.GetTokenID()); err != nil {
			return err
		} else if exists {
			return auth.ErrExpiredToken // 人工标记令牌过期
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// GenerateToken 生成令牌
func (a *Auther) GenerateToken(c context.Context, user auth.UserInfo) (auth.TokenInfo, auth.UserInfo, error) {
	now := time.Now()

	// 访问令牌
	claims := NewUserInfo(user)
	claims.IssuedAt = now.Unix()
	claims.NotBefore = now.Unix()
	claims.ExpiresAt = now.Add(time.Duration(a.opts.expired) * time.Second).Unix()

	refresh := a.opts.refresh
	if a.opts.claimsFunc != nil {
		if rfr, err := a.opts.claimsFunc(c, claims); err != nil {
			return nil, nil, err
		} else if rfr > 0 {
			refresh = rfr
		}
	}

	tokenString, err := a.opts.signingFunc(c, claims, a.opts.signingMethod, a.opts.signingSecret)
	if err != nil {
		return nil, nil, err
	}

	tokenInfo := &TokenInfo{
		//TokenType:  "Bearer",
		TokenID:      claims.Id,
		AccessToken:  tokenString,
		ExpiresAt:    claims.ExpiresAt,
		RefreshToken: NewRefreshToken(claims.Id),
		RefreshExpAt: now.Add(time.Duration(refresh) * time.Second).Unix(),
	}
	return tokenInfo, claims, nil
}

// RefreshToken 刷新令牌
func (a *Auther) RefreshToken(c context.Context, tkn string, chk func(auth.UserInfo, int) error) (auth.TokenInfo, auth.UserInfo, error) {
	if tkn == "" {
		var err error // 没有给定令牌， 使用当前用户访问令牌
		if tkn, err = a.opts.tokenFunc(c); err != nil {
			return nil, nil, err
		}
	}
	claims, err := a.opts.parseRefreshFunc(c, tkn)
	if err != nil {
		var e *jwt.ValidationError
		if errors.As(err, &e) {
			return nil, nil, auth.ErrInvalidToken
		}
		return nil, nil, err
	}
	err = a.callStore(func(store res.Storer) error {
		// 反向验证该用户是否已经登出
		if exists, err := store.Check(c, "token:"+claims.GetTokenID()); err != nil {
			return err
		} else if exists {
			return auth.ErrExpiredToken // 人工标记令牌过期
		}
		return nil
	})
	// 外部自定义验证令牌
	if chk != nil {
		if err := chk(claims, a.opts.refresh); err != nil {
			return nil, nil, err
		}
	}

	// 修正令牌时间
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.NotBefore = now.Unix()
	claims.ExpiresAt = now.Add(time.Duration(a.opts.expired) * time.Second).Unix()

	token, err := a.opts.signingFunc(c, claims, a.opts.signingMethod, a.opts.signingSecret)
	if err != nil {
		return nil, nil, err
	}

	refresh := a.opts.refresh
	if a.opts.claimsFunc != nil {
		if rfr, err := a.opts.claimsFunc(c, claims); err != nil {
			return nil, nil, err
		} else if rfr > 0 {
			refresh = rfr
		}
	}

	tokenInfo := &TokenInfo{
		TokenID:      claims.Id,
		AccessToken:  token,
		ExpiresAt:    claims.ExpiresAt,
		RefreshToken: NewRefreshToken(claims.Id),
		RefreshExpAt: now.Add(time.Duration(refresh) * time.Second).Unix(),
	}
	return tokenInfo, claims, nil
}

// DestroyToken 销毁令牌
func (a *Auther) DestroyToken(c context.Context, user auth.UserInfo) error {
	claims, ok := user.(*UserClaims)
	if !ok {
		return auth.ErrInvalidToken
	}

	// 如果设定了存储，则将未过期的令牌放入
	return a.callStore(func(store res.Storer) error {
		expired := time.Unix(claims.ExpiresAt, 0).Sub(time.Now())
		return store.Set1(c, "token:"+claims.GetTokenID(), expired)
	})
}

// UpdateAuther 更新
func (a *Auther) UpdateAuther(c context.Context) error {
	if a.opts.updateFunc != nil {
		return a.opts.updateFunc(c)
	}
	return nil
}

//===================================================
// 分割线
//===================================================

// 解析令牌
func (a *Auther) parseTokenClaims(c context.Context, tokenString string) (*UserClaims, error) {
	key := func(t *jwt.Token) (interface{}, error) { return a.keyFunc(c, t) }

	claims := &UserClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, key)
	if err != nil {
		return nil, err
	} else if !token.Valid {
		return nil, auth.ErrInvalidToken
	}

	// return token.Claims.(*UserClaims), nil
	return claims, nil
}

// 解析令牌
func (a *Auther) parseRefreshClaims(c context.Context, tokenString string) (*UserClaims, error) {
	key := func(t *jwt.Token) (interface{}, error) { return a.keyFunc(c, t) }

	claims := &UserClaims{}
	parser := jwt.Parser{SkipClaimsValidation: true}
	// 需要忽略自身的验证
	token, err := parser.ParseWithClaims(tokenString, claims, key)
	if err != nil {
		return nil, err
	} else if !token.Valid {
		return nil, auth.ErrInvalidToken
	}

	// return token.Claims.(*UserClaims), nil
	return claims, nil
}

// 获取密钥
func (a *Auther) keyFunc(c context.Context, t *jwt.Token) (interface{}, error) {
	if a.opts.keyFunc == nil {
		return a.opts.signingSecret, nil
	}
	return a.opts.keyFunc(c, t, a.opts.signingMethod, a.opts.signingSecret)
}

// 调用存储方法
func (a *Auther) callStore(fn func(res.Storer) error) error {
	if store := a.store; store != nil {
		return fn(store)
	}
	return nil
}

//===================================================
// 分割线
//===================================================

// KeyFuncCallback 解析方法使用此回调函数来提供验证密钥。
// 该函数接收解析后的内容，但未验证的令牌。这使您可以在令牌的标头（例如 kid），以标识要使用的密钥。
func KeyFuncCallback(c context.Context, token *jwt.Token, method jwt.SigningMethod, secret interface{}) (interface{}, error) {
	//if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	//	return nil, auth.ErrInvalidToken // 无法验证
	//}
	//kid := token.Header["kid"]
	//if kid == "" {
	//	return nil, auth.ErrInvalidToken // 无法验证
	//}
	token.Method = method // 强制使用配置, 防止alg使用none而跳过验证
	return secret, nil
}

// NewWithClaims new claims
// jwt.NewWithClaims
func NewWithClaims(c context.Context, claims *UserClaims, method jwt.SigningMethod, secret interface{}) (string, error) {
	token := &jwt.Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
			// "kid": "zgo123456",
		},
		Claims: claims,
		Method: method,
	}
	return token.SignedString(secret)
}
