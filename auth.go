package auth

import (
	"context"
	"errors"
)

// 定义错误
var (
	// ErrNoneToken 没有令牌
	ErrNoneToken = errors.New("none token")
	// ErrInvalidToken 无效令牌
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken 过期令牌
	ErrExpiredToken = errors.New("expired token")

	// ScopeLogin ...
	ScopeLogin = "snsapi_login"
	// ScopeBase ...
	ScopeBase = "snsapi_base"
	// ScopeUser ...
	ScopeUser = "snsapi_userinfo"
	// ScopePrivate ...
	ScopePrivate = "snsapi_privateinfo"
)

// TokenInfo 令牌信息
type TokenInfo interface {

	// 获取令牌ID
	GetTokenID() string

	// 获取访问令牌
	GetAccessToken() string

	// 获取令牌到期时间戳
	GetExpiresAt() int64

	// 获取刷新令牌
	GetRefreshToken() string

	// 获取刷新令牌过期时间戳
	GetRefreshExpAt() int64

	// JSON
	EncodeToJSON() ([]byte, error)
}

// UserInfo user
type UserInfo interface {
	// GetTokenID 令牌ID, 主要用于验证或者销毁令牌等关于令牌的操作
	GetTokenID() string
	// GetUserAccount 登陆ID, 本身不具备任何意义,只是标记登陆方式, 使用token反向加密
	GetAccount() string
	// GetTokenPID 令牌PID, 字母令牌使用， 一般用于接受第三方登录授权后， 捆绑的第三方登录信息令牌
	GetTokenPID() string
	// GetUserAccount1 用户登录账户信息, account:platform
	GetAccount1() string
	// GetUserAccount2 用户自定义账户信息
	GetAccount2() string

	// GetUserID 用户ID， GetOrgCode不为空(P6M开头的租户除外)，不提供
	GetUserID() string
	// GetUserName 用户名， GetOrgCode不为空(P6M开头的租户除外)，不提供
	GetUserName() string
	// GetUserRoles 角色， GetOrgCode不为空(P6M开头的租户除外)，不提供
	GetUserRoles() []string

	// GetOrgCode
	GetOrgCode() string
	// IsOrgAdmin 'admin'为用户管理员， GetOrgCode为空，提供
	GetOrgAdmin() string
	// GetOrgUsrID 获取用户ID
	GetOrgUsrID() string

	// GetAgent 代理适配器(应用 AppID)
	GetAgent() string
	// GetScope 令牌作用域 snsapi_login snsapi_base snsapi_userinfo
	GetScope() string
	// GetDomain 领域标识
	GetDomain() string
	// GetIssuer 令牌签发者
	GetIssuer() string
	// GetAudience 令牌接收者
	GetAudience() string

	// 通过服务名称获取当前服务的角色
	GetUserSvcRoles(string) []string
}

// Auther 认证接口
type Auther interface {
	// GetUserInfo 获取用户
	GetUserInfo(c context.Context, t string) (UserInfo, error)

	// GenerateToken 生成令牌
	GenerateToken(c context.Context, u UserInfo) (TokenInfo, UserInfo, error)

	// RefreshToken 刷新令牌
	RefreshToken(c context.Context, t string, f func(UserInfo, int) error) (TokenInfo, UserInfo, error)

	// DestroyToken 销毁令牌
	DestroyToken(c context.Context, u UserInfo) error

	// UpdateAuther 更新
	UpdateAuther(c context.Context) error
}
