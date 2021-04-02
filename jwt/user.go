package jwt

import (
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/suisrc/auth.zgo"
	"github.com/suisrc/crypto.zgo"
)

// NewTokenID new ID
func NewTokenID(_ati string) string {
	var builder strings.Builder
	builder.WriteString(crypto.EncodeBaseX32(time.Now().Unix())) // 7位
	if ati, err := strconv.Atoi(_ati); err != nil {
		builder.WriteString(_ati)
	} else {
		builder.WriteString(crypto.EncodeBaseX32(int64(ati)))
	}
	builder.WriteString(crypto.UUID(21)) // 21位
	return builder.String()
}

// NewRefreshToken new refresh token
func NewRefreshToken(_ati string) string {
	var builder strings.Builder
	builder.WriteString(_ati)
	builder.WriteRune('_')
	builder.WriteString(crypto.UUID(20))                         // 20位
	builder.WriteString(crypto.EncodeBaseX32(time.Now().Unix())) // 7位
	builder.WriteString(crypto.UUID(12))                         // 12位
	return builder.String()
}

// NewUserInfo 获取用户信息
func NewUserInfo(user auth.UserInfo) *UserClaims {
	claims := UserClaims{}

	claims.Id = user.GetTokenID()
	if claims.Id == "" {
		claims.Id = NewTokenID(user.GetAccount())
	}

	claims.Account = user.GetAccount()
	claims.TokenPID = user.GetTokenPID()
	claims.Account1 = user.GetAccount1()
	claims.Account2 = user.GetAccount2()

	claims.Subject = user.GetUserID()
	claims.UserName = user.GetUserName()
	claims.UserRoles = user.GetUserRoles()

	claims.OrgCode = user.GetOrgCode()
	claims.OrgAdmin = user.GetOrgAdmin()
	claims.OrgUsrID = user.GetOrgUsrID()

	claims.Agent = user.GetAgent()
	claims.Scope = user.GetScope()

	claims.Domain = user.GetDomain()
	claims.Issuer = user.GetIssuer()
	claims.Audience = user.GetAudience()

	return &claims
}

var _ auth.UserInfo = &UserClaims{}

// UserClaims 用户信息声明
type UserClaims struct {
	jwt.StandardClaims

	// TokenID -> Id
	// UserID -> Subject -> sub, GetOrgCode为空，提供用户平台ID， 否则提供用户租户ID
	Account   string   `json:"ati,omitempty"` // 登陆ID, 本身不具备任何意义,只是标记登陆方式, 使用token反向加密
	TokenPID  string   `json:"pti,omitempty"` // 子母令牌
	Account1  string   `json:"at1,omitempty"` // 用户登录信息
	Account2  string   `json:"at2,omitempty"` // 用户自定义信息
	UserName  string   `json:"nam,omitempty"` // 用户名
	UserRoles []string `json:"ros,omitempty"` // 角色ID, 该角色是平台角色， 也可以理解为平台给机构的角色
	OrgCode   string   `json:"ogc,omitempty"` // 组织/租户code
	OrgAdmin  string   `json:"oga,omitempty"` // admin'为用户管理员， GetOrgCode为空，提供
	OrgUsrID  string   `json:"ogu,omitempty"` // 用户自定义ID
	Agent     string   `json:"agt,omitempty"` // 登录使用的第三方应用
	Scope     string   `json:"sce,omitempty"` // 权限作用域
	Domain    string   `json:"dom,omitempty"` // 业务域，主要用户当前用户跨应用的业务关联，暂时不使用
	// Issuer -> Issuer
	// Audience -> Audience

	// _TmpRoles []string // `json:"-"`
}

// GetTokenID xxx
func (u *UserClaims) GetTokenID() string {
	return u.Id
}

// GetAccount xxx
func (u *UserClaims) GetAccount() string {
	return u.Account
}

// GetTokenPID xxx
func (u *UserClaims) GetTokenPID() string {
	return u.TokenPID
}

// GetAccount1 xxx
func (u *UserClaims) GetAccount1() string {
	return u.Account1
}

// GetAccount2 xxx
func (u *UserClaims) GetAccount2() string {
	return u.Account2
}

// GetUserID xxx
func (u *UserClaims) GetUserID() string {
	return u.Subject
}

// GetUserName xxx
func (u *UserClaims) GetUserName() string {
	return u.UserName
}

// GetUserRoles xxx
func (u *UserClaims) GetUserRoles() []string {
	return u.UserRoles
}

// GetOrgCode xxx
func (u *UserClaims) GetOrgCode() string {
	return u.OrgCode
}

// GetOrgAdmin xxx
func (u *UserClaims) GetOrgAdmin() string {
	return u.OrgAdmin
}

// GetOrgUsrID xxx
func (u *UserClaims) GetOrgUsrID() string {
	return u.OrgUsrID
}

// GetAgent xxx
func (u *UserClaims) GetAgent() string {
	return u.Agent
}

// GetScope xxx
func (u *UserClaims) GetScope() string {
	return u.Scope
}

// GetDomain xxx
func (u *UserClaims) GetDomain() string {
	return u.Domain
}

// GetIssuer xxx
func (u *UserClaims) GetIssuer() string {
	return u.Issuer
}

// GetAudience xxx
func (u *UserClaims) GetAudience() string {
	return u.Audience
}

// GetUserSvcRoles xxx
func (u *UserClaims) GetUserSvcRoles(svc string) []string {
	roles := []string{}
	for _, role := range u.GetUserRoles() {
		if strings.HasPrefix(role, svc) {
			roles = append(roles, role)
		}
	}
	return roles
}
