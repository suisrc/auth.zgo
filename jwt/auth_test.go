package jwt_test

import (
	"context"
	"log"
	"testing"

	"github.com/suisrc/auth.zgo/jwt"
	"github.com/suisrc/buntdb.zgo"
	"github.com/suisrc/logger.zgo"

	"github.com/stretchr/testify/assert"
)

func TestRefreshToken(t *testing.T) {
	store, err := buntdb.NewStore(":memory:")
	assert.Nil(t, err)

	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJkZWYuY29tIiwiZXhwIjoxNTk5NTU0ODk0LCJqdGkiOiJfa3hpcHJ3djZ1eGYzaHVyemxuM3E0MjBxdjFmbGVoYTkiLCJpYXQiOjE1OTk1NTQ4ODksImlzcyI6ImFiYy5jb20iLCJuYmYiOjE1OTk1NTQ4ODksInN1YiI6IjEyMyIsIm5hbSI6Ikpzb24iLCJyb2wiOiI3ODkifQ.085VKYbb7yV5cOQZoIYMhvXyY7gChE6A_w_PoOZnVTQtzkeEnRjU_vSDazkhyZPbA3opOd9wZrpI_pRzbPw2yA"
	// secret := "zgo_c1wcx9vp97pd4iesw68o3byh71fleha9"

	// jwtAuth := jwt.New(store, jwt.Option(func(o *jwt.options) {
	// 	o.signingSecret = []byte(secret)
	// }))
	jwtAuth := jwt.New(store)
	defer jwtAuth.Release()
	ctx := context.Background()

	r, u, err := jwtAuth.RefreshToken(ctx, token, nil)
	log.Println(r)
	log.Println(u)

	assert.Nil(t, err)
	assert.NotNil(t, nil)
}

func TestAuth(t *testing.T) {
	store, err := buntdb.NewStore(":memory:")
	assert.Nil(t, err)
	// var store Storer

	var ref TokenRef

	//jwtAuth := jwt.New(store, jwt.Option(func(o *options) {
	//	o.tokenFunc = func(ctx context.Context) (string, error) {
	//		return ref.ref, nil
	//	}
	//	o.expired = 5
	//}))

	jwtAuth := jwt.New(store)
	defer jwtAuth.Release()

	ctx := context.Background()

	user := &UserInfo{
		UserName: "Json",
		UserID:   "123",
	}

	token, _, err := jwtAuth.GenerateToken(ctx, user)
	assert.Nil(t, err)
	assert.NotNil(t, token)

	data, err := token.EncodeToJSON()
	logger.Infof(ctx, "%s", string(data))

	ref.ref = token.GetAccessToken()
	uInfo, err := jwtAuth.GetUserInfo(ctx, "")
	assert.Nil(t, err)
	assert.Equal(t, user.UserID, uInfo.GetUserID())

	err = jwtAuth.DestroyToken(ctx, uInfo)
	assert.Nil(t, err)

	uInfo, err = jwtAuth.GetUserInfo(ctx, "")
	assert.NotNil(t, err)
	assert.EqualError(t, err, "invalid token")
	//assert.Empty(t, id)
	assert.NotNil(t, nil)
}

type TokenRef struct {
	ref string
}

// UserInfo 用户信息声明
type UserInfo struct {
	UserID   string
	TokenID  string
	UserName string
}

// GetTokenID xxx
func (u *UserInfo) GetTokenID() string {
	return u.TokenID
}

// GetAccount xxx
func (u *UserInfo) GetAccount() string {
	return ""
}

// GetTokenPID xxx
func (u *UserInfo) GetTokenPID() string {
	return ""
}

// GetAccount1 xxx
func (u *UserInfo) GetAccount1() string {
	return ""
}

// GetAccount2 xxx
func (u *UserInfo) GetAccount2() string {
	return ""
}

// GetAgent xxx
func (u *UserInfo) GetAgent() string {
	return ""
}

// GetScope xxx
func (u *UserInfo) GetScope() string {
	return ""
}

// GetDomain xxx
func (u *UserInfo) GetDomain() string {
	return ""
}

// GetIssuer xxx
func (u *UserInfo) GetIssuer() string {
	return ""
}

// GetAudience xxx
func (u *UserInfo) GetAudience() string {
	return ""
}

// GetUserID xxx
func (u *UserInfo) GetUserID() string {
	return ""
}

// GetUserName xxx
func (u *UserInfo) GetUserName() string {
	return ""
}

// GetUserRoles xxx
func (u *UserInfo) GetUserRoles() []string {
	return nil
}

// GetOrgCode xxx
func (u *UserInfo) GetOrgCode() string {
	return ""
}

// GetOrgAdmin xxx
func (u *UserInfo) GetOrgAdmin() string {
	return ""
}

// GetOrgUsrID xxx
func (u *UserInfo) GetOrgUsrID() string {
	return ""
}

// GetUserSvcRoles xxx
func (u *UserInfo) GetUserSvcRoles(svc string) []string {
	return nil
}
