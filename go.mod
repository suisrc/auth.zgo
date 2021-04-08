module github.com/suisrc/auth.zgo

go 1.16

// replace (
// 	github.com/suisrc/buntdb.zgo => ../buntdb
// 	github.com/suisrc/config.zgo => ../config
// 	github.com/suisrc/crypto.zgo => ../crypto
// 	github.com/suisrc/logger.zgo => ../logger
// 	github.com/suisrc/res.zgo => ../res
// )

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/stretchr/testify v1.7.0
	github.com/suisrc/buntdb.zgo v0.0.0-20210408054655-2bc515d0fe2f
	github.com/suisrc/crypto.zgo v0.0.0-20210402012846-6389f578a3e2
	github.com/suisrc/logger.zgo v0.0.0-20210408054212-b4e804e2dc15
	github.com/suisrc/res.zgo v0.0.0-20210408020700-20221959252e
)
