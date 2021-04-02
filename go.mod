module github.com/suisrc/auth.zgo

go 1.16

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/stretchr/testify v1.7.0
	github.com/suisrc/buntdb.zgo v0.0.0
	github.com/suisrc/crypto.zgo v0.0.0
	github.com/suisrc/logger.zgo v0.0.0
	github.com/suisrc/res.zgo v0.0.0
)

replace (
	github.com/suisrc/buntdb.zgo v0.0.0 => ../buntdb
	github.com/suisrc/config.zgo v0.0.0 => ../config
	github.com/suisrc/crypto.zgo v0.0.0 => ../crypto
	github.com/suisrc/logger.zgo v0.0.0 => ../logger
	github.com/suisrc/res.zgo v0.0.0 => ../res
)
