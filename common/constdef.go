package common

const (
	PUNKNOWN = iota
	PSTART
	PMSGID
	PMSGIDEND
	PPKGLEN
	PPKGLENEND
	PCOPYDATA
)

const (
	UNKNOWN_PKGID = iota
	CLIENTAUTH_PKGID
	SERVERAUTHTOKEN_PKGID
	CLIENTAUTHTOKENACK_PKGID
)

const MAX_PKG_LEN = 1024
