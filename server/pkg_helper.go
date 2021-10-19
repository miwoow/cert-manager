package main

import (
	"errors"
	"fmt"
)

type CMPkg struct {
	PkgId   int
	PkgLen  int
	PkgData []byte
	// PkgDataPos int
}

func PackPkg(pkgId int, data []byte) []byte {
	var pkg []byte
	pkg = append(pkg, Int2Byte(len(data)+2)...)
	pkg = append(pkg, Int2Byte(pkgId)...)
	pkg = append(pkg, data...)
	return pkg
}

func CMPkgLoadFromBuf(buf []byte) (*CMPkg, error) {
	if len(buf) < 4 {
		return nil, errors.New("[ERROR] Buf is too short for pkg len and pkg id")
	}
	if len(buf) > MAX_PKG_LEN {
		return nil, errors.New("[ERROR] Buf is too long for pkg")
	}
	var pkg *CMPkg = &CMPkg{}
	var tmp [2]byte

	tmp[0] = buf[0]
	tmp[1] = buf[1]
	pkg.PkgLen = Byte2Int(tmp[:])
	tmp[0] = buf[2]
	tmp[1] = buf[3]
	pkg.PkgId = Byte2Int(tmp[:])
	pkg.PkgData = make([]byte, pkg.PkgLen-2)
	n := copy(pkg.PkgData, buf[4:])
	fmt.Println("Copyed bytes from buf to pkg: ", n)
	return pkg, nil
}
