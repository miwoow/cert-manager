package main

import "errors"

type StreamParseStateMachine struct {
	RemainCache    [1024]byte
	RemainCacheLen int
	ParseStatus    int
	TmpPkg         CMPkg
	PkgDataPos     int
}

func (s *StreamParseStateMachine) ParseData(data []byte) error {
	var longCache []byte
	var tmp [2]byte

	if s.RemainCacheLen > 0 {
		longCache = append(longCache, s.RemainCache[:s.RemainCacheLen]...)
		longCache = append(longCache, data...)
		s.RemainCacheLen = 0
	}

	if len(longCache) > MAX_PKG_LEN {
		return errors.New("pkg too long")
	}

	pos := 0
	for {
		if pos > len(longCache) {
			break
		}
		switch s.ParseStatus {
		case PSTART:
			if len(longCache)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longCache[pos]
			pos++
			s.ParseStatus = PPKGLEN
		case PPKGLEN:
			tmp[1] = longCache[pos]
			pos++
			s.TmpPkg.PkgLen = Byte2Int(tmp[:])
			s.ParseStatus = PPKGLENEND
		case PPKGLENEND:
			if len(longCache)-pos < 2 {
				goto PARSEEND
			}
			tmp[0] = longCache[pos]
			pos++
			s.ParseStatus = PMSGID
		case PMSGID:
			tmp[1] = longCache[pos]
			pos++
			s.TmpPkg.PkgId = Byte2Int(tmp[:])
			s.ParseStatus = PMSGIDEND
		case PMSGIDEND:
			s.PkgDataPos = 0
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			s.ParseStatus = PCOPYDATA
		case PCOPYDATA:
			s.TmpPkg.PkgData = append(s.TmpPkg.PkgData, longCache[pos])
			pos++
			s.PkgDataPos++
			if s.PkgDataPos == int(s.TmpPkg.PkgLen)-2 {
				// parse data.
				// parsePkgAndResponse()
				s.ParseStatus = PSTART
			}
		}
	}
PARSEEND:
	if pos < len(longCache) {
		copy(s.RemainCache[:], longCache[pos:])
		s.RemainCacheLen = len(longCache) - pos
	}
	return nil
}
