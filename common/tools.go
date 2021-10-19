package common

import (
	"bytes"
	"encoding/binary"
)

func Int2Byte(n int) []byte {
	x := uint16(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()
}

func Byte2Int(data []byte) int {
	bytesBuffer := bytes.NewBuffer(data)
	var x uint16
	binary.Read(bytesBuffer, binary.BigEndian, &x)
	return int(x)
}
