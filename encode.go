package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"time"
)

//func unpadding(src []byte) []byte {
//	n := len(src)
//	unpadnum := int(src[n-1])
//	return src[:n-unpadnum]
//}

//加密
func encode() {
	data, _ := os.ReadFile(os.Args[2])
	data2 := string(data)
	encodedata := base64.StdEncoding.EncodeToString([]byte(data2))
	rand.Seed(time.Now().Unix())
	passwd := key()
	ASE_str := Get_Aes_encry(encodedata, passwd)
	result := base64.StdEncoding.EncodeToString([]byte(passwd + ASE_str))
	err := out("./shellcode.txt", result, "w")
	if err != nil {
		return
	}
	fmt.Println(result)
}

func unpadding(src []byte) []byte {
	n := len(src)
	unpadnum := int(src[n-1])
	return src[:n-unpadnum]
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

//生成key
func key() string {
	var key string
	rand.Seed(time.Now().Unix())
	//加上这个每次生成key不同
	for i := 0; i < 16; i++ {
		key += strconv.Itoa(rand.Intn(9) + 1)
		//key每次值不同
	}
	return key
}

func padding(src []byte, blocksize int) []byte {
	padnum := blocksize - len(src)%blocksize
	pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
	return append(src, pad...)
}
func encryptAES(src []byte, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	src = padding(src, block.BlockSize())
	blockmode := cipher.NewCBCEncrypter(block, key)
	blockmode.CryptBlocks(src, src)
	return src
}

func Get_Aes_encry(str string, keys string) string {
	x := []byte(str)
	key := []byte(keys)
	x1 := encryptAES(x, key)
	return string(x1)
}

func out(fileName string, nr string, fangshi string) error {
	var f *os.File
	var err error
	if fangshi == "w" {
		f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	} else if fangshi == "a" {
		f, err = os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0644)
	} else {
		return errors.New("error a/w")
	}
	if err != nil {
		fmt.Println("file create failed. err: " + err.Error())
	} else {
		n, _ := f.Seek(0, os.SEEK_END)
		_, err = f.WriteAt([]byte(nr), n)
		defer f.Close()
	}
	return nil
}

func main() {
	if os.Args[1] == "-e" {
		encode()
	}
}
