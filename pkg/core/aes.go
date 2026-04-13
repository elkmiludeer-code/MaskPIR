package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"unsafe"
)

// func main() {
// 	origData := []byte("Hello World")                 // 待加密的数据
// 	key := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456") // 32字节密钥用于AES-256
// 	log.Println("原文：", string(origData))

// 	log.Println("------------------ GCM模式 --------------------")
// 	encrypted := AesEncryptGCM(origData, key)
// 	log.Println("密文(hex)：", hex.EncodeToString(encrypted))
// 	log.Println("密文(base64)：", base64.StdEncoding.EncodeToString(encrypted))
// 	decrypted := AesDecryptGCM(encrypted, key)
// 	log.Println("解密结果：", string(decrypted))
// }

// =================== GCM ======================
// AesEncryptGCM 使用AES-GCM模式加密数据
// GCM模式提供认证加密，同时保证数据的机密性和完整性
func AesEncryptGCM(origData []byte, key []byte) (encrypted []byte) {
	// 创建AES密码块
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	// 生成随机nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}

	// 加密数据
	ciphertext := gcm.Seal(nil, nonce, origData, nil)

	// 将nonce和密文组合返回
	encrypted = append(nonce, ciphertext...)
	return encrypted
}

// AesDecryptGCM 使用AES-GCM模式解密数据
func AesDecryptGCM(encrypted []byte, key []byte) (decrypted []byte) {
	// 创建AES密码块
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Printf("AES密码块创建失败: %v\n", err)
		return nil
	}

	// 创建GCM模式
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Printf("GCM模式创建失败: %v\n", err)
		return nil
	}

	// 检查数据长度
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		fmt.Printf("密文太短: 需要至少%d字节，实际%d字节\n", nonceSize, len(encrypted))
		return nil
	}

	// 分离nonce和密文
	nonce := encrypted[:nonceSize]
	ciphertext := encrypted[nonceSize:]

	// 解密数据
	decrypted, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		fmt.Printf("GCM解密失败: %v\n", err)
		return nil
	}

	return decrypted
}

// SymmetricEncrypt 为server.go提供的对称加密接口
// 将float64数组加密为字节数组，使用Go原生AES实现
func SymmetricEncrypt(data []float64, key []byte) []byte {
	// 将float64数组转换为字节数组
	byteData := make([]byte, len(data)*8) // 每个float64占8字节
	for i, f := range data {
		bits := *(*uint64)(unsafe.Pointer(&f))
		for j := 0; j < 8; j++ {
			byteData[i*8+j] = byte(bits >> (j * 8))
		}
	}
	
	// 使用Go原生AES-GCM加密
	return AesEncryptGCM(byteData, key)
}

// SymmetricDecrypt 为client.go提供的对称解密接口
// 将字节数组解密为float64数组，使用Go原生AES实现
func SymmetricDecrypt(encrypted []byte, key []byte) []float64 {
	// 使用Go原生AES-GCM解密
	decrypted := AesDecryptGCM(encrypted, key)
	if decrypted == nil {
		return nil
	}
	
	// 将字节数组转换为float64数组
	if len(decrypted)%8 != 0 {
		fmt.Printf("解密数据长度不是8的倍数: %d\n", len(decrypted))
		return nil
	}
	
	result := make([]float64, len(decrypted)/8)
	for i := 0; i < len(result); i++ {
		var bits uint64
		for j := 0; j < 8; j++ {
			bits |= uint64(decrypted[i*8+j]) << (j * 8)
		}
		result[i] = *(*float64)(unsafe.Pointer(&bits))
	}
	
	return result
}
