package core

import (
	"fmt"
)

// ==================== Go原生 Paillier 实现 ====================

// 使用paillier_go.go中的原生实现，这里只提供兼容性接口

// PerformanceStats 性能统计结构
type PerformanceStats struct {
	EncryptCount        int64   `json:"encrypt_count"`
	DecryptCount        int64   `json:"decrypt_count"`
	BatchEncryptCount   int64   `json:"batch_encrypt_count"`
	BatchDecryptCount   int64   `json:"batch_decrypt_count"`
	HomomorphicAddCount int64   `json:"homomorphic_add_count"`
	CacheHits           int64   `json:"cache_hits"`
	CacheMisses         int64   `json:"cache_misses"`
	HitRatio            float64 `json:"hit_ratio"`
}

var globalStats = &PerformanceStats{}

// GetPerformanceStats 获取性能统计
func (pub *PublicKey) GetPerformanceStats() (cacheHits, cacheMisses int64, hitRatio float64) {
	return globalStats.CacheHits, globalStats.CacheMisses, globalStats.HitRatio
}

// ResetPerformanceStats 重置性能统计
func (pub *PublicKey) ResetPerformanceStats() {
	globalStats = &PerformanceStats{}
}

// GetCacheHitRate 获取缓存命中率
func (pub *PublicKey) GetCacheHitRate() float64 {
	total := globalStats.CacheHits + globalStats.CacheMisses
	if total == 0 {
		return 0.0
	}
	return float64(globalStats.CacheHits) / float64(total)
}

// WarmupCache 预热缓存（Go原生实现不需要缓存预热）
func (pub *PublicKey) WarmupCache(maxExp int64) {
	// Go原生实现不需要缓存预热
	fmt.Printf("Go原生实现不需要缓存预热\n")
}

// RunPerformanceTest 运行性能测试
func RunPerformanceTest(pubKey *PublicKey, privKey *PrivateKey) {
	fmt.Println("开始Go原生Paillier性能测试...")

	// 测试数据
	testData := []byte("Hello, Paillier!")

	// 单次加密测试
	fmt.Println("测试单次加密...")
	cipherText, err := Encrypt(pubKey, testData)
	if err != nil {
		fmt.Printf("加密失败: %v\n", err)
		return
	}
	globalStats.EncryptCount++

	// 单次解密测试
	fmt.Println("测试单次解密...")
	plainText, err := Decrypt(privKey, cipherText)
	if err != nil {
		fmt.Printf("解密失败: %v\n", err)
		return
	}
	globalStats.DecryptCount++

	fmt.Printf("解密结果: %s\n", string(plainText))

	// 批量加密测试
	fmt.Println("测试批量加密...")
	testBatch := [][]byte{
		[]byte("Test1"),
		[]byte("Test2"),
		[]byte("Test3"),
	}

	cipherBatch, err := BatchEncrypt(pubKey, testBatch)
	if err != nil {
		fmt.Printf("批量加密失败: %v\n", err)
		return
	}
	globalStats.BatchEncryptCount++

	// 批量解密测试
	fmt.Println("测试批量解密...")
	plainBatch, err := BatchDecrypt(privKey, cipherBatch)
	if err != nil {
		fmt.Printf("批量解密失败: %v\n", err)
		return
	}
	globalStats.BatchDecryptCount++

	fmt.Printf("批量解密结果: %v\n", plainBatch)

	// 同态加法测试
	fmt.Println("测试同态加法...")
	cipher1, _ := Encrypt(pubKey, []byte{5})
	cipher2, _ := Encrypt(pubKey, []byte{3})
	cipherSum := AddCipher(pubKey, cipher1, cipher2)
	plainSum, _ := Decrypt(privKey, cipherSum)
	globalStats.HomomorphicAddCount++

	fmt.Printf("同态加法结果: %d\n", plainSum[0])

	fmt.Println("Go原生Paillier性能测试完成")
}
