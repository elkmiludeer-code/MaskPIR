package vm

import (
	"encoding/gob"
	"fmt"
	"os"
	"github.com/water/pir-system/pkg/core"
)

// savePrivateKey 保存私钥到文件
func savePrivateKey(filename string, sk *core.PrivateKey) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(sk)
	if err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}

	return nil
}

// loadPrivateKey 从文件加载私钥
func loadPrivateKey(filename string) (*core.PrivateKey, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("打开私钥文件失败: %v", err)
	}
	defer file.Close()

	var sk core.PrivateKey
	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&sk)
	if err != nil {
		return nil, fmt.Errorf("解码私钥失败: %v", err)
	}

	return &sk, nil
}