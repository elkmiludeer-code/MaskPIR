package core

import (
	"encoding/csv"
	"encoding/gob"
	"fmt"
	mathrand "math/rand"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/water/pir-system/pkg/config"
)

// ==================== 数据库管理 ====================

// DatabaseManager 数据库管理器结构
type DatabaseManager struct {
	DB      Database
	SymKeys SymmetricKeySet
}

// NewDatabaseManager 创建新的数据库管理器
func NewDatabaseManager() *DatabaseManager {
	return &DatabaseManager{}
}

// LoadFromCSV 从CSV文件读取数据库
func (dm *DatabaseManager) LoadFromCSV(filename string) error {
	db, err := loadDatabaseFromCSV(filename)
	if err != nil {
		return err
	}
	dm.DB = db
	return nil
}

// GenerateSymmetricKeys 为数据库生成对称密钥
func (dm *DatabaseManager) GenerateSymmetricKeys() {
	// 设置随机种子
	mathrand.Seed(time.Now().UnixNano())

	// 为每行生成32字节的对称密钥
	symKeys := make([][]byte, len(dm.DB))
	for i := 0; i < len(dm.DB); i++ {
		// 生成完整的32字节密钥（与测试程序保持一致）
		key := make([]byte, 32)
		for j := range key {
			key[j] = byte(mathrand.Intn(128) + 1) // 1-128，与测试程序一致
		}
		symKeys[i] = key
	}
	dm.SymKeys = symKeys
}

// GetDatabase 获取数据库
func (dm *DatabaseManager) GetDatabase() Database {
	return dm.DB
}

// GetSymmetricKeys 获取对称密钥集合
func (dm *DatabaseManager) GetSymmetricKeys() SymmetricKeySet {
	return dm.SymKeys
}

// GetDatabaseSize 获取数据库大小
func (dm *DatabaseManager) GetDatabaseSize() int {
	return len(dm.DB)
}

// SaveEncryptedDatabase 将加密数据库保存到本地文件
func (dm *DatabaseManager) SaveEncryptedDatabase(filename string, pk HomomorphicPublicKey, sk HomomorphicPrivateKey) error {
	// 创建加密数据库管理器
	encDBManager := NewEncryptedDatabaseManager(pk, sk)

	// 加密数据库
	encDBManager.EncryptDatabase(dm.DB, dm.SymKeys)

	// 加密对称密钥
	homomorphicEncKeys, err := encDBManager.EncryptSymmetricKeys(dm.SymKeys)
	if err != nil {
		return fmt.Errorf("对称密钥加密失败: %v", err)
	}

	// 创建要保存的数据结构
	encryptedData := struct {
		EncryptedDB        EncryptedDatabase
		HomomorphicEncKeys [][]byte
		PublicKey          HomomorphicPublicKey
	}{
		EncryptedDB:        encDBManager.GetEncryptedDatabase(),
		HomomorphicEncKeys: homomorphicEncKeys,
		PublicKey:          pk,
	}

	// 保存到文件
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	err = encoder.Encode(encryptedData)
	if err != nil {
		return fmt.Errorf("编码数据失败: %v", err)
	}

	fmt.Printf("成功保存加密数据库到文件: %s\n", filename)
	return nil
}

// SavePreEncryptedDatabase 将已加密好的数据库直接保存到文件（不重复加密）
func SavePreEncryptedDatabase(filename string, encDBManager *EncryptedDatabaseManager, homomorphicEncKeys [][]byte, pk HomomorphicPublicKey) error {
	// 创建要保存的数据结构
	encryptedData := struct {
		EncryptedDB        EncryptedDatabase
		HomomorphicEncKeys [][]byte
		PublicKey          HomomorphicPublicKey
	}{
		EncryptedDB:        encDBManager.GetEncryptedDatabase(),
		HomomorphicEncKeys: homomorphicEncKeys,
		PublicKey:          pk,
	}

	// 保存到文件
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	encoder := gob.NewEncoder(file)
	if err := encoder.Encode(encryptedData); err != nil {
		return fmt.Errorf("编码数据失败: %v", err)
	}

	fmt.Printf("成功保存加密数据库到文件(无重复加密): %s\n", filename)
	return nil
}

// LoadEncryptedDatabase 从本地文件加载加密数据库
func LoadEncryptedDatabase(filename string) (*EncryptedDatabaseManager, [][]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("打开文件失败: %v", err)
	}
	defer file.Close()

	// 解码数据
	var encryptedData struct {
		EncryptedDB        EncryptedDatabase
		HomomorphicEncKeys [][]byte
		PublicKey          HomomorphicPublicKey
	}

	decoder := gob.NewDecoder(file)
	err = decoder.Decode(&encryptedData)
	if err != nil {
		return nil, nil, fmt.Errorf("解码数据失败: %v", err)
	}

	// 创建加密数据库管理器（注意：这里没有私钥，只能用于读取）
	encDBManager := &EncryptedDatabaseManager{
		EncryptedDB: encryptedData.EncryptedDB,
		PK:          encryptedData.PublicKey,
		SK:          nil, // 加载时不包含私钥
	}

	// 加密数据库加载完成
	return encDBManager, encryptedData.HomomorphicEncKeys, nil
}

// SetPrivateKey 为加密数据库管理器设置私钥
func (edm *EncryptedDatabaseManager) SetPrivateKey(sk HomomorphicPrivateKey) {
	edm.SK = sk
}

// ==================== 加密数据库管理 ====================

// EncryptedDatabaseManager 加密数据库管理器
type EncryptedDatabaseManager struct {
	EncryptedDB EncryptedDatabase
	PK          HomomorphicPublicKey
	SK          HomomorphicPrivateKey
}

// NewEncryptedDatabaseManager 创建新的加密数据库管理器
func NewEncryptedDatabaseManager(pk HomomorphicPublicKey, sk HomomorphicPrivateKey) *EncryptedDatabaseManager {
	return &EncryptedDatabaseManager{
		PK: pk,
		SK: sk,
	}
}

// EncryptDatabase 使用对称密钥加密数据库
// EncryptDatabase 使用对称密钥加密数据库 - 并行优化版本
func (edm *EncryptedDatabaseManager) EncryptDatabase(db Database, symKeys SymmetricKeySet) {
	numRows := len(db)
	encryptedDB := EncryptedDatabase{
		Rows: make([]EncryptedRow, numRows),
		Keys: symKeys,
	}

	start := time.Now()
	fmt.Printf("[加密数据库] 开始对称加密，共 %d 行\n", numRows)

	numWorkers := runtime.NumCPU() * 2 // 使用CPU核心数的两倍作为工作协程数
	jobs := make(chan int, numRows)
	results := make(chan struct {
		int
		EncryptedRow
	}, numRows)

	var wg sync.WaitGroup
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				row := db[i]
				keyIndex := i % len(symKeys)
				encryptedData := SymmetricEncrypt(row.Data, symKeys[keyIndex])
				results <- struct {
					int
					EncryptedRow
				}{
					i,
					EncryptedRow{
						EncryptedData: encryptedData,
						KeyIndex:      keyIndex,
					},
				}
			}
		}()
	}

	for i := 0; i < numRows; i++ {
		jobs <- i
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	// 进度输出：每完成约1%打印一次
	processed := 0
	step := numRows / 100
	if step == 0 {
		step = 1
	}
	for res := range results {
		encryptedDB.Rows[res.int] = res.EncryptedRow
		processed++
		if processed%step == 0 || processed == numRows {
			pct := (processed * 100) / numRows
			fmt.Printf("[加密数据库] 进度: %d%% (%d/%d)\n", pct, processed, numRows)
		}
	}

	edm.EncryptedDB = encryptedDB
	fmt.Printf("[加密数据库] 对称加密完成，耗时: %v\n", time.Since(start))
}

// EncryptSymmetricKeys 使用同态加密对对称密钥进行加密 - 使用批量加密优化CPU利用率
func (edm *EncryptedDatabaseManager) EncryptSymmetricKeys(symKeys SymmetricKeySet) ([][]byte, error) {
	if len(symKeys) == 0 {
		return [][]byte{}, nil
	}

	// 将对称密钥转换为字节切片数组
	keyBytes := make([][]byte, len(symKeys))
	for i, key := range symKeys {
		keyBytes[i] = key
	}

	// 使用批量加密以充分利用多核CPU
	homomorphicEncKeys, err := BatchEncrypt(edm.PK, keyBytes)
	if err != nil {
		fmt.Printf("[加密数据库管理器] 批量加密失败: %v\n", err)
		// 如果批量加密失败，回退到串行加密
		var fallbackKeys [][]byte
		for _, key := range symKeys {
			// 对全部32字节密钥进行加密
			// 使用Paillier同态加密对密钥进行加密: E(ki)
			encryptedKey, err := Encrypt(edm.PK, key)
			if err != nil {
				continue
			}
			fallbackKeys = append(fallbackKeys, encryptedKey)
		}
		return fallbackKeys, nil
	}

	fmt.Printf("[加密数据库管理器] 批量加密完成，处理了 %d 个密钥\n", len(homomorphicEncKeys))
	return homomorphicEncKeys, nil
}

// DecryptHomomorphicResults 解密同态运算结果 - 使用批量解密优化CPU利用率
func (edm *EncryptedDatabaseManager) DecryptHomomorphicResults(homomorphicResults [][]byte) [][]byte {
	if len(homomorphicResults) == 0 {
		return [][]byte{}
	}

	// 使用批量解密以充分利用多核CPU
	decryptedResults, err := BatchDecrypt(edm.SK, homomorphicResults)
	if err != nil {
		fmt.Printf("[加密数据库管理器] 批量解密失败: %v\n", err)
		// 如果批量解密失败，回退到串行解密
		var fallbackResults [][]byte
		for _, homomorphicResult := range homomorphicResults {
			decryptedBytes, err := Decrypt(edm.SK, homomorphicResult)
			if err != nil {
				fallbackResults = append(fallbackResults, []byte{})
				continue
			}
			fallbackResults = append(fallbackResults, decryptedBytes)
		}
		return fallbackResults
	}

	fmt.Printf("[加密数据库管理器] 批量解密完成，处理了 %d 个密钥\n", len(decryptedResults))
	return decryptedResults
}

// GetEncryptedDatabase 获取加密数据库
func (edm *EncryptedDatabaseManager) GetEncryptedDatabase() EncryptedDatabase {
	return edm.EncryptedDB
}

// ==================== 辅助函数 ====================

// loadDatabaseFromCSV 从CSV文件读取数据库（内部函数）
func loadDatabaseFromCSV(filename string) (Database, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("无法打开文件 %s: %v", filename, err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("读取CSV文件失败: %v", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV文件数据不足")
	}

	// 获取错误处理配置
	errorConfig := config.GlobalConfig.ErrorHandling
	skippedRows := 0
	var db Database

	// 跳过标题行，从第二行开始读取数据
	for i, record := range records[1:] {
		lineNum := i + 2 // 实际行号（包含标题行）

		// 根据配置确定需要解析的列（1-based，跳过ID列0）
		useCols := config.GlobalConfig.DataColumns.UseColumns
		if len(useCols) == 0 {
			// 如果未配置，默认解析除ID外的所有列
			useCols = make([]int, 0, len(record)-1)
			for idx := 1; idx < len(record); idx++ {
				useCols = append(useCols, idx)
			}
		}
		// 校验列索引是否在当前记录范围内
		maxCol := 0
		for _, c := range useCols {
			if c > maxCol {
				maxCol = c
			}
		}
		if len(record) <= maxCol {
			skippedRows++
			if errorConfig.StrictParsing {
				return nil, fmt.Errorf("第%d行列索引越界：最大索引%d，实际列数%d", lineNum, maxCol, len(record))
			}
			fmt.Printf("警告：第%d行列索引越界，跳过（最大索引%d，实际列数%d）\n", lineNum, maxCol, len(record))
			if skippedRows > errorConfig.MaxSkippedRows {
				return nil, fmt.Errorf("跳过的错误行数过多（%d行），超过最大限制（%d行）", skippedRows, errorConfig.MaxSkippedRows)
			}
			continue
		}

		// 解析ID
		id, err := strconv.Atoi(record[0])
		if err != nil {
			skippedRows++
			if errorConfig.StrictParsing || errorConfig.FailOnParseError {
				return nil, fmt.Errorf("第%d行ID解析失败: %v", lineNum, err)
			}
			fmt.Printf("警告：第%d行ID解析失败，跳过: %v\n", lineNum, err)

			// 检查是否超过最大跳过行数
			if skippedRows > errorConfig.MaxSkippedRows {
				return nil, fmt.Errorf("跳过的错误行数过多（%d行），超过最大限制（%d行）", skippedRows, errorConfig.MaxSkippedRows)
			}
			continue
		}

		// 解析指定数据列
		var data []float64
		parseError := false
		for _, col := range useCols {
			val, err := strconv.ParseFloat(record[col], 64)
			if err != nil {
				skippedRows++
				if errorConfig.StrictParsing || errorConfig.FailOnParseError {
					return nil, fmt.Errorf("第%d行第%d列数据解析失败: %v", lineNum, col, err)
				}
				fmt.Printf("警告：第%d行第%d列数据解析失败，跳过整行: %v\n", lineNum, col, err)
				parseError = true
				break
			}
			data = append(data, val)
		}

		// 如果解析出错，检查跳过行数限制
		if parseError {
			if skippedRows > errorConfig.MaxSkippedRows {
				return nil, fmt.Errorf("跳过的错误行数过多（%d行），超过最大限制（%d行）", skippedRows, errorConfig.MaxSkippedRows)
			}
			continue
		}

		// 成功解析的行添加到数据库
		if len(data) > 0 {
			db = append(db, DatabaseRow{
				ID:   id,
				Data: data,
			})
		}
	}

	// 检查最终结果
	if len(db) == 0 {
		return nil, fmt.Errorf("没有成功解析任何数据行")
	}

	if skippedRows > 0 {
		fmt.Printf("成功从CSV文件加载 %d 条数据记录（跳过 %d 行错误数据）\n", len(db), skippedRows)
	} else {
		fmt.Printf("成功从CSV文件加载 %d 条数据记录\n", len(db))
	}

	return db, nil
}
