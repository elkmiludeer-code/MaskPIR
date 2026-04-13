package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/csv"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/water/pir-system/pkg/config"
	"github.com/water/pir-system/pkg/core"
	"github.com/water/pir-system/pkg/vm"
)

func init() {
	gob.Register(&core.PublicKey{})
	gob.Register(&core.PrivateKey{})
}

// calcSize 计算对象的GOB编码大小（字节）
func calcSize(v interface{}) int64 {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(v); err != nil {
		fmt.Printf("⚠️ 计算大小时编码失败: %v\n", err)
		return 0
	}
	return int64(buf.Len())
}

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

// 私钥管理
func generateOrLoadKeyPair(publicKeyFile, privateKeyFile string) (*core.PublicKey, *core.PrivateKey, error) {
	// 尝试加载现有密钥对
	if _, err := os.Stat(privateKeyFile); err == nil {
		fmt.Println("加载现有密钥对...")
		sk, err := loadPrivateKey(privateKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("加载私钥失败: %v", err)
		}

		// 从私钥生成公钥
		pk := &core.PublicKey{
			N:        sk.N,
			G:        sk.G,
			NSquared: sk.NSquared,
		}

		fmt.Println("密钥对加载成功")
		return pk, sk, nil
	}

	// 生成新的密钥对
	fmt.Println("生成新的密钥对...")
	sk, err := core.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("生成密钥对失败: %v", err)
	}
	pk := &sk.PublicKey

	// 保存私钥
	err = savePrivateKey(privateKeyFile, sk)
	if err != nil {
		return nil, nil, fmt.Errorf("保存私钥失败: %v", err)
	}

	fmt.Println("密钥对生成并保存成功")
	return pk, sk, nil
}

// PIRClient 客户端结构体
type PIRClient struct {
	Predicate   []float64 // 谓词ρ
	Operators   []string  // 比较操作符
	RowIndices  []int     // 选中的行号j
	PK          core.HomomorphicPublicKey
	SK          core.HomomorphicPrivateKey
	randomMasks [][]byte // 保存随机掩码R用于密钥恢复
}

type PIRServer struct {
	Database        core.Database // 数据库D
	EncryptedDB     []core.EncryptedRow
	SymmetricKeys   [][]byte // 对称密钥ki
	PK              core.HomomorphicPublicKey
	SK              core.HomomorphicPrivateKey
	EncDBManager    *core.EncryptedDatabaseManager
	selectedRows    []int    // SC协议选中的行
	selectedEncKeys [][]byte // 选中行对应的加密密钥
}

// BenchMetrics 用于持久化bench模式的指标
type BenchMetrics struct {
	Timestamp            string    `json:"timestamp"`
	GoOS                 string    `json:"go_os"`
	GoArch               string    `json:"go_arch"`
	NumCPU               int       `json:"num_cpu"`
	DatasetRows          int       `json:"dataset_rows"`
	SelectedRows         int       `json:"selected_rows"`
	BatchSize            int       `json:"batch_size"`
	UseColumns           []int     `json:"use_columns"`
	Predicate            []float64 `json:"predicate"`
	Operators            []string  `json:"operators"`
	S3RMillis            int64     `json:"s3r_ms"`
	PIRSetupMillis       int64     `json:"pir_setup_ms"`
	ClientQueryGenMillis int64     `json:"client_query_gen_ms"`
	ServerDecryptMillis  int64     `json:"server_batch_decrypt_ms"`
	ClientProcessMillis  int64     `json:"client_process_ms"`
	TotalMillis          int64     `json:"total_ms"`
	// Storage Overhead
	StorageOriginalMB  float64 `json:"storage_original_mb"`
	StorageEncryptedMB float64 `json:"storage_encrypted_mb"`
	// Communication Overhead
	CommS3RRequestMB  float64 `json:"comm_s3r_request_mb"`
	CommS3RResponseMB float64 `json:"comm_s3r_response_mb"`
	CommPIRSetupMB    float64 `json:"comm_pir_setup_mb"`
	CommPIRQueryMB    float64 `json:"comm_pir_query_mb"`
	CommPIRResponseMB float64 `json:"comm_pir_response_mb"`
	TotalCommMB       float64 `json:"total_comm_mb"`
}

func saveBenchMetricsJSONCSV(metrics BenchMetrics) {
	// 确保结果目录存在
	outDir := "storage/results"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Printf("写入bench结果失败（创建目录）: %v\n", err)
		return
	}

	// JSON
	jsonPath := filepath.Join(outDir, "bench_summary.json")
	data, err := json.MarshalIndent(metrics, "", "  ")
	if err == nil {
		_ = os.WriteFile(jsonPath, data, 0644)
		fmt.Printf("[bench] 指标已写入: %s\n", jsonPath)
	} else {
		fmt.Printf("序列化bench JSON失败: %v\n", err)
	}

	// CSV（单行汇总，便于表格导入）
	csvPath := filepath.Join(outDir, "bench_summary.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		fmt.Printf("写入bench CSV失败: %v\n", err)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{
		"timestamp", "dataset_rows", "selected_rows", "batch_size",
		"s3r_ms", "pir_setup_ms", "client_query_gen_ms", "server_batch_decrypt_ms", "client_process_ms", "total_ms",
		"storage_original_mb", "storage_encrypted_mb",
		"comm_s3r_req_mb", "comm_s3r_resp_mb", "comm_pir_setup_mb", "comm_pir_query_mb", "comm_pir_resp_mb", "total_comm_mb",
	})
	_ = w.Write([]string{
		metrics.Timestamp,
		fmt.Sprintf("%d", metrics.DatasetRows),
		fmt.Sprintf("%d", metrics.SelectedRows),
		fmt.Sprintf("%d", metrics.BatchSize),
		fmt.Sprintf("%d", metrics.S3RMillis),
		fmt.Sprintf("%d", metrics.PIRSetupMillis),
		fmt.Sprintf("%d", metrics.ClientQueryGenMillis),
		fmt.Sprintf("%d", metrics.ServerDecryptMillis),
		fmt.Sprintf("%d", metrics.ClientProcessMillis),
		fmt.Sprintf("%d", metrics.TotalMillis),
		fmt.Sprintf("%.4f", metrics.StorageOriginalMB),
		fmt.Sprintf("%.4f", metrics.StorageEncryptedMB),
		fmt.Sprintf("%.4f", metrics.CommS3RRequestMB),
		fmt.Sprintf("%.4f", metrics.CommS3RResponseMB),
		fmt.Sprintf("%.4f", metrics.CommPIRSetupMB),
		fmt.Sprintf("%.4f", metrics.CommPIRQueryMB),
		fmt.Sprintf("%.4f", metrics.CommPIRResponseMB),
		fmt.Sprintf("%.4f", metrics.TotalCommMB),
	})
	w.Flush()
	fmt.Printf("[bench] 指标已写入: %s\n", csvPath)
}

// executeLocalS3R 执行本地S3R协议
func (server *PIRServer) executeLocalS3R(predicate []float64, operators []string) core.SCResult {
	// 构建谓词值字符串
	predicateStrs := make([]string, len(predicate))
	for i, val := range predicate {
		predicateStrs[i] = fmt.Sprintf("%.6f", val)
	}
	predicateValues := strings.Join(predicateStrs, ",")

	// 规范化操作符：长度不匹配或非法值一律替换为 ">="
	normalizedOps := make([]string, len(predicate))
	for i := range normalizedOps {
		op := ">="
		if i < len(operators) {
			o := strings.TrimSpace(operators[i])
			if o == ">" || o == "<" || o == ">=" || o == "<=" || o == "==" {
				op = o
			}
		}
		normalizedOps[i] = op
	}
	operatorStr := strings.Join(normalizedOps, ",")

	// 获取配置中的列索引
	useColumns := config.GlobalConfig.GetUseColumnsString()

	// 构建S3R命令
	resultFile := "storage/results/sc_result_local.csv"

	// 确保结果目录存在
	resultDir := filepath.Dir(resultFile)
	if err := os.MkdirAll(resultDir, 0755); err != nil {
		fmt.Printf("⚠️ 创建结果目录失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	// 直接使用参数分离的方式执行命令，避免引号问题
	cmd := exec.Command("python", "scripts/s3r.py",
		"--features_csv", "storage/databases/database.csv",
		"--usecols", useColumns,
		"--predicate_values", predicateValues,
		"--predicate_ops", operatorStr,
		"--out", resultFile,
		"--dtype", "float64")

	_, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("⚠️ S3R执行失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	// 解析结果文件
	selectedRows, err := server.parseS3RResult(resultFile)
	if err != nil {
		fmt.Printf("⚠️ 解析S3R结果失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	return core.SCResult{SelectedRows: selectedRows}
}

// parseS3RResult 解析S3R结果文件
func (server *PIRServer) parseS3RResult(resultFile string) ([]int, error) {
	file, err := os.Open(resultFile)
	if err != nil {
		return nil, fmt.Errorf("打开结果文件失败: %v", err)
	}
	defer file.Close()

	var selectedRows []int
	scanner := bufio.NewScanner(file)
	rowIndex := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "1" {
			selectedRows = append(selectedRows, rowIndex)
		}
		rowIndex++
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取结果文件失败: %v", err)
	}

	return selectedRows, nil
}

func (server *PIRServer) handleSCRequest(request core.SCRequest) core.SCResponse {
	fmt.Printf("[服务器] 处理SC请求，谓词: %v, 操作符: %v\n", request.Predicate, request.Operators)

	// 执行真实的S3R协议
	result := server.executeLocalS3R(request.Predicate, request.Operators)
	server.selectedRows = result.SelectedRows

	return core.SCResponse{
		SelectedRows: result.SelectedRows,
	}
}

// saveDecryptedDataToCSV 保存解密数据到CSV文件
func saveDecryptedDataToCSV(data [][]float64, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	header := []string{"Data1", "Data2", "Data3"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// 写入数据行
	for _, row := range data {
		record := make([]string, len(row))
		for i, val := range row {
			record[i] = strconv.FormatFloat(val, 'f', 6, 64)
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// verifyDecryptedData 验证解密数据与原始数据的一致性
func verifyDecryptedData(decryptedData [][]float64, selectedRows []int) {
	// 加载原始数据库
	originalDB, err := loadOriginalDatabase("storage/databases/database.csv")
	if err != nil {
		fmt.Printf("✗ 加载原始数据库失败: %v\n", err)
		return
	}

	// 验证每一行数据 - 修复：第i个解密结果对应selectedRows[i]行的原始数据
	matchCount := 0
	for i, decryptedRow := range decryptedData {
		if i < len(selectedRows) {
			originalRowIndex := selectedRows[i]
			if originalRowIndex < len(originalDB) {
				originalRow := originalDB[originalRowIndex].Data
				if compareFloatArrays(decryptedRow, originalRow, 1e-6) {
					matchCount++
				}
			}
		}
	}

	fmt.Printf("验证结果: %d/%d 行数据匹配\n", matchCount, len(decryptedData))
	if matchCount == len(decryptedData) {
		fmt.Printf("✅ 所有数据验证通过，PIR协议执行成功！\n")
	} else {
		fmt.Printf("❌ 部分数据验证失败，请检查协议实现\n")
	}
}

// loadOriginalDatabase 加载原始数据库
func loadOriginalDatabase(filename string) (core.Database, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var database core.Database
	for i, record := range records {
		if i == 0 { // 跳过头部
			continue
		}

		// 尝试解析ID列，否则使用行号
		id := i - 1
		if len(record) > 0 {
			if parsedID, err := strconv.Atoi(record[0]); err == nil {
				id = parsedID
			}
		}

		// 根据配置选择列（1-based，跳过ID列0）
		useCols := config.GlobalConfig.DataColumns.UseColumns
		if len(useCols) == 0 {
			useCols = make([]int, 0, len(record)-1)
			for idx := 1; idx < len(record); idx++ {
				useCols = append(useCols, idx)
			}
		}

		var data []float64
		for _, col := range useCols {
			if col >= len(record) { // 越界保护
				continue
			}
			val, err := strconv.ParseFloat(record[col], 64)
			if err != nil {
				return nil, err
			}
			data = append(data, val)
		}

		database = append(database, core.DatabaseRow{ID: id, Data: data})
	}

	return database, nil
}

// compareFloatArrays 比较两个浮点数数组是否相等（在给定精度内）
func compareFloatArrays(a, b []float64, tolerance float64) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if math.Abs(a[i]-b[i]) > tolerance {
			return false
		}
	}

	return true
}

// preparePIRSetup 准备PIR设置
func (server *PIRServer) preparePIRSetup() core.PIRSetup {
	var encDBManager *core.EncryptedDatabaseManager
	var homomorphicEncKeys [][]byte

	// 检查是否已有加密数据库
	if _, err := os.Stat("storage/databases/encrypted_database.gob"); os.IsNotExist(err) {
		// 使用服务器已加载的密钥对
		if server.PK == nil || server.SK == nil {
			fmt.Printf("⚠️ 服务器密钥未初始化，无法创建加密数据库\n")
			return core.PIRSetup{}
		}

		// 创建数据库管理器并加载原始数据库
		dbManager := core.NewDatabaseManager()
		err = dbManager.LoadFromCSV("storage/databases/database.csv")
		if err != nil {
			fmt.Printf("⚠️ 加载数据库失败: %v\n", err)
			return core.PIRSetup{}
		}

		// 生成对称密钥
		dbManager.GenerateSymmetricKeys()

		// 创建加密数据库管理器并加密数据库与密钥
		encDBManager = core.NewEncryptedDatabaseManager(server.PK, server.SK)
		encDBManager.EncryptDatabase(dbManager.GetDatabase(), dbManager.GetSymmetricKeys())
		homomorphicEncKeys, err = encDBManager.EncryptSymmetricKeys(dbManager.GetSymmetricKeys())
		if err != nil {
			fmt.Printf("⚠️ 加密对称密钥失败: %v\n", err)
			return core.PIRSetup{}
		}

		// 保存加密数据库（不重复加密，直接持久化已加密结果）
		err = core.SavePreEncryptedDatabase("storage/databases/encrypted_database.gob", encDBManager, homomorphicEncKeys, server.PK)
		if err != nil {
			fmt.Printf("⚠️ 保存加密数据库失败: %v\n", err)
			return core.PIRSetup{}
		}

		// 保持服务器当前密钥
		server.EncDBManager = encDBManager
	} else {
		// 如果已有加密数据库，直接加载
		var err error
		encDBManager, homomorphicEncKeys, err = core.LoadEncryptedDatabase("storage/databases/encrypted_database.gob")
		if err != nil {
			fmt.Printf("⚠️ 加载加密数据库失败: %v\n", err)
			return core.PIRSetup{}
		}

		// 重要：LoadEncryptedDatabase不包含私钥，需要保持原有的私钥
		encDBManager.PK = server.PK
		encDBManager.SK = server.SK
		server.EncDBManager = encDBManager
	}

	// 获取完整的加密数据库
	fullEncryptedDB := encDBManager.GetEncryptedDatabase()

	// 只选择匹配行的加密数据和密钥
	selectedEncryptedRows := make([]core.EncryptedRow, 0, len(server.selectedRows))
	selectedEncryptedKeys := make([][]byte, 0, len(server.selectedRows))

	for _, rowIdx := range server.selectedRows {
		if rowIdx < len(fullEncryptedDB.Rows) {
			selectedEncryptedRows = append(selectedEncryptedRows, fullEncryptedDB.Rows[rowIdx])
		}
		if rowIdx < len(homomorphicEncKeys) {
			selectedEncryptedKeys = append(selectedEncryptedKeys, homomorphicEncKeys[rowIdx])
		}
	}

	// 创建只包含选中行的加密数据库
	selectedEncryptedDB := core.EncryptedDatabase{
		Rows: selectedEncryptedRows,
		Keys: fullEncryptedDB.Keys, // 保持完整的密钥集合用于索引
	}

	return core.PIRSetup{
		PublicKey:          server.PK,
		EncryptedDB:        selectedEncryptedDB,
		SelectedIndices:    server.selectedRows,
		HomomorphicEncKeys: selectedEncryptedKeys,
	}
}

// handlePIRQuery 处理PIR查询 - 执行真实的PIR协议
func (server *PIRServer) handlePIRQuery(query core.PIRQuery) core.PIRResponse {
	// 执行真实的PIR协议
	// 1. 使用同态运算结果对选中的加密数据进行处理
	// 2. 返回解密的查询结果

	if len(server.selectedRows) == 0 {
		return core.PIRResponse{DecryptedResults: [][]byte{}}
	}

	// 使用私钥批量解密同态运算结果（并行优化）
	decryptedResults, err := core.BatchDecrypt(server.SK, query.HomomorphicResults)
	if err != nil {
		// 发生错误时回退到串行解密，保证稳健性
		decryptedResults = make([][]byte, len(query.HomomorphicResults))
		for i, homomorphicResult := range query.HomomorphicResults {
			dec, derr := core.Decrypt(server.SK, homomorphicResult)
			if derr != nil {
				continue
			}
			decryptedResults[i] = dec
		}
	}

	return core.PIRResponse{
		DecryptedResults: decryptedResults,
	}
}

func runServer() {
	fmt.Println("=== 启动PIR服务器 ===")

	// 加载配置
	err := config.LoadConfig("configs/config.json")
	if err != nil {
		fmt.Printf("加载配置失败: %v\n", err)
		return
	}
	fmt.Println("配置加载成功")

	// 生成或加载密钥对
	pk, sk, err := generateOrLoadKeyPair("storage/keys/public_key.json", "storage/keys/private_key.gob")
	if err != nil {
		fmt.Printf("密钥对生成/加载失败: %v\n", err)
		return
	}
	fmt.Printf("[服务器] 密钥对加载成功，私钥非空: %t\n", sk != nil)

	// 加载数据库
	dbManager := core.NewDatabaseManager()
	err = dbManager.LoadFromCSV("storage/databases/database.csv")
	if err != nil {
		fmt.Printf("数据库加载失败: %v\n", err)
		return
	}
	database := dbManager.GetDatabase()
	fmt.Printf("数据库加载成功，行数: %d\n", len(database))

	// 尝试加载已有的加密数据库
	encDBManager, homomorphicEncKeys, err := core.LoadEncryptedDatabase("storage/databases/encrypted_database.gob")
	if err == nil {
		fmt.Printf("加载已有的加密数据库成功，行数: %d\n", len(encDBManager.GetEncryptedDatabase().Rows))
		// 确保私钥和公钥都正确设置
		encDBManager.SetPrivateKey(sk)
		encDBManager.PK = pk
		fmt.Printf("[服务器] 私钥设置成功，私钥非空: %t\n", sk != nil)
	} else {
		fmt.Printf("未找到已有的加密数据库，创建新的: %v\n", err)

		// 生成对称密钥
		dbManager.GenerateSymmetricKeys()
		symmetricKeys := dbManager.GetSymmetricKeys()

		// 加密数据库
		fmt.Printf("[服务器] 加密数据库，行数: %d\n", len(database))
		encDBManager = core.NewEncryptedDatabaseManager(pk, sk)
		encDBManager.EncryptDatabase(database, symmetricKeys)
		fmt.Printf("[服务器] 新建EncDBManager，私钥非空: %t\n", sk != nil)

		// 加密对称密钥
		homomorphicEncKeys, err = encDBManager.EncryptSymmetricKeys(symmetricKeys)
		if err != nil {
			fmt.Printf("对称密钥加密失败: %v\n", err)
			return
		}

		// 保存加密数据库（不重复加密）
		err = core.SavePreEncryptedDatabase("storage/databases/encrypted_database.gob", encDBManager, homomorphicEncKeys, pk)
		if err != nil {
			fmt.Printf("保存加密数据库失败: %v\n", err)
		}
	}

	// 创建PIR服务器
	pirServer := &PIRServer{
		Database:        database,
		EncryptedDB:     encDBManager.GetEncryptedDatabase().Rows,
		SymmetricKeys:   encDBManager.GetEncryptedDatabase().Keys,
		PK:              pk,
		SK:              sk,
		EncDBManager:    encDBManager,
		selectedRows:    []int{},
		selectedEncKeys: homomorphicEncKeys,
	}

	fmt.Printf("[服务器] PIR服务器创建完成，私钥检查: server.SK=%t, EncDBManager.SK=%t\n",
		pirServer.SK != nil, pirServer.EncDBManager.SK != nil)

	fmt.Println("PIR服务器启动成功")

	// 执行完整的本地S3R模式PIR协议
	runLocalPIRProtocol(pirServer)
}

func main() {
	fmt.Println("=== PIR 系统 ===")

	// 加载配置
	err := config.LoadConfig("configs/s3r_config.json")
	if err != nil {
		fmt.Printf("配置加载失败: %v\n", err)
		return
	}
	fmt.Println("配置加载成功")

	// 检查命令行参数
	if len(os.Args) > 1 {
		mode := strings.ToLower(os.Args[1])
		switch mode {
		case "local":
			runInteractiveMode()
		case "vm":
			runVMInteractiveMode()
		case "bench":
			// 无交互、直接运行虚拟机PIR以便性能验证
			runVMBench()
		default:
			fmt.Printf("未知模式: %s\n", mode)
			fmt.Println("支持的模式: local, vm, bench")
			return
		}
	} else {
		// 默认运行交互模式
		runInteractiveMode()
	}
}

// runInteractiveMode 运行交互式模式
func runInteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n=== PIR系统 ===")
		fmt.Println("请选择模式:")
		fmt.Println("1. 本地模式PIR查询")
		fmt.Println("2. 虚拟机模式PIR查询")
		fmt.Println("3. 查看数据库信息")
		fmt.Println("4. 退出")
		fmt.Print("请输入选择 (1-4): ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			runPIRQuery(scanner)
		case "2":
			runVMPIRQuery(scanner)
		case "3":
			showDatabaseInfo()
		case "4":
			fmt.Println("退出系统")
			return
		default:
			fmt.Println("无效选择，请重新输入")
		}
	}
}

// runPIRQuery 执行PIR查询
func runPIRQuery(scanner *bufio.Scanner) {
	fmt.Println("\n--- PIR查询配置 ---")

	// 获取谓词值
	numCols := len(config.GlobalConfig.DataColumns.UseColumns)
	if numCols == 0 {
		numCols = 3
	}
	fmt.Printf("请输入查询条件 (数据库有%d列)\n", numCols)

	var predicate []float64
	var operators []string

	for i := 0; i < numCols; i++ {
		defVal := -1e308
		if i < len(config.GlobalConfig.DefaultPredicate.Values) {
			defVal = config.GlobalConfig.DefaultPredicate.Values[i]
		}
		fmt.Printf("列 %d - 请输入比较值 (默认 %g, 回车保留): ", i+1, defVal)
		if !scanner.Scan() {
			return
		}

		valueStr := strings.TrimSpace(scanner.Text())
		if valueStr == "" {
			// 跳过该列：使用配置中的默认谓词值与操作符
			if i < len(config.GlobalConfig.DefaultPredicate.Values) {
				predicate = append(predicate, config.GlobalConfig.DefaultPredicate.Values[i])
			} else {
				predicate = append(predicate, -1e308)
			}
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operators = append(operators, config.GlobalConfig.DefaultPredicate.Operators[i])
			} else {
				operators = append(operators, ">=")
			}
			continue
		}

		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			fmt.Printf("无效数值，列 %d 使用默认值\n", i+1)
			if i < len(config.GlobalConfig.DefaultPredicate.Values) {
				predicate = append(predicate, config.GlobalConfig.DefaultPredicate.Values[i])
			} else {
				predicate = append(predicate, -1e308)
			}
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operators = append(operators, config.GlobalConfig.DefaultPredicate.Operators[i])
			} else {
				operators = append(operators, ">=")
			}
			continue
		}

		defOp := ">="
		if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
			defOp = config.GlobalConfig.DefaultPredicate.Operators[i]
		}
		fmt.Printf("列 %d 比较操作符 (>, <, >=, <=, ==) [默认 %s]: ", i+1, defOp)
		if !scanner.Scan() {
			return
		}

		operator := strings.TrimSpace(scanner.Text())
		if operator == "" {
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operator = config.GlobalConfig.DefaultPredicate.Operators[i]
			} else {
				operator = ">="
			}
		} else if operator != ">" && operator != "<" && operator != ">=" && operator != "<=" && operator != "==" {
			fmt.Printf("无效操作符，使用默认 '%s' \n", ">=")
			// 如果配置中有默认，则使用配置，否则回退到 ">="
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operator = config.GlobalConfig.DefaultPredicate.Operators[i]
			} else {
				operator = ">="
			}
		}

		predicate = append(predicate, value)
		operators = append(operators, operator)
	}

	// 显示查询条件
	fmt.Println("\n查询条件:")
	for i, op := range operators {
		fmt.Printf("  列%d %s %g\n", i+1, op, predicate[i])
	}

	fmt.Print("\n确认执行查询? (y/n): ")
	if !scanner.Scan() {
		return
	}

	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
		fmt.Println("查询已取消")
		return
	}

	// 执行PIR协议
	runPIRProtocolWithConditions(predicate, operators)
}

// showDatabaseInfo 显示数据库信息
func showDatabaseInfo() {
	fmt.Println("\n--- 数据库信息 ---")

	db, err := loadOriginalDatabase("storage/databases/database.csv")
	if err != nil {
		fmt.Printf("加载数据库失败: %v\n", err)
		return
	}

	fmt.Printf("数据库总行数: %d\n", len(db))
	cols := 0
	if len(db) > 0 {
		cols = len(db[0].Data)
	} else {
		cols = len(config.GlobalConfig.DataColumns.UseColumns)
	}
	fmt.Printf("数据库列数: %d\n", cols)
	fmt.Println("前5行数据:")

	for i := 0; i < min(5, len(db)); i++ {
		fmt.Printf("  行 %d: %v\n", i, db[i].Data)
	}

	if len(db) > 5 {
		fmt.Printf("  ... 还有 %d 行数据\n", len(db)-5)
	}
}

// runPIRProtocolWithConditions 使用指定条件执行PIR协议
func runPIRProtocolWithConditions(predicate []float64, operators []string) {
	startTime := time.Now()

	// 初始化服务器
	server := &PIRServer{}

	// 生成或加载密钥对
	publicKeyFile := "storage/keys/public_key.gob"
	privateKeyFile := "storage/keys/private_key.gob"

	pk, sk, err := generateOrLoadKeyPair(publicKeyFile, privateKeyFile)
	if err != nil {
		fmt.Printf("密钥生成/加载失败: %v\n", err)
		return
	}

	server.PK = pk
	server.SK = sk

	fmt.Printf("\n=== 开始执行本地PIR协议 ===\n")

	// 初始化客户端
	client := &PIRClient{
		Predicate: predicate,
		Operators: operators,
		PK:        pk,
		SK:        sk,
	}

	// 1. SC协议阶段：执行S3R获取选中行
	step1Start := time.Now()
	fmt.Println("\n--- 第1步：执行S3R协议 ---")
	scResult := server.executeLocalS3R(client.Predicate, client.Operators)
	server.selectedRows = scResult.SelectedRows
	client.RowIndices = scResult.SelectedRows
	fmt.Printf("✓ S3R协议完成，匹配行数: %d (耗时: %v)\n", len(server.selectedRows), time.Since(step1Start))

	if len(server.selectedRows) == 0 {
		fmt.Printf("❌ 没有匹配的数据行，协议结束\n")
		return
	}

	// 2. PIR设置阶段
	step2Start := time.Now()
	fmt.Println("\n--- 第2步：PIR设置阶段 ---")
	pirSetup := server.preparePIRSetup()
	fmt.Printf("✓ 选中行数: %d，加密数据数: %d，加密密钥数: %d (耗时: %v)\n",
		len(client.RowIndices), len(pirSetup.EncryptedDB.Rows), len(pirSetup.HomomorphicEncKeys), time.Since(step2Start))

	// 3. PIR查询阶段
	step3Start := time.Now()
	fmt.Println("\n--- 第3步：客户端生成PIR查询 ---")
	pirQuery := generatePIRQuery(client, pirSetup.HomomorphicEncKeys)
	fmt.Printf("✓ 成功为 %d 个密钥添加掩码 (耗时: %v)\n", len(pirQuery.HomomorphicResults), time.Since(step3Start))

	// 4. PIR响应阶段
	step4Start := time.Now()
	fmt.Println("\n--- 第4步：服务器处理PIR查询 ---")
	pirResponse := server.handlePIRQuery(pirQuery)
	fmt.Printf("✓ 批量解密完成，处理了 %d 个密钥 (耗时: %v)\n", len(pirResponse.DecryptedResults), time.Since(step4Start))

	// 5. 客户端处理响应
	step5Start := time.Now()
	fmt.Println("\n--- 第5步：客户端处理PIR响应 ---")
	handlePIRResponse(client, pirResponse, pirSetup.EncryptedDB.Rows)
	fmt.Printf("✓ 客户端处理完成 (耗时: %v)\n", time.Since(step5Start))

	totalTime := time.Since(startTime)
	fmt.Printf("\n=== 本地PIR协议执行完成 ===\n")
	fmt.Printf("📊 总耗时: %v\n", totalTime)
}

// runVMInteractiveMode 运行虚拟机交互式模式
func runVMInteractiveMode() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n=== PIR系统虚拟机模式 ===")
		fmt.Println("请选择操作:")
		fmt.Println("1. 执行虚拟机PIR查询")
		fmt.Println("2. 查看数据库信息")
		fmt.Println("3. 配置虚拟机连接")
		fmt.Println("4. 退出")
		fmt.Print("请输入选择 (1-4): ")

		if !scanner.Scan() {
			break
		}

		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			runVMPIRQuery(scanner)
		case "2":
			showDatabaseInfo()
		case "3":
			configureVMConnection(scanner)
		case "4":
			fmt.Println("退出系统")
			return
		default:
			fmt.Println("无效选择，请重新输入")
		}
	}
}

// runVMPIRQuery 执行虚拟机PIR查询
func runVMPIRQuery(scanner *bufio.Scanner) {
	fmt.Println("\n--- 虚拟机PIR查询配置 ---")

	// 获取谓词值
	numCols := len(config.GlobalConfig.DataColumns.UseColumns)
	if numCols == 0 {
		numCols = 3
	}
	fmt.Printf("请输入查询条件 (数据库有%d列)\n", numCols)

	var predicate []float64
	var operators []string

	for i := 0; i < numCols; i++ {
		defVal := -1e308
		if i < len(config.GlobalConfig.DefaultPredicate.Values) {
			defVal = config.GlobalConfig.DefaultPredicate.Values[i]
		}
		fmt.Printf("列 %d - 请输入比较值 (默认 %g, 回车保留): ", i+1, defVal)
		if !scanner.Scan() {
			return
		}

		valueStr := strings.TrimSpace(scanner.Text())
		if valueStr == "" {
			// 跳过该列：使用配置中的默认谓词值与操作符
			if i < len(config.GlobalConfig.DefaultPredicate.Values) {
				predicate = append(predicate, config.GlobalConfig.DefaultPredicate.Values[i])
			} else {
				predicate = append(predicate, -1e308)
			}
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operators = append(operators, config.GlobalConfig.DefaultPredicate.Operators[i])
			} else {
				operators = append(operators, ">=")
			}
			continue
		}

		value, err := strconv.ParseFloat(valueStr, 64)
		if err != nil {
			fmt.Printf("无效数值，列 %d 使用默认值\n", i+1)
			if i < len(config.GlobalConfig.DefaultPredicate.Values) {
				predicate = append(predicate, config.GlobalConfig.DefaultPredicate.Values[i])
			} else {
				predicate = append(predicate, -1e308)
			}
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operators = append(operators, config.GlobalConfig.DefaultPredicate.Operators[i])
			} else {
				operators = append(operators, ">=")
			}
			continue
		}

		defOp := ">="
		if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
			defOp = config.GlobalConfig.DefaultPredicate.Operators[i]
		}
		fmt.Printf("列 %d 比较操作符 (>, <, >=, <=, ==) [默认 %s]: ", i+1, defOp)
		if !scanner.Scan() {
			return
		}

		operator := strings.TrimSpace(scanner.Text())
		if operator == "" {
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operator = config.GlobalConfig.DefaultPredicate.Operators[i]
			} else {
				operator = ">="
			}
		} else if operator != ">" && operator != "<" && operator != ">=" && operator != "<=" && operator != "==" {
			fmt.Printf("无效操作符，使用默认 '%s' \n", ">=")
			if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
				operator = config.GlobalConfig.DefaultPredicate.Operators[i]
			} else {
				operator = ">="
			}
		}

		predicate = append(predicate, value)
		operators = append(operators, operator)
	}

	// 显示查询条件
	fmt.Println("\n查询条件:")
	for i, op := range operators {
		fmt.Printf("  列%d %s %g\n", i+1, op, predicate[i])
	}

	fmt.Print("\n确认执行虚拟机查询? (y/n): ")
	if !scanner.Scan() {
		return
	}

	if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
		fmt.Println("查询已取消")
		return
	}

	// 执行虚拟机PIR协议
	runVMPIRProtocolWithConditions(predicate, operators)
}

// configureVMConnection 配置虚拟机连接
func configureVMConnection(scanner *bufio.Scanner) {
	fmt.Println("\n--- 虚拟机连接配置 ---")
	fmt.Println("当前默认配置:")
	fmt.Println("  IP地址: 192.168.196.129")
	fmt.Println("  用户名: milu")
	fmt.Println("  端口: 22")
	fmt.Println("  工作目录: /home/milu/pir_project")
	fmt.Println("\n注意: 请确保虚拟机已安装Python3和numpy库")
	fmt.Println("注意: 请确保SSH服务已启动且可以连接")
}

// runVMPIRProtocolWithConditions 使用指定条件执行虚拟机PIR协议
func runVMPIRProtocolWithConditions(predicate []float64, operators []string) {
	startTime := time.Now()
	fmt.Printf("\n=== 开始执行虚拟机PIR协议 ===\n")

	// 生成或加载密钥对
	publicKeyFile := "storage/keys/public_key.gob"
	privateKeyFile := "storage/keys/private_key.gob"

	pk, sk, err := generateOrLoadKeyPair(publicKeyFile, privateKeyFile)
	if err != nil {
		fmt.Printf("❌ 密钥生成/加载失败: %v\n", err)
		return
	}

	// 初始化客户端
	client := &PIRClient{
		Predicate: predicate,
		Operators: operators,
		PK:        pk,
		SK:        sk,
	}

	// 1. 虚拟机S3R协议阶段
	step1Start := time.Now()
	fmt.Printf("\n--- 第1步：虚拟机S3R协议 ---\n")
	selectedRows := executeVMS3R(client.Predicate, client.Operators)
	if len(selectedRows) == 0 {
		fmt.Println("❌ 虚拟机S3R协议执行失败或没有匹配的行")
		return
	}

	client.RowIndices = selectedRows
	fmt.Printf("✓ S3R协议完成，匹配行数: %d (耗时: %v)\n", len(client.RowIndices), time.Since(step1Start))

	// 2. 初始化本地服务器
	step2Start := time.Now()
	fmt.Printf("\n--- 第2步：初始化PIR服务器 ---\n")

	// 尝试从文件加载已存在的加密数据库
	encryptedDBFile := "storage/databases/encrypted_database.gob"
	var encDBManager *core.EncryptedDatabaseManager
	var homomorphicEncKeys [][]byte
	var database core.Database

	if _, err := os.Stat(encryptedDBFile); os.IsNotExist(err) {
		// 如果加密数据库不存在，创建新的
		fmt.Println("正在创建加密数据库...")

		// 加载原始数据库
		dbManager := core.NewDatabaseManager()
		err = dbManager.LoadFromCSV("storage/databases/database.csv")
		if err != nil {
			fmt.Printf("❌ 加载数据库失败: %v\n", err)
			return
		}
		database = dbManager.GetDatabase()

		// 生成对称密钥
		dbManager.GenerateSymmetricKeys()
		symmetricKeys := dbManager.GetSymmetricKeys()

		// 加密数据库
		encDBManager = core.NewEncryptedDatabaseManager(pk, sk)
		encDBManager.EncryptDatabase(database, symmetricKeys)

		// 加密对称密钥
		homomorphicEncKeys, err = encDBManager.EncryptSymmetricKeys(symmetricKeys)
		if err != nil {
			fmt.Printf("❌ 对称密钥加密失败: %v\n", err)
			return
		}

		// 保存加密数据库（不重复加密）
		err = core.SavePreEncryptedDatabase("storage/databases/encrypted_database.gob", encDBManager, homomorphicEncKeys, pk)
		if err != nil {
			fmt.Printf("⚠️ 保存加密数据库失败: %v\n", err)
		}
	} else {
		// 如果已有加密数据库，直接加载
		fmt.Println("正在加载已存在的加密数据库...")
		var err error
		encDBManager, homomorphicEncKeys, err = core.LoadEncryptedDatabase("storage/databases/encrypted_database.gob")
		if err != nil {
			fmt.Printf("❌ 加载加密数据库失败: %v\n", err)
			return
		}

		// 重要：LoadEncryptedDatabase不包含私钥，需要设置私钥
		encDBManager.PK = pk
		encDBManager.SK = sk

		// 加载原始数据库用于验证
		dbManager := core.NewDatabaseManager()
		err = dbManager.LoadFromCSV("storage/databases/database.csv")
		if err != nil {
			fmt.Printf("❌ 加载原始数据库失败: %v\n", err)
			return
		}
		database = dbManager.GetDatabase()
	}

	// 创建PIR服务器
	server := &PIRServer{
		Database:        database,
		EncryptedDB:     encDBManager.GetEncryptedDatabase().Rows,
		SymmetricKeys:   encDBManager.GetEncryptedDatabase().Keys,
		PK:              pk,
		SK:              sk,
		EncDBManager:    encDBManager,
		selectedRows:    selectedRows,
		selectedEncKeys: homomorphicEncKeys,
	}

	fmt.Printf("✓ PIR服务器初始化完成 (耗时: %v)\n", time.Since(step2Start))

	// 3. PIR设置阶段
	step3Start := time.Now()
	fmt.Printf("\n--- 第3步：PIR设置阶段 ---\n")
	pirSetup := server.preparePIRSetup()
	fmt.Printf("✓ 选中行数: %d，加密数据数: %d，加密密钥数: %d (耗时: %v)\n",
		len(selectedRows), len(pirSetup.EncryptedDB.Rows), len(pirSetup.HomomorphicEncKeys), time.Since(step3Start))

	// 4. PIR查询阶段
	step4Start := time.Now()
	fmt.Printf("\n--- 第4步：客户端生成PIR查询 ---\n")
	pirQuery := generatePIRQuery(client, pirSetup.HomomorphicEncKeys)
	fmt.Printf("✓ 成功为 %d 个密钥添加掩码 (耗时: %v)\n", len(pirQuery.HomomorphicResults), time.Since(step4Start))

	// 5. PIR响应阶段
	step5Start := time.Now()
	fmt.Printf("\n--- 第5步：服务器处理PIR查询 ---\n")
	pirResponse := server.handlePIRQuery(pirQuery)
	fmt.Printf("✓ 批量解密完成，处理了 %d 个密钥 (耗时: %v)\n", len(pirResponse.DecryptedResults), time.Since(step5Start))

	// 6. 客户端处理响应
	step6Start := time.Now()
	fmt.Printf("\n--- 第6步：客户端处理PIR响应 ---\n")
	handlePIRResponse(client, pirResponse, pirSetup.EncryptedDB.Rows)
	fmt.Printf("✓ 客户端处理完成 (耗时: %v)\n", time.Since(step6Start))

	totalTime := time.Since(startTime)
	fmt.Printf("\n=== 虚拟机PIR协议执行完成 ===\n")
	fmt.Printf("📊 总耗时: %v\n", totalTime)
}

// executeVMS3R 在虚拟机中执行S3R协议
func executeVMS3R(predicate []float64, operators []string) []int {
	fmt.Printf("[虚拟机S3R] 开始在虚拟机中执行S3R协议...\n")

	// 默认虚拟机配置
	vmConfig := vm.VMConfig{
		Host:    "192.168.196.129",
		User:    "milu",
		Port:    "22",
		KeyPath: "",
		WorkDir: "/home/milu/pir_project",
	}

	fmt.Printf("[虚拟机S3R] 虚拟机地址: %s@%s:%s\n", vmConfig.User, vmConfig.Host, vmConfig.Port)

	// 步骤1: 传输数据文件到虚拟机
	if err := transferDataToVM(vmConfig); err != nil {
		fmt.Printf("[虚拟机S3R] 数据传输失败: %v\n", err)
		return []int{}
	}

	// 步骤2: 在虚拟机中执行S3R协议
	selectedRows, err := executeRemoteS3R(vmConfig, predicate, operators)
	if err != nil {
		fmt.Printf("[虚拟机S3R] S3R协议执行失败: %v\n", err)
		return []int{}
	}

	fmt.Printf("[虚拟机S3R] S3R协议执行成功，选中行数: %d\n", len(selectedRows))
	return selectedRows
}

// transferDataToVM 传输数据文件到虚拟机
func transferDataToVM(vmConfig vm.VMConfig) error {
	fmt.Printf("[虚拟机S3R] 传输数据文件到虚拟机...\n")

	// 确保虚拟机工作目录存在
	mkdirCmd := fmt.Sprintf("mkdir -p %s", vmConfig.WorkDir)
	sshArgs := []string{"-o", "StrictHostKeyChecking=no", "-p", vmConfig.Port,
		fmt.Sprintf("%s@%s", vmConfig.User, vmConfig.Host), mkdirCmd}

	cmd := exec.Command("ssh", sshArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("创建虚拟机目录失败: %v", err)
	}

	// 传输数据库文件
	localDataPath := "storage/databases/database.csv"
	remoteDataPath := fmt.Sprintf("%s/data.csv", vmConfig.WorkDir)

	scpArgs := []string{"-o", "StrictHostKeyChecking=no", "-P", vmConfig.Port,
		localDataPath, fmt.Sprintf("%s@%s:%s", vmConfig.User, vmConfig.Host, remoteDataPath)}

	cmd = exec.Command("scp", scpArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("传输数据文件失败: %v", err)
	}

	// 传输 S3R 脚本到虚拟机 (使用SecretFlow版本)
	localScriptPath := "scripts/s3r_secretflow.py"
	remoteScriptPath := fmt.Sprintf("%s/s3r_secretflow.py", vmConfig.WorkDir)

	scpArgs = []string{"-o", "StrictHostKeyChecking=no", "-P", vmConfig.Port,
		localScriptPath, fmt.Sprintf("%s@%s:%s", vmConfig.User, vmConfig.Host, remoteScriptPath)}

	cmd = exec.Command("scp", scpArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("传输SecretFlow S3R脚本失败: %v", err)
	}

	fmt.Printf("[虚拟机S3R] 数据文件传输完成\n")
	return nil
}

// executeRemoteS3R 在虚拟机中执行S3R协议
func executeRemoteS3R(vmConfig vm.VMConfig, predicate []float64, operators []string) ([]int, error) {
	fmt.Printf("[虚拟机S3R] 在虚拟机中执行S3R协议...\n")

	// 构建谓词值字符串
	predicateStrs := make([]string, len(predicate))
	for i, val := range predicate {
		predicateStrs[i] = fmt.Sprintf("%.6f", val)
	}
	predicateValues := strings.Join(predicateStrs, ",")

	// 规范化操作符：长度不匹配或非法值一律替换为 ">="
	normalizedOps := make([]string, len(predicate))
	for i := range normalizedOps {
		op := ">="
		if i < len(operators) {
			o := strings.TrimSpace(operators[i])
			if o == ">" || o == "<" || o == ">=" || o == "<=" || o == "==" {
				op = o
			}
		}
		normalizedOps[i] = op
	}
	operatorStr := strings.Join(normalizedOps, ",")

	// 构建S3R命令
	resultFile := "sc_result_vm.csv"
	remoteCmd := fmt.Sprintf(
		"source /home/milu/miniconda3/bin/activate && conda activate secretflow && cd %s && RAY_memory_usage_threshold=0.99 python s3r_secretflow.py --features_csv data.csv --usecols %s --predicate_values %s --predicate_ops \"%s\" --out %s --dtype float32 --chunksize 20000",
		vmConfig.WorkDir, config.GlobalConfig.GetUseColumnsString(), predicateValues, operatorStr, resultFile,
	)

	fmt.Printf("[虚拟机S3R] 执行远程命令: %s\n", remoteCmd)

	// 执行SSH命令
	sshArgs := []string{"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-p", vmConfig.Port,
		fmt.Sprintf("%s@%s", vmConfig.User, vmConfig.Host), remoteCmd}

	cmd := exec.Command("ssh", sshArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[虚拟机S3R] 远程S3R协议执行失败: %v\n输出: %s\n", err, string(output))
		return []int{}, err
	}

	fmt.Printf("[虚拟机S3R] S3R协议执行成功\n输出: %s\n", string(output))

	// 从虚拟机获取结果文件
	localResultPath := "storage/results/sc_result_vm.csv"
	remoteResultPath := fmt.Sprintf("%s/%s", vmConfig.WorkDir, resultFile)

	scpArgs := []string{"-o", "StrictHostKeyChecking=no", "-P", vmConfig.Port,
		fmt.Sprintf("%s@%s:%s", vmConfig.User, vmConfig.Host, remoteResultPath), localResultPath}

	cmd = exec.Command("scp", scpArgs...)
	if err := cmd.Run(); err != nil {
		return []int{}, fmt.Errorf("结果文件传输失败: %v", err)
	}

	// 解析结果文件
	selectedRows, err := parseVMS3RResult(localResultPath)
	if err != nil {
		return []int{}, fmt.Errorf("解析S3R结果失败: %v", err)
	}

	return selectedRows, nil
}

// parseVMS3RResult 解析虚拟机S3R结果文件
func parseVMS3RResult(resultFile string) ([]int, error) {
	file, err := os.Open(resultFile)
	if err != nil {
		return []int{}, err
	}
	defer file.Close()

	var selectedRows []int
	scanner := bufio.NewScanner(file)
	rowIndex := 0

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "1" {
			selectedRows = append(selectedRows, rowIndex)
		}
		rowIndex++
	}

	if err := scanner.Err(); err != nil {
		return []int{}, err
	}

	return selectedRows, nil
}

// runLocalPIRProtocol 执行完整的本地PIR协议
func runLocalPIRProtocol(server *PIRServer) {
	startTime := time.Now()
	var overheadDuration time.Duration
	fmt.Printf("\n=== 开始执行本地PIR协议 ===\n")

	// 初始化客户端 - 直接使用服务器的私钥，避免深拷贝问题
	// 使用配置中的默认谓词与操作符，长度对齐use_columns
	cols := len(config.GlobalConfig.DataColumns.UseColumns)
	if cols == 0 {
		cols = 3
	}
	predicate := make([]float64, cols)
	ops := make([]string, cols)
	for i := 0; i < cols; i++ {
		if i < len(config.GlobalConfig.DefaultPredicate.Values) {
			predicate[i] = config.GlobalConfig.DefaultPredicate.Values[i]
		} else {
			predicate[i] = -1e308
		}
		if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
			ops[i] = config.GlobalConfig.DefaultPredicate.Operators[i]
		} else {
			ops[i] = ">="
		}
	}
	client := &PIRClient{
		Predicate: predicate,
		Operators: ops,
		PK:        server.PK,
		SK:        server.SK,
	}

	// 第1步：执行S3R协议
	fmt.Printf("\n--- 第1步：执行S3R协议 ---\n")
	scRequest := core.SCRequest{
		Predicate: client.Predicate,
		Operators: client.Operators,
	}
	t0 := time.Now()
	commS3RReqBytes := calcSize(scRequest)
	overheadDuration += time.Since(t0)

	step1Start := time.Now()
	scResponse := server.handleSCRequest(scRequest)
	client.RowIndices = scResponse.SelectedRows
	step1Dur := time.Since(step1Start)

	t0 = time.Now()
	commS3RRespBytes := calcSize(scResponse)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ S3R协议完成，匹配行数: %d (耗时: %v)\n", len(client.RowIndices), step1Dur)

	if len(client.RowIndices) == 0 {
		fmt.Printf("❌ 没有匹配的数据行，协议结束\n")
		return
	}

	// 第2步：PIR设置阶段
	fmt.Printf("\n--- 第2步：PIR设置阶段 ---\n")
	step2Start := time.Now()
	pirSetup := server.preparePIRSetup()
	step2Dur := time.Since(step2Start)

	t0 = time.Now()
	commPIRSetupBytes := calcSize(pirSetup)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 选中行数: %d，加密数据数: %d，加密密钥数: %d (耗时: %v)\n",
		len(client.RowIndices), len(pirSetup.EncryptedDB.Rows), len(pirSetup.HomomorphicEncKeys), step2Dur)

	// 第3步：客户端生成PIR查询
	fmt.Printf("\n--- 第3步：客户端生成PIR查询 ---\n")
	step3Start := time.Now()
	pirQuery := generatePIRQuery(client, pirSetup.HomomorphicEncKeys)
	step3Dur := time.Since(step3Start)

	t0 = time.Now()
	commPIRQueryBytes := calcSize(pirQuery)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 成功为 %d 个密钥添加掩码 (耗时: %v)\n", len(pirQuery.HomomorphicResults), step3Dur)

	// 第4步：服务器处理PIR查询
	fmt.Printf("\n--- 第4步：服务器处理PIR查询 ---\n")
	step4Start := time.Now()
	pirResponse := server.handlePIRQuery(pirQuery)
	step4Dur := time.Since(step4Start)

	t0 = time.Now()
	commPIRResponseBytes := calcSize(pirResponse)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 批量解密完成，处理了 %d 个密钥 (耗时: %v)\n", len(pirResponse.DecryptedResults), step4Dur)

	// 第5步：客户端处理PIR响应
	fmt.Printf("\n--- 第5步：客户端处理PIR响应 ---\n")
	step5Start := time.Now()
	handlePIRResponse(client, pirResponse, pirSetup.EncryptedDB.Rows)
	step5Dur := time.Since(step5Start)
	fmt.Printf("✓ 客户端处理完成 (耗时: %v)\n", step5Dur)

	totalTime := time.Since(startTime) - overheadDuration
	fmt.Printf("\n=== 本地PIR协议执行完成 ===\n")
	fmt.Printf("📊 总耗时: %v (扣除统计开销 %v)\n", totalTime, overheadDuration)

	// 计算存储开销（修正：包含云端存储的同态加密密钥）
	storageOriginalBytes := calcSize(server.Database)
	// 加密数据库 = AES加密数据 + 同态加密密钥（用于PIR取回）
	storageEncryptedBytes := calcSize(server.EncryptedDB) + calcSize(server.selectedEncKeys)
	totalCommBytes := commS3RReqBytes + commS3RRespBytes + commPIRSetupBytes + commPIRQueryBytes + commPIRResponseBytes

	// 转换为MB
	toMB := func(b int64) float64 {
		return float64(b) / 1024 / 1024
	}

	// 生成并写出bench指标
	metrics := BenchMetrics{
		Timestamp:            time.Now().Format(time.RFC3339),
		GoOS:                 runtime.GOOS,
		GoArch:               runtime.GOARCH,
		NumCPU:               runtime.NumCPU(),
		DatasetRows:          len(server.Database),
		SelectedRows:         len(client.RowIndices),
		BatchSize:            config.GlobalConfig.Performance.BatchSize,
		UseColumns:           append([]int(nil), config.GlobalConfig.DataColumns.UseColumns...),
		Predicate:            append([]float64(nil), client.Predicate...),
		Operators:            append([]string(nil), client.Operators...),
		S3RMillis:            step1Dur.Milliseconds(),
		PIRSetupMillis:       step2Dur.Milliseconds(),
		ClientQueryGenMillis: step3Dur.Milliseconds(),
		ServerDecryptMillis:  step4Dur.Milliseconds(),
		ClientProcessMillis:  step5Dur.Milliseconds(),
		TotalMillis:          totalTime.Milliseconds(),
		StorageOriginalMB:    toMB(storageOriginalBytes),
		StorageEncryptedMB:   toMB(storageEncryptedBytes),
		CommS3RRequestMB:     toMB(commS3RReqBytes),
		CommS3RResponseMB:    toMB(commS3RRespBytes),
		CommPIRSetupMB:       toMB(commPIRSetupBytes),
		CommPIRQueryMB:       toMB(commPIRQueryBytes),
		CommPIRResponseMB:    toMB(commPIRResponseBytes),
		TotalCommMB:          toMB(totalCommBytes),
	}
	saveBenchMetricsJSONCSV(metrics)
}

// generatePIRQuery 生成PIR查询（客户端添加随机掩码）
func generatePIRQuery(client *PIRClient, homomorphicEncKeys [][]byte) core.PIRQuery {
	client.randomMasks = make([][]byte, len(homomorphicEncKeys))

	// 1) 生成所有随机掩码
	masks := make([][]byte, len(homomorphicEncKeys))
	for i := range homomorphicEncKeys {
		mask := make([]byte, 32) // 256位随机掩码
		mathrand.Read(mask)
		client.randomMasks[i] = mask
		masks[i] = mask
	}

	// 2) 批量同态加密掩码 E(R)
	encMasks, err := core.BatchEncrypt(client.PK, masks)
	if err != nil {
		// 回退到单个加密保证兼容性
		encMasks = make([][]byte, len(masks))
		for i := range masks {
			c, e := core.Encrypt(client.PK, masks[i])
			if e != nil {
				continue
			}
			encMasks[i] = c
		}
	}

	// 3) 批量同态加法 E(ki + R) = E(ki) ⊕ E(R)
	homomorphicResults := core.BatchAddCipher(client.PK, homomorphicEncKeys, encMasks)

	return core.PIRQuery{
		HomomorphicResults: homomorphicResults,
		RandomMasks:        client.randomMasks,
	}
}

// handlePIRResponse 处理PIR响应（客户端恢复密钥并解密数据）
func handlePIRResponse(client *PIRClient, response core.PIRResponse, selectedEncryptedRows []core.EncryptedRow) {
	// 恢复对称密钥：从服务器返回的(ki + R)中减去掩码R
	recoveredKeys := make([][]byte, len(response.DecryptedResults))
	successCount := 0

	for i, maskedKeyBytes := range response.DecryptedResults {
		if i < len(client.randomMasks) {
			// 将解密结果转换为大整数
			maskedKeyBigInt := new(big.Int).SetBytes(maskedKeyBytes)

			// 将随机掩码转换为大整数
			maskBigInt := new(big.Int).SetBytes(client.randomMasks[i])

			// 获取Paillier公钥的模数N
			N := client.PK.N

			// 执行模运算减法：(ki + R) - R mod N = ki mod N
			recoveredKeyBigInt := new(big.Int).Sub(maskedKeyBigInt, maskBigInt)
			recoveredKeyBigInt.Mod(recoveredKeyBigInt, N)

			// 将恢复的密钥转换回字节数组，确保长度为32字节（AES-256）
			recoveredKeyBytes := recoveredKeyBigInt.Bytes()

			// 如果密钥长度不足32字节，在前面补零
			if len(recoveredKeyBytes) < 32 {
				paddedKey := make([]byte, 32)
				copy(paddedKey[32-len(recoveredKeyBytes):], recoveredKeyBytes)
				recoveredKeys[i] = paddedKey
			} else if len(recoveredKeyBytes) > 32 {
				// 如果密钥长度超过32字节，取后32字节
				recoveredKeys[i] = recoveredKeyBytes[len(recoveredKeyBytes)-32:]
			} else {
				recoveredKeys[i] = recoveredKeyBytes
			}

			successCount++
		}
	}
	fmt.Printf("✓ 成功恢复 %d 个密钥\n", successCount)

	// 解密选中的行数据
	var decryptedData [][]float64
	decryptedCount := 0
	for i, encRow := range selectedEncryptedRows {
		if i < len(recoveredKeys) {
			// 使用恢复的对称密钥解密行数据
			rowData := core.SymmetricDecrypt(encRow.EncryptedData, recoveredKeys[i])
			if rowData != nil {
				decryptedData = append(decryptedData, rowData)
				decryptedCount++
			}
		}
	}
	fmt.Printf("✓ 成功解密 %d 行数据\n", decryptedCount)

	// 保存解密后的数据到CSV文件
	err := saveDecryptedDataToCSV(decryptedData, "storage/results/client_decrypted_data.csv")
	if err != nil {
		fmt.Printf("⚠️ 保存解密数据失败: %v\n", err)
	} else {
		fmt.Printf("✓ 解密数据已保存到 client_decrypted_data.csv\n")
	}

	// 验证解密数据的正确性
	fmt.Println("\n--- 数据验证阶段 ---")
	if _, statErr := os.Stat("storage/databases/database.csv"); os.IsNotExist(statErr) {
		// 原始数据库缺失，采用重加密比对验证
		matchCount := 0
		for i := 0; i < len(decryptedData) && i < len(selectedEncryptedRows) && i < len(recoveredKeys); i++ {
			reenc := core.SymmetricEncrypt(decryptedData[i], recoveredKeys[i])
			equal := len(reenc) == len(selectedEncryptedRows[i].EncryptedData)
			if equal {
				for j := 0; j < len(reenc); j++ {
					if reenc[j] != selectedEncryptedRows[i].EncryptedData[j] {
						equal = false
						break
					}
				}
			}
			if equal {
				matchCount++
			}
		}
		fmt.Printf("验证结果: %d/%d 行数据匹配（重加密比对）\n", matchCount, len(decryptedData))
		if matchCount == len(decryptedData) {
			fmt.Printf("✅ 所有数据验证通过，无需原始数据库\n")
		} else {
			fmt.Printf("❌ 部分数据验证失败，请检查密钥恢复和加密流程\n")
		}
	} else {
		verifyDecryptedData(decryptedData, client.RowIndices)
	}

	// 显示解密结果摘要
	fmt.Printf("\n=== 解密结果摘要 ===\n")
	fmt.Printf("成功解密 %d 行数据\n", len(decryptedData))
	if len(decryptedData) > 0 {
		fmt.Printf("前3行数据:\n")
		for i := 0; i < min(3, len(decryptedData)); i++ {
			fmt.Printf("  行 %d: %v\n", i, decryptedData[i])
		}
		if len(decryptedData) > 3 {
			fmt.Printf("  ... 还有 %d 行数据\n", len(decryptedData)-3)
		}
	}
}

// min 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ... existing code ...

// runVMBench 以非交互方式在虚拟机模式下执行完整PIR协议，并记录bench指标
func runVMBench() {
	startTime := time.Now()
	var overheadDuration time.Duration
	fmt.Printf("\n=== 开始执行虚拟机PIR协议（Bench） ===\n")

	// 生成或加载密钥对
	publicKeyFile := "storage/keys/public_key.gob"
	privateKeyFile := "storage/keys/private_key.gob"
	pk, sk, err := generateOrLoadKeyPair(publicKeyFile, privateKeyFile)
	if err != nil {
		fmt.Printf("❌ 密钥生成/加载失败: %v\n", err)
		return
	}

	// 使用配置中的默认谓词与操作符，长度对齐use_columns
	cols := len(config.GlobalConfig.DataColumns.UseColumns)
	if cols == 0 {
		cols = 3
	}
	predicate := make([]float64, cols)
	ops := make([]string, cols)
	for i := 0; i < cols; i++ {
		if i < len(config.GlobalConfig.DefaultPredicate.Values) {
			predicate[i] = config.GlobalConfig.DefaultPredicate.Values[i]
		} else {
			predicate[i] = -1e308
		}
		if i < len(config.GlobalConfig.DefaultPredicate.Operators) {
			ops[i] = config.GlobalConfig.DefaultPredicate.Operators[i]
		} else {
			ops[i] = ">="
		}
	}

	client := &PIRClient{
		Predicate: predicate,
		Operators: ops,
		PK:        pk,
		SK:        sk,
	}

	// 第1步：在虚拟机执行S3R协议
	fmt.Printf("\n--- 第1步：虚拟机S3R协议 ---\n")

	// 计算请求开销
	t0 := time.Now()
	scRequest := core.SCRequest{
		Predicate: client.Predicate,
		Operators: client.Operators,
	}
	commS3RReqBytes := calcSize(scRequest)
	overheadDuration += time.Since(t0)

	step1Start := time.Now()
	selectedRows := executeVMS3R(client.Predicate, client.Operators)
	client.RowIndices = selectedRows
	step1Dur := time.Since(step1Start)

	// 计算响应开销
	t0 = time.Now()
	scResponse := core.SCResponse{
		SelectedRows: selectedRows,
	}
	commS3RRespBytes := calcSize(scResponse)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ S3R协议完成，匹配行数: %d (耗时: %v)\n", len(client.RowIndices), step1Dur)
	if len(client.RowIndices) == 0 {
		fmt.Printf("❌ 没有匹配的数据行，协议结束\n")
		return
	}

	// 第2步：初始化PIR服务器（加载/创建加密数据库）
	step2Start := time.Now()
	fmt.Printf("\n--- 第2步：初始化PIR服务器 ---\n")
	encryptedDBFile := "storage/databases/encrypted_database.gob"
	var encDBManager *core.EncryptedDatabaseManager
	var homomorphicEncKeys [][]byte
	var database core.Database

	if _, err := os.Stat(encryptedDBFile); os.IsNotExist(err) {
		fmt.Println("正在创建加密数据库...")
		dbManager := core.NewDatabaseManager()
		if err := dbManager.LoadFromCSV("storage/databases/database.csv"); err != nil {
			fmt.Printf("❌ 加载数据库失败: %v\n", err)
			return
		}
		database = dbManager.GetDatabase()

		dbManager.GenerateSymmetricKeys()
		symmetricKeys := dbManager.GetSymmetricKeys()

		encDBManager = core.NewEncryptedDatabaseManager(pk, sk)
		encDBManager.EncryptDatabase(database, symmetricKeys)

		homomorphicEncKeys, err = encDBManager.EncryptSymmetricKeys(symmetricKeys)
		if err != nil {
			fmt.Printf("❌ 对称密钥加密失败: %v\n", err)
			return
		}

		if err := core.SavePreEncryptedDatabase("storage/databases/encrypted_database.gob", encDBManager, homomorphicEncKeys, pk); err != nil {
			fmt.Printf("⚠️ 保存加密数据库失败: %v\n", err)
		}
	} else {
		fmt.Println("正在加载已存在的加密数据库...")
		var err error
		encDBManager, homomorphicEncKeys, err = core.LoadEncryptedDatabase(encryptedDBFile)
		if err != nil {
			fmt.Printf("❌ 加载加密数据库失败: %v\n", err)
			return
		}
		encDBManager.PK = pk
		encDBManager.SK = sk

		dbManager := core.NewDatabaseManager()
		if err := dbManager.LoadFromCSV("storage/databases/database.csv"); err != nil {
			fmt.Printf("❌ 加载原始数据库失败: %v\n", err)
			return
		}
		database = dbManager.GetDatabase()
	}

	server := &PIRServer{
		Database:        database,
		EncryptedDB:     encDBManager.GetEncryptedDatabase().Rows,
		SymmetricKeys:   encDBManager.GetEncryptedDatabase().Keys,
		PK:              pk,
		SK:              sk,
		EncDBManager:    encDBManager,
		selectedRows:    client.RowIndices,
		selectedEncKeys: homomorphicEncKeys,
	}
	step2Dur := time.Since(step2Start)
	fmt.Printf("✓ PIR服务器初始化完成 (耗时: %v)\n", step2Dur)

	// 第3步：PIR设置阶段
	fmt.Printf("\n--- 第3步：PIR设置阶段 ---\n")
	step3Start := time.Now()
	pirSetup := server.preparePIRSetup()
	step3Dur := time.Since(step3Start)

	t0 = time.Now()
	commPIRSetupBytes := calcSize(pirSetup)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 选中行数: %d，加密数据数: %d，加密密钥数: %d (耗时: %v)\n",
		len(client.RowIndices), len(pirSetup.EncryptedDB.Rows), len(pirSetup.HomomorphicEncKeys), step3Dur)

	// 第4步：客户端生成PIR查询
	fmt.Printf("\n--- 第4步：客户端生成PIR查询 ---\n")
	step4Start := time.Now()
	pirQuery := generatePIRQuery(client, pirSetup.HomomorphicEncKeys)
	step4Dur := time.Since(step4Start)

	t0 = time.Now()
	commPIRQueryBytes := calcSize(pirQuery)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 成功为 %d 个密钥添加掩码 (耗时: %v)\n", len(pirQuery.HomomorphicResults), step4Dur)

	// 第5步：服务器处理PIR查询
	fmt.Printf("\n--- 第5步：服务器处理PIR查询 ---\n")
	step5Start := time.Now()
	pirResponse := server.handlePIRQuery(pirQuery)
	step5Dur := time.Since(step5Start)

	t0 = time.Now()
	commPIRResponseBytes := calcSize(pirResponse)
	overheadDuration += time.Since(t0)

	fmt.Printf("✓ 批量解密完成，处理了 %d 个密钥 (耗时: %v)\n", len(pirResponse.DecryptedResults), step5Dur)

	// 第6步：客户端处理PIR响应
	fmt.Printf("\n--- 第6步：客户端处理PIR响应 ---\n")
	step6Start := time.Now()
	handlePIRResponse(client, pirResponse, pirSetup.EncryptedDB.Rows)
	step6Dur := time.Since(step6Start)
	fmt.Printf("✓ 客户端处理完成 (耗时: %v)\n", step6Dur)

	totalTime := time.Since(startTime) - overheadDuration
	fmt.Printf("\n=== 虚拟机PIR协议执行完成（Bench） ===\n")
	fmt.Printf("📊 总耗时: %v (扣除统计开销 %v)\n", totalTime, overheadDuration)

	// 计算存储开销
	storageOriginalBytes := calcSize(server.Database)
	storageEncryptedBytes := calcSize(server.EncDBManager.GetEncryptedDatabase())
	totalCommBytes := commS3RReqBytes + commS3RRespBytes + commPIRSetupBytes + commPIRQueryBytes + commPIRResponseBytes

	// 转换为MB
	toMB := func(b int64) float64 {
		return float64(b) / 1024 / 1024
	}

	// 写出bench指标（与本地bench字段保持一致）
	metrics := BenchMetrics{
		Timestamp:            time.Now().Format(time.RFC3339),
		GoOS:                 runtime.GOOS,
		GoArch:               runtime.GOARCH,
		NumCPU:               runtime.NumCPU(),
		DatasetRows:          len(server.Database),
		SelectedRows:         len(client.RowIndices),
		BatchSize:            config.GlobalConfig.Performance.BatchSize,
		UseColumns:           append([]int(nil), config.GlobalConfig.DataColumns.UseColumns...),
		Predicate:            append([]float64(nil), client.Predicate...),
		Operators:            append([]string(nil), client.Operators...),
		S3RMillis:            step1Dur.Milliseconds(),
		PIRSetupMillis:       step3Dur.Milliseconds(),
		ClientQueryGenMillis: step4Dur.Milliseconds(),
		ServerDecryptMillis:  step5Dur.Milliseconds(),
		ClientProcessMillis:  step6Dur.Milliseconds(),
		TotalMillis:          totalTime.Milliseconds(),
		StorageOriginalMB:    toMB(storageOriginalBytes),
		StorageEncryptedMB:   toMB(storageEncryptedBytes),
		CommS3RRequestMB:     toMB(commS3RReqBytes),
		CommS3RResponseMB:    toMB(commS3RRespBytes),
		CommPIRSetupMB:       toMB(commPIRSetupBytes),    // This is Cloud Download
		CommPIRQueryMB:       toMB(commPIRQueryBytes),    // This is Client -> Server
		CommPIRResponseMB:    toMB(commPIRResponseBytes), // This is Server -> Client
		TotalCommMB:          toMB(totalCommBytes),
	}
	fmt.Printf("\n--- 通信开销拆解 ---\n")
	fmt.Printf("☁️  云端下载 (Cloud Download): %.4f MB\n", metrics.CommPIRSetupMB)
	fmt.Printf("📡 在线交互 (Server Interaction): %.4f MB\n", metrics.CommPIRQueryMB+metrics.CommPIRResponseMB)
	saveBenchMetricsJSONCSV(metrics)
}
