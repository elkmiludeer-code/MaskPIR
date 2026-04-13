package vm

import (
	"bufio"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"github.com/water/pir-system/pkg/config"
	"github.com/water/pir-system/pkg/core"
)

// 生成VM模式下的PIR查询
func generateVMPIRQuery(selectedRows []int, homomorphicEncKeys [][]byte, pk core.HomomorphicPublicKey) core.PIRQuery {
	fmt.Printf("[VM客户端] 开始生成PIR查询，匹配行数: %d\n", len(selectedRows))
	startTime := time.Now()
	
	// 生成随机掩码R用于对称密钥掩码
	randomGenStart := time.Now()
	R := make([][]byte, len(homomorphicEncKeys))
	for i := range R {
		// 生成32字节的随机掩码，与对称密钥长度一致
		mask := make([]byte, 32)
		_, err := rand.Read(mask)
		if err != nil {
			fmt.Printf("生成随机掩码失败: %v\n", err)
			// 使用伪随机数作为备选
			for j := range mask {
				mask[j] = byte(mathrand.Intn(256))
			}
		}
		R[i] = mask
	}
	randomGenTime := time.Since(randomGenStart)
	fmt.Printf("[VM客户端] 随机掩码生成完成 (耗时: %v)\n", randomGenTime)

	// 使用批量加密优化性能：一次性加密所有随机掩码
	encryptStart := time.Now()
	fmt.Printf("[VM客户端] 开始批量加密 %d 个随机掩码...\n", len(R))
	encryptedMasks, err := core.BatchEncrypt(pk, R)
	if err != nil {
		fmt.Printf("[VM客户端] 批量加密失败，回退到串行加密: %v\n", err)
		// 回退到串行加密
		encryptedMasks = make([][]byte, len(R))
		for i, mask := range R {
			encryptedMask, err := core.Encrypt(pk, mask)
			if err != nil {
				fmt.Printf("加密随机掩码失败: %v\n", err)
				continue
			}
			encryptedMasks[i] = encryptedMask
			
			// 每处理50个显示进度
			if (i+1)%50 == 0 || i == len(R)-1 {
				fmt.Printf("[VM客户端] 加密进度: %d/%d\n", i+1, len(R))
			}
		}
	}
	encryptTime := time.Since(encryptStart)
	fmt.Printf("[VM客户端] 随机掩码加密完成 (耗时: %v)\n", encryptTime)

	// 使用批量同态加法优化性能：一次性执行所有同态加法
	maskingStart := time.Now()
	fmt.Printf("[VM客户端] 开始批量同态加法...\n")
	homomorphicResults := core.BatchAddCipher(pk, homomorphicEncKeys, encryptedMasks)
	if homomorphicResults == nil {
		fmt.Printf("[VM客户端] 批量同态加法失败，回退到串行操作\n")
		// 回退到串行同态加法
		homomorphicResults = make([][]byte, len(homomorphicEncKeys))
		for i := range homomorphicEncKeys {
			maskedKey := core.AddCipher(pk, homomorphicEncKeys[i], encryptedMasks[i])
			if maskedKey == nil {
				fmt.Printf("同态加法失败，索引: %d\n", i)
				continue
			}
			homomorphicResults[i] = maskedKey
			
			// 每处理50个显示进度
			if (i+1)%50 == 0 || i == len(homomorphicEncKeys)-1 {
				fmt.Printf("[VM客户端] 掩码进度: %d/%d\n", i+1, len(homomorphicEncKeys))
			}
		}
	}
	maskingTime := time.Since(maskingStart)
	totalTime := time.Since(startTime)
	
	fmt.Printf("[VM客户端] 对称密钥掩码完成 (耗时: %v)\n", maskingTime)
	fmt.Printf("[VM客户端] PIR查询生成完成，查询向量长度: %d (总耗时: %v)\n", len(homomorphicResults), totalTime)

	// 存储随机掩码以便后续去掩码使用
	return core.PIRQuery{
		HomomorphicResults: homomorphicResults,
		RandomMasks:        R, // 添加随机掩码字段
	}
}

// PIRServer 结构体定义
type PIRServer struct {
	DB core.Database
	PK core.HomomorphicPublicKey
	SK core.HomomorphicPrivateKey
	K  core.SymmetricKeySet
}

// PIRServer 方法 - 处理SC协议请求
func (server *PIRServer) handleSCRequest(request core.SCRequest) core.SCResponse {
	result := server.realSCProtocol(request.Predicate, request.Operators)
	return core.SCResponse{SelectedRows: result.SelectedRows}
}

// PIRServer 方法 - 安全比较协议实现
func (server *PIRServer) realSCProtocol(predicate []float64, operators []string) core.SCResult {
	// 构建谓词值字符串
	predicateStrs := make([]string, len(predicate))
	for i, val := range predicate {
		predicateStrs[i] = fmt.Sprintf("%.6f", val)
	}
	predicateValues := strings.Join(predicateStrs, ",")

	// 构建操作符字符串，如果没有提供则使用默认值
	var operatorStr string
	if len(operators) == len(predicate) {
		operatorStr = strings.Join(operators, ",")
	} else {
		// 默认使用 >= 操作符
		defaultOps := make([]string, len(predicate))
		for i := range defaultOps {
			defaultOps[i] = ">="
		}
		operatorStr = strings.Join(defaultOps, ",")
		fmt.Printf("[服务器] 操作符数量不匹配，使用默认操作符: %s\n", operatorStr)
	}

	// 构建 Python 脚本调用参数
	args := []string{
		"scripts/s3r.py",
		"--features_csv", "storage/databases/database.csv",
		"--usecols", config.GlobalConfig.GetUseColumnsString(), // 使用配置文件中的列选择
		"--predicate_values", predicateValues,
		"--predicate_ops", operatorStr, // 使用客户端提供的操作符
		"--out", "../../storage/results/sc_result.csv",
		"--dtype", "float64",
	}

	// 执行 Python 脚本
	cmd := exec.Command("python", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] Python 脚本执行失败: %v\n输出: %s\n", err, string(output))
		return core.SCResult{SelectedRows: []int{}}
	}

	fmt.Printf("[服务器] Python 脚本执行成功: %s\n", string(output))

	// 读取结果文件
	resultFile := "../../storage/results/sc_result.csv"
	file, err := os.Open(resultFile)
	if err != nil {
		fmt.Printf("[服务器] 无法打开结果文件: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}
	defer file.Close()

	// 解析结果，找出匹配的行索引
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
		fmt.Printf("[服务器] 读取结果文件失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	fmt.Printf("[服务器] 安全比较完成，匹配行数: %d\n", len(selectedRows))
	return core.SCResult{SelectedRows: selectedRows}
}

// PIRServer 方法 - 准备PIR设置数据
func (server *PIRServer) preparePIRSetup(selectedRows []int) core.PIRSetup {
	// 尝试从文件加载已存在的加密数据库
	encryptedDBFile := "../../storage/databases/encrypted_database.gob"
	encDBManager, homomorphicEncKeys, err := core.LoadEncryptedDatabase(encryptedDBFile)
	if err != nil {
		// 如果加载失败，重新创建加密数据库
		encDBManager = core.NewEncryptedDatabaseManager(server.PK, server.SK)
		encDBManager.EncryptDatabase(server.DB, server.K)
		homomorphicEncKeys, err = encDBManager.EncryptSymmetricKeys(server.K)
		if err != nil {
			fmt.Printf("[服务器] 对称密钥加密失败: %v\n", err)
		}
	}
	encDBManager.SetPrivateKey(server.SK)

	// 获取完整的加密数据库
	fullEncryptedDB := encDBManager.GetEncryptedDatabase()
	
	// 只选择匹配行的加密数据和密钥
	selectedEncryptedRows := make([]core.EncryptedRow, 0, len(selectedRows))
	selectedEncryptedKeys := make([][]byte, 0, len(selectedRows))
	
	for _, rowIdx := range selectedRows {
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
	}
	
	fmt.Printf("[服务器] PIR设置准备完成，选中行数: %d，加密密钥数: %d\n", len(selectedEncryptedRows), len(selectedEncryptedKeys))

	return core.PIRSetup{
		PublicKey:          server.PK,
		EncryptedDB:        selectedEncryptedDB,
		HomomorphicEncKeys: selectedEncryptedKeys,
	}
}

// PIRServer 方法 - 处理PIR查询
func (server *PIRServer) handlePIRQuery(query core.PIRQuery) core.PIRResponse {
	// 创建加密数据库管理器
	encDBManager := core.NewEncryptedDatabaseManager(server.PK, server.SK)

	// Algorithm 3 Online Stage Step 2: S decrypts the result using sk and sends the decrypted result to C
	// 批量解密客户端发送的所有同态运算结果 E(ki + R)
	decryptedResults := encDBManager.DecryptHomomorphicResults(query.HomomorphicResults)

	// 解密结果包含 (ki + R)，将发送给客户端进行进一步处理
	return core.PIRResponse{DecryptedResults: decryptedResults}
}

// 虚拟机配置结构
type VMConfig struct {
	Host     string // 虚拟机IP地址
	User     string // SSH用户名
	Port     string // SSH端口
	KeyPath  string // SSH私钥路径（可选）
	WorkDir  string // 虚拟机工作目录
}

// 支持虚拟机的PIR服务器
type PIRServerVM struct {
	DB       core.Database
	PK       core.HomomorphicPublicKey
	SK       core.HomomorphicPrivateKey
	K        core.SymmetricKeySet
	VMConfig VMConfig
}

// 默认虚拟机配置
func getDefaultVMConfig() VMConfig {
	return VMConfig{
		Host:    "192.168.196.129",         // 默认虚拟机IP
		User:    "milu",                    // 默认用户名
		Port:    "22",                      // 默认SSH端口
		KeyPath: "",                        // 使用默认SSH密钥
		WorkDir: "/home/milu/pir_project",  // 虚拟机工作目录
	}
}

// 在虚拟机中执行S3R协议
func (server *PIRServerVM) realSCProtocolVM(predicate []float64, operators []string) core.SCResult {
	fmt.Printf("[服务器] 开始在虚拟机中执行S3R协议...\n")
	fmt.Printf("[服务器] 虚拟机地址: %s@%s:%s\n", server.VMConfig.User, server.VMConfig.Host, server.VMConfig.Port)

	// 构建谓词值字符串
	predicateStrs := make([]string, len(predicate))
	for i, val := range predicate {
		predicateStrs[i] = fmt.Sprintf("%.6f", val)
	}
	predicateValues := strings.Join(predicateStrs, ",")

	// 构建操作符字符串
	var operatorStr string
	if len(operators) == len(predicate) {
		operatorStr = strings.Join(operators, ",")
	} else {
		defaultOps := make([]string, len(predicate))
		for i := range defaultOps {
			defaultOps[i] = ">="
		}
		operatorStr = strings.Join(defaultOps, ",")
		fmt.Printf("[服务器] 操作符数量不匹配，使用默认操作符: %s\n", operatorStr)
	}

	// 步骤1: 将数据文件传输到虚拟机
	if err := server.transferDataToVM(); err != nil {
		fmt.Printf("[服务器] 数据传输失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	// 步骤2: 在虚拟机中执行S3R协议
	resultFile := "sc_result.csv"
	remoteCmd := fmt.Sprintf(
		"cd %s && python3 s3r.py --features_csv data/data.csv --usecols %s --predicate_values '%s' --predicate_ops '%s' --out %s --dtype float64",
		server.VMConfig.WorkDir, config.GlobalConfig.GetUseColumnsString(), predicateValues, operatorStr, resultFile,
	)

	sshCmd := server.buildSSHCommand(remoteCmd)
	fmt.Printf("[服务器] 执行远程命令: %s\n", sshCmd)

	// 构建SSH命令参数
	var sshArgs []string
	baseArgs := []string{"-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=60"}
	
	if server.VMConfig.KeyPath != "" {
		sshArgs = append([]string{"-i", server.VMConfig.KeyPath, "-p", server.VMConfig.Port}, baseArgs...)
		sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", server.VMConfig.User, server.VMConfig.Host), remoteCmd)
	} else {
		sshArgs = append([]string{"-p", server.VMConfig.Port}, baseArgs...)
		sshArgs = append(sshArgs, fmt.Sprintf("%s@%s", server.VMConfig.User, server.VMConfig.Host), remoteCmd)
	}
	
	// 直接使用ssh命令，不使用bash包装
	cmd := exec.Command("ssh", sshArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] 远程S3R协议执行失败: %v\n输出: %s\n", err, string(output))
		return core.SCResult{SelectedRows: []int{}}
	}

	fmt.Printf("[服务器] S3R协议执行成功\n输出: %s\n", string(output))

	// 步骤3: 从虚拟机获取结果文件
	localResultPath := "../../storage/results/sc_result_vm.csv"
	if err := server.transferResultFromVM(resultFile, localResultPath); err != nil {
		fmt.Printf("[服务器] 结果文件传输失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	// 步骤4: 解析结果文件
	result := server.parseResultFile(localResultPath)
	fmt.Printf("[服务器] 虚拟机S3R协议完成，选中行数: %d\n", len(result.SelectedRows))

	return result
}

// 构建SSH命令
func (server *PIRServerVM) buildSSHCommand(remoteCmd string) string {
	var sshCmd string
	
	if server.VMConfig.KeyPath != "" {
		// 使用指定的私钥文件
		sshCmd = fmt.Sprintf(
			"ssh -i %s -p %s -o StrictHostKeyChecking=no %s@%s '%s'",
			server.VMConfig.KeyPath, server.VMConfig.Port, server.VMConfig.User, server.VMConfig.Host, remoteCmd,
		)
	} else {
		// 使用默认SSH配置
		sshCmd = fmt.Sprintf(
			"ssh -p %s -o StrictHostKeyChecking=no %s@%s '%s'",
			server.VMConfig.Port, server.VMConfig.User, server.VMConfig.Host, remoteCmd,
		)
	}
	
	return sshCmd
}

// 构建SCP命令
func (server *PIRServerVM) buildSCPCommand(localPath, remotePath string, toRemote bool) string {
	var scpCmd string
	
	if server.VMConfig.KeyPath != "" {
		if toRemote {
			scpCmd = fmt.Sprintf(
				"scp -i %s -P %s -o StrictHostKeyChecking=no %s %s@%s:%s",
				server.VMConfig.KeyPath, server.VMConfig.Port, localPath, server.VMConfig.User, server.VMConfig.Host, remotePath,
			)
		} else {
			scpCmd = fmt.Sprintf(
				"scp -i %s -P %s -o StrictHostKeyChecking=no %s@%s:%s %s",
				server.VMConfig.KeyPath, server.VMConfig.Port, server.VMConfig.User, server.VMConfig.Host, remotePath, localPath,
			)
		}
	} else {
		if toRemote {
			scpCmd = fmt.Sprintf(
				"scp -P %s -o StrictHostKeyChecking=no %s %s@%s:%s",
				server.VMConfig.Port, localPath, server.VMConfig.User, server.VMConfig.Host, remotePath,
			)
		} else {
			scpCmd = fmt.Sprintf(
				"scp -P %s -o StrictHostKeyChecking=no %s@%s:%s %s",
				server.VMConfig.Port, server.VMConfig.User, server.VMConfig.Host, remotePath, localPath,
			)
		}
	}
	
	return scpCmd
}

// 将数据文件传输到虚拟机
func (server *PIRServerVM) transferDataToVM() error {
	fmt.Printf("[服务器] 传输数据文件到虚拟机...\n")

	// 创建虚拟机目录结构
	mkdirCmd := fmt.Sprintf("mkdir -p %s/data %s/python-version", server.VMConfig.WorkDir, server.VMConfig.WorkDir)
	
	var sshArgs []string
	if server.VMConfig.KeyPath != "" {
		sshArgs = []string{"-i", server.VMConfig.KeyPath, "-p", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s", server.VMConfig.User, server.VMConfig.Host), mkdirCmd}
	} else {
		sshArgs = []string{"-p", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s", server.VMConfig.User, server.VMConfig.Host), mkdirCmd}
	}
	
	cmd := exec.Command("ssh", sshArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] 创建目录命令输出: %s\n", string(output))
		return fmt.Errorf("创建虚拟机目录失败: %v", err)
	}

	// 传输数据文件
	dataFile := "storage/databases/database.csv"
	remoteDataPath := fmt.Sprintf("%s/data/data.csv", server.VMConfig.WorkDir)
	if err := server.transferFileToVM(dataFile, remoteDataPath); err != nil {
		return fmt.Errorf("传输数据文件失败: %v", err)
	}

	// 传输 S3R 脚本到虚拟机 (使用numpy备用版本进行功能验证)
	s3rScript := "scripts/s3r_secretflow_mock.py"
	remoteS3RPath := fmt.Sprintf("%s/s3r.py", server.VMConfig.WorkDir)
	if err := server.transferFileToVM(s3rScript, remoteS3RPath); err != nil {
		return fmt.Errorf("传输SecretFlow S3R脚本失败: %v", err)
	}

	fmt.Printf("[服务器] 数据文件传输完成\n")
	return nil
}

// 传输单个文件到虚拟机
func (server *PIRServerVM) transferFileToVM(localPath, remotePath string) error {
	fmt.Printf("[服务器] 传输文件: %s -> %s\n", localPath, remotePath)
	
	// 构建SCP命令参数
	var scpArgs []string
	if server.VMConfig.KeyPath != "" {
		scpArgs = []string{"-i", server.VMConfig.KeyPath, "-P", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			localPath, fmt.Sprintf("%s@%s:%s", server.VMConfig.User, server.VMConfig.Host, remotePath)}
	} else {
		scpArgs = []string{"-P", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			localPath, fmt.Sprintf("%s@%s:%s", server.VMConfig.User, server.VMConfig.Host, remotePath)}
	}
	
	cmd := exec.Command("scp", scpArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] SCP输出: %s\n", string(output))
		return fmt.Errorf("文件传输失败: %v", err)
	}

	fmt.Printf("[服务器] 文件传输成功: %s\n", remotePath)
	return nil
}

// 从虚拟机获取结果文件
func (server *PIRServerVM) transferResultFromVM(remoteResultFile, localResultPath string) error {
	fmt.Printf("[服务器] 从虚拟机获取结果文件...\n")

	remoteResultPath := fmt.Sprintf("%s/%s", server.VMConfig.WorkDir, remoteResultFile)
	
	// 构建SCP命令参数
	var scpArgs []string
	if server.VMConfig.KeyPath != "" {
		scpArgs = []string{"-i", server.VMConfig.KeyPath, "-P", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s:%s", server.VMConfig.User, server.VMConfig.Host, remoteResultPath), localResultPath}
	} else {
		scpArgs = []string{"-P", server.VMConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s:%s", server.VMConfig.User, server.VMConfig.Host, remoteResultPath), localResultPath}
	}
	
	// 直接使用scp命令，不使用bash包装
	cmd := exec.Command("scp", scpArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] SCP输出: %s\n", string(output))
		return fmt.Errorf("获取结果文件失败: %v", err)
	}

	fmt.Printf("[服务器] 结果文件获取完成: %s\n", localResultPath)
	return nil
}

// 解析结果文件
func (server *PIRServerVM) parseResultFile(filename string) core.SCResult {
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("[服务器] 打开结果文件失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}
	defer file.Close()

	var selectedRows []int
	scanner := bufio.NewScanner(file)
	
	// 跳过标题行
	if scanner.Scan() {
		// 处理数据行
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			
			parts := strings.Split(line, ",")
			if len(parts) > 0 {
				if rowIndex, err := strconv.Atoi(parts[0]); err == nil {
					selectedRows = append(selectedRows, rowIndex)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("[服务器] 读取结果文件失败: %v\n", err)
		return core.SCResult{SelectedRows: []int{}}
	}

	return core.SCResult{SelectedRows: selectedRows}
}

// 测试虚拟机连接（独立函数）
func testVMConnection(vmConfig VMConfig) error {
	testCmd := "echo 'VM连接测试成功'"
	
	var cmd *exec.Cmd
	if vmConfig.KeyPath != "" {
		cmd = exec.Command("ssh", "-i", vmConfig.KeyPath, "-p", vmConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s", vmConfig.User, vmConfig.Host), testCmd)
	} else {
		cmd = exec.Command("ssh", "-p", vmConfig.Port, "-o", "StrictHostKeyChecking=no", 
			fmt.Sprintf("%s@%s", vmConfig.User, vmConfig.Host), testCmd)
	}
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("虚拟机连接失败: %v, 输出: %s", err, string(output))
	}

	return nil
}

// 处理SC请求（虚拟机版本）
func (server *PIRServerVM) handleSCRequestVM(request core.SCRequest) core.SCResponse {
	result := server.realSCProtocolVM(request.Predicate, request.Operators)
	return core.SCResponse{SelectedRows: result.SelectedRows}
}

// 执行远程S3R协议
func (server *PIRServerVM) executeRemoteS3R(predicate []float64, operators []string) (*core.SCResult, error) {
	fmt.Printf("[服务器] 在虚拟机中执行S3R协议...\n")
	fmt.Printf("[服务器] 虚拟机地址: %s@%s:%s\n", server.VMConfig.User, server.VMConfig.Host, server.VMConfig.Port)

	// 传输数据到虚拟机
	if err := server.transferDataToVM(); err != nil {
		return nil, fmt.Errorf("数据传输失败: %v", err)
	}

	// 构建S3R命令参数
	predicateStr := fmt.Sprintf("[%s]", strings.Join(func() []string {
		strs := make([]string, len(predicate))
		for i, v := range predicate {
			strs[i] = fmt.Sprintf("%.6f", v)
		}
		return strs
	}(), ","))
	
	operatorsStr := fmt.Sprintf("[%s]", strings.Join(func() []string {
		strs := make([]string, len(operators))
		for i, op := range operators {
			strs[i] = fmt.Sprintf("'%s'", op)
		}
		return strs
	}(), ","))

	// 构建S3R命令 - 使用正确的参数格式
	s3rCmd := fmt.Sprintf("cd %s && python3 s3r.py --features_csv data.csv --usecols %s --predicate_values %s --predicate_ops %s --out sc_result.csv --dtype float64", 
		server.VMConfig.WorkDir, config.GlobalConfig.GetUseColumnsString(), predicateStr, operatorsStr)
	
	// 执行S3R协议
	cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", 
		fmt.Sprintf("%s@%s", server.VMConfig.User, server.VMConfig.Host), s3rCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[服务器] S3R执行输出: %s\n", string(output))
		return nil, fmt.Errorf("S3R协议执行失败: %v", err)
	}

	fmt.Printf("[服务器] S3R协议执行完成\n")
	fmt.Printf("[服务器] 输出: %s\n", string(output))

	// 解析结果
	result, err := server.parseS3RResult(string(output))
	if err != nil {
		return nil, fmt.Errorf("解析S3R结果失败: %v", err)
	}

	return result, nil
}

// 解析S3R结果
func (server *PIRServerVM) parseS3RResult(output string) (*core.SCResult, error) {
	// 从虚拟机传输结果文件并解析
	remoteResultFile := "sc_result.csv"
	localResultPath := "../../storage/results/sc_result_vm.csv"
	
	// 传输结果文件
	if err := server.transferResultFromVM(remoteResultFile, localResultPath); err != nil {
		fmt.Printf("[服务器] 传输结果文件失败: %v\n", err)
		return &core.SCResult{SelectedRows: []int{}}, nil
	}
	
	// 解析结果文件
	file, err := os.Open(localResultPath)
	if err != nil {
		fmt.Printf("[服务器] 打开结果文件失败: %v\n", err)
		return &core.SCResult{SelectedRows: []int{}}, nil
	}
	defer file.Close()

	// 解析结果，找出匹配的行索引
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
		fmt.Printf("[服务器] 读取结果文件失败: %v\n", err)
		return &core.SCResult{SelectedRows: []int{}}, nil
	}
	
	return &core.SCResult{SelectedRows: selectedRows}, nil
}

// 运行虚拟机版本的服务器
// RunServerLocal 运行本地模式服务器
// RunServerLocalWithPredicate 运行本地模式服务器，使用自定义谓词值
func RunServerLocalWithPredicate(customPredicate []float64) {
	fmt.Printf("=== PIR协议系统 (本地模式) ===\n")
	fmt.Printf("正在初始化本地服务器...\n\n")

	// 1. 初始化数据库
	fmt.Printf("[服务器] 正在加载数据库...\n")
	dbManager := core.NewDatabaseManager()
	err := dbManager.LoadFromCSV("storage/databases/database.csv")
	if err != nil {
		fmt.Printf("[服务器] 数据库加载失败: %v\n", err)
		return
	}
	database := dbManager.GetDatabase()
	fmt.Printf("[服务器] 数据库加载成功，共 %d 行数据\n", len(database))

	// 2. 生成或加载Paillier密钥对
	var pk *core.PublicKey
	var sk *core.PrivateKey

	privateKeyFile := "../../storage/keys/private_key.gob"
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		fmt.Printf("[服务器] 生成新的Paillier密钥对...\n")
		sk, err = core.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("[服务器] 密钥生成失败: %v\n", err)
			return
		}
		pk = &sk.PublicKey

		// 保存私钥
		err = savePrivateKey(privateKeyFile, sk)
		if err != nil {
			fmt.Printf("[服务器] 私钥保存失败: %v\n", err)
			return
		}
		fmt.Printf("[服务器] 密钥对生成并保存成功\n")
	} else {
		fmt.Printf("[服务器] 加载现有Paillier密钥对...\n")
		sk, err = loadPrivateKey(privateKeyFile)
		if err != nil {
			fmt.Printf("[服务器] 私钥加载失败: %v\n", err)
			return
		}
		pk = &sk.PublicKey
		fmt.Printf("[服务器] 密钥对加载成功\n")
	}

	// 3. 生成对称密钥
	fmt.Printf("[服务器] 生成对称密钥...\n")
	dbManager.GenerateSymmetricKeys()
	symmetricKeys := dbManager.GetSymmetricKeys()
	fmt.Printf("[服务器] 对称密钥生成成功，共 %d 个密钥\n", len(symmetricKeys))

	// 4. 创建通信通道
	scRequestChan := make(chan core.SCRequest)
	scResponseChan := make(chan core.SCResponse)
	pirSetupChan := make(chan core.PIRSetup)
	pirQueryChan := make(chan core.PIRQuery)
	pirResponseChan := make(chan core.PIRResponse)
	completionChan := make(chan bool)

	// 5. 创建PIR服务器实例
	server := &PIRServer{
		DB: database,
		PK: pk,
		SK: sk,
		K:  symmetricKeys,
	}

	// 6. 启动客户端goroutine
	go func() {
		// 模拟客户端行为
		fmt.Printf("[客户端] 开始PIR协议...\n")
		
		// 发送SC请求 - 使用自定义谓词值
		operators := []string{">=", ">=", ">="}
		scRequest := core.SCRequest{
			Predicate: customPredicate,
			Operators: operators,
		}
		scRequestChan <- scRequest
		
		// 接收SC响应
		scResponse := <-scResponseChan
		// 计算实际匹配的行数（非零索引的数量）
		actualMatchCount := 0
		for _, rowIdx := range scResponse.SelectedRows {
			if rowIdx >= 0 { // 有效的行索引
				actualMatchCount++
			}
		}
		fmt.Printf("[客户端] 收到SC响应，匹配行数: %d\n", actualMatchCount)
		
		// 接收PIR设置
		pirSetup := <-pirSetupChan
		fmt.Printf("[客户端] 收到PIR设置数据\n")
		
		// 生成PIR查询 - 实现正确的同态加密查询生成
		pirQuery := generateVMPIRQuery(scResponse.SelectedRows, pirSetup.HomomorphicEncKeys, pirSetup.PublicKey)
		pirQueryChan <- pirQuery
		
		// 接收PIR响应
		pirResponse := <-pirResponseChan
		fmt.Printf("[客户端] 收到PIR响应，解密结果数: %d\n", len(pirResponse.DecryptedResults))
		
		completionChan <- true
	}()

	// 7. 服务器主循环
	fmt.Printf("[服务器] 等待客户端连接...\n")

	// 处理SC协议请求
	scRequest := <-scRequestChan
	fmt.Printf("[服务器] 收到SC请求，谓词: %v，操作符: %v\n", scRequest.Predicate, scRequest.Operators)
	
	scResponse := server.handleSCRequest(scRequest)
	scResponseChan <- scResponse
	fmt.Printf("[服务器] SC协议完成，匹配行数: %d\n", len(scResponse.SelectedRows))

	// 发送PIR设置数据
	setup := server.preparePIRSetup(scResponse.SelectedRows)
	pirSetupChan <- setup
	fmt.Printf("[服务器] PIR设置数据发送完成\n")

	// 处理PIR查询
	pirQuery := <-pirQueryChan
	fmt.Printf("[服务器] 收到PIR查询\n")
	
	pirResponse := server.handlePIRQuery(pirQuery)
	pirResponseChan <- pirResponse
	fmt.Printf("[服务器] PIR查询处理完成\n")

	// 等待完成
	<-completionChan
	fmt.Printf("\n=== PIR协议执行完成 ===\n")
}

// RunServerLocal 运行本地模式服务器
func RunServerLocal() {
	// 使用默认谓词值
	defaultPredicate := []float64{25.0, 30000.0, 3.5}
	RunServerLocalWithPredicate(defaultPredicate)
}

// RunServerVMWithPredicate 运行虚拟机模式服务器，使用自定义谓词值
func RunServerVMWithPredicate(customPredicate []float64) {

	// 初始化虚拟机配置
	vmConfig := getDefaultVMConfig()
	
	// 检查是否存在SSH密钥
	homeDir, _ := os.UserHomeDir()
	defaultKeyPath := fmt.Sprintf("%s/.ssh/id_rsa", homeDir)
	if _, err := os.Stat(defaultKeyPath); err == nil {
		vmConfig.KeyPath = defaultKeyPath
		fmt.Printf("✅ 检测到SSH密钥: %s\n", defaultKeyPath)
	}
	
	// 允许用户自定义虚拟机配置
	fmt.Printf("请输入虚拟机配置 (直接回车使用默认值):\n")
	
	fmt.Printf("虚拟机IP地址 [%s]: ", vmConfig.Host)
	var input string
	fmt.Scanln(&input)
	if input != "" {
		vmConfig.Host = input
	}
	
	fmt.Printf("SSH用户名 [%s]: ", vmConfig.User)
	fmt.Scanln(&input)
	if input != "" {
		vmConfig.User = input
	}
	
	fmt.Printf("SSH端口 [%s]: ", vmConfig.Port)
	fmt.Scanln(&input)
	if input != "" {
		vmConfig.Port = input
	}

	// SSH密钥配置
	if vmConfig.KeyPath != "" {
		fmt.Printf("SSH密钥路径 [%s]: ", vmConfig.KeyPath)
		fmt.Scanln(&input)
		if input != "" {
			vmConfig.KeyPath = input
		}
	} else {
		fmt.Printf("SSH密钥路径 (留空使用密码认证): ")
		fmt.Scanln(&input)
		if input != "" {
			vmConfig.KeyPath = input
		}
	}

	// 测试虚拟机连接
	fmt.Printf("[服务器] 测试虚拟机连接...\n")
	if err := testVMConnection(vmConfig); err != nil {
		fmt.Printf("[服务器] ❌ VM连接测试失败: %v\n", err)
		if vmConfig.KeyPath == "" {
			fmt.Printf("💡 建议运行 setup_ssh_keys.bat 设置SSH密钥认证以避免重复输入密码\n")
		}
		return
	}
	fmt.Printf("[服务器] ✅ VM连接测试成功\n")

	// 初始化数据库
	dbManager := core.NewDatabaseManager()
	err := dbManager.LoadFromCSV("storage/databases/database.csv")
	if err != nil {
		fmt.Printf("[服务器] 数据库加载失败: %v\n", err)
		return
	}
	db := dbManager.GetDatabase()
	fmt.Printf("[服务器] 数据库加载完成，共 %d 行数据\n", len(db))

	// 生成或加载Paillier密钥对
	var pk core.HomomorphicPublicKey
	var sk core.HomomorphicPrivateKey
	
	privateKeyFile := "../../storage/keys/private_key.gob"
	if loadedSK, err := loadPrivateKey(privateKeyFile); err == nil {
		sk = loadedSK
		pk = &loadedSK.PublicKey
		fmt.Printf("[服务器] 从文件加载Paillier密钥对\n")
	} else {
		sk, err = core.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("[服务器] 生成密钥失败: %v\n", err)
			return
		}
		pk = &sk.PublicKey
		if err := savePrivateKey(privateKeyFile, sk); err != nil {
			fmt.Printf("[服务器] 保存私钥失败: %v\n", err)
		}
		fmt.Printf("[服务器] 生成新的Paillier密钥对\n")
	}

	// 生成对称密钥
	symmetricKeys := make([][]byte, len(db))
	for i := range symmetricKeys {
		key := make([]byte, 32)
		rand.Read(key)
		symmetricKeys[i] = key
	}
	K := core.SymmetricKeySet(symmetricKeys)

	// 创建虚拟机服务器实例
	server := &PIRServerVM{
		DB:       db,
		PK:       pk,
		SK:       sk,
		K:        K,
		VMConfig: vmConfig,
	}

	// 测试虚拟机连接
	if err := testVMConnection(server.VMConfig); err != nil {
		fmt.Printf("[服务器] 虚拟机连接测试失败: %v\n", err)
		fmt.Printf("[服务器] 请检查虚拟机配置和网络连接\n")
		return
	}

	fmt.Printf("[服务器] 虚拟机配置完成，等待客户端连接...\n")

	// 创建通信通道
	scRequestChan := make(chan core.SCRequest)
	scResponseChan := make(chan core.SCResponse)
	pirSetupChan := make(chan core.PIRSetup)
	pirQueryChan := make(chan core.PIRQuery)
	pirResponseChan := make(chan core.PIRResponse)
	completionChan := make(chan bool) // 添加完成信号通道

	// 启动客户端 - 使用外部包的函数
	go func() {
		// 模拟客户端行为
		fmt.Printf("[客户端] 开始PIR协议...\n")
		
		// 发送SC请求 - 使用自定义谓词值
		operators := []string{">=", ">=", ">="}
		scRequest := core.SCRequest{
			Predicate: customPredicate,
			Operators: operators,
		}
		scRequestChan <- scRequest
		
		// 接收SC响应
		scResponse := <-scResponseChan
		// 计算实际匹配的行数（非零索引的数量）
		actualMatchCount := 0
		for _, rowIdx := range scResponse.SelectedRows {
			if rowIdx >= 0 { // 有效的行索引
				actualMatchCount++
			}
		}
		fmt.Printf("[客户端] 收到SC响应，匹配行数: %d\n", actualMatchCount)
		
		// 接收PIR设置
		pirSetup := <-pirSetupChan
		fmt.Printf("[客户端] 收到PIR设置数据\n")
		
		// 生成PIR查询 - 实现正确的同态加密查询生成
		pirQuery := generateVMPIRQuery(scResponse.SelectedRows, pirSetup.HomomorphicEncKeys, pirSetup.PublicKey)
		pirQueryChan <- pirQuery
		
		// 接收PIR响应
		pirResponse := <-pirResponseChan
		fmt.Printf("[客户端] 收到PIR响应，解密结果数: %d\n", len(pirResponse.DecryptedResults))
		
		completionChan <- true
	}()

	// 服务器主循环
	fmt.Printf("[服务器] 等待客户端连接...\n")

	// 1. 处理SC协议请求
	scRequest := <-scRequestChan
	scStart := time.Now()
	scResponse := server.handleSCRequestVM(scRequest)
	scTime := time.Since(scStart)
	fmt.Printf("[服务器] SC协议完成 (耗时: %v)\n", scTime)
	scResponseChan <- scResponse

	// 2. 发送PIR设置数据
	setupStart := time.Now()
	standardServer := &PIRServer{
		DB: server.DB,
		PK: server.PK,
		SK: server.SK,
		K:  server.K,
	}
	pirSetup := standardServer.preparePIRSetup(scResponse.SelectedRows)
	setupTime := time.Since(setupStart)
	fmt.Printf("[服务器] PIR设置完成 (耗时: %v)\n", setupTime)
	pirSetupChan <- pirSetup

	// 3. 处理PIR查询
	pirQuery := <-pirQueryChan
	queryStart := time.Now()
	pirResponse := standardServer.handlePIRQuery(pirQuery)
	queryTime := time.Since(queryStart)
	fmt.Printf("[服务器] PIR查询完成，解密结果: %d 个 (耗时: %v)\n", len(pirResponse.DecryptedResults), queryTime)
	pirResponseChan <- pirResponse

	// 服务器性能统计
	fmt.Printf("\n=== 服务器性能统计 ===\n")
	fmt.Printf("SC协议耗时: %v\n", scTime)
	fmt.Printf("PIR设置耗时: %v\n", setupTime)
	fmt.Printf("PIR查询耗时: %v\n", queryTime)

	// 等待客户端完成信号
	<-completionChan
	fmt.Printf("[服务器] 收到完成信号，程序正常退出\n")
}

// RunServerVM 运行虚拟机模式服务器
func RunServerVM() {
	// 使用默认谓词值
	defaultPredicate := []float64{25.0, 30000.0, 3.5}
	RunServerVMWithPredicate(defaultPredicate)
}