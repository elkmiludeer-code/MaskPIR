package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	mathrand "math/rand"
)

// ==================== 共享数据结构 ====================

// 向量结构
type Vector []float64

// 数据库行结构
type DatabaseRow struct {
	ID   int
	Data []float64
}

// 数据库结构
type Database []DatabaseRow

// 对称密钥集合
type SymmetricKeySet [][]byte

// 同态加密公钥 - 使用Paillier公钥
type HomomorphicPublicKey = *PublicKey

// 同态加密私钥 - 使用Paillier私钥
type HomomorphicPrivateKey = *PrivateKey

// 加密的行
type EncryptedRow struct {
	EncryptedData []byte `json:"encrypted_data"`
	KeyIndex      int    `json:"key_index"`
}

// 加密的数据库
type EncryptedDatabase struct {
	Rows []EncryptedRow
	Keys SymmetricKeySet
}

// 参与方S的结构（安全比较协议）
type PartyS struct {
	vs     Vector // S的秘密向量
	alpha  Vector
	omega1 Vector
	gamma1 Vector
}

// 参与方C的结构（安全比较协议）
type PartyC struct {
	rho0   float64 // C的秘密值
	k      Vector  // 将rho0扩展为向量
	beta   Vector
	gamma2 Vector
	omega2 Vector
	h      Vector
}

// SC协议结果
type SCResult struct {
	SelectedRows []int
}

// ==================== 通信消息结构 ====================

// SC协议第一步: S -> C
type SC_Round1_Message struct {
	E Vector
}

// SC协议第二步: C -> S
type SC_Round2_Message struct {
	H Vector
}

// SC协议第三步: S -> C
type SC_Round3_Message struct {
	Omega1 Vector
}

// SC协议请求
type SCRequest struct {
	Predicate []float64
	Operators []string // 比较操作符，如 [">=", ">", "<="]
}

// SC协议响应
type SCResponse struct {
	SelectedRows []int
}

// PIR协议消息
type PIRMessage struct {
	Type string      // "pir_setup", "pir_query", "pir_response"
	Data interface{} // 具体的消息数据
}

// PIR设置消息（服务器发送给客户端）
type PIRSetup struct {
	PublicKey          HomomorphicPublicKey
	EncryptedDB        EncryptedDatabase
	SelectedIndices    []int
	HomomorphicEncKeys [][]byte // 同态加密的对称密钥
}

// PIR查询消息（客户端发送给服务器）
type PIRQuery struct {
	HomomorphicResult  []byte   // 单个同态运算结果（向后兼容）
	HomomorphicResults [][]byte // 批量同态运算结果
	RandomMasks        [][]byte // 随机掩码，用于后续去掩码操作
}

// PIR响应消息（服务器发送给客户端）
type PIRResponse struct {
	DecryptedResult  []byte   // 单个解密结果（向后兼容）
	DecryptedResults [][]byte // 批量解密结果
}

// ==================== 向量操作函数 ====================

// 向量加法
func vectorAdd(a, b Vector) Vector {
	result := make(Vector, len(a))
	for i := range a {
		result[i] = a[i] + b[i]
	}
	return result
}

// 向量减法
func vectorSub(a, b Vector) Vector {
	result := make(Vector, len(a))
	for i := range a {
		result[i] = a[i] - b[i]
	}
	return result
}

// 向量逐元素乘法

// 向量逐元素除法
func vectorElementWiseDiv(a, b Vector) (Vector, error) {
	result := make(Vector, len(a))
	for i := range a {
		if math.Abs(b[i]) <= 1e-10 { // 使用浮点数精度检查
			return nil, fmt.Errorf("除数向量的元素 %d 接近零: %e", i, b[i])
		}
		result[i] = a[i] / b[i]
	}
	return result, nil
}

// 创建常数向量
func createConstantVector(value float64, size int) Vector {
	vec := make(Vector, size)
	for i := range vec {
		vec[i] = value
	}
	return vec
}

// 生成满足约束条件的四个向量：α ⊙ β = γ1 + γ2
func generateConstrainedVectors(n int) (Vector, Vector, Vector, Vector) {
	alpha := make(Vector, n)
	beta := make(Vector, n)
	gamma1 := make(Vector, n)
	gamma2 := make(Vector, n)

	for i := 0; i < n; i++ {
		// 随机生成α和β，确保α不为0
		for {
			alpha[i] = mathrand.Float64()*100 - 50 // 范围[-50, 50)
			if math.Abs(alpha[i]) > 1e-10 {
				break
			}
		}
		beta[i] = mathrand.Float64()*100 - 50

		// 计算α[i] * β[i]
		product := alpha[i] * beta[i]

		// 随机分配给γ1和γ2，使得γ1[i] + γ2[i] = product
		gamma1[i] = mathrand.Float64()*100 - 50
		gamma2[i] = product - gamma1[i]
	}

	return alpha, beta, gamma1, gamma2
}

// ==================== JSON序列化支持 ====================

// MarshalJSON 自定义JSON序列化，将EncryptedData编码为base64
func (er *EncryptedRow) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"encrypted_data": base64.StdEncoding.EncodeToString(er.EncryptedData),
		"key_index":      er.KeyIndex,
	})
}

// UnmarshalJSON 自定义JSON反序列化，将base64字符串解码为EncryptedData
func (er *EncryptedRow) UnmarshalJSON(data []byte) error {
	var temp map[string]interface{}
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	
	// 处理encrypted_data字段
	if encDataStr, ok := temp["encrypted_data"].(string); ok {
		// 尝试base64解码
		if decoded, err := base64.StdEncoding.DecodeString(encDataStr); err == nil {
			er.EncryptedData = decoded
		} else {
			// 如果base64解码失败，尝试使用latin-1编码转换
			er.EncryptedData = []byte(encDataStr)
		}
	}
	
	// 处理key_index字段
	if keyIndex, ok := temp["key_index"].(float64); ok {
		er.KeyIndex = int(keyIndex)
	}
	
	return nil
}

// ==================== 密码学函数 ====================

// 注意：对称加密和解密的实际实现已移至 aes.go 文件中
// 使用 SymmetricEncrypt 和 SymmetricDecrypt 函数，基于 AES-GCM 模式
