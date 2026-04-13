package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// S3RConfig S3R协议配置
type S3RConfig struct {
	// 数据列配置
	DataColumns struct {
		UseColumns []int    `json:"use_columns"` // 使用的列索引 (1-based)
		SkipHeader bool     `json:"skip_header"` // 是否跳过标题行
		DataTypes  []string `json:"data_types"`  // 数据类型
	} `json:"data_columns"`

	// 默认谓词配置
	DefaultPredicate struct {
		Values    []float64 `json:"values"`    // 默认谓词值
		Operators []string  `json:"operators"` // 默认操作符
	} `json:"default_predicate"`

	// 虚拟机配置
	VMConfig struct {
		Host    string `json:"host"`     // 虚拟机IP地址
		User    string `json:"user"`     // SSH用户名
		Port    string `json:"port"`     // SSH端口
		KeyPath string `json:"key_path"` // SSH私钥路径
		WorkDir string `json:"work_dir"` // 虚拟机工作目录
	} `json:"vm_config"`

	// 性能配置
	Performance struct {
		EnableDebugOutput bool `json:"enable_debug_output"` // 是否启用调试输出
		UseMemoryTransfer bool `json:"use_memory_transfer"` // 是否使用内存传输而非临时文件
		BatchSize         int  `json:"batch_size"`          // 批处理大小
	} `json:"performance"`

	// 错误处理配置
	ErrorHandling struct {
		StrictParsing    bool `json:"strict_parsing"`      // 是否严格解析数据
		MaxSkippedRows   int  `json:"max_skipped_rows"`    // 最大跳过行数
		FailOnParseError bool `json:"fail_on_parse_error"` // 解析错误时是否失败
	} `json:"error_handling"`
}

// 全局配置实例
var GlobalConfig *S3RConfig

// 默认配置
func getDefaultConfig() *S3RConfig {
	return &S3RConfig{
		DataColumns: struct {
			UseColumns []int    `json:"use_columns"`
			SkipHeader bool     `json:"skip_header"`
			DataTypes  []string `json:"data_types"`
		}{
			UseColumns: []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, // 默认使用前10列 (跳过ID列)
			SkipHeader: true,
			DataTypes:  []string{"float64", "float64", "float64", "float64", "float64", "float64", "float64", "float64", "float64", "float64"},
		},
		DefaultPredicate: struct {
			Values    []float64 `json:"values"`
			Operators []string  `json:"operators"`
		}{
			Values:    []float64{-1e308, -1e308, -1e308, -1e308, -1e308, -1e308, -1e308, -1e308, -1e308, -1e308},
			Operators: []string{">=", ">=", ">=", ">=", ">=", ">=", ">=", ">=", ">=", ">="},
		},
		VMConfig: struct {
			Host    string `json:"host"`
			User    string `json:"user"`
			Port    string `json:"port"`
			KeyPath string `json:"key_path"`
			WorkDir string `json:"work_dir"`
		}{
			Host:    "192.168.196.129",
			User:    "milu",
			Port:    "22",
			KeyPath: "",
			WorkDir: "/home/milu/pir_project",
		},
		Performance: struct {
			EnableDebugOutput bool `json:"enable_debug_output"`
			UseMemoryTransfer bool `json:"use_memory_transfer"`
			BatchSize         int  `json:"batch_size"`
		}{
			EnableDebugOutput: false,
			UseMemoryTransfer: false,
			BatchSize:         1000,
		},
		ErrorHandling: struct {
			StrictParsing    bool `json:"strict_parsing"`
			MaxSkippedRows   int  `json:"max_skipped_rows"`
			FailOnParseError bool `json:"fail_on_parse_error"`
		}{
			StrictParsing:    true,
			MaxSkippedRows:   10,
			FailOnParseError: false,
		},
	}
}

// LoadConfig 加载配置文件
func LoadConfig(configPath string) error {
	// 如果配置文件不存在，创建默认配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		fmt.Printf("[配置] 配置文件不存在，创建默认配置: %s\n", configPath)
		return CreateDefaultConfig(configPath)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON配置
	config := getDefaultConfig()
	if err := json.Unmarshal(data, config); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}

	GlobalConfig = config
	fmt.Printf("[配置] 配置加载成功: %s\n", configPath)
	return nil
}

// CreateDefaultConfig 创建默认配置文件
func CreateDefaultConfig(configPath string) error {
	// 确保目录存在
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建配置目录失败: %v", err)
	}

	// 生成默认配置
	config := getDefaultConfig()
	GlobalConfig = config

	// 序列化为JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化配置失败: %v", err)
	}

	// 写入文件
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	fmt.Printf("[配置] 默认配置文件已创建: %s\n", configPath)
	return nil
}

// GetUseColumnsString 获取usecols参数字符串
func (c *S3RConfig) GetUseColumnsString() string {
	if len(c.DataColumns.UseColumns) == 0 {
		return "1,2,3" // 默认值
	}

	result := ""
	for i, col := range c.DataColumns.UseColumns {
		if i > 0 {
			result += ","
		}
		result += fmt.Sprintf("%d", col)
	}
	return result
}

// GetOperatorsString 获取操作符参数字符串
func (c *S3RConfig) GetOperatorsString() string {
	if len(c.DefaultPredicate.Operators) == 0 {
		return ">=,>=,>=" // 默认值
	}

	result := ""
	for i, op := range c.DefaultPredicate.Operators {
		if i > 0 {
			result += ","
		}
		result += op
	}
	return result
}

// InitConfig 初始化配置系统
func InitConfig() error {
	configPath := "configs/s3r_config.json"
	return LoadConfig(configPath)
}
