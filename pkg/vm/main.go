package vm

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/water/pir-system/pkg/config"
)

func RunVMMain() {
	// 初始化配置系统
	if err := config.InitConfig(); err != nil {
		fmt.Printf("配置初始化失败: %v\n", err)
		os.Exit(1)
	}

	// 检查命令行参数
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	mode := os.Args[1]
	switch mode {
	case "local":
		if len(os.Args) > 2 {
			// 使用自定义谓词值
			predicate := parsePredicateArgs(os.Args[2:])
			RunServerLocalWithPredicate(predicate)
		} else {
			// 使用默认谓词值
			RunServerLocal()
		}
	case "vm":
		if len(os.Args) > 2 {
			// 使用自定义谓词值
			predicate := parsePredicateArgs(os.Args[2:])
			RunServerVMWithPredicate(predicate)
		} else {
			// 使用默认谓词值
			RunServerVM()
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("错误: 未知模式 '%s'\n", mode)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
    cols := len(config.GlobalConfig.DataColumns.UseColumns)
    if cols == 0 { cols = 3 }
    fmt.Printf("\n使用方法:\n")
    fmt.Printf("  go run . [模式] [谓词值x%d]\n\n", cols)
	fmt.Printf("可用模式:\n")
	fmt.Printf("  local, 1     - 本地模式，在本机运行S3R协议\n")
	fmt.Printf("  vm, 2        - 虚拟机模式，在本地虚拟机中运行S3R协议\n")
	fmt.Printf("  help         - 显示此帮助信息\n\n")
    fmt.Printf("谓词值 (可选):\n")
    fmt.Printf("  与配置的列数一致的数值，用于数据库查询条件\n")
    fmt.Printf("  默认按配置长度应用 \">=\" 操作符\n\n")
	fmt.Printf("示例:\n")
	fmt.Printf("  go run .                    # 交互式选择模式\n")
	fmt.Printf("  go run . local              # 直接启动本地模式\n")
	fmt.Printf("  go run . vm                 # 直接启动虚拟机模式\n")
    fmt.Printf("  go run . local 50 2 49999   # 本地模式，自定义谓词值\n")
    fmt.Printf("  go run . vm 30 15000 2.5    # 虚拟机模式，自定义谓词值\n")
	fmt.Printf("  go run . help               # 显示帮助信息\n\n")
	fmt.Printf("虚拟机模式配置:\n")
	fmt.Printf("  在虚拟机模式下，程序会提示您输入虚拟机的连接信息，\n")
	fmt.Printf("  包括IP地址、SSH用户名和端口等。请确保:\n")
	fmt.Printf("  1. 虚拟机已启动并可通过SSH访问\n")
	fmt.Printf("  2. 虚拟机中已安装Python3和必要的依赖包\n")
	fmt.Printf("  3. 已配置SSH免密登录或提供正确的认证信息\n")
}

// 解析命令行谓词参数
func parsePredicateArgs(args []string) []float64 {
    cols := len(config.GlobalConfig.DataColumns.UseColumns)
    if cols == 0 { cols = 3 }
    if len(args) != cols {
        fmt.Printf("错误: 谓词值需要恰好%d个数值参数\n", cols)
        printUsage()
        os.Exit(1)
    }

    predicate := make([]float64, cols)
    for i, arg := range args {
        val, err := strconv.ParseFloat(arg, 64)
        if err != nil {
            fmt.Printf("错误: 无法解析谓词值 '%s': %v\n", arg, err)
            printUsage()
            os.Exit(1)
        }
        predicate[i] = val
    }
    fmt.Printf("使用自定义谓词值: %v\n", predicate)
    return predicate
}

// 交互式输入谓词值
func promptForPredicate() []float64 {
    cols := len(config.GlobalConfig.DataColumns.UseColumns)
    if cols == 0 { cols = 3 }
    fmt.Printf("请输入%d个谓词值 (用空格分隔): ", cols)
    var input string
    fmt.Scanln(&input)

    parts := strings.Fields(input)
    if len(parts) != cols {
        fmt.Printf("错误: 需要恰好%d个数值，您输入了 %d 个\n", cols, len(parts))
        return promptForPredicate() // 递归重新输入
    }

    predicate := make([]float64, cols)
    for i, part := range parts {
        val, err := strconv.ParseFloat(part, 64)
        if err != nil {
            fmt.Printf("错误: 无法解析数值 '%s': %v\n", part, err)
            return promptForPredicate() // 递归重新输入
        }
        predicate[i] = val
    }
    fmt.Printf("使用自定义谓词值: %v\n", predicate)
    return predicate
}
