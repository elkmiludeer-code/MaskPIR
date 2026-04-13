# 本地虚拟机运行S3R协议配置指南

## 概述
本指南将帮助您在本地虚拟机中配置和运行真正的S3R（Secure Scalar Comparison）协议，实现分布式的安全比较计算。

## 系统要求

### 虚拟机配置
- **操作系统**: Ubuntu 20.04 LTS 或更高版本
- **内存**: 至少 4GB RAM
- **存储**: 至少 20GB 可用空间
- **网络**: 支持SSH和HTTP通信

### 软件依赖
- Python 3.8+
- NumPy
- pandas
- SSH服务器
- Git

## 配置步骤

### 1. 虚拟机网络配置

#### 方案A: 桥接模式（推荐）
```bash
# 在虚拟机中配置静态IP
sudo nano /etc/netplan/01-netcfg.yaml

# 示例配置
network:
  version: 2
  ethernets:
    enp0s3:
      dhcp4: no
      addresses: [192.168.1.100/24]
      gateway4: 192.168.1.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]

# 应用配置
sudo netplan apply
```

#### 方案B: NAT + 端口转发
```bash
# 在VirtualBox中设置端口转发
# 主机端口 2222 -> 虚拟机端口 22 (SSH)
# 主机端口 8080 -> 虚拟机端口 8080 (S3R服务)
```

### 2. 虚拟机环境准备

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装必要软件
sudo apt install -y python3 python3-pip git openssh-server

# 安装Python依赖
pip3 install numpy pandas

# 启用SSH服务
sudo systemctl enable ssh
sudo systemctl start ssh

# 创建工作目录
mkdir -p ~/s3r-protocol
cd ~/s3r-protocol
```

### 3. 部署S3R协议代码

```bash
# 复制Python版本的S3R代码到虚拟机
# 方法1: 使用SCP从主机复制
scp -r /path/to/python-version user@vm-ip:~/s3r-protocol/

# 方法2: 在虚拟机中直接创建
mkdir -p python-version
cd python-version
```

### 4. 修改Go代码以支持远程S3R调用

在主机的 `server.go` 中修改 `realSCProtocol` 函数：

```go
func (server *PIRServer) realSCProtocol(predicate []float64, operators []string) SCResult {
    // 配置虚拟机连接信息
    vmHost := "192.168.1.100"  // 虚拟机IP地址
    vmUser := "username"       // 虚拟机用户名
    vmPort := "22"            // SSH端口
    
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
    }
    
    // 通过SSH执行远程S3R协议
    sshCmd := fmt.Sprintf(
        "ssh -p %s %s@%s 'cd ~/s3r-protocol && python3 python-version/s3r.py --features_csv data.csv --usecols 1,2,3 --predicate_values %s --predicate_ops %s --out sc_result.csv --dtype float64'",
        vmPort, vmUser, vmHost, predicateValues, operatorStr,
    )
    
    cmd := exec.Command("bash", "-c", sshCmd)
    output, err := cmd.CombinedOutput()
    if err != nil {
        fmt.Printf("[服务器] 远程S3R协议执行失败: %v\n输出: %s\n", err, string(output))
        return SCResult{SelectedRows: []int{}}
    }
    
    // 从虚拟机复制结果文件
    scpCmd := fmt.Sprintf("scp -P %s %s@%s:~/s3r-protocol/sc_result.csv ../shared/test_results/", vmPort, vmUser, vmHost)
    exec.Command("bash", "-c", scpCmd).Run()
    
    // 解析结果文件
    return server.parseResultFile("../shared/test_results/sc_result.csv")
}
```

### 5. 配置SSH免密登录

在主机上生成SSH密钥并配置免密登录：

```bash
# 在主机上生成SSH密钥对
ssh-keygen -t rsa -b 4096 -C "s3r-protocol"

# 将公钥复制到虚拟机
ssh-copy-id -p 22 username@192.168.1.100

# 测试连接
ssh -p 22 username@192.168.1.100 "echo 'SSH连接成功'"
```

### 6. 数据同步配置

```bash
# 在虚拟机中创建数据目录
mkdir -p ~/s3r-protocol/data

# 从主机同步数据文件
scp -P 22 ../data/data.csv username@192.168.1.100:~/s3r-protocol/data/
```

## 测试验证

### 1. 本地测试
```bash
# 在虚拟机中测试S3R脚本
cd ~/s3r-protocol
python3 python-version/s3r.py --features_csv data/data.csv --usecols 1,2,3 --predicate_values "50,2,49999" --predicate_ops ">=,>=,>=" --out sc_result.csv --dtype float64
```

### 2. 远程调用测试
```bash
# 在主机上测试远程调用
ssh username@192.168.1.100 'cd ~/s3r-protocol && python3 python-version/s3r.py --features_csv data/data.csv --usecols 1,2,3 --predicate_values "50,2,49999" --predicate_ops ">=,>=,>=" --out sc_result.csv --dtype float64'
```

### 3. 完整流程测试
```bash
# 在主机上运行Go程序，验证虚拟机S3R协议调用
cd go-version
go run .
```

## 性能优化建议

### 1. 网络优化
- 使用有线网络连接
- 配置合适的MTU大小
- 启用网络压缩

### 2. 虚拟机优化
```bash
# 增加虚拟机CPU核心数
# 分配更多内存
# 启用硬件加速
```

### 3. SSH优化
```bash
# 在 ~/.ssh/config 中添加配置
Host s3r-vm
    HostName 192.168.1.100
    User username
    Port 22
    Compression yes
    ServerAliveInterval 60
    ServerAliveCountMax 3
```

## 故障排除

### 常见问题

1. **SSH连接失败**
   ```bash
   # 检查虚拟机SSH服务状态
   sudo systemctl status ssh
   
   # 检查防火墙设置
   sudo ufw status
   ```

2. **Python脚本执行失败**
   ```bash
   # 检查Python环境
   python3 --version
   pip3 list | grep -E "(numpy|pandas)"
   
   # 检查文件权限
   ls -la ~/s3r-protocol/python-version/s3r.py
   ```

3. **网络连通性问题**
   ```bash
   # 测试网络连接
   ping 192.168.1.100
   
   # 测试端口连通性
   telnet 192.168.1.100 22
   ```

## 安全注意事项

1. **SSH安全配置**
   - 禁用密码登录，仅使用密钥认证
   - 更改默认SSH端口
   - 配置防火墙规则

2. **数据保护**
   - 加密传输敏感数据
   - 定期备份重要文件
   - 限制虚拟机网络访问权限

3. **访问控制**
   - 创建专用用户账户
   - 配置最小权限原则
   - 监控系统日志

## 扩展配置

### 多虚拟机部署
可以配置多个虚拟机实现真正的分布式S3R协议：

```bash
# 虚拟机1: 数据提供方
VM1_IP=192.168.1.100

# 虚拟机2: 查询方
VM2_IP=192.168.1.101

# 虚拟机3: 计算协调方
VM3_IP=192.168.1.102
```

### 容器化部署
使用Docker容器简化部署：

```dockerfile
FROM ubuntu:20.04
RUN apt-get update && apt-get install -y python3 python3-pip openssh-server
RUN pip3 install numpy pandas
COPY python-version/ /app/
WORKDIR /app
EXPOSE 22 8080
CMD ["/usr/sbin/sshd", "-D"]
```

通过以上配置，您可以在本地虚拟机中成功运行真正的S3R协议，实现分布式的安全比较计算。