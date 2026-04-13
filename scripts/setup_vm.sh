#!/bin/bash

# PIR协议虚拟机自动化配置脚本
# 用于在Ubuntu虚拟机中快速部署S3R协议环境

set -e  # 遇到错误时退出

echo "=== PIR协议虚拟机配置脚本 ==="
echo "本脚本将在Ubuntu虚拟机中配置S3R协议运行环境"
echo

# 检查是否为root用户
if [[ $EUID -eq 0 ]]; then
   echo "请不要以root用户运行此脚本"
   exit 1
fi

# 获取虚拟机配置信息
read -p "请输入虚拟机IP地址 [192.168.1.100]: " VM_IP
VM_IP=${VM_IP:-192.168.1.100}

read -p "请输入SSH用户名 [ubuntu]: " VM_USER
VM_USER=${VM_USER:-ubuntu}

read -p "请输入SSH端口 [22]: " VM_PORT
VM_PORT=${VM_PORT:-22}

echo
echo "配置信息:"
echo "  虚拟机IP: $VM_IP"
echo "  SSH用户: $VM_USER"
echo "  SSH端口: $VM_PORT"
echo

read -p "确认配置信息是否正确? (y/N): " confirm
if [[ ! $confirm =~ ^[Yy]$ ]]; then
    echo "配置已取消"
    exit 0
fi

echo
echo "=== 步骤1: 测试虚拟机连接 ==="
if ssh -p $VM_PORT -o ConnectTimeout=5 -o StrictHostKeyChecking=no $VM_USER@$VM_IP "echo '连接测试成功'"; then
    echo "✓ 虚拟机连接正常"
else
    echo "✗ 虚拟机连接失败，请检查网络配置和SSH服务"
    exit 1
fi

echo
echo "=== 步骤2: 更新虚拟机系统 ==="
ssh -p $VM_PORT $VM_USER@$VM_IP "sudo apt update && sudo apt upgrade -y"
echo "✓ 系统更新完成"

echo
echo "=== 步骤3: 安装必要软件 ==="
ssh -p $VM_PORT $VM_USER@$VM_IP "sudo apt install -y python3 python3-pip git openssh-server curl wget"
echo "✓ 基础软件安装完成"

echo
echo "=== 步骤4: 安装Python依赖 ==="
ssh -p $VM_PORT $VM_USER@$VM_IP "pip3 install numpy pandas --user"
echo "✓ Python依赖安装完成"

echo
echo "=== 步骤5: 创建工作目录 ==="
ssh -p $VM_PORT $VM_USER@$VM_IP "mkdir -p ~/s3r-protocol/data ~/s3r-protocol/python-version ~/s3r-protocol/results"
echo "✓ 工作目录创建完成"

echo
echo "=== 步骤6: 传输S3R协议文件 ==="
# 检查本地文件是否存在
if [[ ! -f "../python-version/s3r.py" ]]; then
    echo "✗ 本地S3R脚本文件不存在: ../python-version/s3r.py"
    exit 1
fi

if [[ ! -f "../data/data.csv" ]]; then
    echo "✗ 本地数据文件不存在: ../data/data.csv"
    exit 1
fi

# 传输文件
scp -P $VM_PORT ../python-version/s3r.py $VM_USER@$VM_IP:~/s3r-protocol/python-version/
scp -P $VM_PORT ../data/data.csv $VM_USER@$VM_IP:~/s3r-protocol/data/
echo "✓ 文件传输完成"

echo
echo "=== 步骤7: 测试S3R协议 ==="
ssh -p $VM_PORT $VM_USER@$VM_IP "cd ~/s3r-protocol && python3 python-version/s3r.py --features_csv data/data.csv --usecols 1,2,3 --predicate_values '50,2,49999' --predicate_ops '>=,>=,>=' --out results/test_result.csv --dtype float64"

if ssh -p $VM_PORT $VM_USER@$VM_IP "test -f ~/s3r-protocol/results/test_result.csv"; then
    echo "✓ S3R协议测试成功"
    
    # 显示测试结果
    echo
    echo "测试结果:"
    ssh -p $VM_PORT $VM_USER@$VM_IP "head -10 ~/s3r-protocol/results/test_result.csv"
else
    echo "✗ S3R协议测试失败"
    exit 1
fi

echo
echo "=== 步骤8: 配置SSH免密登录 (可选) ==="
read -p "是否配置SSH免密登录? (y/N): " setup_ssh
if [[ $setup_ssh =~ ^[Yy]$ ]]; then
    # 检查本地是否有SSH密钥
    if [[ ! -f ~/.ssh/id_rsa.pub ]]; then
        echo "生成SSH密钥对..."
        ssh-keygen -t rsa -b 4096 -C "pir-protocol" -f ~/.ssh/id_rsa -N ""
    fi
    
    # 复制公钥到虚拟机
    ssh-copy-id -p $VM_PORT $VM_USER@$VM_IP
    
    # 测试免密登录
    if ssh -p $VM_PORT $VM_USER@$VM_IP "echo '免密登录测试成功'" >/dev/null 2>&1; then
        echo "✓ SSH免密登录配置成功"
    else
        echo "✗ SSH免密登录配置失败"
    fi
fi

echo
echo "=== 步骤9: 创建虚拟机配置文件 ==="
cat > vm_config.txt << EOF
# PIR协议虚拟机配置
VM_HOST=$VM_IP
VM_USER=$VM_USER
VM_PORT=$VM_PORT
VM_WORKDIR=~/s3r-protocol
SETUP_DATE=$(date)
EOF
echo "✓ 配置文件已保存到 vm_config.txt"

echo
echo "=== 配置完成 ==="
echo "虚拟机S3R协议环境配置成功！"
echo
echo "使用方法:"
echo "1. 运行虚拟机模式: go run . vm"
echo "2. 或使用新的主程序: go run main_vm.go vm"
echo
echo "配置信息已保存到 vm_config.txt 文件中"
echo "您现在可以在Go程序中使用虚拟机模式运行S3R协议"

echo
echo "=== 验证配置 ==="
echo "正在进行最终验证..."

# 最终验证
if ssh -p $VM_PORT $VM_USER@$VM_IP "cd ~/s3r-protocol && python3 --version && python3 -c 'import numpy, pandas; print(\"Python依赖正常\")' && ls -la python-version/s3r.py data/data.csv" >/dev/null 2>&1; then
    echo "✓ 所有配置验证通过"
    echo
    echo "🎉 虚拟机配置完成！现在可以使用虚拟机模式运行PIR协议了。"
else
    echo "✗ 配置验证失败，请检查虚拟机环境"
    exit 1
fi