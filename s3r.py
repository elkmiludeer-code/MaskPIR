import spu
import secretflow as sf
import numpy as np
import pdb  # 调试用模块，可设置断点
from joblib import Parallel, delayed  # 用于并行计算（本脚本中未实际使用）
import random  # 用于生成随机操作符

# 关闭已存在的 SecretFlow 环境（如果存在）
sf.shutdown()

# 初始化 SecretFlow 环境，注册两个参与方：'sender'（发送方）和 'receiver'（接收方）
# address='local' 表示在本地模拟多方计算环境
sf.init(['sender', 'receiver'], address='local')

# 定义 SPU（Secure Processing Unit，安全计算单元）的配置
# 使用 cheetah 协议配置，指定两方参与计算
cheetah_config = sf.utils.testing.cluster_def(
    parties=['sender', 'receiver'],  # 参与计算的两方
    runtime_config={
        'protocol': spu.spu_pb2.SEMI2K,  # 使用 SEMI2K 协议（半诚实模型下的两方安全计算协议）
        'field': spu.spu_pb2.FM64,       # 使用 64 位有限域进行计算
        'enable_pphlo_profile': True,    # 启用 PPHLO（隐私保护高级语言）性能分析
        'enable_hal_profile': True,      # 启用 HAL（硬件抽象层）性能分析
    },
)

# 创建 SPU 设备实例，用于执行多方安全计算
spu_device2 = sf.SPU(cheetah_config)

# 将两个参与方映射为 PYU（Private Computing Unit，私有计算单元）对象
# sender 在 'sender' 方执行本地计算，receiver 在 'receiver' 方执行本地计算
sender, receiver = sf.PYU('sender'), sf.PYU('receiver')

# 定义数据规模
n = 1 << 20   # 数据行数：2^20 = 1,048,576 行
dnum = 5      # 特征/条件列数：5 列

# 定义操作符映射字典，每个操作符对应一个二次多项式系数 [常数项, 一次项系数, 二次项系数]
# 该多项式用于将比较结果（0, 1, 2, 3）映射为逻辑真值（近似 1 为真，0 为假）
# 例如：对于 ">"，多项式为 0 + 2*x - 1*x^2，当 x=2 (即大于成立) 时，结果为 0+4-4=0？此处设计需结合 compare 函数理解
# 实际上，compare 函数将 (greater, smaller) 映射为 0~3 的整数，然后多项式将其映射为接近 0 或 1 的值
ops = {
    ">": [0, 2, -1],   # 大于
    ">=": [1, 0.5, -0.5], # 大于等于
    "<": [0, -0.5, 0.5],  # 小于
    "<=": [1, -2, 1],     # 小于等于
    "=": [1, -1.5, 0.5],  # 等于
    "/": [1, 0, 0]        # 默认/占位操作（恒为1？）
}

# 所有支持的比较操作符列表
symbols = [">", "<", "=", ">=", "<=", "/"]

# 定义逻辑连接符（AND/OR）的多项式系数映射
# AND: [0, 1] -> 对应多项式 0*(x+y) + 1*(x*y) = x*y （乘法近似 AND）
# OR: [1, -1] -> 对应多项式 1*(x+y) + (-1)*(x*y) = x + y - x*y （加法减乘法近似 OR）
opsshare = {"AND": [0, 1], "OR": [1, -1]}

# 支持的逻辑连接符列表
conops = ["AND", "OR"]

# 为 dnum 个条件生成随机的比较操作符列表（每个条件一个操作符）
op_list = [random.choice(symbols) for _ in range(dnum)]

# 为 dnum-1 个逻辑连接生成随机的连接符列表（用于连接 dnum 个条件）
con_list = [random.choice(conops) for _ in range(dnum - 1)]

# 生成 dnum 个随机的整数作为谓词（predicate）阈值，数据类型为 int32，范围覆盖整个 int32 区间
predicate_num = np.random.randint(np.iinfo(np.int32).min, np.iinfo(np.int32).max, size=dnum, dtype=np.int32)

# 将谓词阈值数组扩展为 n 行 dnum 列的矩阵，每行内容相同（即每个样本都与相同的阈值比较）
predicate_matrix = np.tile(predicate_num, (n, 1))

# 生成发送方的特征数据：n 行 dnum 列的随机 int32 整数矩阵
sender_features = np.random.randint(np.iinfo(np.int32).min, np.iinfo(np.int32).max, size=(n, dnum), dtype=np.int32)


# 定义大于比较函数
def greater(x, y):
    return (x > y)  # 返回布尔数组

# 定义小于比较函数
def smaller(x, y):
    return (x < y)  # 返回布尔数组

# 定义组合比较函数：将大于和小于的结果编码为一个整数
# 编码规则：result = (greater_result) + (smaller_result << 1)
# 即：0: 都不成立（等于）, 1: 仅大于成立, 2: 仅小于成立, 3: 大于和小于同时成立（理论上不可能，除非数据异常）
def compare(x, y):
    return x.astype(int) + (y.astype(int) << 1)

# 定义减法函数
def sub(x, y):
    return x - y

# 定义多项式评估函数：对第 i 列应用指定操作符 op 的二次多项式
# x: 输入矩阵 (n, dnum)
# i: 列索引
# op: 包含 [常数项, 一次项系数, 二次项系数] 的列表
def poly(x, i, op):
    return op[0] + op[1] * x[:, i] + op[2] * x[:, i] ** 2

# 定义交互多项式函数（用于逻辑 AND/OR）
# x, y: 两个输入（通常是前一个条件的结果和当前条件的结果）
# op: 包含 [线性系数, 乘积系数] 的列表，用于计算 op[0]*(x+y) + op[1]*(x*y)
def im(x, y, op):
    return op[0] * (x + y) + op[1] * (x * y)

# 将操作符映射字典 ops 发送到 receiver 方（虽然函数中又在循环内重新发送，此处可能冗余或用于初始化）
ss_ops = sf.to(receiver, ops)


# 主要函数 1: 执行基础比较
# 功能：对 sender_features 和 predicate_matrix 的每一列执行大于和小于比较，并将结果编码
def COMPARE():
    # 将 sender_features 数据放置到 sender 方
    x = sf.to(sender, sender_features)
    # 将 predicate_matrix 数据放置到 receiver 方
    y = sf.to(receiver, predicate_matrix)
    
    # 在 SPU 上安全地计算 x > y（逐元素比较）
    op_greater = spu_device2(greater)(x, y)
    # 在 SPU 上安全地计算 x < y（逐元素比较）
    op_smaller = spu_device2(smaller)(x, y)
    
    # 在 SPU 上安全地将大于和小于的结果组合编码
    res = spu_device2(compare)(op_greater, op_smaller)
    
    # 返回编码后的比较结果矩阵 (n, dnum)，每个元素是 0, 1, 2, 或 3
    return res


# 主要函数 2: 执行谓词多项式转换 (Predicate Polynomial Transformation)
# 功能：根据预先随机选择的操作符列表 op_list，对 COMPARE 的结果应用对应的二次多项式
# 输入：res - COMPARE 函数的输出 (n, dnum)
def PPT(res):
    ppts = []  # 存储每个条件转换后的结果
    
    # 遍历每一列（即每个条件）
    for i in range(0, dnum):
        if op_list[i] == ">":
            # 将 ">" 操作符对应的多项式系数发送到 receiver 方
            ss_ops = sf.to(receiver, ops[">"])
            # 在 SPU 上应用多项式：poly(res, i, ss_ops)
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
        elif op_list[i] == ">=":
            ss_ops = sf.to(receiver, ops[">="])
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
        elif op_list[i] == "<":
            ss_ops = sf.to(receiver, ops["<"])
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
        elif op_list[i] == "<=":
            ss_ops = sf.to(receiver, ops["<="])
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
        elif op_list[i] == "=":
            ss_ops = sf.to(receiver, ops["="])
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
        else:  # op_list[i] == "/"
            ss_ops = sf.to(receiver, ops["/"])
            ppt = spu_device2(poly)(res, i, ss_ops)
            ppts.append(ppt)
    
    # 返回一个列表，包含 dnum 个数组，每个数组是 (n,) 形状，代表该条件的（近似）真值
    return ppts


# 主要函数 3: 执行交互式合并 (Interactive Merge)
# 功能：根据逻辑连接符列表 con_list，使用 im 函数逐步合并 PPT 的结果
# 输入：ppts - PPT 函数的输出（包含 dnum 个条件的真值数组的列表）
def IM(ppts):
    # 初始化结果为第一个条件的结果
    srres = ppts[0]
    
    # 从第二个条件开始，依次与前面的结果进行逻辑合并
    for i in range(1, dnum):
        if con_list[i - 1] == "AND":
            # 将 "AND" 对应的系数发送到 receiver 方
            ss_ops = sf.to(receiver, opsshare["AND"])
            # 在 SPU 上执行 AND 操作：im(srres, ppts[i], ss_ops) -> 近似为乘法
            srres = spu_device2(im)(srres, ppts[i], ss_ops)
        else:  # con_list[i-1] == "OR"
            ss_ops = sf.to(receiver, opsshare["OR"])
            # 在 SPU 上执行 OR 操作：im(srres, ppts[i], ss_ops) -> 近似为 x + y - x*y
            srres = spu_device2(im)(srres, ppts[i], ss_ops)
    
    # 返回最终的合并结果，一个 (n,) 形状的数组，代表每个样本是否满足整个复合条件（近似真值）
    return srres


# 执行流程：
# 1. 执行基础比较
res = COMPARE()

# 2. 对每个比较结果应用谓词多项式，得到每个条件的（近似）真值
ppts = PPT(res)

# 3. 根据逻辑连接符合并所有条件，得到最终的（近似）真值向量
srres = IM(ppts)

# 生成接收方的随机份额（用于秘密共享）
# 生成 n 个 [0, 65535] 范围内的随机整数
receivershare = np.random.randint(0, 65536, size=n, dtype=np.int32)

# 创建一个全 1 向量，用于后续计算（可能用于调整或校验）
ones_vector = np.ones(n, dtype=np.int32)

# 将接收方的随机份额放置到 receiver 方
spu_receivershare = sf.to(receiver, receivershare)

# 在 SPU 上计算发送方的份额：最终结果减去接收方的份额
# 这实现了加法秘密共享：sendershare + receivershare = srres (mod 某个数，但此处未显式取模)
spu_sendershare = spu_device2(sub)(srres, spu_receivershare)

# 将发送方的份额从 SPU 中揭示（reveal）出来，转换为明文（仅在本地模拟环境下安全）
sendershare = sf.reveal(spu_sendershare)

# 将 sendershare 转换为 int 类型（确保数据类型一致）
sendershare = sendershare.astype(int)

# 计算最终要写入文件的接收方份额：这里似乎是用 1 减去原始随机份额？
# 注意：这可能导致负数或非常大的数，因为 receivershare 是 [0, 65535]，而 ones_vector 是 1。
# 这可能是一个错误，或者是为了某种特定的共享方案（如布尔共享）。通常秘密共享是 sendershare + receivershare = secret。
# 此处操作后，receivershare 变为 1 - 原始随机数，这与 sendershare 相加不再等于 srres。
# 可能意图是生成一个布尔共享或其他，但逻辑与前面的 sub 操作不一致。
receivershare = ones_vector - receivershare

# 将接收方份额写入文件（相对路径，需确保目录存在）
with open('../../bazel-bin/examples/pfrpsi/receivershare', 'w') as file:
    for value in receivershare:
        file.write(f"{value}\n")

# 将发送方份额写入文件（相对路径，需确保目录存在）
with open('../../bazel-bin/examples/pfrpsi/sendershare', 'w') as file:
    for value in sendershare:
        file.write(f"{value}\n")