import argparse
import os
import numpy as np
# import secretflow as sf
# import spu

# 关闭已存在的 SecretFlow 环境（如果存在）
# sf.shutdown()

# 初始化 SecretFlow 环境，注册两个参与方：'sender'（服务器：提供 features）和 'receiver'（客户端：提供 predicate）
# sf.init(['sender', 'receiver'], address='local')

# 定义 SPU 配置（两方协议）
# cheetah_config = sf.utils.testing.cluster_def(
#     parties=['sender', 'receiver'],
#     runtime_config={
#         'protocol': spu.spu_pb2.SEMI2K,
#         'field': spu.spu_pb2.FM64,
#         'enable_pphlo_profile': False,
#         'enable_hal_profile': False,
#     },
# )
# spu_device = sf.SPU(cheetah_config)

# 定义双方设备
# sender, receiver = sf.PYU('sender'), sf.PYU('receiver')

# 比较函数（纯本地 numpy 实现）

def cmp_gt(x, y):
    return (x > y).astype(np.int32)

def cmp_ge(x, y):
    return (x >= y).astype(np.int32)

def cmp_lt(x, y):
    return (x < y).astype(np.int32)

def cmp_le(x, y):
    return (x <= y).astype(np.int32)

def cmp_eq(x, y):
    return (x == y).astype(np.int32)

OP_MAP = {
    '>': cmp_gt,
    '>=': cmp_ge,
    '<': cmp_lt,
    '<=': cmp_le,
    '=': cmp_eq,
    '==': cmp_eq,  # 支持双等号
}


def parse_args():
    parser = argparse.ArgumentParser(description='Local numpy comparison: features vs predicate per column')
    parser.add_argument('--features_csv', required=True, help='CSV 文件路径（服务器端数据库），例如 ../data/data.csv')
    parser.add_argument('--usecols', default='1,2,3', help='读取 CSV 的列索引（从0开始），逗号分隔，默认 1,2,3')
    parser.add_argument('--predicate_values', required=True, help='客户端谓词值，逗号分隔，例如 50,2,49999.0')
    parser.add_argument('--predicate_ops', required=False, help='每列比较操作符，逗号分隔（>,>=,<,<=,=），长度与列数一致；默认全部 ">="')
    parser.add_argument('--out', required=True, help='结果矩阵输出文件路径（CSV，0/1）')
    parser.add_argument('--dtype', default='float64', choices=['int32','float32','float64'], help='特征与谓词的数据类型')
    return parser.parse_args()


def load_features(csv_path: str, usecols: str, dtype: str):
    cols = [int(x) for x in usecols.split(',') if x.strip() != '']
    # 跳过表头行；读取指定列
    np_dtype = {'int32': np.int32, 'float32': np.float32, 'float64': np.float64}[dtype]
    data = np.genfromtxt(csv_path, delimiter=',', skip_header=1, usecols=cols, dtype=np_dtype)
    # 保证二维矩阵形状 (n, d)
    if data.ndim == 1:
        data = data.reshape(-1, 1)
    return data


def build_predicate_matrix(values_str: str, n_rows: int, d_cols: int, dtype: str):
    # 解析谓词值
    vals = [float(x) for x in values_str.split(',')]
    if len(vals) != d_cols:
        raise ValueError(f'predicate_values 列数不匹配，期望 {d_cols}，实际 {len(vals)}')
    np_dtype = {'int32': np.int32, 'float32': np.float32, 'float64': np.float64}[dtype]
    v = np.array(vals, dtype=np_dtype)
    return np.tile(v, (n_rows, 1))


def parse_ops(ops_str: str, d_cols: int):
    if ops_str is None or ops_str.strip() == '':
        return ['>='] * d_cols
    ops = [x.strip() for x in ops_str.split(',')]
    if len(ops) != d_cols:
        raise ValueError(f'predicate_ops 列数不匹配，期望 {d_cols}，实际 {len(ops)}')
    for op in ops:
        if op not in OP_MAP:
            raise ValueError(f'不支持的操作符: {op}')
    return ops


def main():
    args = parse_args()

    # 加载特征矩阵（服务器侧）
    features = load_features(args.features_csv, args.usecols, args.dtype)
    n, d = features.shape

    # 构造谓词矩阵（客户端侧）
    predicate = build_predicate_matrix(args.predicate_values, n, d, args.dtype)
    ops = parse_ops(args.predicate_ops, d)

    # 纯本地 numpy 计算：逐列比较
    col_results = []
    for i, op in enumerate(ops):
        # 取第 i 列进行比较
        xi = features[:, i]
        yi = predicate[:, i]
        res_i = OP_MAP[op](xi, yi)
        col_results.append(res_i)

    # 将列结果拼为矩阵 (n, d)，然后进行逻辑AND操作
    res_matrix = np.stack(col_results, axis=1)
    # 只有所有列都满足条件时才返回1（逻辑AND）
    final_result = np.all(res_matrix, axis=1).astype(np.int32)

    # 保存为单列 0/1 CSV
    out_dir = os.path.dirname(args.out)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)
    np.savetxt(args.out, final_result, delimiter=',', fmt='%d')

    # 同时打印基本信息（使用英文避免编码问题）
    print(f"[s3r] Comparison completed: samples={n}, columns={d}, output={args.out}")


if __name__ == '__main__':
    main()