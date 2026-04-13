#!/usr/bin/env python3
"""
S3R协议 - SPU版本
保持原scripts/s3r_secretflow.py的命令行与功能不变：
- 读取CSV指定列
- 按给定谓词逐列进行安全比较
- 对所有列按逻辑AND合并
- 输出0/1向量到CSV
"""
import argparse, sys, os, gc
import numpy as np
import pandas as pd
import secretflow as sf
import spu


def setup_spu():
    """初始化SecretFlow与SPU设备"""
    try:
        try:
            sf.shutdown()
        except Exception:
            pass
        sf.init(['sender', 'receiver'], address='local')
        cheetah = sf.utils.testing.cluster_def(
            parties=['sender', 'receiver'],
            runtime_config={
                'protocol': spu.spu_pb2.SEMI2K,
                'field': spu.spu_pb2.FM32,
                'enable_pphlo_profile': False,
                'enable_hal_profile': False,
            },
        )
        spu_dev = sf.SPU(cheetah)
        sender = sf.PYU('sender')
        receiver = sf.PYU('receiver')
        return spu_dev, sender, receiver
    except Exception as e:
        raise RuntimeError(f'SPU初始化失败: {e}')


def _ge(x, y):
    return x >= y


def _gt(x, y):
    return x > y


def _le(x, y):
    return x <= y


def _lt(x, y):
    return x < y


def _eq(x, y):
    return x == y


def _ne(x, y):
    return x != y


def secure_compare_spu(spu_dev, sender_dev, receiver_dev, column, pred_val, op):
    """在SPU上对单列数据与谓词值进行安全比较，返回0/1向量"""
    # 将数据分布到两方
    x = sf.to(sender_dev, column)
    y_arr = np.full(column.shape[0], pred_val, dtype=column.dtype)
    y = sf.to(receiver_dev, y_arr)

    if op == '>=':
        res = spu_dev(_ge)(x, y)
    elif op == '>':
        res = spu_dev(_gt)(x, y)
    elif op == '<=':
        res = spu_dev(_le)(x, y)
    elif op == '<':
        res = spu_dev(_lt)(x, y)
    elif op in ('==', '='):
        res = spu_dev(_eq)(x, y)
    elif op == '!=':
        res = spu_dev(_ne)(x, y)
    else:
        raise ValueError(f'不支持的操作符: {op}')

    return np.array(sf.reveal(res), dtype=int)


def main():
    parser = argparse.ArgumentParser(description='S3R协议 - SPU版本')
    parser.add_argument('--features_csv', required=True, help='CSV 文件路径（服务器端数据库）')
    parser.add_argument('--usecols', default='1,2,3', help='读取 CSV 的列索引（从0开始），逗号分隔')
    parser.add_argument('--predicate_values', required=True, help='客户端谓词值，逗号分隔')
    parser.add_argument('--predicate_ops', required=False, help='每列比较操作符，逗号分隔（>,>=,<,<=,=,!=），长度与列数一致；默认全部 ">="')
    parser.add_argument('--out', required=True, help='结果矩阵输出文件路径（CSV，0/1）')
    parser.add_argument('--dtype', default='float32', choices=['int32', 'float32', 'float64'], help='特征与谓词的数据类型')
    parser.add_argument('--chunksize', type=int, default=0, help='分块读取大小（行数），0表示不分块读取')
    args = parser.parse_args()

    # 解析列索引
    try:
        cols = [int(x) for x in args.usecols.split(',') if x.strip() != '']
    except Exception as e:
        print(f'错误：无法解析列索引 "{args.usecols}": {e}')
        sys.exit(1)

    # 加载CSV并取列（支持分块）
    dtype_map = {'int32': np.int32, 'float32': np.float32, 'float64': np.float64}
    np_dtype = dtype_map[args.dtype]
    total_rows = 0

    # 谓词值与操作符
    try:
        pred_vals = [dtype_map[args.dtype](x.strip()) for x in args.predicate_values.split(',')]
    except Exception as e:
        print(f'错误：无法解析谓词值 "{args.predicate_values}": {e}')
        sys.exit(1)
    ops = [x.strip() for x in args.predicate_ops.split(',')] if args.predicate_ops else ['>='] * len(pred_vals)

    # 仅检查谓词值数量与列数一致（列数直接来自 usecols 长度）
    if len(pred_vals) != len(cols):
        print(f'错误：谓词值数量({len(pred_vals)})与列数({len(cols)})不匹配')
        sys.exit(1)
    if len(ops) != len(pred_vals):
        print(f'错误：操作符数量({len(ops)})与谓词值数量({len(pred_vals)})不匹配')
        sys.exit(1)
    valid_ops = {'>', '<', '>=', '<=', '==', '!=', '='}
    for op in ops:
        if op not in valid_ops:
            print(f'错误：不支持的操作符 "{op}"。支持: {sorted(valid_ops)}')
            sys.exit(1)

    spu_dev, sender_dev, receiver_dev = None, None, None
    try:
        spu_dev, sender_dev, receiver_dev = setup_spu()
        # 输出目录准备
        out_dir = os.path.dirname(args.out)
        if out_dir and not os.path.exists(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        # 清空输出文件
        open(args.out, 'w').close()

        if args.chunksize and args.chunksize > 0:
            # 分块读取处理，降低内存占用
            reader = pd.read_csv(
                args.features_csv,
                usecols=cols,
                dtype=np_dtype,
                chunksize=args.chunksize
            )
            match_cnt = 0
            for chunk_idx, df_chunk in enumerate(reader, start=1):
                selected = df_chunk.values.astype(np_dtype)
                n_rows = selected.shape[0]
                total_rows += n_rows
                final = np.ones(n_rows, dtype=int)
                for i, (pv, op) in enumerate(zip(pred_vals, ops)):
                    col = selected[:, i]
                    print(f'分块{chunk_idx} 处理第{i+1}列: {len(col)} 个值，谓词 {op} {pv}')
                    res = secure_compare_spu(spu_dev, sender_dev, receiver_dev, col, pv, op)
                    final &= res
                # 追加写出结果
                with open(args.out, 'a') as f:
                    for v in final:
                        f.write(f"{int(v)}\n")
                match_cnt += int(final.sum())
                # 主动释放内存
                del selected, final
                gc.collect()
            print(f'S3R协议执行完成: 样本数={total_rows}, 列数={len(cols)}, 匹配行数={match_cnt}')
            print(f'结果已保存到: {args.out}')
        else:
            # 不分块，原逻辑
            df = pd.read_csv(args.features_csv, usecols=cols, dtype=np_dtype)
            selected = df.values.astype(np_dtype)
            n_rows = selected.shape[0]
            total_rows = n_rows
            final = np.ones(n_rows, dtype=int)
            for i, (pv, op) in enumerate(zip(pred_vals, ops)):
                col = selected[:, i]
                print(f'处理第{i+1}列: {len(col)} 个值，谓词 {op} {pv}')
                res = secure_compare_spu(spu_dev, sender_dev, receiver_dev, col, pv, op)
                final &= res
            np.savetxt(args.out, final, delimiter=',', fmt='%d')
            match_cnt = int(final.sum())
            print(f'S3R协议执行完成: 样本数={n_rows}, 列数={len(cols)}, 匹配行数={match_cnt}')
            print(f'结果已保存到: {args.out}')
    except Exception as e:
        print(f'程序执行失败: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        try:
            sf.shutdown()
        except Exception:
            pass


if __name__ == '__main__':
    main()
