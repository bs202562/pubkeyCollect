# Bitcoin 链上公钥收集器

Bitcoin on-chain public key collector with CPU/GPU dual storage formats.

## 功能特性

- **完整公钥收集**: 收集比特币主网上所有出现过的公钥
- **多类型支持**: P2PK, P2PKH, P2WPKH, P2TR (Taproot)
- **双格式存储**:
  - CPU 格式: RocksDB 索引，支持精确查询
  - GPU 格式: Bloom Filter + FP64 表，支持高速过滤
- **增量更新**: 支持按区块高度增量更新

## 支持的公钥类型

| 类型 | 来源 | 格式 |
|------|------|------|
| P2PK | scriptPubKey | 33/65 字节 → 压缩为 33 字节 |
| P2PKH | scriptSig | 33/65 字节 → 压缩为 33 字节 |
| P2WPKH | witness | 33 字节压缩 |
| P2TR | scriptPubKey | 32 字节 x-only |

## 构建

```bash
# Debug 构建
cargo build

# Release 构建 (推荐)
cargo build --release

# 运行测试
cargo test
```

## 使用方法

### 全量扫描

```bash
collect-pubkey scan --blocks-dir /path/to/bitcoin/blocks --output ./output
```

选项:
- `--blocks-dir`: Bitcoin blocks 目录路径 (包含 blk*.dat 文件)
- `--output`: 输出目录 (默认: ./output)
- `--start-height`: 起始高度 (默认: 0)
- `--end-height`: 结束高度 (默认: 最新)

### 增量更新

```bash
collect-pubkey update --blocks-dir /path/to/bitcoin/blocks --output ./output
```

### 重建 GPU 格式

从 RocksDB 重新生成 Bloom Filter 和 FP64 表:

```bash
collect-pubkey rebuild-gpu --output ./output
```

### 查询公钥

```bash
collect-pubkey query --hash160 <40位十六进制> --output ./output
```

### 查看统计信息

```bash
collect-pubkey stats --output ./output
```

## 输出文件

| 文件 | 描述 |
|------|------|
| `pubkey.rocksdb/` | RocksDB 数据库 (CPU 查询格式) |
| `bloom.bin` | Bloom Filter 二进制文件 (GPU 格式) |
| `fp64.bin` | FP64 排序数组 (GPU 格式) |
| `stats.json` | 统计报告 |

## 存储格式

### RocksDB 格式

**Key**: `HASH160(pubkey)` - 20 字节

**Value**: 39 字节
- `pubkey_type`: u8 (0=legacy, 1=segwit, 2=taproot)
- `pubkey_len`: u8 (32 或 33)
- `pubkey_raw`: [u8; 33] (Taproot 前补 0)
- `first_seen_height`: u32 (小端序)

### Bloom Filter 格式

```
Header (16 bytes):
  magic: u32 = 0x424C4F4D ("BLOM")
  version: u32 = 1
  num_elements: u64

Params (16 bytes):
  bit_size: u64
  num_hashes: u32
  padding: u32

Data:
  bits: [u8; bit_size / 8]
```

- 目标误判率: 1e-7
- Hash 函数: 6-8 个 (double hashing)
- 元素: HASH160(pubkey)

### FP64 格式

```
Header (16 bytes):
  magic: u32 = 0x46503634 ("FP64")
  version: u32 = 1
  num_elements: u64

Data:
  fingerprints: [u64; num_elements]  # 已排序
```

- 指纹构造: `fp64 = SHA256(HASH160(pubkey))[0..8]`
- 存储: 排序后的 u64 数组
- GPU 查询: 二分查找

## GPU 查询流程

```
GPU 侧:
privkey → pubkey → HASH160 → Bloom test → fp64 lookup → report candidate

CPU 侧:
使用 RocksDB 进行完整 pubkey 精确比对
```

## 预估资源占用 (5000万公钥)

| 资源 | 大小 |
|------|------|
| RocksDB | ~2.5 GB |
| Bloom Filter | ~1.7 GB |
| FP64 Table | ~400 MB |

## 依赖

- **bitcoin**: 区块解析、脚本处理
- **secp256k1**: 公钥压缩转换
- **rocksdb**: CPU 存储引擎
- **sha2/ripemd**: 哈希计算
- **memmap2**: 内存映射 blk*.dat
- **rayon**: 并行处理

## License

MIT

