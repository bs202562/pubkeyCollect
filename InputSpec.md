Bitcoin 链上公钥收集 & CPU / GPU 双格式存储方案
AI 执行需求稳定版（Stable Spec v1.0）

一、项目目标

构建一个系统，用于完整收集所有在比特币主网上链上出现过的公钥，并生成两套存储格式：

1）CPU / 程序精确查询格式
2）GPU 批量扫描 / 高速过滤格式

系统必须支持按区块高度进行增量更新。

二、数据范围

必须收集以下链上出现过的公钥类型：

A. P2PK
来源：scriptPubKey
公钥直接可见

B. P2PKH / P2WPKH
来源：scriptSig 或 witness
只从交易输入中提取
不从 scriptPubKey 推断

C. Taproot（P2TR）
来源：scriptPubKey
只使用 key-path output key
仅提取 32 字节 x-only pubkey

三、公钥标准化规则（Canonicalization）

1）Legacy / SegWit 公钥
输入可能为 65 字节未压缩或 33 字节压缩
必须统一转换为 33 字节 compressed 格式

2）Taproot 公钥
直接使用 32 字节 x-only pubkey
不进行 tweak 或 parity 恢复

四、CPU 查询格式（精确存储）

存储引擎要求：
使用 RocksDB 或 LevelDB
支持 mmap
支持千万级 key

Key / Value 定义：

Key = HASH160(pubkey)

Value 包含以下字段：
pubkey_type: u8（0=legacy，1=segwit，2=taproot）
pubkey_len: u8（32 或 33）
pubkey_raw: 原始公钥字节
first_seen_height: u32

Key 必须唯一
如果公钥重复出现，仅保留最小的 first_seen_height

五、GPU 查询格式（高速过滤）

第一层：Bloom Filter（必须）

Bloom 元素为 HASH160(pubkey)
目标误判率小于等于 1e-7
Hash 函数数量 6 到 8 个
Bit array 必须连续存储

GPU 访问要求：
Bloom test 在单个 kernel 内完成
禁止使用指针结构
禁止动态内存分配

第二层：64 位 Fingerprint 表（强烈推荐）

Fingerprint 构造方式：
fp64 = trunc64(SHA256(HASH160(pubkey)))

使用 uint64
全量排序
连续 flat array 存储

GPU 使用方式：
仅在 Bloom 命中后访问
GPU 内执行 binary search 或 warp-level search

六、GPU 查询完整执行路径

GPU 侧流程：
privkey -> pubkey -> HASH160 -> Bloom test -> fp64 lookup -> report candidate

CPU 侧流程：
使用 RocksDB 进行完整 pubkey 精确比对

七、数据生成流程

数据源：
Bitcoin Core
通过 RPC 或直接解析 blk*.dat

处理流程：
遍历区块
遍历交易
提取公钥
执行标准化
写入 CPU 数据库
更新 Bloom Filter
追加 fp64 数据

八、增量更新要求

以区块高度为单位更新
新区块只处理新增公钥

Bloom Filter 与 fp64 表允许：
定期离线重建
或追加后重新排序

九、非目标（明确排除）

不生成私钥
不枚举 secp256k1 全空间
不推断未在链上暴露的公钥
不处理 Taproot script-path 分支

十、输出产物

系统必须输出以下内容：

1）RocksDB / LevelDB 公钥索引
2）GPU 可直接加载的 Bloom Filter 二进制文件
3）GPU 可 mmap 的 fp64 连续数组
4）数据规模统计报告（公钥数量、内存占用）

十一、实现语言建议（非强制）

CPU 解析：Rust 或 C++
GPU：CUDA 或 OpenCL
工具脚本：Python

十二、稳定性声明

本需求文档为最终稳定版本
不允许 AI 自行扩展需求
不允许更改数据结构语义
所有实现必须严格遵循本规范