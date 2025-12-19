# 脑钱包碰撞扫描器 (Brain Wallet Collision Scanner)

这是一个高效的脑钱包碰撞程序，用于测试常见密码短语是否对应已知的比特币公钥。

## 原理

脑钱包 (Brain Wallet) 是一种通过将密码短语哈希成私钥的方式来生成比特币地址：

1. **密码短语 → 私钥**: `SHA256(passphrase)` 得到 32 字节私钥
2. **私钥 → 公钥**: 使用 secp256k1 椭圆曲线导出压缩公钥 (33 字节)
3. **公钥 → HASH160**: `RIPEMD160(SHA256(pubkey))` 得到 20 字节哈希
4. **查询数据库**: 检查 HASH160 是否在已收集的公钥数据库中

## 查询路径（高效）

程序使用三层过滤来高效查询：

1. **Bloom Filter** (2.1 GB): 极快的概率过滤，99.99999% 准确率
2. **FP64 Table** (4.1 GB): 64 位指纹表，二分查找确认
3. **RocksDB** (35 GB): 精确查询获取完整公钥信息

## 安装

```bash
cargo build --release --bin brain-wallet
```

## 使用方法

### 1. 测试单个密码短语

```bash
brain-wallet test "your passphrase here"
```

示例：
```bash
brain-wallet test "satoshi nakamoto"
brain-wallet test "password123"
brain-wallet test "In the beginning God created the heaven and the earth."
```

**查询余额** - 测试单个密码短语并查询余额：
```bash
brain-wallet test "password" --electrs 192.168.1.19:50001
```

### 2. 扫描密码短语文件

```bash
brain-wallet scan -i wordlists/common_passphrases.txt -d output -o matches.txt
```

扫描多个文件：
```bash
brain-wallet scan -i wordlists/common_passphrases.txt -i wordlists/bible_sample.txt -i wordlists/famous_quotes.txt -d output -o matches.txt
```

**带余额查询** - 通过 electrs 服务器查询匹配地址的余额：
```bash
brain-wallet scan -i wordlists/common_passphrases.txt --electrs 192.168.1.19:50001
```

参数说明：
- `-i, --input`: 输入文件（每行一个密码短语）
- `-d, --data-dir`: 公钥数据库目录（默认 `output`）
- `-o, --output`: 匹配结果输出文件（默认 `matches.txt`）
- `-t, --threads`: 线程数（默认使用所有 CPU）
- `--skip-bloom`: 跳过 Bloom Filter（更快加载，适合小批量测试）
- `--with-variations`: 生成密码短语变体（大小写、添加后缀等）
- `--electrs`: Electrs 服务器地址（例如 `192.168.1.19:50001`），用于查询余额

### 3. 从文本生成密码短语

```bash
brain-wallet generate -i bible.txt -o bible_phrases.txt
```

参数说明：
- `-i, --input`: 输入文本文件（如圣经全文）
- `-o, --output`: 输出密码短语文件
- `--min-len`: 最小长度（默认 3）
- `--max-len`: 最大长度（默认 100）
- `--word-combos`: 生成词组合
- `--max-words`: 最大组合词数（默认 4）

## 词典文件

项目提供了一些示例词典：

- `wordlists/common_passphrases.txt`: 常见密码短语
- `wordlists/bible_sample.txt`: 圣经经典语句
- `wordlists/famous_quotes.txt`: 名言名句

## 获取更多词典

你可以从以下来源获取更多密码短语：

1. **圣经全文**:
   - 下载 King James Version: https://www.gutenberg.org/ebooks/10
   
2. **词典**:
   - SecLists: https://github.com/danielmiessler/SecLists
   - RockYou 密码列表

3. **文学作品**:
   - 古腾堡计划: https://www.gutenberg.org/

## 性能

在典型配置下：

- **加载时间**: Bloom + FP64 约 30 秒
- **扫描速度**: ~100,000-500,000 密码短语/秒（取决于 CPU）
- **内存使用**: 约 6-7 GB（Bloom + FP64 表）

## 警告

⚠️ **重要安全提示**:

1. 脑钱包非常不安全！不要使用简单密码短语存储真实比特币。
2. 本工具仅用于安全研究和教育目的。
3. 如果发现匹配，说明该地址的私钥已被泄露，任何人都可以访问其中的资金。

## 示例输出

### 基础匹配结果
```
=== MATCH FOUND ===
Passphrase: satoshi
Private Key (hex): da2876b3eb31edb4436fa4650673fc6f01f90de2f1793c4ec332b2387b09726f
Private Key (WIF): L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1
Public Key: 03c4f00a8aa87f595b60b1e390f17fc64d12c1a1f505354a7eea5f2ee353e427b7
HASH160: 0a8ba9e453383d4561cbcdda36e5789c2870dd41

Addresses:
  P2PKH (Legacy):      1234...
  P2WPKH (SegWit):     bc1q...
  P2SH-P2WPKH (Nested):3abc...

First Seen Height: 344628
Pubkey Type: Legacy
==================
```

### 带余额查询结果
```
=== MATCH FOUND ===
Passphrase: password
Private Key (hex): 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Private Key (WIF): 5JUZJqDzjZpB8eDdR1pYBWz6rKQrRhT5rCQBPAcaZHNdLd2rkdB
Public Key: 02b568858a407a8721923b89df9963d30013639ac690cce5f555529b77b83cbfc7
HASH160: 400453ac5e19a058ec45a33550fdc496e0b26ad0

Addresses:
  P2PKH (Legacy):      16ga2uqnF1NqpAuQeeg7sTCAdtDUwDyJav
  P2WPKH (SegWit):     bc1qgqz98tzt3ngpvms2qx4fauey9hqmfk6stj5t08
  P2SH-P2WPKH (Nested):3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC

Balances:
    P2PKH:       0.00012345 BTC (confirmed: 12345, unconfirmed: 0)
    P2WPKH:      0 BTC (confirmed: 0, unconfirmed: 0)
    P2SH-P2WPKH: 0 BTC (confirmed: 0, unconfirmed: 0)
    TOTAL:       0.00012345 BTC

First Seen Height: 191745
Pubkey Type: Legacy
==================
```

## Electrs 余额查询

当配置了 `--electrs` 参数时，程序会通过 Electrum 协议连接到 electrs 服务器，查询以下三种地址类型的余额：

- **P2PKH** (Legacy): 以 "1" 开头的传统地址
- **P2WPKH** (Native SegWit): 以 "bc1q" 开头的原生隔离见证地址  
- **P2SH-P2WPKH** (Nested SegWit): 以 "3" 开头的嵌套隔离见证地址

这样可以快速判断找到的匹配是否有可用余额。

