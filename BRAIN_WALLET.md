# 脑钱包碰撞扫描器 (Brain Wallet Collision Scanner)

这是一个高效的脑钱包碰撞程序，用于测试常见密码短语是否对应已知的比特币公钥。

## 原理

脑钱包 (Brain Wallet) 是一种通过将密码短语哈希成私钥的方式来生成比特币地址：

1. **密码短语 → 私钥**: `SHA256(passphrase)` 得到 32 字节私钥
2. **私钥 → 公钥**: 使用 secp256k1 椭圆曲线导出压缩公钥 (33 字节)
3. **公钥 → HASH160**: `RIPEMD160(SHA256(pubkey))` 得到 20 字节哈希
4. **查询数据库**: 检查 HASH160 是否在已收集的公钥数据库中

### 多哈希变体

除了标准的单次 SHA256 哈希外，某些脑钱包生成器可能使用：
- **不同的哈希算法**: MD5, SHA1, SHA512, RIPEMD160
- **多次哈希迭代**: 如 `SHA256(SHA256(passphrase))` 进行双重哈希

程序支持通过 `--multi-hash` 模式遍历这些变体，增加发现匹配的概率。

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

有余额的结果会自动保存到 `matches_with_balance.txt`，也可自定义：
```bash
brain-wallet scan -i wordlists/common_passphrases.txt --electrs 192.168.1.19:50001 --balance-output found_balance.txt
```

参数说明：
- `-i, --input`: 输入文件（每行一个密码短语）
- `-d, --data-dir`: 公钥数据库目录（默认 `output`）
- `-o, --output`: 匹配结果输出文件（默认 `matches.txt`）
- `-t, --threads`: 线程数（默认使用所有 CPU）
- `--skip-bloom`: 跳过 Bloom Filter（更快加载，适合小批量测试）
- `--with-variations`: 生成密码短语变体（大小写、添加后缀等）
- `--electrs`: Electrs 服务器地址（例如 `192.168.1.19:50001`），用于查询余额
- `--balance-output`: 有余额的匹配结果单独保存文件（默认 `matches_with_balance.txt`）
- `--resume`: 从上次中断的位置恢复扫描
- `--progress-file`: 进度缓存文件路径（默认 `.brain_wallet_progress.json`）
- `--save-interval`: 自动保存进度的间隔秒数（默认 30 秒）
- `--multi-hash`: 启用多哈希遍历模式
- `--hash-algorithms`: 要尝试的哈希算法（逗号分隔，如 `sha256,md5,sha1`）
- `--max-iterations`: 每种算法的最大迭代次数（如 2 表示尝试 hash 和 hash(hash)）

### 3. 多哈希模式扫描

启用多哈希模式可以尝试不同的哈希算法和迭代次数：

```bash
# 使用 SHA256 和 MD5，各尝试 1-3 次迭代
brain-wallet scan -i wordlists/common_passphrases.txt --multi-hash --hash-algorithms sha256,md5 --max-iterations 3
```

支持的哈希算法：
- `sha256`: 标准脑钱包哈希（32 字节输出）
- `sha512`: SHA-512（使用前 32 字节）
- `sha1`: SHA-1（20 字节，后续填充零）
- `md5`: MD5（16 字节，后续填充零）
- `ripemd160`: RIPEMD-160（20 字节，后续填充零）

**测试单个密码的多种哈希方式：**
```bash
# 标准 SHA256（默认）
brain-wallet test "password"

# 使用 MD5 算法
brain-wallet test "password" --hash-algorithm md5

# 使用 SHA256 双重哈希
brain-wallet test "password" --hash-algorithm sha256 --iterations 2
```

**多哈希模式的工作量说明：**
- 假设有 1000 个密码短语
- 使用 2 种算法（sha256, md5）× 3 次迭代 = 每个密码 6 种派生
- 总共检查：1000 × 6 = 6000 种派生

### 4. 从文本生成密码短语

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
Hash Derivation: sha256(passphrase)
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

### 多哈希匹配结果（双重 SHA256）
```
=== MATCH FOUND ===
Passphrase: password123
Hash Derivation: sha256^2(passphrase)
Private Key (hex): ...
...
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

## 已知脑钱包数据库

程序会自动维护一个已知脑钱包数据库（`known_brainwallets.jsonl`），用于：

1. **避免重复扫描**：已知的脑钱包会在扫描时自动跳过
2. **自动收集新发现**：新匹配的脑钱包会自动添加到数据库
3. **持久化存储**：使用 JSON Lines 格式，便于查看和编辑

### 管理已知脑钱包

**从 matches.txt 导入现有记录：**
```bash
brain-wallet import -i matches.txt -d known_brainwallets.jsonl
```

**查看已知脑钱包列表：**
```bash
# 表格格式（默认）
brain-wallet list

# JSON 格式
brain-wallet list --format json

# CSV 格式
brain-wallet list --format csv

# 显示所有记录
brain-wallet list --limit 0
```

**查看数据库统计信息：**
```bash
brain-wallet stats
```

**导出到文件：**
```bash
# 导出为 txt 格式（兼容 matches.txt）
brain-wallet export -o exported.txt

# 导出为 JSON 格式
brain-wallet export -o exported.json --format json

# 导出为 CSV 格式
brain-wallet export -o exported.csv --format csv
```

### 扫描时的行为

默认情况下，扫描会：
- 加载已知脑钱包数据库
- 跳过已知的 HASH160（避免重复）
- 将新发现的匹配自动添加到数据库

```bash
# 使用默认数据库路径
brain-wallet scan -i wordlists/common_passphrases.txt

# 指定自定义数据库路径
brain-wallet scan -i wordlists/common_passphrases.txt --known-db my_brainwallets.jsonl

# 禁用已知脑钱包追踪（每次都完整扫描）
brain-wallet scan -i wordlists/common_passphrases.txt --no-known-db
```

## 断点续传（大文件扫描）

当扫描超大文件（如 40GB+）时，程序可能因为各种原因中断。为了支持从中断处继续扫描，程序提供了进度缓存功能。

### 工作原理

1. **自动保存进度**: 程序会每隔 N 秒（默认 30 秒）自动保存当前进度到缓存文件
2. **优雅退出**: 按 Ctrl+C 会触发优雅退出，程序会保存当前进度后再退出
3. **恢复扫描**: 使用 `--resume` 参数可以从上次中断的位置继续扫描
4. **自动清理**: 扫描成功完成后，进度文件会自动删除

### 使用方法

**正常扫描（自动保存进度）：**
```bash
brain-wallet scan -i huge_wordlist.txt -d output -o matches.txt
```

**从中断处恢复：**
```bash
brain-wallet scan -i huge_wordlist.txt -d output -o matches.txt --resume
```

**自定义保存间隔和进度文件：**
```bash
# 每 60 秒保存一次进度
brain-wallet scan -i huge_wordlist.txt --save-interval 60 --resume

# 使用自定义进度文件路径
brain-wallet scan -i huge_wordlist.txt --progress-file my_progress.json --resume
```

### 进度文件格式

进度文件（默认 `.brain_wallet_progress.json`）包含以下信息：

```json
{
  "current_file_index": 0,
  "current_file_offset": 1234567890,
  "current_line_number": 50000000,
  "total_lines_processed": 50000000,
  "total_checked": 49500000,
  "known_skipped": 500000,
  "bloom_hits": 1234,
  "fp64_hits": 567,
  "matches_found": 42,
  "new_matches": 10,
  "input_files": ["huge_wordlist.txt"],
  "last_save_timestamp": 1703123456,
  "with_variations": false,
  "multi_hash_config": {
    "enabled": true,
    "algorithms": ["sha256", "md5"],
    "max_iterations": 2
  }
}
```

### 注意事项

1. **输入文件必须一致**: 恢复时必须使用与上次完全相同的输入文件列表和顺序
2. **变体模式必须一致**: `--with-variations` 设置必须与上次保持一致
3. **多哈希配置必须一致**: `--multi-hash`, `--hash-algorithms`, `--max-iterations` 设置必须与上次保持一致
4. **不要修改输入文件**: 在恢复之前不要修改输入文件内容，否则字节偏移会不正确
5. **批处理模式**: 对于超大文件，建议同时使用 `--batch-size` 参数控制内存使用

### 推荐的大文件扫描配置

```bash
# 扫描 40GB+ 文件的推荐配置
brain-wallet scan \
  -i huge_wordlist.txt \
  -d output \
  -o matches.txt \
  --batch-size 1000000 \
  --save-interval 30 \
  --resume
```

## Electrs 余额查询

当配置了 `--electrs` 参数时，程序会通过 Electrum 协议连接到 electrs 服务器，查询以下三种地址类型的余额：

- **P2PKH** (Legacy): 以 "1" 开头的传统地址
- **P2WPKH** (Native SegWit): 以 "bc1q" 开头的原生隔离见证地址  
- **P2SH-P2WPKH** (Nested SegWit): 以 "3" 开头的嵌套隔离见证地址

这样可以快速判断找到的匹配是否有可用余额。



## 宸茬煡鑴戦挶鍖呰凯浠ｅ搱甯屾壂鎻?(IterateKnown Mode)

杩欐槸涓€涓宸茬煡鑴戦挶鍖呰繘琛屾繁搴︽寲鎺樼殑妯″紡銆傚畠浼氳鍙栧凡鐭ョ殑鑴戦挶鍖呮暟鎹簱锛屽姣忎釜閽卞寘鐨勭閽ヨ繘琛屽娆?SHA256 鍝堝笇锛? 鍒?N 娆★級锛屾瘡娆″搱甯屽悗閮芥鏌ュ搴旂殑鍏挜鏄惁鍦ㄦ暟鎹簱涓紝骞跺彲閫夊湴鏌ヨ浣欓銆?
### 鍘熺悊

鏌愪簺鏃╂湡鐨勬瘮鐗瑰竵鐢ㄦ埛鍙兘浼氬湪鍘熷鑴戦挶鍖呯閽ョ殑鍩虹涓婂啀杩涜棰濆鐨勫搱甯屾搷浣滄潵澧炲己瀹夊叏鎬э紝渚嬪锛?
- 瀵圭閽ュ仛 1000 娆?SHA256
- 浣跨敤 PBKDF2 鎴栫被浼肩殑杩唬鍝堝笇鏂规

杩欎釜妯″紡鍙互鍙戠幇杩欎簺娲剧敓閽卞寘銆?
### 浣跨敤鏂规硶

**鍩虹鐢ㄦ硶锛?*

\\ash
# 瀵瑰凡鐭ヨ剳閽卞寘杩涜 1000 娆?SHA256 杩唬锛屾瘡娆￠兘鏌ヨ鏁版嵁搴?brain-wallet iterate-known --max-iterations 1000
\
**甯︿綑棰濇煡璇細**

\\ash
# 鍚屾椂鏌ヨ姣忔杩唬鐨勪綑棰?brain-wallet iterate-known --max-iterations 1000 --electrs 192.168.1.19:50001
\
**浠呮煡璇綑棰濓紙涓嶆鏌ユ暟鎹簱锛夛細**

\\ash
# 璺宠繃鏁版嵁搴撴鏌ワ紝鍙煡璇綑棰?brain-wallet iterate-known --max-iterations 500 --electrs 192.168.1.19:50001 --balance-only
\
**瀹屾暣鍙傛暟锛?*

\\ash
brain-wallet iterate-known \
  --known-db known_brainwallets.jsonl \
  --data-dir output \
  --output iterate_matches.txt \
  --balance-output iterate_matches_with_balance.txt \
  --max-iterations 1000 \
  --electrs 192.168.1.19:50001 \
  --threads 8
\
### 鍙傛暟璇存槑

| 鍙傛暟 | 璇存槑 | 榛樿鍊?|
|------|------|--------|
| \--known-db\ | 宸茬煡鑴戦挶鍖呮暟鎹簱璺緞 | \known_brainwallets.jsonl\ |
| \--data-dir\ | 鍏挜鏁版嵁搴撶洰褰?| \output\ |
| \--output\ | 鏁版嵁搴撳尮閰嶇粨鏋滆緭鍑烘枃浠?| \iterate_matches.txt\ |
| \--balance-output\ | 鏈変綑棰濈殑鍖归厤缁撴灉杈撳嚭鏂囦欢 | \iterate_matches_with_balance.txt\ |
| \--max-iterations\ | 鏈€澶?SHA256 杩唬娆℃暟 | @0\ |
| \--electrs\ | Electrs 鏈嶅姟鍣ㄥ湴鍧€ | (鏃? |
| \--threads\ | 绾跨▼鏁?| (鎵€鏈?CPU) |
| \--skip-bloom\ | 璺宠繃 Bloom Filter | \alse\ |
| \--balance-only\ | 浠呮煡璇綑棰濓紝璺宠繃鏁版嵁搴撴鏌?| \alse\ |

### 宸ヤ綔閲忎及绠?
- 鍋囪鏈?100 涓凡鐭ヨ剳閽卞寘
- 璁剧疆 1000 娆¤凯浠?- 鎬诲叡妫€鏌ワ細100 x 1000 = 100,000 涓€欓€?
### 鍖归厤缁撴灉绀轰緥

\=== ITERATE MATCH FOUND ===
Original Passphrase: password
Original Private Key: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
Derivation: SHA256^42(original_privkey)
Derived Private Key (hex): a1b2c3d4...
Derived Private Key (WIF): 5Kb8kL...
Public Key: 03abc123...
HASH160: def456...

Addresses:
  P2PKH (Legacy):       1ABC...
  P2WPKH (SegWit):      bc1q...
  P2SH-P2WPKH (Nested): 3XYZ...

First Seen Height: 12345
Pubkey Type: Legacy

Balances:
    P2PKH:       0.00012345 BTC (confirmed: 12345, unconfirmed: 0)
    P2WPKH:      0 BTC (confirmed: 0, unconfirmed: 0)
    P2SH-P2WPKH: 0 BTC (confirmed: 0, unconfirmed: 0)
    TOTAL:       0.00012345 BTC
===========================
\