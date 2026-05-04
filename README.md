# Vault-Backup — 双层级联加密备份工具

## 加密方案说明

### 为什么这套方案"文件泄露也无法破解"

本工具采用**三层独立保护**，每一层单独被攻破都不够：

| 层次 | 技术 | 作用 |
|------|------|------|
| 密钥派生 | **Argon2id**（内存 256 MB，3 轮） | 暴力破解密码极其昂贵 |
| 内层加密 | **AES-256-GCM**（认证加密） | 国家级标准，篡改即报错 |
| 外层加密 | **ChaCha20-Poly1305**（认证加密） | 即使 AES 被攻破仍有保护 |

**级联逻辑**：
```
明文
 └─→ AES-256-GCM  (密钥 A)  →  中间密文
      └─→ ChaCha20-Poly1305 (密钥 B)  →  最终密文
```
攻击者必须**同时破解两个独立算法**，才能得到明文，当前计算能力下不可行。

**密钥设计**（每个文件独立，互不影响）：
```
密码 + 随机盐 ──Argon2id──→ 64字节主密钥
                                ├─ 前32字节  →  头部密钥（保护文件元数据）
                                └─ 后32字节  →  会话密钥
                                               └─ HKDF-SHA3-256 + 随机文件种子
                                                   ├─ 密钥A（AES层）
                                                   └─ 密钥B（ChaCha层）
```

**文件格式**：加密文件头部无任何可识别的魔数/标识，无法从文件本身判断用了什么加密方案。

---

## 环境要求

- Python 3.11+
- Windows / macOS / Linux

---

## 安装步骤

### 第一步：安装 Python

从 https://python.org 下载并安装 Python 3.11 或更高版本。
安装时勾选 **"Add Python to PATH"**。

### 第二步：下载工具

将以下文件放到同一个目录，例如 `C:\vault-backup\`：
```
crypto.py
walker.py
encrypt.py      ← 加密器
decrypt.py      ← 解密器（含完整性校验）
requirements.txt
```

### 第三步：安装依赖

打开命令提示符（Win+R 输入 cmd），进入工具目录：

```cmd
cd C:\vault-backup
pip install -r requirements.txt
```

安装完成后验证：
```cmd
python encrypt.py --help
python decrypt.py --help
```
看到命令帮助说明安装成功。

---

## 使用教程

### 场景一：加密整个 C 盘（自动跳过系统目录）

```cmd
python encrypt.py --dest "E:\Backup\enc"
```

执行后：
1. 提示输入密码（不回显），输入两次确认
2. 显示"正在生成主密钥"（约1-2秒，Argon2id计算）
3. 自动扫描 C:\ 下所有文件，跳过系统目录
4. 进度条显示加密进度
5. 完成后输出成功/失败统计

**重要**：目标目录会生成 `.vault_session` 文件，这是解密所必需的，**务必保留**。

**自动跳过的系统目录（不会被加密）：**

| 目录 | 说明 |
|------|------|
| `C:\Windows` | Windows 系统文件 |
| `C:\Windows.old` | 系统升级残留 |
| `C:\$Recycle.Bin` | 回收站 |
| `C:\Recovery` | 系统恢复分区 |
| `C:\System Volume Information` | 系统卷信息 |
| `C:\Boot` | 启动文件 |
| `C:\PerfLogs` | 性能日志 |
| `C:\MSOCache` | Office 安装缓存 |
| `pagefile.sys` / `hiberfil.sys` / `swapfile.sys` | 系统虚拟内存文件 |

**加密的目录（示例）：**
```
C:\Users\          ← 所有用户文件
C:\Program Files\  ← 已安装软件
C:\ProgramData\    ← 应用数据
C:\Work\           ← 自定义目录
...（其余非系统目录）
```

---

### 场景二：加密其他盘符

```cmd
python encrypt.py --dest "E:\Backup\enc" --drive D
```

---

### 场景三：预览将被跳过/加密的目录（不执行加密）

正式加密前可先查看哪些目录会被处理：

```cmd
python encrypt.py --dest "E:\Backup\enc" --show-skipped
```

输出示例：
```
扫描根目录: C:\
以下顶层目录将被跳过（系统目录）：
  [跳过] C:\$Recycle.Bin
  [跳过] C:\Recovery
  [跳过] C:\System Volume Information
  [跳过] C:\Windows

以下顶层目录将被加密：
  [加密] C:\Program Files
  [加密] C:\Program Files (x86)
  [加密] C:\ProgramData
  [加密] C:\Users
  [加密] C:\Work
```

---

### 场景四：从备份中还原所有文件

```cmd
python decrypt.py restore "E:\Backup\enc" "E:\Restore"
```

执行后：
1. 提示输入密码
2. 验证密码正确性（从 `.vault_session` 校验）
3. 还原所有文件到 `E:\Restore\`，完整保留原始目录结构

还原后的结构：
```
E:\Restore\
└── C\
    ├── Users\Alice\...（与原始 C:\Users\Alice 完全一致）
    └── Work\...
```

---

### 场景四：验证备份完整性（不写磁盘）

定期运行此命令确认备份未损坏、未被篡改：

```cmd
python decrypt.py verify "E:\Backup\enc"
```

- 如果全部通过：输出 `All N file(s) passed integrity check.`
- 如果有文件损坏：列出具体文件名，退出码为 2

---

### 场景五：指定密码（脚本自动化）

```cmd
python encrypt.py --dest "E:\Backup\enc" --password "你的强密码"
python decrypt.py restore "E:\Backup\enc" "E:\Restore" --password "你的强密码"
```

> 警告：命令行密码可能被系统日志记录，建议手动输入。

---

### 场景六：调整并行线程数（大量文件时加速）

```cmd
python encrypt.py --dest "E:\Backup\enc" --workers 8
```

默认4个线程，SSD 可调到 8，机械硬盘建议保持 2-4。

---

## 密码安全建议

推荐密码格式（强度足以抵抗当前所有已知攻击）：
- 长度 ≥ 20 字符
- 包含大小写字母、数字、符号
- 例：`Horse!Battery$Staple#2024`

Argon2id 参数（256 MB 内存 + 3轮）意味着：
- 普通 GPU 每秒只能尝试约 **3-5 次密码**
- 暴力破解 8 位随机密码需要数千年

---

## .vault_session 文件说明

| 字段 | 大小 | 内容 |
|------|------|------|
| Argon2id 盐 | 32 字节 | 随机，用于密码→主密钥推导 |
| 验证 nonce | 12 字节 | 随机 |
| 验证密文 | 24 字节 | 用于快速校验密码是否正确 |

**此文件本身不含密钥**，泄露后攻击者仍需要正确密码才能解密任何文件。
但建议将它与加密文件存放在一起（同一备份目录）。

---

## 常见问题

**Q: 忘记密码怎么办？**  
A: 无法恢复。Argon2id 是单向函数，不存在后门。请务必在密码管理器中保存密码。

**Q: 备份过程中断了怎么办？**  
A: 重新运行加密命令即可，已加密的文件会被覆盖重加密（每次都用新的随机 nonce，不影响安全性）。

**Q: 加密后原文件还在吗？**  
A: 在。本工具只读取源文件，绝不修改或删除原始数据。

**Q: .vault 文件能看出原始文件名吗？**  
A: 不能。`.vault` 文件头部经过加密，原始文件名存储在加密头部中。目录结构（路径）保留在文件系统层面（`.vault` 后缀前的路径），如需隐藏路径，请先将源目录打包为 zip 再加密。

**Q: 两个独立的备份能用同一密码吗？**  
A: 可以。每次 `encrypt` 都生成全新的随机 Argon2id 盐和文件种子，密钥完全独立。
