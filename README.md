# Vault — 原地双层级联加密工具

## 加密方案说明

### 为什么文件泄露后无法破解

本工具采用**三层独立保护**，每一层单独被攻破都不够：

| 层次 | 技术 | 作用 |
|------|------|------|
| 密钥派生 | **Argon2id**（内存 256 MB，3 轮） | 暴力猜密码极其昂贵 |
| 内层加密 | **AES-256-GCM**（认证加密） | 国家级标准，篡改即报错 |
| 外层加密 | **ChaCha20-Poly1305**（认证加密） | 即使 AES 被攻破仍有保护 |

**级联逻辑**：
```
明文
 └─→ AES-256-GCM  (密钥 A)  →  中间密文
      └─→ ChaCha20-Poly1305 (密钥 B)  →  最终 .vault 文件
```
攻击者必须**同时破解两个独立算法**，才能还原明文，当前计算能力下不可行。

**密钥设计**（每个文件独立，互不影响）：
```
密码 + 随机盐 ──Argon2id──→ 64 字节主密钥
                               ├─ 前 32 字节 → 头部密钥（加密文件元数据）
                               └─ 后 32 字节 → 会话密钥
                                              └─ HKDF-SHA3-256 + 随机文件种子
                                                  ├─ 密钥 A（AES 层）
                                                  └─ 密钥 B（ChaCha 层）
```

**文件格式**：`.vault` 文件头部无任何可识别的魔数，无法从文件内容判断使用了什么加密方案。

---

## 工作原理

本工具执行**原地加密**，不产生额外副本：

```
加密：  原始文件  ──→  原始文件.vault   （原始文件加密成功后立即删除）
解密：  原始文件.vault  ──→  原始文件   （.vault 文件解密成功后立即删除）
```

`.vault_session` 密钥文件保存在被加密盘符的根目录（如 `C:\.vault_session`），解密时自动读取。

---

## 文件说明

| 文件 | 作用 |
|------|------|
| `encrypt.py` | 加密器 |
| `decrypt.py` | 解密器（含完整性校验） |
| `crypto.py` | 底层加密核心（勿删） |
| `walker.py` | 目录遍历引擎（勿删） |
| `requirements.txt` | Python 依赖列表 |

---

## 环境要求

- Python 3.11+
- Windows / macOS / Linux

---

## 安装步骤

### 第一步：安装 Python

从 https://python.org 下载并安装 Python 3.11 或更高版本。
Windows 安装时勾选 **"Add Python to PATH"**。

### 第二步：放置工具文件

将所有 `.py` 文件和 `requirements.txt` 放到同一目录，例如 `C:\vault\`。

### 第三步：安装依赖

```cmd
cd C:\vault
pip install -r requirements.txt
```

验证安装：
```cmd
python encrypt.py --help
python decrypt.py --help
```

---

## 使用教程

### 场景一：加密整个 C 盘

```cmd
python encrypt.py
```

执行流程：
1. 提示输入密码（不回显），输入两次确认
2. 生成主密钥（Argon2id，约 1-2 秒）
3. 自动扫描 `C:\`，跳过系统目录
4. 每个文件就地加密为 `.vault`，原始文件删除
5. 完成后输出统计

**加密前后对比：**
```
加密前：  C:\Users\Alice\报告.docx   C:\Work\代码.py
加密后：  C:\Users\Alice\报告.docx.vault   C:\Work\代码.py.vault
```

---

### 场景二：加密其他盘符

```cmd
python encrypt.py --drive D
```

---

### 场景三：预览将跳过/加密的顶层目录（不执行加密）

```cmd
python encrypt.py --show-skipped
```

输出示例：
```
扫描根目录: C:\

将被跳过（系统目录）：
  [跳过] C:\$Recycle.Bin
  [跳过] C:\Boot
  [跳过] C:\Recovery
  [跳过] C:\System Volume Information
  [跳过] C:\Windows

将被加密：
  [加密] C:\Program Files
  [加密] C:\Program Files (x86)
  [加密] C:\ProgramData
  [加密] C:\Users
  [加密] C:\Work
```

---

### 场景四：解密还原

```cmd
python decrypt.py restore
```

将 `C:\` 下所有 `.vault` 文件就地解密，还原为原始文件，`.vault` 文件删除。

解密其他盘符：
```cmd
python decrypt.py restore --drive D
```

---

### 场景五：校验完整性（不修改任何文件）

加密完成后或定期运行，确认文件未损坏、未被篡改：

```cmd
python decrypt.py verify
```

- 全部通过：`全部 N 个文件校验通过。`
- 有损坏：列出具体文件名，退出码为 2

---

### 场景六：调整并行线程数

```cmd
python encrypt.py --workers 8
python decrypt.py restore --workers 8
```

默认 4 线程。SSD 可调到 8，机械硬盘建议 2-4。

---

### 场景七：脚本自动化（指定密码）

```cmd
python encrypt.py --password "你的强密码"
python decrypt.py restore --password "你的强密码"
```

> 注意：命令行密码可能被系统日志记录，建议交互式输入。

---

## 自动跳过的系统目录

| 目录 | 说明 |
|------|------|
| `C:\Windows` | Windows 系统文件 |
| `C:\Windows.old` | 系统升级残留 |
| `C:\$Recycle.Bin` | 回收站 |
| `C:\Recovery` | 系统恢复分区 |
| `C:\System Volume Information` | 系统卷信息 |
| `C:\Boot` | 启动引导文件 |
| `C:\PerfLogs` | 性能日志 |
| `C:\MSOCache` | Office 安装缓存 |
| `pagefile.sys` / `hiberfil.sys` / `swapfile.sys` | 系统虚拟内存 / 休眠文件 |

---

## .vault_session 文件说明

| 字段 | 大小 | 内容 |
|------|------|------|
| Argon2id 盐 | 32 字节 | 随机，用于密码 → 主密钥推导 |
| 验证 nonce | 12 字节 | 随机 |
| 验证密文 | 24 字节 | 用于校验密码正确性 |

- **不含任何密钥本身**，泄露后攻击者仍需正确密码才能解密
- 保存在被加密盘符根目录（如 `C:\.vault_session`），勿删除

---

## 密码安全建议

- 长度 ≥ 20 字符，包含大小写字母、数字、符号
- 示例：`Maple#River$9271!Zero`
- 务必用密码管理器保存，**忘记密码后无法恢复任何文件**

Argon2id 参数（256 MB 内存 + 3 轮）：
- 普通 GPU 每秒仅能尝试约 **3-5 次密码**
- 20 位随机密码暴力破解需要数亿年

---

## 常见问题

**Q：忘记密码怎么办？**  
A：无法恢复。Argon2id 是单向函数，不存在后门。

**Q：加密中途断电/中断怎么办？**  
A：已完成加密的文件保持 `.vault` 状态不受影响；正在处理的单个文件可能产生不完整的 `.vault`，重新运行加密器会跳过已有的 `.vault` 文件，再次执行不会损坏已加密文件。

**Q：.vault 文件能看出原始文件名吗？**  
A：文件系统路径保留（如 `报告.docx.vault`），但文件内容、大小、原始元数据均已加密，无法从文件内容推断任何信息。如需隐藏路径，先将目录打包为 zip 再加密。

**Q：.vault_session 文件被删了怎么办？**  
A：无法解密。该文件包含 Argon2id 盐，没有它无法从密码重新推导出主密钥。
