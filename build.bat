@echo off
setlocal
chcp 65001 >nul

echo ============================================================
echo  Vault — 构建独立 exe（无需 Python 环境）
echo ============================================================
echo.

:: 安装依赖
echo [1/3] 安装 Python 依赖和 PyInstaller...
pip install -r requirements.txt pyinstaller >nul 2>&1
if errorlevel 1 (
    echo 错误：pip 安装失败，请确认 Python 已正确安装并加入 PATH。
    pause & exit /b 1
)
echo       完成。
echo.

:: 构建 vault-encrypt.exe
echo [2/3] 构建 vault-encrypt.exe...
pyinstaller --onefile ^
    --name vault-encrypt ^
    --hidden-import cryptography.hazmat.backends.openssl ^
    --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
    --hidden-import argon2 ^
    --hidden-import argon2.low_level ^
    --distpath dist ^
    --workpath build\encrypt ^
    --specpath build ^
    encrypt.py
if errorlevel 1 (
    echo 错误：vault-encrypt.exe 构建失败。
    pause & exit /b 1
)
echo       完成 → dist\vault-encrypt.exe
echo.

:: 构建 vault-decrypt.exe
echo [3/3] 构建 vault-decrypt.exe...
pyinstaller --onefile ^
    --name vault-decrypt ^
    --hidden-import cryptography.hazmat.backends.openssl ^
    --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
    --hidden-import argon2 ^
    --hidden-import argon2.low_level ^
    --distpath dist ^
    --workpath build\decrypt ^
    --specpath build ^
    decrypt.py
if errorlevel 1 (
    echo 错误：vault-decrypt.exe 构建失败。
    pause & exit /b 1
)
echo       完成 → dist\vault-decrypt.exe
echo.

echo ============================================================
echo  构建成功！
echo  vault-encrypt.exe  →  dist\vault-encrypt.exe
echo  vault-decrypt.exe  →  dist\vault-decrypt.exe
echo  将两个 exe 复制到任意目录即可使用，无需安装 Python。
echo ============================================================
pause
