@echo off
setlocal
chcp 65001 >nul

echo ============================================================
echo  Vault — 构建独立 exe（无需 Python 环境）
echo ============================================================
echo.

echo [1/2] 安装 Python 依赖和 PyInstaller...
pip install -r requirements.txt pyinstaller >nul 2>&1
if errorlevel 1 (
    echo 错误：pip 安装失败，请确认 Python 已正确安装并加入 PATH。
    pause & exit /b 1
)
echo       完成。
echo.

echo [2/2] 构建 vault.exe...
pyinstaller --onefile ^
    --name vault ^
    --hidden-import cryptography.hazmat.backends.openssl ^
    --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
    --hidden-import argon2 ^
    --hidden-import argon2.low_level ^
    --distpath dist ^
    --workpath build ^
    --specpath build ^
    vault.py
if errorlevel 1 (
    echo 错误：vault.exe 构建失败。
    pause & exit /b 1
)
echo       完成 → dist\vault.exe
echo.

echo ============================================================
echo  构建成功！
echo  将 dist\vault.exe 复制到目标机器即可使用，无需安装 Python。
echo ============================================================
pause
