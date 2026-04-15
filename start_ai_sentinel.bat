@echo off
chcp 65001 >nul
title 正在启动 AI 流量哨兵...

:: 1. 检查并启动 Ollama 服务（如果未运行）
tasklist /FI "IMAGENAME eq ollama.exe" 2>NUL | find /I /N "ollama.exe">NUL
if "%ERRORLEVEL%"=="1" (
    echo [提示] Ollama 服务未运行，正在启动...
    start "" "C:\Users\%USERNAME%\AppData\Local\Programs\Ollama\ollama.exe"
    :: 等待 Ollama 初始化
    timeout /t 3 /nobreak >nul
) else (
    echo [提示] Ollama 服务已在运行。
)

:: 2. 激活虚拟环境并启动 Streamlit
echo [提示] 正在启动 Streamlit 应用...
cd /d E:\AI_Network_Sentinel
call venv\Scripts\activate.bat
start "" http://localhost:8501
streamlit run src/app.py --server.headless true

:: 如果 Streamlit 意外退出，暂停显示错误信息
pause