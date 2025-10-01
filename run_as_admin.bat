@echo off

:: 检查是否以管理员权限运行
NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo 正在以管理员权限运行端口管理工具...
) ELSE (
    echo 请求管理员权限...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /B
)

:: 检查Python是否安装
where python >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo 错误: 未找到Python。请先安装Python 3.6或更高版本。
    pause
    exit /B
)

:: 检查psutil是否安装
python -c "import psutil" 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo 安装psutil依赖...
    pip install psutil
)

:: 运行端口管理工具
echo 启动端口管理工具...
python %~dp0port_manager.py

:: 程序退出后
pause