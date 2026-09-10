@echo off
chcp 65001 >nul
title B-Block 文件夹恢复工具
echo.
echo   ============================================
echo    B-Block 文件夹恢复工具
echo    只用系统自带命令，不会删除任何文件
echo   ============================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0B-Block文件恢复.ps1"
echo.
pause
