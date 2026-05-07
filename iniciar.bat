@echo off
echo ========================================
echo   SISTEMA DE CAIXA - INICIANDO
echo ========================================
echo.

set "PYTHON_EXE="
if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=.venv\Scripts\python.exe"
if not defined PYTHON_EXE if exist "venv\Scripts\python.exe" set "PYTHON_EXE=venv\Scripts\python.exe"

if not defined PYTHON_EXE (
    echo ERRO: Ambiente virtual nao encontrado!
    echo Execute primeiro: instalar.bat
    pause
    exit /b 1
)

echo Iniciando servidor Flask...
echo.
echo ========================================
echo   SISTEMA RODANDO!
echo ========================================
echo.
echo O sistema vai escolher automaticamente uma porta livre.
echo Se a 5000 estiver ocupada, ele usa a 5001.
echo.
echo Usuario: admin
echo Senha: 123
echo.
echo Pressione CTRL+C para encerrar o servidor
echo ========================================
echo.

"%PYTHON_EXE%" app.py

pause
