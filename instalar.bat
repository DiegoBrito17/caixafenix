@echo off
echo ========================================
echo   INSTALADOR - SISTEMA DE CAIXA
echo ========================================
echo.

echo [1/4] Criando ambiente virtual...
python -m venv .venv
if %errorlevel% neq 0 (
    echo ERRO: Falha ao criar ambiente virtual
    echo Certifique-se de que o Python esta instalado
    pause
    exit /b 1
)

echo [2/4] Ativando ambiente virtual...
call .venv\Scripts\activate.bat

echo [3/4] Instalando dependencias...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo ERRO: Falha ao instalar dependencias
    pause
    exit /b 1
)

echo [4/4] Criando pasta database...
if not exist "database" mkdir database

echo.
echo ========================================
echo   INSTALACAO CONCLUIDA COM SUCESSO!
echo ========================================
echo.
echo Para iniciar o sistema, execute: iniciar.bat
echo.
pause
