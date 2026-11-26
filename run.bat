@echo off
rem Nhap dup vao file nay de chay SOC Toolkit: cai thu vien, nap du lieu mau, mo dashboard.
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Tao moi truong ao .venv ...
    python -m venv .venv
    if errorlevel 1 (
        echo LOI: khong tim thay Python. Cai Python 3.11+ tu python.org va tick "Add python.exe to PATH".
        pause
        exit /b 1
    )
) else (
    echo [1/4] Da co .venv
)

call ".venv\Scripts\activate.bat"

echo [2/4] Cai thu vien ...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo LOI: cai thu vien that bai. Kiem tra ket noi mang roi chay lai.
    pause
    exit /b 1
)

echo [3/4] Nap du lieu mau va chay phat hien ...
python main.py run-sample > data\run-sample-output.json
if errorlevel 1 (
    echo LOI: run-sample that bai. Xem thong bao phia tren.
    pause
    exit /b 1
)
echo      Xong. Ket qua chi tiet: data\run-sample-output.json

echo [4/4] Mo dashboard tai http://localhost:8501  (dong cua so nay de dung)
python main.py dashboard
pause
