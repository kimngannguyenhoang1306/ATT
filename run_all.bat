@echo off
REM Setup and Run Script cho Windows
REM Cài đặt requirements và chạy toàn bộ pipeline

echo.
echo ========================================================================
echo                    ATT Pipeline - Setup and Run
echo ========================================================================
echo.

REM Bước 1: Cài đặt requirements
echo [1/4] Cài đặt requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ✗ Lỗi cài đặt dependencies
    pause
    exit /b 1
)
echo ✓ Cài đặt xong!

REM Bước 2: Download malware
echo.
echo [2/4] Tải về malware samples...
python download_malware.py
echo ✓ Download malware xong (hoặc có lỗi, tiếp tục)

REM Bước 3: Download benign
echo.
echo [3/4] Tải về benign samples...
python download_benign.py
echo ✓ Download benign xong (hoặc có lỗi, tiếp tục)

REM Bước 4: Training
echo.
echo [4/4] Bắt đầu training...
python train.py
if errorlevel 1 (
    echo ✗ Lỗi trong quá trình training
    pause
    exit /b 1
)

echo.
echo ========================================================================
echo ✓ Hoàn thành toàn bộ pipeline!
echo ========================================================================
echo.
pause
