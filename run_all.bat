@echo off
REM Setup and Run Script cho Windows
REM Cài đặt requirements và chạy toàn bộ pipeline

echo.
echo ========================================================================
echo                    ATT Pipeline - Setup and Run
echo ========================================================================
echo.

REM Bước 0: Cài đặt apktool
echo [0/5] Kiểm tra apktool...
where apktool >nul 2>nul
if %errorlevel% neq 0 (
    echo ⚠ apktool chưa được cài đặt
    echo Vui lòng cài apktool thủ công từ:
    echo https://ibotpeaches.github.io/Apktool/
    echo.
    echo Sau đó thêm apktool vào PATH hoặc đặt trong thư mục hệ thống
    pause
) else (
    echo ✓ apktool đã được cài đặt
)

REM Bước 1: Cài đặt requirements
echo.
echo [1/5] Cài đặt requirements...
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo ✗ Lỗi cài đặt dependencies
    pause
    exit /b 1
)
echo ✓ Cài đặt xong!

REM Bước 2: Download malware
echo.
echo [2/5] Tải về malware samples...
python download_malware.py
echo ✓ Download malware xong (hoặc có lỗi, tiếp tục)

REM Bước 3: Download benign
echo.
echo [3/5] Tải về benign samples...
python download_benign.py
echo ✓ Download benign xong (hoặc có lỗi, tiếp tục)

REM Bước 4: Training
echo.
echo [4/5] Bắt đầu training...
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
