#!/bin/bash
# Setup and Run Script cho Ubuntu/Linux
# Cài đặt requirements và chạy toàn bộ pipeline

echo ""
echo "========================================================================"
echo "                    ATT Pipeline - Setup and Run"
echo "========================================================================"
echo ""

# Bước 0: Cài đặt apktool
echo "[0/5] Cài đặt apktool..."
if ! command -v apktool &> /dev/null; then
    echo "⚠ apktool chưa được cài đặt, tiến hành cài đặt..."
    sudo apt-get update
    sudo apt-get install -y apktool
    if command -v apktool &> /dev/null; then
        echo "✓ apktool cài đặt thành công!"
    else
        echo "⚠ Cảnh báo: apktool cài đặt có thể thất bại, vui lòng cài thủ công"
    fi
else
    echo "✓ apktool đã được cài đặt"
fi

# Bước 1: Cài đặt requirements
echo ""
echo "[1/5] Cài đặt Python requirements..."
python3 -m pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo "✗ Lỗi cài đặt dependencies"
    exit 1
fi
echo "✓ Cài đặt xong!"

# Bước 2: Download malware
echo ""
echo "[2/5] Tải về malware samples..."
python3 download_malware.py
echo "✓ Download malware xong (hoặc có lỗi, tiếp tục)"

# Bước 3: Download benign
echo ""
echo "[3/5] Tải về benign samples..."
python3 download_benign.py
echo "✓ Download benign xong (hoặc có lỗi, tiếp tục)"

# Bước 4: Training
echo ""
echo "[4/5] Bắt đầu training..."
python3 train.py
if [ $? -ne 0 ]; then
    echo "✗ Lỗi trong quá trình training"
    exit 1
fi

echo ""
echo "========================================================================"
echo "✓ Hoàn thành toàn bộ pipeline!"
echo "========================================================================"
echo ""
