# Setup Instructions

## Yêu cầu hệ thống

Trước khi chạy pipeline, bạn cần cài đặt:
1. **Python 3.7+**
2. **Java** (phải có để chạy apktool)
3. **apktool** (để decode APK files)

## Cài đặt Apktool

### Windows
```bash
# Cách 1: Sử dụng Chocolatey (nếu đã cài)
choco install apktool

# Cách 2: Download thủ công
# 1. Tải từ: https://ibotpeaches.github.io/Apktool/
# 2. Giải nén và thêm vào PATH
# 3. Hoặc copy apktool.bat vào C:\Windows\System32\
```

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install -y apktool
```

### macOS
```bash
brew install apktool
```

## Chạy Pipeline

### Tùy chọn 1: Python Script (tất cả platforms)
```bash
python3 run.py
```

### Tùy chọn 2: Shell Script (Linux/macOS)
```bash
chmod +x run.sh
./run.sh
```

### Tùy chọn 3: Batch Script (Windows)
```cmd
run_all.bat
```

## Quy trình Tự Động

Script sẽ thực hiện các bước:
1. ✓ Cài đặt apktool (nếu cần)
2. ✓ Cài đặt Python dependencies từ requirements.txt
3. ✓ Chạy download_malware.py
4. ✓ Chạy download_benign.py
5. ✓ Chạy train.py

## Xử lý Lỗi

### Nếu apktool không được tìm thấy
```bash
# Windows
where apktool

# Linux/macOS
which apktool

# Nếu không có, cài thủ công theo hướng dẫn ở trên
```

### Nếu Java không được cài đặt
```bash
# Windows: tải từ java.com hoặc dùng choco
choco install openjdk

# Linux
sudo apt-get install -y default-jdk

# macOS
brew install openjdk
```

## Cấu hình Download

Bạn có thể chỉnh sửa các giá trị trong file:

**download_malware.py:**
- `LIMIT_PER_CALL = 1000` - số samples tại một lần gọi API
- `MAX_WORKERS = 5` - số threads parallel

**download_benign.py:**
- `N_DOWNLOAD = 300` - số APK muốn tải
- `MIN_SIZE_KB = 50` - kích thước tối thiểu
- `MAX_SIZE_MB = 10` - kích thước tối đa
- `MAX_WORKERS = 8` - số threads parallel

## Thư Mục Output

Sau khi chạy xong:
- `raw_apk/malware/` - malware samples
- `raw_apk/benign/` - benign samples
- `decoded/` - APK files đã được decode
- `android_hashes_*.txt` - hash files
