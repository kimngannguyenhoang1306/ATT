#!/usr/bin/env python3
"""
Setup and Run Script - Cài đặt requirements và chạy toàn bộ pipeline
Thứ tự thực hiện:
1. Cài đặt các packages cần thiết
2. Chạy download_malware.py
3. Chạy download_benign.py
4. Chạy train.py
"""

import subprocess
import sys
import os


def run_command(cmd, description):
    """Chạy một command và in ra thông tin"""
    print("\n" + "=" * 70)
    print(f"▶ {description}")
    print("=" * 70)
    try:
        result = subprocess.run(cmd, check=True, shell=True)
        print(f"✓ {description} hoàn thành thành công!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Lỗi khi {description}")
        print(f"  Exit code: {e.returncode}")
        return False
    except Exception as e:
        print(f"✗ Lỗi không mong muốn: {e}")
        return False


def main():
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 10 + "ATT Pipeline - Setup & Run" + " " * 32 + "║")
    print("╚" + "=" * 68 + "╝")

    # Bước 1: Cài đặt requirements
    print("\n[1/4] Cài đặt requirements...")
    if not run_command(
        f"{sys.executable} -m pip install -r requirements.txt", "Cài đặt dependencies"
    ):
        print("\n⚠ Không thể cài đặt dependencies!")
        return False

    # Bước 2: Download malware
    print("\n[2/4] Tải về malware samples...")
    if not run_command(f"{sys.executable} download_malware.py", "Download malware"):
        print("\n⚠ Có lỗi trong quá trình tải malware, nhưng tiếp tục...")

    # Bước 3: Download benign
    print("\n[3/4] Tải về benign samples...")
    if not run_command(f"{sys.executable} download_benign.py", "Download benign"):
        print("\n⚠ Có lỗi trong quá trình tải benign, nhưng tiếp tục...")

    # Bước 4: Training
    print("\n[4/4] Bắt đầu training...")
    if not run_command(f"{sys.executable} train.py", "Training model"):
        print("\n✗ Quá trình training thất bại!")
        return False

    # Hoàn thành
    print("\n" + "=" * 70)
    print("✓ Hoàn thành toàn bộ pipeline!")
    print("=" * 70 + "\n")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
