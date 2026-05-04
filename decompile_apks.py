#!/usr/bin/env python3
"""
decompile_apks.py - Decompile toàn bộ APK vào raw_apk/decompiled/
Tạo folder structure mà step2.py mong đợi
"""

import os
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from config import MALWARE_DIR, BENIGN_DIR, DECOMPILED_DIR

MAX_WORKERS = 4


def decompile_apk(apk_path: str, output_dir: str) -> bool:
    """
    Decompile 1 APK bằng apktool

    Args:
        apk_path: đường dẫn tới file APK
        output_dir: thư mục output

    Returns:
        True nếu thành công, False nếu thất bại
    """
    try:
        subprocess.run(
            ["apktool", "d", apk_path, "-o", output_dir, "-f", "-r"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=300,
        )
        return True
    except Exception as e:
        print(f"❌ Error decoding {apk_path}: {e}")
        return False


def decompile_all_apks():
    """Decompile toàn bộ APK từ malware/ và benign/ vào raw_apk/decompiled/"""

    os.makedirs(DECOMPILED_DIR, exist_ok=True)

    # Thu thập danh sách APK cần decompile
    apk_tasks = []

    for label, source_dir in [("malware", MALWARE_DIR), ("benign", BENIGN_DIR)]:
        if not os.path.exists(source_dir):
            print(f"⚠️  {source_dir} không tồn tại, bỏ qua...")
            continue

        print(f"\n📂 Quét {label} APK từ {source_dir}...")

        for apk_file in os.listdir(source_dir):
            if not apk_file.endswith(".apk"):
                continue

            apk_path = os.path.join(source_dir, apk_file)
            apk_name = apk_file.replace(".apk", "")

            # Output folder: raw_apk/decompiled/APK_NAME_smali/
            output_dir = os.path.join(DECOMPILED_DIR, f"{apk_name}_smali")

            # Nếu đã decompile rồi thì skip
            if os.path.exists(output_dir) and os.path.exists(
                os.path.join(output_dir, "smali")
            ):
                continue

            apk_tasks.append((apk_path, output_dir, apk_name, label))

    if not apk_tasks:
        print("✅ Toàn bộ APK đã được decompile rồi!")
        return

    print(f"\n🚀 Bắt đầu decompile {len(apk_tasks)} APK với {MAX_WORKERS} threads...\n")

    def decompile_task(args):
        apk_path, output_dir, apk_name, label = args
        success = decompile_apk(apk_path, output_dir)
        status = "✓" if success else "✗"
        return f"{status} {label}: {apk_name[:30]}"

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(decompile_task, task) for task in apk_tasks]

        results = []
        for future in tqdm(
            as_completed(futures), total=len(futures), desc="Decompiling"
        ):
            results.append(future.result())

        for result in results:
            print(f"  {result}")

    print(f"\n✅ Decompilation hoàn thành!")
    print(f"📁 Decompiled files: {DECOMPILED_DIR}")


if __name__ == "__main__":
    print("╔" + "=" * 60 + "╗")
    print("║" + " " * 15 + "APK Decompiler" + " " * 32 + "║")
    print("╚" + "=" * 60 + "╝\n")

    # Kiểm tra apktool
    if not shutil.which("apktool"):
        print("❌ ERROR: apktool không được cài đặt!")
        print("   Vui lòng cài đặt apktool trước:")
        print("   - Windows: choco install apktool")
        print("   - Linux: sudo apt-get install apktool")
        print("   - macOS: brew install apktool")
        exit(1)

    print("✓ apktool found\n")

    decompile_all_apks()
