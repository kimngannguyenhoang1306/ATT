import requests, os, time, json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import threading

# ── CẤU HÌNH ──────────────────────────────────────────────────
OUT_DIR = "./raw_apk/benign"  # thư mục lưu APK
N_DOWNLOAD = 300  # số APK muốn tải
MIN_SIZE_KB = 50  # bỏ qua APK nhỏ hơn 50KB
MAX_SIZE_MB = 10  # bỏ qua APK lớn hơn 10MB
MAX_WORKERS = 8  # số threads để download
# ──────────────────────────────────────────────────────────────

os.makedirs(OUT_DIR, exist_ok=True)
lock = threading.Lock()

FDROID_REPO = "https://f-droid.org/repo"


def get_fdroid_index():
    """Tải F-Droid package index"""
    print("[1] Tải F-Droid package index...")

    # Thử index-v1 (nhỏ hơn, nhanh hơn)
    try:
        url = f"{FDROID_REPO}/index-v1.json"
        print(f"    GET {url}")
        r = requests.get(url, timeout=60)
        if r.status_code == 200:
            data = r.json()
            apps = data.get("apps", [])
            pkgs = data.get("packages", {})
            print(f"    → {len(apps)} apps, {len(pkgs)} packages")
            return apps, pkgs
    except Exception as e:
        print(f"    index-v1 lỗi: {e}")

    # Fallback: index-v2
    try:
        url = f"{FDROID_REPO}/index-v2.json"
        print(f"    Fallback GET {url}")
        r = requests.get(url, timeout=120, stream=True)
        if r.status_code == 200:
            data = r.json()
            pkgs = data.get("packages", {})
            print(f"    → {len(pkgs)} packages")
            return [], pkgs
    except Exception as e:
        print(f"    index-v2 lỗi: {e}")

    return [], {}


def get_download_url_v1(pkg_name, packages):
    """Lấy URL download từ index-v1"""
    pkg_list = packages.get(pkg_name, [])
    if not pkg_list:
        return None, None

    # Lấy version mới nhất (index 0)
    latest = pkg_list[0]
    apk_name = latest.get("apkName", "")
    size = latest.get("size", 0)

    if not apk_name:
        return None, None

    return f"{FDROID_REPO}/{apk_name}", size


def get_download_url_v2(pkg_name, pkg_info):
    """Lấy URL download từ index-v2"""
    versions = pkg_info.get("versions", {})
    if not versions:
        return None, None

    # Lấy version đầu tiên
    ver = list(versions.values())[0]
    file_info = ver.get("file", {})
    name = file_info.get("name", "")
    size = file_info.get("size", 0)

    if not name:
        return None, None

    # name có thể bắt đầu bằng '/'
    name = name.lstrip("/")
    return f"{FDROID_REPO}/{name}", size


def download_apk(url, pkg_name, out_dir, min_size, max_size):
    """Tải 1 APK từ F-Droid"""
    # Tạo tên file an toàn
    safe_name = pkg_name.replace(".", "_")[:40]
    out_path = os.path.join(out_dir, f"{safe_name}.apk")

    if os.path.exists(out_path) and os.path.getsize(out_path) > min_size:
        return pkg_name, "skip", safe_name

    try:
        r = requests.get(url, timeout=60, stream=True)
        if r.status_code != 200:
            return pkg_name, "fail", f"HTTP {r.status_code}"

        # Download với kiểm tra size
        data = b""
        for chunk in r.iter_content(8192):
            data += chunk
            if len(data) > max_size:
                return pkg_name, "fail", "too large"

        if len(data) < min_size:
            return pkg_name, "fail", "too small"

        with open(out_path, "wb") as f:
            f.write(data)

        return pkg_name, "ok", safe_name

    except requests.Timeout:
        return pkg_name, "fail", "timeout"
    except Exception as e:
        return pkg_name, "fail", str(e)[:40]


def main():
    print("=" * 60)
    print("  Download Benign APKs từ F-Droid (Multi-threaded)")
    print("  Nguồn: https://f-droid.org (open source apps)")
    print("=" * 60)
    print(f"  Output  : {os.path.abspath(OUT_DIR)}")
    print(f"  Số APK  : {N_DOWNLOAD}")
    print(f"  Size    : {MIN_SIZE_KB}KB – {MAX_SIZE_MB}MB")
    print(f"  Threads : {MAX_WORKERS}")
    print()

    # Lấy index
    apps, packages = get_fdroid_index()

    if not packages:
        print("Không lấy được index. Kiểm tra kết nối mạng.")
        return

    # Chuẩn bị danh sách packages
    pkg_names = list(packages.keys())
    print(f"[2] Chuẩn bị download từ {len(pkg_names)} packages...")

    min_size = MIN_SIZE_KB * 1024
    max_size = MAX_SIZE_MB * 1024 * 1024

    # Chuẩn bị danh sách download tasks
    print(f"[3] Chuẩn bị danh sách download...")
    download_tasks = []
    skipped_count = 0
    need_to_download = N_DOWNLOAD

    for pkg_name in pkg_names:
        if len(download_tasks) >= need_to_download:  # Chỉ chuẩn bị đúng số cần
            break

        # Kiểm tra xem APK đã tồn tại không
        safe_name = pkg_name.replace(".", "_")[:40]
        apk_path = os.path.join(OUT_DIR, f"{safe_name}.apk")
        if os.path.exists(apk_path) and os.path.getsize(apk_path) >= MIN_SIZE_KB * 1024:
            skipped_count += 1
            need_to_download += 1  # Nếu đã có, tăng số cần tải lên để tìm 300 cái mới
            continue

        # Lấy URL
        pkg_info = packages[pkg_name]
        if isinstance(pkg_info, list):
            url, size = get_download_url_v1(pkg_name, packages)
        else:
            url, size = get_download_url_v2(pkg_name, pkg_info)

        if not url:
            continue

        # Bỏ qua nếu size đã biết là quá lớn/nhỏ
        if size and (size < min_size or size > max_size):
            continue

        download_tasks.append((url, pkg_name, min_size, max_size))

    print(f"   ↺ Đã tồn tại : {skipped_count}")
    print(f"   📥 Cần tải   : {len(download_tasks)}")

    # Download multi-threaded
    print(f"\n[4] Downloading với {MAX_WORKERS} threads...")
    results = {"ok": 0, "skip": 0, "fail": 0}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                download_apk, url, pkg_name, OUT_DIR, min_size, max_size
            ): pkg_name
            for url, pkg_name, min_size, max_size in download_tasks
        }

        for f in tqdm(as_completed(futures), total=len(futures), desc="Downloading"):
            if results["ok"] + results["skip"] >= N_DOWNLOAD:
                # Đủ rồi, cancel những futures còn lại
                for future in futures:
                    future.cancel()
                break

            pkg_name, status, detail = f.result()

            if status == "ok":
                results["ok"] += 1
            elif status == "skip":
                results["skip"] += 1
            else:
                results["fail"] += 1

    print()
    print(f"[5] Kết quả:")
    print(f"    ✓ Downloaded : {results['ok']}")
    print(f"    ↺ Đã có sẵn : {results['skip']}")
    print(f"    ✗ Lỗi       : {results['fail']}")

    # Thống kê
    apk_files = list(Path(OUT_DIR).glob("*.apk"))
    total_mb = sum(f.stat().st_size for f in apk_files) / 1024**2
    print(f"    📁 Tổng file: {len(apk_files)} APKs ({total_mb:.1f} MB)")
    print(f"    📂 Thư mục  : {os.path.abspath(OUT_DIR)}")
    print()
    print("→ Upload thư mục dataset/ lên Google Drive")
    print("→ Sau đó điền đường dẫn vào Cell 3 của notebook")
    print()


if __name__ == "__main__":
    main()
