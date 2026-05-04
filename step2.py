# step2.py
import os
import hashlib
import pickle
import json
from collections import Counter
from tqdm import tqdm
from config import CAT1_MAPPING, DECOMPILED_DIR, APK_MOS_DIR, MALWARE_DIR, BENIGN_DIR

# Cache configuration
CACHE_ROOT = "feature_cache"
os.makedirs(CACHE_ROOT, exist_ok=True)


def extract_opcode_from_line(line):
    """
    Đọc 1 dòng smali, trả về opcode nếu có

    Ví dụ:
    "    invoke-virtual {v0}, Landroid/..." → "invoke-virtual"
    "    const/4 v0, 0x1"                  → "const/4"
    ".method public foo()V"                → None
    """
    line = line.strip()

    # Bỏ qua dòng trống, comment, directive
    if not line or line.startswith("#") or line.startswith("."):
        return None

    # Lấy từ đầu tiên = opcode
    parts = line.split()
    if parts:
        return parts[0].lower()
    return None


# =========================
# CACHE LAYER (tương tự train.py)
# =========================
def _mos_cache_path(decompiled_dir: str) -> str:
    """Tạo đường dẫn cache dựa trên MD5 hash của directory"""
    key = hashlib.md5(decompiled_dir.encode()).hexdigest()
    return os.path.join(CACHE_ROOT, f"apk_mos_{key}.pkl")


def get_apk_mos_cached(
    decompiled_dir: str, opcode_mapping: dict, force_refresh: bool = False
) -> list:
    """
    Đọc MOS từ cache nếu có, nếu không thì parse smali files và lưu cache

    Args:
        decompiled_dir: đường dẫn thư mục đã decompile
        opcode_mapping: mapping từ opcode → ký hiệu
        force_refresh: nếu True, bỏ qua cache và parse lại

    Returns:
        dict của MOS → count (multiset)
        Ví dụ: {"MIM": 2, "R": 1, "GGP": 3}
    """
    cache_path = _mos_cache_path(decompiled_dir)

    # Nếu cache tồn tại và không force_refresh → load cache
    if not force_refresh and os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass  # Nếu load lỗi, sẽ parse lại

    # Parse smali files
    apk_mos = generate_apk_mos(decompiled_dir, opcode_mapping)

    # Lưu cache
    try:
        with open(cache_path, "wb") as f:
            pickle.dump(apk_mos, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass  # Bỏ qua lỗi save cache

    return apk_mos


def extract_mos_from_smali_file(smali_path, opcode_mapping):
    mos_per_method = []

    try:
        with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except:
        return mos_per_method

    in_method = False
    current_sequence = []
    current_mos = []

    for line in lines:
        line_stripped = line.strip()

        if line_stripped.startswith(".method"):
            in_method = True
            current_sequence = []
            current_mos = []
            continue

        if line_stripped.startswith(".end method"):
            if current_sequence:
                current_mos.append("".join(current_sequence))

            if current_mos:
                mos_per_method.append(dict(Counter(current_mos)))

            in_method = False
            current_sequence = []
            current_mos = []
            continue

        if not in_method:
            continue

        opcode = extract_opcode_from_line(line_stripped)
        if opcode is None:
            continue

        symbol = opcode_mapping.get(opcode, None)
        if symbol is None:
            continue

        if symbol == "V":
            if current_sequence:
                current_mos.append("".join(current_sequence))
                current_sequence = []
        else:
            current_sequence.append(symbol)

    return mos_per_method


def generate_apk_mos(decompiled_dir, opcode_mapping):
    all_method_mos = []

    for root, _, files in os.walk(decompiled_dir):
        for filename in files:
            if filename.endswith(".smali"):
                smali_path = os.path.join(root, filename)
                mos_list = extract_mos_from_smali_file(smali_path, opcode_mapping)
                all_method_mos.extend(mos_list)

    # Deduplicate MOS (convert dict → tuple để hash)
    unique_mos = set()

    for mos in all_method_mos:
        key = tuple(sorted(mos.items()))
        unique_mos.add(key)

    # convert lại dict
    apk_mos = [dict(m) for m in unique_mos]

    return apk_mos


def process_all_apks():
    """
    Xử lý toàn bộ APK đã decompile (MOSDroid Pipeline)

    Logic:
    1. Lấy danh sách folder từ raw_apk/malware/ và raw_apk/benign/
    2. Đối chiếu với folder trong raw_apk/decompiled/ để gán label
    3. Extract MOS từ từng decompiled folder
    4. Lưu MOS ra file với format: TEN_APK_{label}.txt
    """
    os.makedirs(APK_MOS_DIR, exist_ok=True)

    # Bước 1: Lấy danh sách tên folder từ malware/ và benign/ để xác định label
    # (lấy folder name, không phải .apk file name)
    malware_names = set()
    if os.path.exists(MALWARE_DIR):
        malware_names = set(
            d
            for d in os.listdir(MALWARE_DIR)
            if os.path.isdir(os.path.join(MALWARE_DIR, d))
        )

    benign_names = set()
    if os.path.exists(BENIGN_DIR):
        benign_names = set(
            d
            for d in os.listdir(BENIGN_DIR)
            if os.path.isdir(os.path.join(BENIGN_DIR, d))
        )

    print(f"Malware folder : {len(malware_names)}")
    print(f"Benign folder  : {len(benign_names)}")

    # Bước 2: Lấy danh sách folder đã decompile
    apk_dirs = [
        d
        for d in os.listdir(DECOMPILED_DIR)
        if os.path.isdir(os.path.join(DECOMPILED_DIR, d))
    ]
    print(f"Folder decompiled: {len(apk_dirs)}\n")

    # Bước 3: Xử lý từng APK
    stats = {"malware": 0, "benign": 0, "unknown": 0, "empty": 0}

    for folder_name in tqdm(apk_dirs, desc="Extracting MOS"):
        apk_dir = os.path.join(DECOMPILED_DIR, folder_name)

        # Gán label dựa vào tên folder
        # folder_name = "009ab0ff..._smali"
        # clean_name  = "009ab0ff..."  ← khớp với tên APK gốc
        clean_name = folder_name.replace("_smali", "")

        if clean_name in malware_names:
            label = "malware"
            stats["malware"] += 1
        elif clean_name in benign_names:
            label = "benign"
            stats["benign"] += 1
        else:
            label = "unknown"
            stats["unknown"] += 1

        # Extract MOS (từ cache hoặc parse smali files)
        # apk_mos: dict {"MIM": 2, "R": 1, ...}
        apk_mos = get_apk_mos_cached(apk_dir, CAT1_MAPPING)

        if len(apk_mos) == 0:
            stats["empty"] += 1

        # Lưu file với tên rõ ràng: TEN_APK_label.json
        # Format:
        # [
        #   {"MIM": 2, "R": 1},
        #   {"GGP": 1}
        # ]
        # Ví dụ: 009ab0ff..._malware.json
        #        a2dp_Vol_benign.json
        output_filename = f"{clean_name}_{label}.json"
        output_path = os.path.join(APK_MOS_DIR, output_filename)

        with open(output_path, "w") as f:
            json.dump(apk_mos, f, indent=2, ensure_ascii=False)

    # Bước 4: In thống kê
    print(f"\n{'='*40}")
    print(f"THỐNG KÊ:")
    print(f"  Malware : {stats['malware']}")
    print(f"  Benign  : {stats['benign']}")
    print(f"  Unknown : {stats['unknown']}")
    print(f"  Empty   : {stats['empty']}")
    print(f"  Tổng    : {sum(stats.values()) - stats['empty']}")
    print(f"\nFile MOS đã lưu tại: {APK_MOS_DIR}")
    print(f"Format: [{{'MOS': count}}, ...] (List of multisets)")
    print(f"Tên file: TEN_APK_malware.json / TEN_APK_benign.json")


if __name__ == "__main__":
    print("=" * 50)
    print("STEP 2: Extract MOS (Multiset) từ APK")
    print("Format output: JSON {MOS: count}")
    print("=" * 50)
    print(f"📁 Cache root: {os.path.abspath(CACHE_ROOT)}")
    print(f"📁 Decompiled: {os.path.abspath(DECOMPILED_DIR)}")
    print(f"💾 Output: {os.path.abspath(APK_MOS_DIR)}")
    print("=" * 50 + "\n")
    process_all_apks()
