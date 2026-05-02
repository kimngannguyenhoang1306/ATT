# step2_extract_mos.py
import os
from tqdm import tqdm
from config import CAT1_MAPPING, DECOMPILED_DIR, APK_MOS_DIR, MALWARE_DIR, BENIGN_DIR


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


def extract_mos_from_smali_file(smali_path, opcode_mapping):
    """
    Đọc 1 file .smali → trả về list MOS

    Cách hoạt động:
    - Duyệt từng method trong file
    - Map opcode → ký hiệu (M, R, I, V, G, P)
    - Gặp V → cắt tạo 1 MOS mới
    - Kết thúc method → flush đoạn còn lại
    """
    mos_list = []

    try:
        with open(smali_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except:
        return mos_list

    in_method = False
    current_sequence = []

    for line in lines:
        line_stripped = line.strip()

        # Bắt đầu method
        if line_stripped.startswith(".method"):
            in_method = True
            current_sequence = []
            continue

        # Kết thúc method → lưu đoạn còn lại
        if line_stripped.startswith(".end method"):
            if current_sequence:
                mos_list.append("".join(current_sequence))
            in_method = False
            current_sequence = []
            continue

        if not in_method:
            continue

        # Lấy opcode
        opcode = extract_opcode_from_line(line_stripped)
        if opcode is None:
            continue

        # Map opcode → ký hiệu
        symbol = opcode_mapping.get(opcode, None)
        if symbol is None:
            continue

        # V = dấu phân cách → cắt tạo MOS mới
        if symbol == "V":
            if current_sequence:
                mos_list.append("".join(current_sequence))
                current_sequence = []
        else:
            current_sequence.append(symbol)

    return mos_list


def generate_apk_mos(decompiled_dir, opcode_mapping):
    """
    Duyệt toàn bộ smali files trong 1 APK đã decompile
    → Trả về set MOS duy nhất của APK đó
    """
    all_mos = []

    for root, dirs, files in os.walk(decompiled_dir):
        for filename in files:
            if filename.endswith(".smali"):
                smali_path = os.path.join(root, filename)
                mos = extract_mos_from_smali_file(smali_path, opcode_mapping)
                all_mos.extend(mos)

    # Loại MOS rỗng + loại trùng lặp TRONG APK này
    apk_mos = set(m for m in all_mos if len(m) > 0)
    return apk_mos


def process_all_apks():
    """
    Xử lý toàn bộ APK đã decompile
    - Tự động gán label từ tên APK gốc trong malware/ và benign/
    - Lưu MOS ra file: apk_mos/TEN_APK_malware.txt hoặc TEN_APK_benign.txt
    """
    os.makedirs(APK_MOS_DIR, exist_ok=True)

    # Bước 1: Lấy danh sách tên APK gốc để gán label
    malware_names = set(
        f.replace(".apk", "") for f in os.listdir(MALWARE_DIR) if f.endswith(".apk")
    )
    benign_names = set(
        f.replace(".apk", "") for f in os.listdir(BENIGN_DIR) if f.endswith(".apk")
    )
    print(f"Malware APK gốc : {len(malware_names)}")
    print(f"Benign APK gốc  : {len(benign_names)}")

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

        # Extract MOS
        apk_mos = generate_apk_mos(apk_dir, CAT1_MAPPING)

        if len(apk_mos) == 0:
            stats["empty"] += 1

        # Lưu file với tên rõ ràng: TEN_APK_label.txt
        # Ví dụ: 009ab0ff..._malware.txt
        #        a2dp_Vol_benign.txt
        output_filename = f"{clean_name}_{label}.txt"
        output_path = os.path.join(APK_MOS_DIR, output_filename)

        with open(output_path, "w") as f:
            for mos in sorted(apk_mos):
                f.write(mos + "\n")

    # Bước 4: In thống kê
    print(f"\n{'='*40}")
    print(f"THỐNG KÊ:")
    print(f"  Malware : {stats['malware']}")
    print(f"  Benign  : {stats['benign']}")
    print(f"  Unknown : {stats['unknown']}")
    print(f"  Empty   : {stats['empty']}")
    print(f"  Tổng    : {sum(stats.values()) - stats['empty']}")
    print(f"\nFile MOS đã lưu tại: {APK_MOS_DIR}")
    print(f"Tên file format: TEN_APK_malware.txt / TEN_APK_benign.txt")


if __name__ == "__main__":
    print("=" * 40)
    print("STEP 2: Extract MOS từ APK đã decompile")
    print("=" * 40 + "\n")
    process_all_apks()
