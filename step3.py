import os
import json
import pandas as pd
from tqdm import tqdm
from config import APK_MOS_DIR, FEATURES_DIR, MIN_FREQUENCY


def mos_dict_to_str(mos_dict):
    """Convert MOS dict → string để làm feature"""
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


def build_feature_matrix():
    os.makedirs(FEATURES_DIR, exist_ok=True)

    # ── Bước 1: Đọc JSON ──────────────────────────
    print("Bước 1: Đọc tất cả APK_MOS JSON files...")
    apk_mos_dict = {}
    labels = {}

    mos_files = [f for f in os.listdir(APK_MOS_DIR) if f.endswith(".json")]

    for mos_file in tqdm(mos_files, desc="  Đọc file"):
        filepath = os.path.join(APK_MOS_DIR, mos_file)

        with open(filepath, "r") as f:
            mos_list = json.load(f)

        # Convert list[dict] → set[str]
        mos_set = set()
        for mos_dict in mos_list:
            mos_str = mos_dict_to_str(mos_dict)
            mos_set.add(mos_str)

        # 🔥 Lấy label từ filename
        if mos_file.endswith("_malware.json"):
            apk_name = mos_file.replace("_malware.json", "")
            labels[apk_name] = 1
        elif mos_file.endswith("_benign.json"):
            apk_name = mos_file.replace("_benign.json", "")
            labels[apk_name] = 0
        else:
            continue

        apk_mos_dict[apk_name] = mos_set

    total = len(apk_mos_dict)
    n_mal = sum(1 for v in labels.values() if v == 1)
    n_ben = sum(1 for v in labels.values() if v == 0)

    print(f"  Tổng APK : {total}")
    print(f"  Malware  : {n_mal}")
    print(f"  Benign   : {n_ben}")

    # ── Bước 2: Unique MOS ────────────────────────
    print("\nBước 2: Tìm tất cả unique MOS...")
    all_mos = set()
    for mos_set in apk_mos_dict.values():
        all_mos.update(mos_set)

    print(f"  Unique MOS (trước lọc): {len(all_mos):,}")

    # ── Bước 3: Lọc theo frequency ───────────────
    print(f"\nBước 3: Lọc MOS xuất hiện < {MIN_FREQUENCY*100:.0f}% apps...")
    min_count = max(2, int(total * MIN_FREQUENCY))
    print(f"  Min count = {min_count} apps")

    frequent_mos = []
    for mos in tqdm(all_mos, desc="  Đếm tần suất"):
        count = sum(1 for mos_set in apk_mos_dict.values() if mos in mos_set)
        if count >= min_count:
            frequent_mos.append(mos)

    frequent_mos = sorted(frequent_mos)
    print(f"  Unique MOS (sau lọc) : {len(frequent_mos):,}")

    # ── Bước 4: Build matrix ─────────────────────
    print("\nBước 4: Xây dựng feature matrix...")
    apk_names = list(apk_mos_dict.keys())
    data = []

    for apk_name in tqdm(apk_names, desc="  Build matrix"):
        mos_set = apk_mos_dict[apk_name]
        row = [1 if mos in mos_set else 0 for mos in frequent_mos]
        row.append(labels[apk_name])
        data.append(row)

    columns = frequent_mos + ["label"]
    df = pd.DataFrame(data, index=apk_names, columns=columns)

    # ── Save ────────────────────────────────────
    output_path = os.path.join(FEATURES_DIR, "feature_matrix.csv")
    df.to_csv(output_path)

    print(f"\n{'='*40}")
    print(f"THỐNG KÊ FEATURE MATRIX:")
    print(f"  Số APK (hàng)    : {df.shape[0]}")
    print(f"  Số MOS (cột)     : {df.shape[1]-1}")
    print(f"  Malware          : {(df['label']==1).sum()}")
    print(f"  Benign           : {(df['label']==0).sum()}")
    print(f"  File lưu tại     : {output_path}")
    print(f"{'='*40}")

    return df, frequent_mos


if __name__ == "__main__":
    print("=" * 40)
    print("STEP 3: Build Feature Matrix (JSON version)")
    print("=" * 40 + "\n")

    df, mos_list = build_feature_matrix()

    print("\nPreview 5 hàng đầu:")
    preview_cols = mos_list[:5] + ["label"]
    print(df[preview_cols].head())
