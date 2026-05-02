"""
Dùng để phân tích 1 APK bất kỳ
→ Dự đoán là MALWARE hay BENIGN
"""

import os
import sys
import pickle
import subprocess
import numpy as np

from config import CAT1_MAPPING, DECOMPILED_DIR, MODELS_DIR
from step2_extract_mos import generate_apk_mos


def decompile_apk(apk_path):
    """Decompile APK → smali"""
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(DECOMPILED_DIR, f"{apk_name}_predict")

    if os.path.exists(output_dir):
        print(" Đã decompile trước đó, dùng lại...")
        return output_dir

    print(f" Đang decompile {apk_name}...")

    cmd = ["apktool", "d", apk_path, "-o", output_dir, "--no-res", "-f"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        print("❌ Decompile timeout!")
        return None

    if result.returncode == 0:
        return output_dir
    else:
        print(f"❌ Lỗi decompile: {result.stderr[:200]}")
        return None


def predict_apk(apk_path):
    """
    Pipeline đầy đủ:
    APK → decompile → MOS → vector → predict
    """

    print(f"\n{'='*50}")
    print(f"PHÂN TÍCH APK: {os.path.basename(apk_path)}")
    print(f"{'='*50}")

    # ───────────── Bước 1: Load model ─────────────
    model_path = os.path.join(MODELS_DIR, "best_model.pkl")

    if not os.path.exists(model_path):
        print("❌ Chưa có model! Chạy step4 trước.")
        return

    print("Bước 1: Load model...")

    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    model = model_data["model"]
    selected_idx = model_data["selected_idx"]
    feature_names = model_data["feature_names"]

    print(f" ✅ Model loaded ({len(feature_names)} features)")
    print(f" 🔎 Model type: {type(model)}")

    # ───────────── Bước 2: Decompile ─────────────
    print("Bước 2: Decompile APK...")

    decomp_dir = decompile_apk(apk_path)
    if decomp_dir is None:
        print("❌ Decompile thất bại!")
        return

    # ───────────── Bước 3: Extract MOS ─────────────
    print("Bước 3: Extract MOS...")

    apk_mos = generate_apk_mos(decomp_dir, CAT1_MAPPING)

    print(f" ✅ Tìm thấy {len(apk_mos)} MOS duy nhất")

    # ───────────── Bước 4: Feature vector ─────────────
    print("Bước 4: Tạo feature vector...")

    full_vector = np.array(
        [1 if mos in apk_mos else 0 for mos in feature_names], dtype=np.float32
    )

    selected_vector = full_vector[selected_idx].reshape(1, -1)

    print(f" ✅ Vector shape: {selected_vector.shape}")

    # ───────────── Bước 5: Predict ─────────────
    print("Bước 5: Dự đoán...")

    # ===== CASE 1: SKLEARN =====
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(selected_vector)[0]

        prob_benign = probs[0] * 100
        prob_malware = probs[1] * 100

        prediction = model.predict(selected_vector)[0]

    # ===== CASE 2: KERAS / TENSORFLOW =====
    else:
        prob = model.predict(selected_vector)[0]

        # sigmoid output
        prob_malware = float(prob[0]) * 100
        prob_benign = 100.0 - prob_malware

        prediction = 1 if prob_malware >= 50 else 0

    # ───────────── Kết quả ─────────────
    print(f"\n{'='*50}")
    print("KẾT QUẢ:")
    print(f" Xác suất BENIGN  : {prob_benign:.2f}%")
    print(f" Xác suất MALWARE : {prob_malware:.2f}%")

    if prediction == 1:
        print("\n ⚠️ KẾT LUẬN: MALWARE")
    else:
        print("\n ✅ KẾT LUẬN: BENIGN")

    print(f"{'='*50}\n")

    return prediction, [prob_benign / 100, prob_malware / 100]


# ───────────── MAIN ─────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cách dùng: python3 predict.py <đường_dẫn_APK>")
        print("Ví dụ : python3 predict.py /home/kali/test.apk")
        sys.exit(1)

    apk_path = sys.argv[1]

    if not os.path.exists(apk_path):
        print(f"❌ Không tìm thấy file: {apk_path}")
        sys.exit(1)

    predict_apk(apk_path)
