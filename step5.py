"""
STEP 5: Predict APK + (Optional) Obfuscation Testing
"""

import os
import sys
import pickle
import subprocess
import numpy as np

from config import CAT1_MAPPING, DECOMPILED_DIR, MODELS_DIR
from step2_extract_mos import generate_apk_mos


# ═══════════════════════════════════════════════
# UTIL: MOS dict → string (QUAN TRỌNG)
# ═══════════════════════════════════════════════
def mos_dict_to_str(mos_dict):
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


# ═══════════════════════════════════════════════
# STEP 1: DECOMPILE
# ═══════════════════════════════════════════════
def decompile_apk(apk_path):
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(DECOMPILED_DIR, f"{apk_name}_predict")

    if os.path.exists(output_dir):
        print("🔁 Dùng lại decompiled...")
        return output_dir

    print(f"🔧 Decompile {apk_name}...")

    cmd = ["apktool", "d", apk_path, "-o", output_dir, "--no-res", "-f"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        print("❌ Decompile timeout!")
        return None

    if result.returncode == 0:
        return output_dir
    else:
        print(f"❌ Lỗi decompile: {result.stderr[:200]}")
        return None


# ═══════════════════════════════════════════════
# STEP 2: EXTRACT MOS + CONVERT
# ═══════════════════════════════════════════════
def extract_mos_set(decomp_dir):
    apk_mos_list = generate_apk_mos(decomp_dir, CAT1_MAPPING)

    # 🔥 FIX QUAN TRỌNG
    apk_mos_set = set(mos_dict_to_str(m) for m in apk_mos_list)

    return apk_mos_set


# ═══════════════════════════════════════════════
# STEP 3: VECTORIZE
# ═══════════════════════════════════════════════
def build_feature_vector(apk_mos_set, feature_names):
    vector = np.array(
        [1 if mos in apk_mos_set else 0 for mos in feature_names],
        dtype=np.float32,
    )
    return vector


# ═══════════════════════════════════════════════
# STEP 4: PREDICT
# ═══════════════════════════════════════════════
def predict_vector(vector, model_data):
    model = model_data["model"]
    selected_idx = model_data["selected_idx"]

    vector_sel = vector[selected_idx].reshape(1, -1)

    # SKLEARN
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vector_sel)[0]
        pred = model.predict(vector_sel)[0]

        prob_benign = probs[0] * 100
        prob_malware = probs[1] * 100

    else:
        # DNN
        prob = model.predict(vector_sel, verbose=0)[0][0]
        prob_malware = prob * 100
        prob_benign = 100 - prob_malware
        pred = 1 if prob >= 0.5 else 0

    return pred, prob_benign, prob_malware


# ═══════════════════════════════════════════════
# MAIN PREDICT
# ═══════════════════════════════════════════════
def predict_apk(apk_path):
    print(f"\n{'='*50}")
    print(f"📱 APK: {os.path.basename(apk_path)}")
    print(f"{'='*50}")

    # Load model
    model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    if not os.path.exists(model_path):
        print("❌ Chưa train model!")
        return

    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    feature_names = model_data["feature_names"]

    # Decompile
    decomp_dir = decompile_apk(apk_path)
    if decomp_dir is None:
        return

    # Extract MOS
    apk_mos_set = extract_mos_set(decomp_dir)
    print(f"🔍 MOS count: {len(apk_mos_set)}")

    # Vectorize
    vector = build_feature_vector(apk_mos_set, feature_names)

    # Predict
    pred, prob_benign, prob_malware = predict_vector(vector, model_data)

    print(f"\n📊 KẾT QUẢ:")
    print(f"  BENIGN  : {prob_benign:.2f}%")
    print(f"  MALWARE : {prob_malware:.2f}%")

    if pred == 1:
        print("\n⚠️  MALWARE")
    else:
        print("\n✅ BENIGN")

    return pred


# ═══════════════════════════════════════════════
# OPTIONAL: OBFUSCATION TEST (THEO PAPER)
# ═══════════════════════════════════════════════

OBFUSCATION_MODES = [
    "rename",
    "reflection",
    "string_encryption",
    "goto",
    "junk",
    "reorder",
    "debug_removal",
    "call_indirection",
    "method_rename",
    "field_rename",
]


def obfuscate_apk(apk_path, mode):
    out_dir = "obfuscated_apks"
    os.makedirs(out_dir, exist_ok=True)

    apk_name = os.path.basename(apk_path).replace(".apk", "")
    out_apk = os.path.join(out_dir, f"{apk_name}_{mode}.apk")

    cmd = [
        "obfuscapk",
        "-i",
        apk_path,
        "-o",
        out_apk,
        "-o",
        mode,
    ]

    try:
        subprocess.run(cmd, timeout=300)
        return out_apk
    except:
        print(f"❌ Obfuscate fail: {mode}")
        return None


def evaluate_obfuscation(apk_path):
    print("\n🔬 TEST OBFUSCATION")

    results = []

    # original
    print("\n[ORIGINAL]")
    pred = predict_apk(apk_path)
    results.append(("original", pred))

    for mode in OBFUSCATION_MODES:
        print(f"\n[{mode.upper()}]")

        obf_apk = obfuscate_apk(apk_path, mode)
        if obf_apk is None:
            continue

        pred = predict_apk(obf_apk)
        results.append((mode, pred))

    print("\n📊 SUMMARY:")
    for mode, pred in results:
        print(f"{mode:20s}: {'MALWARE' if pred else 'BENIGN'}")

    return results


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 predict.py app.apk")
        print("  python3 predict.py app.apk --obf")
        sys.exit(1)

    apk_path = sys.argv[1]

    if not os.path.exists(apk_path):
        print("❌ File không tồn tại")
        sys.exit(1)

    if len(sys.argv) > 2 and sys.argv[2] == "--obf":
        evaluate_obfuscation(apk_path)
    else:
        predict_apk(apk_path)
