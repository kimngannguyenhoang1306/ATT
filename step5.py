"""
STEP 5: Predict APK + (Optional) Obfuscation Testing (FIXED VERSION)
"""

import os
import sys
import pickle
import subprocess
import numpy as np
import shutil

from config import CAT1_MAPPING, DECOMPILED_DIR, MODELS_DIR
from step2 import generate_apk_mos


# ═══════════════════════════════════════════════
# UTIL: MOS dict → string
# ═══════════════════════════════════════════════
def mos_dict_to_str(mos_dict):
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


# ═══════════════════════════════════════════════
# STEP 1: DECOMPILE APK
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
# STEP 2: EXTRACT MOS
# ═══════════════════════════════════════════════
def extract_mos_set(decomp_dir):
    apk_mos_list = generate_apk_mos(decomp_dir, CAT1_MAPPING)
    return set(mos_dict_to_str(m) for m in apk_mos_list)


# ═══════════════════════════════════════════════
# STEP 3: VECTORIZE
# ═══════════════════════════════════════════════
def build_feature_vector(apk_mos_set, feature_names):
    return np.array(
        [1 if mos in apk_mos_set else 0 for mos in feature_names],
        dtype=np.float32,
    )


# ═══════════════════════════════════════════════
# STEP 4: PREDICT VECTOR
# ═══════════════════════════════════════════════
def predict_vector(vector, model_data):
    model = model_data["model"]
    selected_idx = model_data["selected_idx"]

    vector_sel = vector[selected_idx].reshape(1, -1)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(vector_sel)[0]
        pred = model.predict(vector_sel)[0]

        prob_benign = probs[0] * 100
        prob_malware = probs[1] * 100
    else:
        prob = model.predict(vector_sel, verbose=0)[0][0]
        prob_malware = prob * 100
        prob_benign = 100 - prob_malware
        pred = 1 if prob >= 0.5 else 0

    return pred, prob_benign, prob_malware


# ═══════════════════════════════════════════════
# STEP 5: PREDICT APK (GỐC)
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

    # ✔ decompile APK GỐC
    decomp_dir = decompile_apk(apk_path)
    if decomp_dir is None:
        return

    # ✔ extract MOS
    apk_mos_set = extract_mos_set(decomp_dir)
    print(f"🔍 MOS count: {len(apk_mos_set)}")

    # ✔ vectorize
    vector = build_feature_vector(apk_mos_set, feature_names)

    # ✔ predict
    pred, prob_benign, prob_malware = predict_vector(vector, model_data)

    print(f"\n📊 KẾT QUẢ:")
    print(f"  BENIGN  : {prob_benign:.2f}%")
    print(f"  MALWARE : {prob_malware:.2f}%")

    print("\n⚠️ MALWARE" if pred == 1 else "\n✅ BENIGN")

    return pred


# ═══════════════════════════════════════════════
# OBFUSCATION MAP
# ═══════════════════════════════════════════════
OBFUSCATION_MAP = {
    "rename": "ClassRename",
    "reflection": "AdvancedReflection",
    "string_encryption": "ConstStringEncryption",
    "goto": "Goto",
    "junk": "Nop",
    "reorder": "Reorder",
    "debug_removal": "DebugRemoval",
    "call_indirection": "CallIndirection",
    "method_rename": "MethodRename",
    "field_rename": "FieldRename",
}


# ═══════════════════════════════════════════════
# OBFUSCATE APK (FIXED)
# ═══════════════════════════════════════════════
def obfuscate_apk(apk_path, mode):
    out_dir = "obfuscated_apks"
    os.makedirs(out_dir, exist_ok=True)

    apk_name = os.path.basename(apk_path).replace(".apk", "")
    out_apk = os.path.join(out_dir, f"{apk_name}_{mode}.apk")

    obf_class = OBFUSCATION_MAP[mode]

    cmd = [
        "python3",
        "-m",
        "obfuscapk.cli",
        apk_path,
        "-o",
        obf_class,
        "-d",
        out_apk,  # 🔥 IMPORTANT FIX
    ]

    print(f"⚙️ Running {mode} -> {obf_class}")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Obfuscation failed:")
        print(result.stderr[-500:])
        return None

    if os.path.exists(out_apk):
        return out_apk

    print("❌ No obfuscated APK generated")
    return None


# ═══════════════════════════════════════════════
# OBFUSCATION EVALUATION
# ═══════════════════════════════════════════════
def evaluate_obfuscation(apk_path):
    print("\n🔬 TEST OBFUSCATION")

    results = []

    # original
    print("\n[ORIGINAL]")
    pred = predict_apk(apk_path)
    results.append(("original", pred))

    for mode in OBFUSCATION_MAP.keys():
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
