"""
STEP 5: Predict APK + Obfuscation Testing (FIXED CLEAN VERSION)
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
# MOS utils
# ═══════════════════════════════════════════════
def mos_dict_to_str(mos_dict):
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


# ═══════════════════════════════════════════════
# DECOMPILE APK
# ═══════════════════════════════════════════════
def decompile_apk(apk_path):
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    output_dir = os.path.join(DECOMPILED_DIR, f"{apk_name}_predict")

    if os.path.exists(output_dir):
        print("🔁 Dùng lại decompiled...")
        return output_dir

    print(f"🔧 Decompile {apk_name}...")

    cmd = ["apktool", "d", apk_path, "-o", output_dir, "--no-res", "-f"]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Decompile failed:")
        print(result.stderr[-300:])
        return None

    return output_dir


# ═══════════════════════════════════════════════
# EXTRACT MOS
# ═══════════════════════════════════════════════
def extract_mos_set(decomp_dir):
    apk_mos_list = generate_apk_mos(decomp_dir, CAT1_MAPPING)
    return set(mos_dict_to_str(m) for m in apk_mos_list)


# ═══════════════════════════════════════════════
# VECTORIZE
# ═══════════════════════════════════════════════
def build_feature_vector(apk_mos_set, feature_names):
    return np.array(
        [1 if mos in apk_mos_set else 0 for mos in feature_names],
        dtype=np.float32,
    )


# ═══════════════════════════════════════════════
# PREDICT
# ═══════════════════════════════════════════════
def predict_vector(vector, model_data):
    model = model_data["model"]
    selected_idx = model_data["selected_idx"]

    v = vector[selected_idx].reshape(1, -1)

    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(v)[0]
        pred = model.predict(v)[0]

        return pred, probs[0] * 100, probs[1] * 100

    prob = model.predict(v, verbose=0)[0][0]
    return (1 if prob >= 0.5 else 0), (1 - prob) * 100, prob * 100


# ═══════════════════════════════════════════════
# MAIN PREDICT (GỐC APK)
# ═══════════════════════════════════════════════
def predict_apk(apk_path):
    print(f"\n{'='*50}")
    print(f"📱 APK: {os.path.basename(apk_path)}")
    print(f"{'='*50}")

    model_path = os.path.join(MODELS_DIR, "best_model.pkl")

    if not os.path.exists(model_path):
        print("❌ Missing model")
        return

    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    feature_names = model_data["feature_names"]

    decomp_dir = decompile_apk(apk_path)
    if not decomp_dir:
        return

    mos_set = extract_mos_set(decomp_dir)
    print(f"🔍 MOS count: {len(mos_set)}")

    vector = build_feature_vector(mos_set, feature_names)

    pred, benign, malware = predict_vector(vector, model_data)

    print("\n📊 RESULT:")
    print(f"  BENIGN  : {benign:.2f}%")
    print(f"  MALWARE : {malware:.2f}%")

    print("\n⚠️ MALWARE" if pred == 1 else "\n✅ BENIGN")

    return pred


# ═══════════════════════════════════════════════
# OBFUSCATION MAP (REAL CLI NAMES)
# ═══════════════════════════════════════════════
OBFUSCATION_MAP = {
    "rename": "ClassRename",
    "reflection": "Reflection",
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
# OBFUSCATE APK (FIXED PROPER WAY)
# ═══════════════════════════════════════════════
def obfuscate_apk(apk_path, mode):
    apk_name = os.path.basename(apk_path).replace(".apk", "")
    work_dir = f"obfus_tmp/{apk_name}_{mode}"

    os.makedirs(work_dir, exist_ok=True)

    obf_class = OBFUSCATION_MAP[mode]

    print(f"⚙️ {mode} -> {obf_class}")

    cmd = [
        "python3",
        "-m",
        "obfuscapk.cli",
        apk_path,
        "-o",
        obf_class,
        "-d",
        work_dir,  # ✅ DIRECTORY ONLY
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Obfuscation failed:")
        print(result.stderr[-400:])
        return None

    # 🔥 SEARCH OUTPUT APK (IMPORTANT FIX)
    for root, _, files in os.walk(work_dir):
        for f in files:
            if f.endswith(".apk"):
                out_path = os.path.join(root, f)

                final_path = f"obfuscated_apks/{apk_name}_{mode}.apk"
                os.makedirs("obfuscated_apks", exist_ok=True)

                shutil.copy(out_path, final_path)

                print(f"✅ APK GENERATED: {final_path}")
                return final_path

    print("❌ NO APK FOUND (only smali modified)")
    return None


# ═══════════════════════════════════════════════
# EVALUATION
# ═══════════════════════════════════════════════
def evaluate_obfuscation(apk_path):
    print("\n🔬 OBFUSCATION TEST")

    results = []

    print("\n[ORIGINAL]")
    results.append(("original", predict_apk(apk_path)))

    for mode in OBFUSCATION_MAP:
        print(f"\n[{mode}]")

        obf_apk = obfuscate_apk(apk_path, mode)

        if not obf_apk:
            continue

        results.append((mode, predict_apk(obf_apk)))

    print("\n📊 SUMMARY")
    for m, r in results:
        print(f"{m:20s}: {'MALWARE' if r else 'BENIGN'}")

    return results


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("python3 predict.py app.apk [--obf]")
        sys.exit(1)

    apk = sys.argv[1]

    if len(sys.argv) > 2 and sys.argv[2] == "--obf":
        evaluate_obfuscation(apk)
    else:
        predict_apk(apk)
