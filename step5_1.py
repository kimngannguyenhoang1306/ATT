#!/usr/bin/env python3
"""
STEP 5.1: Obfuscation Resilience Testing with ObfuscAPK CLI Tool
"""

import os
import sys
import subprocess
import shutil
import tempfile
import pickle
from pathlib import Path

from config import CAT1_MAPPING, DECOMPILED_DIR, MODELS_DIR
from step2 import generate_apk_mos

import numpy as np

# ═══════════════════════════════════════════════
# OBFUSCATION TECHNIQUES
# ═══════════════════════════════════════════════

OBFUSCATION_TECHNIQUES = {
    "rebuild": "Rebuild",
    "field_rename": "FieldRename",
    "method_rename": "MethodRename",
    "class_rename": "ClassRename",
    "method_overload": "MethodOverload",
    "goto": "Goto",
    "call_indirect": "CallIndirection",
    "reflection": "Reflection",
    "string_encrypt": "ConstStringEncryption",
    "reorder": "Reorder",
}


# ═══════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════


def check_obfuscapk():
    try:
        result = subprocess.run(
            ["python3", "-m", "obfuscapk.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "usage" in result.stderr.lower() or "usage" in result.stdout.lower()
    except Exception:
        return False


def decompile_apk(apk_path, output_dir):
    """Decompile APK using apktool"""
    print(f"  🔧 Decompiling {os.path.basename(apk_path)}...")
    try:
        subprocess.run(
            ["apktool", "d", apk_path, "-o", output_dir, "-f", "-r"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=True,
        )
        return True
    except Exception as e:
        print(f"     ❌ Decompile failed: {e}")
        return False


def recompile_apk(decompiled_dir, output_apk_path):
    """Recompile decompiled directory back to APK using apktool"""
    print(f"  🔨 Recompiling to APK...")
    try:
        subprocess.run(
            ["apktool", "b", decompiled_dir, "-o", output_apk_path, "--use-aapt2"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=True,
        )
        return os.path.exists(output_apk_path)
    except Exception as e:
        print(f"     ❌ Recompile failed: {e}")
        return False


def obfuscate_apk(apk_path, obf_class, work_dir):
    """
    obfuscapk tự decompile APK vào work_dir/<apk_stem>/<apk_stem>/smali/
    Trả về đường dẫn smali folder đó.
    """
    print(f"     Applying {obf_class}...")

    cmd = [
        "python3",
        "-m",
        "obfuscapk.cli",
        "-o",
        obf_class,
        "-w",
        work_dir,
        apk_path,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        if result.returncode != 0:
            print(f"     ⚠️  stderr: {result.stderr[-300:]}")

        # Cấu trúc: work_dir/<apk_stem>/smali/
        apk_stem = os.path.splitext(os.path.basename(apk_path))[0]
        smali_dir = os.path.join(work_dir, apk_stem, "smali")

        if os.path.isdir(smali_dir):
            return smali_dir

        # Fallback: tìm bất kỳ smali/ folder nào trong work_dir
        for root, dirs, _ in os.walk(work_dir):
            if "smali" in dirs:
                candidate = os.path.join(root, "smali")
                print(f"     📁 Found smali at: {candidate}")
                return candidate

        print(f"     ❌ No smali dir found in {work_dir}")
        print(f"     stdout: {result.stdout[-200:]}")
        print(f"     stderr: {result.stderr[-200:]}")
        return None

    except Exception as e:
        print(f"     ❌ obfuscapk error: {e}")
        return None


def extract_mos_set(decompiled_dir):
    """Return MOS as a set of canonical strings for set-intersection comparison."""
    mos_list = generate_apk_mos(decompiled_dir, CAT1_MAPPING)
    return set("|".join(f"{k}:{v}" for k, v in sorted(m.items())) for m in mos_list)


def build_feature_vector(mos_set, feature_names):
    """
    Convert a MOS set into a binary feature vector aligned to feature_names.
    feature_names is the full list of MOS strings used during training.
    """
    mos_index = {name: i for i, name in enumerate(feature_names)}
    vector = np.zeros(len(feature_names), dtype=np.float32)
    for mos_str in mos_set:
        if mos_str in mos_index:
            vector[mos_index[mos_str]] = 1.0
    return vector


def predict_vector(vector, model_data):
    """
    Run inference with the saved model.
    Returns (pred_label, benign_pct, malware_pct).
    """
    model = model_data["model"]
    model_name = model_data["model_name"]
    sel_idx = model_data["selected_idx"]

    X = vector[sel_idx].reshape(1, -1)

    if model_name == "DNN":
        prob_malware = float(model.predict(X, verbose=0).flatten()[0])
        prob_benign = 1.0 - prob_malware
        pred = int(prob_malware >= 0.5)

    elif model_name == "RF":
        proba = model.predict_proba(X)[0]
        prob_benign = float(proba[0])
        prob_malware = float(proba[1])
        pred = int(model.predict(X)[0])

    elif model_name == "SVM":
        decision = float(model.decision_function(X)[0])
        # LinearSVC has no probability; use sigmoid approximation
        prob_malware = float(1 / (1 + np.exp(-decision)))
        prob_benign = 1.0 - prob_malware
        pred = int(model.predict(X)[0])

    else:
        raise ValueError(f"Unknown model: {model_name}")

    return pred, prob_benign * 100, prob_malware * 100


def compare_mos(original_mos, obfuscated_mos):
    kept = original_mos & obfuscated_mos
    lost = original_mos - obfuscated_mos
    new = obfuscated_mos - original_mos

    preservation = len(kept) / len(original_mos) * 100 if original_mos else 0.0

    return {
        "kept": len(kept),
        "lost": len(lost),
        "new": len(new),
        "preservation_rate": preservation,
    }


# ═══════════════════════════════════════════════
# MAIN TEST FUNCTION
# ═══════════════════════════════════════════════


def test_obfuscation_with_obfuscapk(apk_path):
    """Test obfuscation resilience using obfuscapk CLI tool"""

    print("\n" + "=" * 70)
    print("MOSDroid Obfuscation Resilience Test (with ObfuscAPK)")
    print("=" * 70)
    print(f"\nTesting: {os.path.basename(apk_path)}")

    if not check_obfuscapk():
        print("⚠️  obfuscapk not available. Install with: pip install obfuscapk")
        print("    Falling back to step5.py (simulated obfuscation)")
        return None

    # Load saved model
    model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    if not os.path.exists(model_path):
        print(f"❌ Model not found at {model_path}. Run step4 first.")
        return None

    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    feature_names = model_data["feature_names"]

    results = {}
    temp_base = tempfile.mkdtemp(prefix="mosdroid_obf_")

    try:
        # ── Step 1: Decompile original APK ──────────────────────────────
        print("\n📦 ORIGINAL APK")
        original_decomp = os.path.join(temp_base, "original")
        os.makedirs(original_decomp, exist_ok=True)

        if not decompile_apk(apk_path, original_decomp):
            print("❌ Failed to decompile original APK")
            return None

        print("  🔍 Extracting MOS...")
        original_mos = extract_mos_set(original_decomp)
        print(f"     MOS count: {len(original_mos)}")

        orig_vector = build_feature_vector(original_mos, feature_names)
        orig_pred, orig_benign, orig_malware = predict_vector(orig_vector, model_data)

        print(f"     📊 BENIGN  : {orig_benign:.2f}%")
        print(f"     📊 MALWARE : {orig_malware:.2f}%")
        print(f"     {'⚠️  MALWARE' if orig_pred == 1 else '✅ BENIGN'}")

        results["original"] = {
            "mos_count": len(original_mos),
            "preservation_rate": 100.0,
            "pred": orig_pred,
            "benign": orig_benign,
            "malware": orig_malware,
        }

        # ── Step 2: Test each obfuscation technique ──────────────────────
        print("\n📝 OBFUSCATION TESTS")

        for technique, obf_class in OBFUSCATION_TECHNIQUES.items():
            print(f"\n  [{technique}]")

            work_dir = os.path.join(temp_base, f"obf_{technique}")
            os.makedirs(work_dir, exist_ok=True)

            # obfuscapk tự decompile → trả về smali dir luôn
            smali_dir = obfuscate_apk(apk_path, obf_class, work_dir)
            if not smali_dir:
                print(f"     ⚠️  Skipping {technique}")
                results[technique] = None
                continue

            # Extract MOS thẳng từ smali
            print(f"     🔍 Extracting MOS from smali...")
            obfuscated_mos = extract_mos_set(smali_dir)
            print(f"        MOS count: {len(obfuscated_mos)}")

            # Predict
            obf_vector = build_feature_vector(obfuscated_mos, feature_names)
            pred, benign_pct, malware_pct = predict_vector(obf_vector, model_data)

            print(f"     📊 BENIGN  : {benign_pct:.2f}%")
            print(f"     📊 MALWARE : {malware_pct:.2f}%")
            print(f"     {'⚠️  MALWARE' if pred == 1 else '✅ BENIGN'}")

            comparison = compare_mos(original_mos, obfuscated_mos)
            results[technique] = {
                "pred": pred,
                "benign": benign_pct,
                "malware": malware_pct,
                **comparison,
            }

            print(
                f"     ✓ Kept:  {comparison['kept']:4d} ({comparison['preservation_rate']:6.2f}%)"
            )
            print(f"     ✗ Lost:  {comparison['lost']:4d}")
            print(f"     + New:   {comparison['new']:4d}")

    finally:
        if os.path.exists(temp_base):
            shutil.rmtree(temp_base)

    # ── Summary Report ───────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY REPORT")
    print("=" * 70)
    print(
        f"{'Technique':<20} {'MOS Count':>10} {'Kept':>6} {'Lost':>6} "
        f"{'Preservation':>12} {'Prediction':>12}"
    )
    print("-" * 70)

    orig_count = results["original"]["mos_count"]
    print(
        f"{'original':<20} {orig_count:>10} {orig_count:>6} {'0':>6} "
        f"{'100.00%':>12} "
        f"{'MALWARE' if results['original']['pred'] == 1 else 'BENIGN':>12}"
    )

    preservation_rates = []
    for technique, result in results.items():
        if technique == "original" or result is None:
            continue
        obf_count = orig_count + result["new"] - result["lost"]
        print(
            f"{technique:<20} {obf_count:>10} {result['kept']:>6} {result['lost']:>6} "
            f"{result['preservation_rate']:>11.2f}% "
            f"{'MALWARE' if result['pred'] == 1 else 'BENIGN':>12}"
        )
        preservation_rates.append(result["preservation_rate"])

    avg_rate = (
        sum(preservation_rates) / len(preservation_rates) if preservation_rates else 0.0
    )
    print("-" * 70)
    print(
        f"{'Average Preservation':<20} {' ':>10} {' ':>6} {' ':>6} {avg_rate:>11.2f}%"
    )
    print("=" * 70)

    return results


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python step5_1.py <apk_file_path>")
        print("Example: python step5_1.py app.apk")
        print("\nNote: Requires obfuscapk:")
        print("  pip install obfuscapk")
        sys.exit(1)

    apk_path = sys.argv[1]

    if not os.path.exists(apk_path):
        print(f"❌ APK not found: {apk_path}")
        sys.exit(1)

    if not apk_path.endswith(".apk"):
        print(f"❌ File must be APK: {apk_path}")
        sys.exit(1)

    test_obfuscation_with_obfuscapk(apk_path)
