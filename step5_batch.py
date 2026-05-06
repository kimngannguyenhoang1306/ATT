#!/usr/bin/env python3
"""
STEP 5 Batch: Process multiple decoded APKs for obfuscation resilience testing

Reads decoded APK folders from:
- test_samples/malware_decoded/
- test_samples/benign_decoded/

Uses smali folders directly (skips decompilation).
Tests obfuscation techniques using ObfuscAPK.

Outputs results to test_samples/results/

Generates summary statistics for each category
"""

import os
import json
import sys
import tempfile
import shutil
import pickle
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from config import MODELS_DIR
from step5_1 import (
    extract_mos_set,
    build_feature_vector,
    predict_vector,
    compare_mos,
    obfuscate_apk,
    OBFUSCATION_TECHNIQUES,
)

# ═══════════════════════════════════════════════
# BATCH PROCESSING - Use decoded folders
# ═══════════════════════════════════════════════


def find_decoded_folders(decoded_dir):
    """Find all decoded APK folders (each folder is a decompiled APK)"""
    if not os.path.exists(decoded_dir):
        return []

    folders = []
    for item in os.listdir(decoded_dir):
        item_path = os.path.join(decoded_dir, item)
        if os.path.isdir(item_path):
            # Check if it contains smali folder (valid decompiled APK)
            if os.path.exists(os.path.join(item_path, "smali")):
                folders.append(item_path)

    return sorted(folders)


def test_decoded_apk(decoded_dir, apk_name):
    """Test obfuscation resilience for single decoded APK (already decompiled)"""

    print(f"\n🔍 Testing: {apk_name}")
    print("-" * 70)

    # Load model
    model_path = os.path.join(MODELS_DIR, "best_model.pkl")
    if not os.path.exists(model_path):
        print(f"❌ Model not found at {model_path}")
        return None

    with open(model_path, "rb") as f:
        model_data = pickle.load(f)

    feature_names = model_data["feature_names"]

    # Extract original MOS from decoded folder
    print("  🔍 Extracting original MOS...")
    original_mos = extract_mos_set(decoded_dir)
    print(f"     MOS count: {len(original_mos)}")

    if len(original_mos) == 0:
        print(f"  ⚠️  No MOS extracted, skipping...")
        return None

    # Get original prediction
    orig_vector = build_feature_vector(original_mos, feature_names)
    orig_pred, orig_benign, orig_malware = predict_vector(orig_vector, model_data)

    print(f"     📊 BENIGN  : {orig_benign:.2f}%")
    print(f"     📊 MALWARE : {orig_malware:.2f}%")
    print(f"     {'⚠️  MALWARE' if orig_pred == 1 else '✅ BENIGN'}")

    results = {}
    results["original"] = {
        "mos_count": len(original_mos),
        "preservation_rate": 100.0,
        "pred": orig_pred,
        "benign": orig_benign,
        "malware": orig_malware,
    }

    # Test each obfuscation technique
    print("\n  📝 OBFUSCATION TESTS")

    temp_base = tempfile.mkdtemp(prefix="mosdroid_obf_")

    try:
        for technique, obf_class in OBFUSCATION_TECHNIQUES.items():
            print(f"\n    [{technique}]")

            work_dir = os.path.join(temp_base, f"obf_{technique}")
            os.makedirs(work_dir, exist_ok=True)

            # Create a fake APK path pointing to decoded dir
            # obfuscate_apk will handle the obfuscation
            fake_apk_path = os.path.join(decoded_dir, "fake.apk")

            try:
                # Apply obfuscation
                smali_dir = obfuscate_apk(fake_apk_path, obf_class, work_dir)
                if not smali_dir:
                    print(f"      ⚠️  Skipping {technique}")
                    results[technique] = None
                    continue

                # Extract MOS from obfuscated smali
                print(f"      🔍 Extracting MOS...")
                obfuscated_mos = extract_mos_set(smali_dir)
                print(f"         MOS count: {len(obfuscated_mos)}")

                # Predict
                obf_vector = build_feature_vector(obfuscated_mos, feature_names)
                pred, benign_pct, malware_pct = predict_vector(obf_vector, model_data)

                print(f"      📊 BENIGN  : {benign_pct:.2f}%")
                print(f"      📊 MALWARE : {malware_pct:.2f}%")
                print(f"      {'⚠️  MALWARE' if pred == 1 else '✅ BENIGN'}")

                # Compare MOS
                comparison = compare_mos(original_mos, obfuscated_mos)
                results[technique] = {
                    "pred": pred,
                    "benign": benign_pct,
                    "malware": malware_pct,
                    **comparison,
                }

                print(
                    f"      ✓ Kept:  {comparison['kept']:4d} ({comparison['preservation_rate']:6.2f}%)"
                )
                print(f"      ✗ Lost:  {comparison['lost']:4d}")
                print(f"      + New:   {comparison['new']:4d}")

            except Exception as e:
                print(f"      ❌ Error: {e}")
                results[technique] = None

    finally:
        if os.path.exists(temp_base):
            shutil.rmtree(temp_base)

    return results


def process_batch(
    malware_decoded_dir="test_samples/malware_decoded",
    benign_decoded_dir="test_samples/benign_decoded",
    result_dir="test_samples/results",
):
    """Process all decoded APK folders in batch mode"""

    os.makedirs(result_dir, exist_ok=True)

    # Find decoded folders
    malware_folders = find_decoded_folders(malware_decoded_dir)
    benign_folders = find_decoded_folders(benign_decoded_dir)

    print("\n" + "=" * 70)
    print("MOSDroid Batch Obfuscation Resilience Testing (from decoded APKs)")
    print("=" * 70)
    print(f"Malware samples: {len(malware_folders)}")
    print(f"Benign samples:  {len(benign_folders)}")
    print("=" * 70)

    malware_results = {}
    benign_results = {}

    # Process malware decoded folders
    if malware_folders:
        print("\n" + "=" * 70)
        print("MALWARE SAMPLES")
        print("=" * 70)

        for i, decoded_path in enumerate(malware_folders, 1):
            apk_name = os.path.basename(decoded_path)
            print(f"\n[{i}/{len(malware_folders)}] Processing: {apk_name}")
            print("-" * 70)

            try:
                result = test_decoded_apk(decoded_path, apk_name)
                if result:
                    malware_results[apk_name] = result
                    print(f"✅ Completed: {apk_name}")
                else:
                    print(f"⚠️  No results for: {apk_name}")
                    malware_results[apk_name] = None
            except Exception as e:
                print(f"❌ Error processing {apk_name}: {e}")
                malware_results[apk_name] = None

    # Process benign decoded folders
    if benign_folders:
        print("\n" + "=" * 70)
        print("BENIGN SAMPLES")
        print("=" * 70)

        for i, decoded_path in enumerate(benign_folders, 1):
            apk_name = os.path.basename(decoded_path)
            print(f"\n[{i}/{len(benign_folders)}] Processing: {apk_name}")
            print("-" * 70)

            try:
                result = test_decoded_apk(decoded_path, apk_name)
                if result:
                    benign_results[apk_name] = result
                    print(f"✅ Completed: {apk_name}")
                else:
                    print(f"⚠️  No results for: {apk_name}")
                    benign_results[apk_name] = None
            except Exception as e:
                print(f"❌ Error processing {apk_name}: {e}")
                benign_results[apk_name] = None

    # Calculate and save summary
    malware_stats = calculate_stats(malware_results)
    benign_stats = calculate_stats(benign_results)
    save_summary(
        result_dir, malware_results, benign_results, malware_stats, benign_stats
    )

    return malware_results, benign_results, malware_stats, benign_stats


def calculate_stats(results_dict):
    """Calculate statistics from obfuscation testing results"""
    if not results_dict:
        return None

    stats_by_technique = defaultdict(list)

    for apk_name, results in results_dict.items():
        if not results:
            continue

        for technique, result in results.items():
            if technique == "original" or result is None:
                continue

            preservation = result.get("preservation_rate", 0)
            stats_by_technique[technique].append(preservation)

    # Calculate aggregates
    averages = {}
    for technique, rates in stats_by_technique.items():
        if rates:
            averages[technique] = {
                "avg_preservation": sum(rates) / len(rates),
                "min_preservation": min(rates),
                "max_preservation": max(rates),
                "samples_tested": len(rates),
            }

    return averages


def save_summary(
    result_dir, malware_results, benign_results, malware_stats, benign_stats
):
    """Save comprehensive summary report"""

    summary = {
        "timestamp": datetime.now().isoformat(),
        "malware": {
            "samples_tested": len([r for r in malware_results.values() if r]),
            "statistics": malware_stats,
            "individual_results": malware_results,
        },
        "benign": {
            "samples_tested": len([r for r in benign_results.values() if r]),
            "statistics": benign_stats,
            "individual_results": benign_results,
        },
    }

    summary_file = os.path.join(result_dir, "batch_summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Save text report
    report_file = os.path.join(result_dir, "batch_summary_report.txt")
    with open(report_file, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("MOSDroid Batch Testing Summary Report\n")
        f.write("=" * 70 + "\n\n")

        f.write("MALWARE SAMPLES\n")
        f.write("-" * 70 + "\n")
        f.write(
            f"Samples tested: {len([r for r in malware_results.values() if r])}\n\n"
        )

        if malware_stats:
            f.write(
                f"{'Obfuscation Type':<20} {'Avg Preservation':>15} {'Min':>8} {'Max':>8}\n"
            )
            f.write("-" * 70 + "\n")

            for technique, stats in sorted(malware_stats.items()):
                f.write(
                    f"{technique:<20} {stats['avg_preservation']:>14.2f}% "
                    f"{stats['min_preservation']:>7.2f}% {stats['max_preservation']:>7.2f}%\n"
                )

            # Calculate overall average
            all_rates = []
            for apk_name, results in malware_results.items():
                if results:
                    for technique, result in results.items():
                        if technique != "original" and result:
                            all_rates.append(result.get("preservation_rate", 0))

            if all_rates:
                avg_all = sum(all_rates) / len(all_rates)
                f.write("-" * 70 + "\n")
                f.write(f"{'Overall Average':<20} {avg_all:>14.2f}%\n")

        f.write("\n\nBENIGN SAMPLES\n")
        f.write("-" * 70 + "\n")
        f.write(f"Samples tested: {len([r for r in benign_results.values() if r])}\n\n")

        if benign_stats:
            f.write(
                f"{'Obfuscation Type':<20} {'Avg Preservation':>15} {'Min':>8} {'Max':>8}\n"
            )
            f.write("-" * 70 + "\n")

            for technique, stats in sorted(benign_stats.items()):
                f.write(
                    f"{technique:<20} {stats['avg_preservation']:>14.2f}% "
                    f"{stats['min_preservation']:>7.2f}% {stats['max_preservation']:>7.2f}%\n"
                )

            # Calculate overall average
            all_rates = []
            for apk_name, results in benign_results.items():
                if results:
                    for technique, result in results.items():
                        if technique != "original" and result:
                            all_rates.append(result.get("preservation_rate", 0))

            if all_rates:
                avg_all = sum(all_rates) / len(all_rates)
                f.write("-" * 70 + "\n")
                f.write(f"{'Overall Average':<20} {avg_all:>14.2f}%\n")

        f.write("\n" + "=" * 70 + "\n")

    print(f"\n✅ Summary saved to: {summary_file}")
    print(f"✅ Report saved to: {report_file}")


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    # Default paths for decoded APK folders
    malware_decoded_dir = "test_samples/malware_decoded"
    benign_decoded_dir = "test_samples/benign_decoded"
    result_dir = "test_samples/results"

    # Allow override via command line
    if len(sys.argv) > 1:
        malware_decoded_dir = sys.argv[1]
    if len(sys.argv) > 2:
        benign_decoded_dir = sys.argv[2]
    if len(sys.argv) > 3:
        result_dir = sys.argv[3]

    print(f"Malware decoded dir: {malware_decoded_dir}")
    print(f"Benign decoded dir:  {benign_decoded_dir}")
    print(f"Result dir:          {result_dir}")

    # Run batch processing with decoded APK folders
    malware_results, benign_results, malware_stats, benign_stats = process_batch(
        malware_decoded_dir, benign_decoded_dir, result_dir
    )

    print("\n" + "=" * 70)
    print("✅ Batch processing completed!")
    print("=" * 70)
