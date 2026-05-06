#!/usr/bin/env python3
"""
STEP 5 Batch: Process multiple APK files for obfuscation resilience testing

Processes APK files and calls step5_1.test_obfuscation_with_obfuscapk() for each
to perform real obfuscation testing using ObfuscAPK CLI tool.

Reads APK files from specified directories (malware/benign)
Outputs results to result/ directory

Generates summary statistics for each category
"""

import os
import json
import sys
import glob
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from step5_1 import test_obfuscation_with_obfuscapk

# ═══════════════════════════════════════════════
# BATCH PROCESSING - Call step5_1 for each APK
# ═══════════════════════════════════════════════


def find_apk_files(directory):
    """Find all APK files in directory recursively"""
    if not os.path.exists(directory):
        return []

    apk_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".apk"):
                apk_files.append(os.path.join(root, file))

    return sorted(apk_files)


def process_batch(malware_dir, benign_dir, result_dir="result"):
    """Process all APK files in batch mode using step5_1"""

    os.makedirs(result_dir, exist_ok=True)

    # Find all APK files
    malware_apks = find_apk_files(malware_dir)
    benign_apks = find_apk_files(benign_dir)

    print("\n" + "=" * 70)
    print("MOSDroid Batch Obfuscation Resilience Testing (step5_1)")
    print("=" * 70)
    print(f"Malware samples: {len(malware_apks)}")
    print(f"Benign samples:  {len(benign_apks)}")
    print("=" * 70)

    malware_results = {}
    benign_results = {}

    # Process malware APKs
    if malware_apks:
        print("\n" + "=" * 70)
        print("MALWARE SAMPLES")
        print("=" * 70)

        for i, apk_path in enumerate(malware_apks, 1):
            apk_name = os.path.basename(apk_path)
            print(f"\n[{i}/{len(malware_apks)}] Processing: {apk_name}")
            print("-" * 70)

            try:
                result = test_obfuscation_with_obfuscapk(apk_path)
                if result:
                    malware_results[apk_name] = result
                    print(f"✅ Completed: {apk_name}")
                else:
                    print(f"⚠️  No results for: {apk_name}")
                    malware_results[apk_name] = None
            except Exception as e:
                print(f"❌ Error processing {apk_name}: {e}")
                malware_results[apk_name] = None

    # Process benign APKs
    if benign_apks:
        print("\n" + "=" * 70)
        print("BENIGN SAMPLES")
        print("=" * 70)

        for i, apk_path in enumerate(benign_apks, 1):
            apk_name = os.path.basename(apk_path)
            print(f"\n[{i}/{len(benign_apks)}] Processing: {apk_name}")
            print("-" * 70)

            try:
                result = test_obfuscation_with_obfuscapk(apk_path)
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

    # Default paths for APK files
    malware_dir = "raw_apk/malware"
    benign_dir = "raw_apk/benign"
    result_dir = "result"

    # Allow override via command line
    if len(sys.argv) > 1:
        malware_dir = sys.argv[1]
    if len(sys.argv) > 2:
        benign_dir = sys.argv[2]
    if len(sys.argv) > 3:
        result_dir = sys.argv[3]

    print(f"Malware dir: {malware_dir}")
    print(f"Benign dir:  {benign_dir}")
    print(f"Result dir:  {result_dir}")

    # Run batch processing with step5_1
    malware_results, benign_results, malware_stats, benign_stats = process_batch(
        malware_dir, benign_dir, result_dir
    )

    print("\n" + "=" * 70)
    print("✅ Batch processing completed!")
    print("=" * 70)

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

    # Default paths for APK files
    malware_dir = "raw_apk/malware"
    benign_dir = "raw_apk/benign"
    result_dir = "result"

    # Allow override via command line
    if len(sys.argv) > 1:
        malware_dir = sys.argv[1]
    if len(sys.argv) > 2:
        benign_dir = sys.argv[2]
    if len(sys.argv) > 3:
        result_dir = sys.argv[3]

    print(f"Malware dir: {malware_dir}")
    print(f"Benign dir:  {benign_dir}")
    print(f"Result dir:  {result_dir}")

    # Run batch processing with step5_1
    malware_results, benign_results, malware_stats, benign_stats = process_batch(
        malware_dir, benign_dir, result_dir
    )

    print("\n" + "=" * 70)
    print("✅ Batch processing completed!")
    print("=" * 70)
