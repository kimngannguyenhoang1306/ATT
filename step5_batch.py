#!/usr/bin/env python3
"""
STEP 5 Batch: Process multiple decoded APKs for obfuscation resilience testing

Reads each decoded APK from test_samples folder:
- test_samples/malware_decoded/
- test_samples/benign_decoded/

Outputs results to:
- test_samples/results/malware_*.json
- test_samples/benign_*.json

Generates summary statistics for each category
"""

import os
import json
import pickle
import random
import re
import shutil
from pathlib import Path
from copy import deepcopy
from collections import Counter, defaultdict
from datetime import datetime

from config import CAT1_MAPPING, MODELS_DIR
from step2 import generate_apk_mos

# ═══════════════════════════════════════════════
# OBFUSCATION TECHNIQUES (10 types per paper)
# ═══════════════════════════════════════════════


def obfus_junk_code(lines):
    """1. Insert junk NOP operations"""
    result = []
    for i, line in enumerate(lines):
        result.append(line)
        if "invoke" in line or "return" in line:
            result.append("    nop\n")
    return result


def obfus_rename_class(lines):
    """2. Class renaming"""
    mapping = {}
    result = []
    for line in lines:
        if "L" in line and "/" in line:
            match = re.search(r"(L[^;]+)", line)
            if match:
                class_name = match.group(1)
                if class_name not in mapping:
                    mapping[class_name] = f"L{random.randint(1000,9999)}/obf"
                line = line.replace(class_name, mapping[class_name])
        result.append(line)
    return result


def obfus_rename_method(lines):
    """3. Method renaming"""
    result = []
    method_map = {}
    for line in lines:
        if ".method " in line:
            line = re.sub(
                r"public \w+\(",
                lambda m: f"public obf_{random.randint(1000,9999)}(",
                line,
            )
        elif "invoke" in line and "->" in line:
            line = re.sub(r"->(\w+)\(", lambda m: f"->{m.group(1)}_obf(", line)
        result.append(line)
    return result


def obfus_rename_field(lines):
    """4. Field renaming"""
    result = []
    for line in lines:
        if (
            "L" in line
            and ":" in line
            and not ".method" in line
            and not ".field" in line
        ):
            line = re.sub(r":(\w+)", lambda m: f":{m.group(1)}_obf", line)
        result.append(line)
    return result


def obfus_string_encryption(lines):
    """5. String encryption (replace with constants)"""
    result = []
    for line in lines:
        if '"' in line:
            line = re.sub(r'"[^"]*"', "p_encr_str", line)
        result.append(line)
    return result


def obfus_control_flow(lines):
    """6. Control flow obfuscation (add GOTO)"""
    result = []
    for i, line in enumerate(lines):
        result.append(line)
        if "if-" in line or "return" in line:
            result.append("    :label_obf\n")
            result.append("    goto :end_obf\n")
            result.append("    :end_obf\n")
    return result


def obfus_reflection(lines):
    """7. Add reflection calls"""
    result = []
    for line in lines:
        result.append(line)
        if "invoke" in line and "direct" not in line:
            result.append('    const-string v_temp, "java/lang/reflection"\n')
            result.append(
                "    invoke-static {v_temp}, Ljava/lang/Class;.forName(Ljava/lang/String;)Ljava/lang/Class;\n"
            )
    return result


def obfus_call_indirection(lines):
    """8. Call indirection (wrap calls)"""
    result = []
    for line in lines:
        if "invoke-virtual" in line:
            line = line.replace("invoke-virtual", "invoke-interface")
        result.append(line)
    return result


def obfus_dead_code(lines):
    """9. Dead code insertion"""
    result = []
    for line in lines:
        result.append(line)
        if ".method" in line:
            result.append("    const v_dead, 0xdeadbeef\n")
            result.append("    if-nez v_dead, :skip_dead\n")
            result.append("    # unreachable dead code\n")
            result.append("    :skip_dead\n")
    return result


def obfus_reorder_instructions(lines):
    """10. Reorder instructions (randomize order)"""
    result = []
    current_method = []
    in_method = False

    for line in lines:
        if ".method" in line:
            if current_method:
                instrs = [
                    l
                    for l in current_method
                    if not any(
                        x in l for x in [".method", ".end", "goto", "if-", "return"]
                    )
                ]
                controls = [
                    l
                    for l in current_method
                    if any(x in l for x in [".method", ".end", "goto", "if-", "return"])
                ]
                random.shuffle(instrs)
                result.extend(controls[:1])
                result.extend(instrs)
                result.extend(controls[1:])
                current_method = []
            in_method = True
            current_method.append(line)
        elif ".end method" in line:
            current_method.append(line)
            result.extend(current_method)
            current_method = []
            in_method = False
        else:
            current_method.append(line)

    if current_method:
        result.extend(current_method)

    return result if result else lines


# ═══════════════════════════════════════════════
# OBFUSCATION PIPELINE
# ═══════════════════════════════════════════════

OBFUSCATION_FUNCS = {
    "junk_code": obfus_junk_code,
    "class_rename": obfus_rename_class,
    "method_rename": obfus_rename_method,
    "field_rename": obfus_rename_field,
    "string_encrypt": obfus_string_encryption,
    "control_flow": obfus_control_flow,
    "reflection": obfus_reflection,
    "call_indirect": obfus_call_indirection,
    "dead_code": obfus_dead_code,
    "reorder": obfus_reorder_instructions,
}


def apply_obfuscation(smali_file_path, obfus_type):
    """Apply obfuscation to smali file"""
    try:
        with open(smali_file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except:
        return None

    if obfus_type not in OBFUSCATION_FUNCS:
        return None

    obfus_func = OBFUSCATION_FUNCS[obfus_type]
    obfuscated_lines = obfus_func(lines)

    return obfuscated_lines


def create_obfuscated_copy(decompiled_dir, obfus_type, output_dir):
    """Create obfuscated copy of decompiled APK"""
    os.makedirs(output_dir, exist_ok=True)

    for root, dirs, files in os.walk(decompiled_dir):
        rel_path = os.path.relpath(root, decompiled_dir)
        target_dir = os.path.join(output_dir, rel_path)
        os.makedirs(target_dir, exist_ok=True)

        for file in files:
            src = os.path.join(root, file)
            dst = os.path.join(target_dir, file)

            if file.endswith(".smali"):
                obfuscated = apply_obfuscation(src, obfus_type)
                if obfuscated:
                    with open(dst, "w", encoding="utf-8") as f:
                        f.writelines(obfuscated)
                else:
                    shutil.copy2(src, dst)
            else:
                shutil.copy2(src, dst)

    return output_dir


# ═══════════════════════════════════════════════
# MOS EXTRACTION & COMPARISON
# ═══════════════════════════════════════════════


def mos_dict_to_str(mos_dict):
    """Convert MOS dict to string"""
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


def extract_mos_set(decompiled_dir):
    """Extract MOS as set of strings"""
    try:
        mos_list = generate_apk_mos(decompiled_dir, CAT1_MAPPING)
        return set(mos_dict_to_str(m) for m in mos_list)
    except Exception as e:
        print(f"   ⚠️  Error extracting MOS: {e}")
        return set()


def compare_mos(original_mos, obfuscated_mos):
    """Compare MOS sets"""
    kept = original_mos & obfuscated_mos
    lost = original_mos - obfuscated_mos
    new = obfuscated_mos - original_mos

    preservation = len(kept) / len(original_mos) * 100 if original_mos else 0

    return {
        "kept": len(kept),
        "lost": len(lost),
        "new": len(new),
        "preservation_rate": preservation,
    }


# ═══════════════════════════════════════════════
# BATCH PROCESSING
# ═══════════════════════════════════════════════


def test_single_apk(decompiled_dir, apk_name, temp_dir="obfus_batch_test"):
    """Test obfuscation resilience for single APK"""

    print(f"\n🔍 Testing APK: {apk_name}")
    print("-" * 70)

    # Extract original MOS
    original_mos = extract_mos_set(decompiled_dir)
    print(f"   Original MOS count: {len(original_mos)}")

    if len(original_mos) == 0:
        print(f"   ⚠️  No MOS extracted, skipping...")
        return None

    results = {}

    # Test each obfuscation
    for obfus_type in OBFUSCATION_FUNCS.keys():
        obfus_dir = os.path.join(temp_dir, f"{apk_name}_{obfus_type}")

        try:
            create_obfuscated_copy(decompiled_dir, obfus_type, obfus_dir)
            obfuscated_mos = extract_mos_set(obfus_dir)

            comparison = compare_mos(original_mos, obfuscated_mos)
            results[obfus_type] = comparison

            print(
                f"   {obfus_type:<20} Preservation: {comparison['preservation_rate']:6.2f}%"
            )

        except Exception as e:
            print(f"   {obfus_type:<20} Error: {e}")
            results[obfus_type] = None

        finally:
            if os.path.exists(obfus_dir):
                shutil.rmtree(obfus_dir)

    return results


def process_batch(malware_dir, benign_dir, result_dir, temp_dir="obfus_batch_test"):
    """Process all APKs in batch mode"""

    os.makedirs(result_dir, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)

    # Collect all decoded APK folders
    malware_samples = []
    benign_samples = []

    if os.path.exists(malware_dir):
        malware_samples = [
            d
            for d in os.listdir(malware_dir)
            if os.path.isdir(os.path.join(malware_dir, d))
        ]

    if os.path.exists(benign_dir):
        benign_samples = [
            d
            for d in os.listdir(benign_dir)
            if os.path.isdir(os.path.join(benign_dir, d))
        ]

    print("\n" + "=" * 70)
    print(f"MOSDroid Batch Obfuscation Resilience Testing")
    print("=" * 70)
    print(f"Malware samples: {len(malware_samples)}")
    print(f"Benign samples:  {len(benign_samples)}")
    print("=" * 70)

    # Process malware
    malware_results = {}
    if malware_samples:
        print("\n" + "=" * 70)
        print("MALWARE SAMPLES")
        print("=" * 70)

        for i, sample in enumerate(malware_samples, 1):
            sample_path = os.path.join(malware_dir, sample)
            result = test_single_apk(sample_path, sample, temp_dir)
            if result:
                malware_results[sample] = result
                # Save individual result
                result_file = os.path.join(result_dir, f"malware_{sample}.json")
                with open(result_file, "w") as f:
                    json.dump(
                        {
                            "sample": sample,
                            "timestamp": datetime.now().isoformat(),
                            "results": result,
                        },
                        f,
                        indent=2,
                    )

    # Process benign
    benign_results = {}
    if benign_samples:
        print("\n" + "=" * 70)
        print("BENIGN SAMPLES")
        print("=" * 70)

        for i, sample in enumerate(benign_samples, 1):
            sample_path = os.path.join(benign_dir, sample)
            result = test_single_apk(sample_path, sample, temp_dir)
            if result:
                benign_results[sample] = result
                # Save individual result
                result_file = os.path.join(result_dir, f"benign_{sample}.json")
                with open(result_file, "w") as f:
                    json.dump(
                        {
                            "sample": sample,
                            "timestamp": datetime.now().isoformat(),
                            "results": result,
                        },
                        f,
                        indent=2,
                    )

    # Calculate statistics
    malware_stats = calculate_stats(malware_results)
    benign_stats = calculate_stats(benign_results)

    # Save summary
    save_summary(
        result_dir, malware_results, benign_results, malware_stats, benign_stats
    )

    # Cleanup
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    return malware_results, benign_results, malware_stats, benign_stats


def calculate_stats(results_dict):
    """Calculate statistics from all results"""
    if not results_dict:
        return None

    # Aggregate results by obfuscation type
    stats_by_type = defaultdict(list)

    for sample, results in results_dict.items():
        for obfus_type, result in results.items():
            if result:
                stats_by_type[obfus_type].append(result["preservation_rate"])

    # Calculate averages
    averages = {}
    for obfus_type, rates in stats_by_type.items():
        if rates:
            averages[obfus_type] = {
                "avg_preservation": sum(rates) / len(rates),
                "min_preservation": min(rates),
                "max_preservation": max(rates),
                "samples_tested": len(rates),
            }

    return averages


def save_summary(
    result_dir, malware_results, benign_results, malware_stats, benign_stats
):
    """Save comprehensive summary"""

    summary = {
        "timestamp": datetime.now().isoformat(),
        "malware": {
            "samples_tested": len(malware_results),
            "statistics": malware_stats,
            "individual_results": malware_results,
        },
        "benign": {
            "samples_tested": len(benign_results),
            "statistics": benign_stats,
            "individual_results": benign_results,
        },
    }

    summary_file = os.path.join(result_dir, "summary.json")
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    # Also save as text report
    report_file = os.path.join(result_dir, "summary_report.txt")
    with open(report_file, "w") as f:
        f.write("=" * 70 + "\n")
        f.write("MOSDroid Batch Testing Summary Report\n")
        f.write("=" * 70 + "\n\n")

        f.write("MALWARE SAMPLES\n")
        f.write("-" * 70 + "\n")
        f.write(f"Samples tested: {len(malware_results)}\n\n")

        if malware_stats:
            f.write(
                f"{'Obfuscation Type':<20} {'Avg Preservation':>15} {'Min':>8} {'Max':>8}\n"
            )
            f.write("-" * 70 + "\n")

            for obfus_type, stats in sorted(malware_stats.items()):
                f.write(
                    f"{obfus_type:<20} {stats['avg_preservation']:>14.2f}% "
                    f"{stats['min_preservation']:>7.2f}% {stats['max_preservation']:>7.2f}%\n"
                )

            all_rates = []
            for sample, results in malware_results.items():
                for result in results.values():
                    if result:
                        all_rates.append(result["preservation_rate"])

            if all_rates:
                avg_all = sum(all_rates) / len(all_rates)
                f.write("-" * 70 + "\n")
                f.write(f"{'Overall Average':<20} {avg_all:>14.2f}%\n")

        f.write("\n\nBENIGN SAMPLES\n")
        f.write("-" * 70 + "\n")
        f.write(f"Samples tested: {len(benign_results)}\n\n")

        if benign_stats:
            f.write(
                f"{'Obfuscation Type':<20} {'Avg Preservation':>15} {'Min':>8} {'Max':>8}\n"
            )
            f.write("-" * 70 + "\n")

            for obfus_type, stats in sorted(benign_stats.items()):
                f.write(
                    f"{obfus_type:<20} {stats['avg_preservation']:>14.2f}% "
                    f"{stats['min_preservation']:>7.2f}% {stats['max_preservation']:>7.2f}%\n"
                )

            all_rates = []
            for sample, results in benign_results.items():
                for result in results.values():
                    if result:
                        all_rates.append(result["preservation_rate"])

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

    # Default paths
    malware_dir = "test_samples/malware_decoded"
    benign_dir = "test_samples/benign_decoded"
    result_dir = "test_samples/results"

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

    # Run batch processing
    malware_results, benign_results, malware_stats, benign_stats = process_batch(
        malware_dir, benign_dir, result_dir
    )

    print("\n" + "=" * 70)
    print("✅ Batch processing completed!")
    print("=" * 70)
