#!/usr/bin/env python3
"""
STEP 5: Obfuscation Resilience Testing (MOSDroid Paper)

Tạo 10 loại obfuscation và test MOS extraction:
1. Junk code insertion (NOP)
2. Class renaming
3. Method renaming
4. Field renaming
5. String encryption
6. Control flow obfuscation (GOTO)
7. Reflection
8. Call indirection
9. Dead code insertion
10. Reordering instructions
"""

import os
import json
import pickle
import random
import re
import shutil
from pathlib import Path
from copy import deepcopy
from collections import Counter

from config import CAT1_MAPPING, DECOMPILED_DIR, APK_MOS_DIR, MODELS_DIR
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
        # Replace Landroid/app/Activity → LObf123/xyz/Activity
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
            # Rename method public foo → public obf_123
            line = re.sub(
                r"public \w+\(",
                lambda m: f"public obf_{random.randint(1000,9999)}(",
                line,
            )
        elif "invoke" in line and "->" in line:
            # Rename method calls
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
            # Rename field references
            line = re.sub(r":(\w+)", lambda m: f":{m.group(1)}_obf", line)
        result.append(line)
    return result


def obfus_string_encryption(lines):
    """5. String encryption (replace with constants)"""
    result = []
    for line in lines:
        if '"' in line:
            # Replace string with const reference
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
            # Convert direct to indirect
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
    # Group by method
    result = []
    current_method = []
    in_method = False

    for line in lines:
        if ".method" in line:
            if current_method:
                # Shuffle non-control-flow instructions
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

    # Copy all files
    for root, dirs, files in os.walk(decompiled_dir):
        rel_path = os.path.relpath(root, decompiled_dir)
        target_dir = os.path.join(output_dir, rel_path)
        os.makedirs(target_dir, exist_ok=True)

        for file in files:
            src = os.path.join(root, file)
            dst = os.path.join(target_dir, file)

            if file.endswith(".smali"):
                # Apply obfuscation
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
    mos_list = generate_apk_mos(decompiled_dir, CAT1_MAPPING)
    return set(mos_dict_to_str(m) for m in mos_list)


def compare_mos(original_mos, obfuscated_mos):
    """Compare MOS sets"""
    kept = original_mos & obfuscated_mos  # Intersection
    lost = original_mos - obfuscated_mos  # Lost
    new = obfuscated_mos - original_mos  # New

    preservation = len(kept) / len(original_mos) * 100 if original_mos else 0

    return {
        "kept": len(kept),
        "lost": len(lost),
        "new": len(new),
        "preservation_rate": preservation,
    }


# ═══════════════════════════════════════════════
# OBFUSCATION RESILIENCE TEST
# ═══════════════════════════════════════════════


def test_obfuscation_resilience(decompiled_dir):
    """Test all 10 obfuscation types"""

    print("\n" + "=" * 70)
    print("MOSDroid Obfuscation Resilience Test")
    print("=" * 70)

    # Extract original MOS
    print("\n🔍 Extracting MOS from ORIGINAL APK...")
    original_mos = extract_mos_set(decompiled_dir)
    print(f"   Original MOS count: {len(original_mos)}")

    results = {}

    # Test each obfuscation
    for obfus_type in OBFUSCATION_FUNCS.keys():
        print(f"\n📝 Testing: {obfus_type}")

        # Create obfuscated copy
        obfus_dir = os.path.join(
            "obfus_test", f"{os.path.basename(decompiled_dir)}_{obfus_type}"
        )
        create_obfuscated_copy(decompiled_dir, obfus_type, obfus_dir)

        # Extract MOS from obfuscated
        try:
            obfuscated_mos = extract_mos_set(obfus_dir)
            print(f"   Obfuscated MOS count: {len(obfuscated_mos)}")

            # Compare
            comparison = compare_mos(original_mos, obfuscated_mos)
            results[obfus_type] = comparison

            print(
                f"   ✓ Kept:  {comparison['kept']:4d} ({comparison['preservation_rate']:6.2f}%)"
            )
            print(f"   ✗ Lost:  {comparison['lost']:4d}")
            print(f"   + New:   {comparison['new']:4d}")

        except Exception as e:
            print(f"   ❌ Error: {e}")
            results[obfus_type] = None

        # Cleanup
        if os.path.exists(obfus_dir):
            shutil.rmtree(obfus_dir)

    # Summary Report
    print("\n" + "=" * 70)
    print("SUMMARY REPORT")
    print("=" * 70)
    print(
        f"{'Obfuscation Type':<20} {'Kept':>6} {'Lost':>6} {'New':>6} {'Preservation':>12}"
    )
    print("-" * 70)

    for obfus_type, result in results.items():
        if result:
            print(
                f"{obfus_type:<20} {result['kept']:>6} {result['lost']:>6} {result['new']:>6} "
                f"{result['preservation_rate']:>11.2f}%"
            )

    # Average preservation rate
    preservation_rates = [r["preservation_rate"] for r in results.values() if r]
    avg_rate = (
        sum(preservation_rates) / len(preservation_rates) if preservation_rates else 0
    )

    print("-" * 70)
    print(f"{'Average Preservation Rate':<20} {avg_rate:>50.2f}%")
    print("=" * 70)

    return results


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python step5.py <decompiled_apk_dir>")
        print("Example: python step5.py raw_apk/decompiled/app123_smali")
        sys.exit(1)

    decompiled_dir = sys.argv[1]

    if not os.path.exists(decompiled_dir):
        print(f"❌ Directory not found: {decompiled_dir}")
        sys.exit(1)

    # Run obfuscation resilience test
    test_obfuscation_resilience(decompiled_dir)
