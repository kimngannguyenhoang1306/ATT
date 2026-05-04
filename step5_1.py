#!/usr/bin/env python3
"""
STEP 5.1: Obfuscation Resilience Testing with ObfuscAPK CLI Tool

Uses obfuscapk library CLI (if available) to apply 10 obfuscation techniques:
1. Rename (ClassRename)
2. Reflection
3. ConstStringEncryption
4. Goto
5. Nop (junk code)
6. Reorder
7. DebugRemoval
8. CallIndirection
9. MethodRename
10. FieldRename

Then compares MOS between original and obfuscated APK SMALI.
"""

import os
import sys
import subprocess
import shutil
import tempfile
import json
from pathlib import Path

from config import CAT1_MAPPING, DECOMPILED_DIR
from step2 import generate_apk_mos

# ═══════════════════════════════════════════════
# OBFUSCAPK CLI MAPPING
# ═══════════════════════════════════════════════

OBFUSCATION_TECHNIQUES = {
    "rename": "ClassRename",
    "reflection": "Reflection",
    "string_encrypt": "ConstStringEncryption",
    "goto": "Goto",
    "junk": "Nop",
    "reorder": "Reorder",
    "debug_removal": "DebugRemoval",
    "call_indirect": "CallIndirection",
    "method_rename": "MethodRename",
    "field_rename": "FieldRename",
}


def check_obfuscapk():
    try:
        result = subprocess.run(
            ["python3", "-m", "obfuscapk.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "usage" in result.stderr.lower() or "usage" in result.stdout.lower()
    except:
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


def obfuscate_apk_with_technique(apk_path, technique, work_dir):
    obf_class = OBFUSCATION_TECHNIQUES.get(technique, technique)

    print(f"     Applying {technique} ({obf_class})...")

    cmd = [
        "python3",
        "-m",
        "obfuscapk.cli",
        apk_path,
        "-o",
        obf_class,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )

        # 🔥 IMPORTANT: DO NOT trust returncode
        apk = find_apk_anywhere(work_dir)

        if apk:
            return apk

        apk = find_apk_anywhere(tempfile.gettempdir())
        return apk

    except Exception as e:
        print(f"     ❌ Error: {e}")
        return None


def extract_mos_set(decompiled_dir):
    """Extract MOS as set of strings"""
    mos_list = generate_apk_mos(decompiled_dir, CAT1_MAPPING)
    return set("|".join(f"{k}:{v}" for k, v in sorted(m.items())) for m in mos_list)


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
# MAIN TEST FUNCTION
# ═══════════════════════════════════════════════


def test_obfuscation_with_obfuscapk(apk_path):
    """Test obfuscation resilience using obfuscapk CLI tool"""

    print("\n" + "=" * 70)
    print("MOSDroid Obfuscation Resilience Test (with ObfuscAPK)")
    print("=" * 70)
    print(f"\nTesting: {os.path.basename(apk_path)}")

    # Check if obfuscapk available
    if not check_obfuscapk():
        print("⚠️  obfuscapk not available. Install with: pip install obfuscapk")
        print("    Falling back to step5.py (simulated obfuscation)")
        return None

    results = {}
    temp_base = tempfile.mkdtemp(prefix="mosdroid_obf_")

    try:
        # Step 1: Decompile original APK
        print("\n📦 ORIGINAL APK")
        original_decomp = os.path.join(temp_base, "original")
        os.makedirs(original_decomp, exist_ok=True)

        if not decompile_apk(apk_path, original_decomp):
            print("❌ Failed to decompile original APK")
            return None

        # Extract original MOS
        print("  🔍 Extracting MOS...")
        original_mos = extract_mos_set(original_decomp)
        print(f"     MOS count: {len(original_mos)}")
        results["original"] = {
            "mos_count": len(original_mos),
            "preservation_rate": 100.0,
        }

        # Step 2: Test each obfuscation technique
        print("\n📝 OBFUSCATION TESTS")

        for technique in OBFUSCATION_TECHNIQUES.keys():
            print(f"\n  [{technique}]")

            # Create working directory
            work_dir = os.path.join(temp_base, f"obf_{technique}")
            os.makedirs(work_dir, exist_ok=True)

            # Apply obfuscation
            obfuscated_apk = obfuscate_apk_with_technique(apk_path, technique, work_dir)

            if not obfuscated_apk:
                print(f"     ⚠️  Skipped")
                results[technique] = None
                continue

            # Decompile obfuscated APK
            obf_decomp = os.path.join(work_dir, "decompiled")
            if not decompile_apk(obfuscated_apk, obf_decomp):
                print(f"     ⚠️  Could not decompile obfuscated APK")
                results[technique] = None
                continue

            # Extract obfuscated MOS
            print(f"     🔍 Extracting MOS...")
            obfuscated_mos = extract_mos_set(obf_decomp)
            print(f"        MOS count: {len(obfuscated_mos)}")

            # Compare
            comparison = compare_mos(original_mos, obfuscated_mos)
            results[technique] = comparison

            print(
                f"     ✓ Kept:  {comparison['kept']:4d} ({comparison['preservation_rate']:6.2f}%)"
            )
            print(f"     ✗ Lost:  {comparison['lost']:4d}")
            print(f"     + New:   {comparison['new']:4d}")

    finally:
        # Cleanup
        if os.path.exists(temp_base):
            shutil.rmtree(temp_base)

    # Summary Report
    print("\n" + "=" * 70)
    print("SUMMARY REPORT")
    print("=" * 70)
    print(
        f"{'Technique':<20} {'MOS Count':>10} {'Kept':>6} {'Lost':>6} {'Preservation':>12}"
    )
    print("-" * 70)

    preservation_rates = []

    print(
        f"{'original':<20} {results['original']['mos_count']:>10} "
        f"{results['original']['mos_count']:>6} {'0':>6} {'100.00%':>12}"
    )

    for technique, result in results.items():
        if technique != "original" and result:
            print(
                f"{technique:<20} {len(original_mos) + result['new'] - result['lost']:>10} "
                f"{result['kept']:>6} {result['lost']:>6} {result['preservation_rate']:>11.2f}%"
            )
            preservation_rates.append(result["preservation_rate"])

    avg_rate = (
        sum(preservation_rates) / len(preservation_rates) if preservation_rates else 0
    )

    print("-" * 70)
    print(f"{'Average Preservation':<20} {' '*10} {' '*6} {' '*6} {avg_rate:>11.2f}%")
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

    # Run test
    test_obfuscation_with_obfuscapk(apk_path)
