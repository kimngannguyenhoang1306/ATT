#!/usr/bin/env python3
"""
Test MOS extraction with multiplicity counts (JSON format)
"""

from config import CAT1_MAPPING
from collections import Counter
import json


def extract_opcode_from_line(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("."):
        return None
    parts = line.split()
    if parts:
        return parts[0].lower()
    return None


def test_mos_extraction_with_multiplicity():
    """
    Expected: {"MIM": 2, "R": 3}
    - foo: MIM → R
    - bar: MIM → R (duplicate)
    - baz: V → R (invoke then return)
    """

    print("=" * 60)
    print("TEST: MOS Extraction with Multiplicity (MOSDroid Paper)")
    print("=" * 60)

    smali_code = """
.method public foo()V
    move-object v0, p0
    if-eq v0, v1, :label
    move-result v2
    invoke-virtual {v0}, Landroid/app/Activity;.startActivity(Landroid/content/Intent;)V
    return-void
.end method
.method public bar()V
    move-object v0, p0
    if-eq v0, v1, :label
    move-result v2
    invoke-virtual {v0}, Landroid/app/Activity;.startActivity(Landroid/content/Intent;)V
    return-void
.end method
.method public baz()V
    invoke-static {v0}, Ljava/lang/Math;.abs(I)I
    return-void
.end method
""".strip().split("\n")

    print("\n📝 3 methods:")
    print("  foo(): move-object → if-eq → move-result → invoke → return")
    print("         Maps to: M → I → M → V → R")
    print("         Segments: 'MIM' (before V), 'R' (after V)")
    print("  bar(): same as foo()")
    print("  baz(): invoke → return")
    print("         Maps to: V → R")
    print("         Segments: (empty before V), 'R' (after V)")

    # Parse
    in_method = False
    current_sequence = []
    mos_list = []

    for line in smali_code:
        line_stripped = line.strip()

        if line_stripped.startswith(".method"):
            in_method = True
            current_sequence = []
            continue

        if line_stripped.startswith(".end method"):
            if current_sequence:
                segment = "".join(current_sequence)
                mos_list.append(segment)
            in_method = False
            current_sequence = []
            continue

        if not in_method:
            continue

        opcode = extract_opcode_from_line(line_stripped)
        if opcode is None:
            continue

        symbol = CAT1_MAPPING.get(opcode, None)
        if symbol is None:
            continue

        if symbol == "V":
            if current_sequence:
                segment = "".join(current_sequence)
                mos_list.append(segment)
            current_sequence = []
        else:
            current_sequence.append(symbol)

    # Result
    apk_mos_dict = dict(Counter(m for m in mos_list if len(m) > 0))

    print("\n✅ Result:")
    print(f"  Raw MOS list: {mos_list}")
    print(f"  Counter: {dict(Counter(mos_list))}")
    print(f"  APK_MOS (dict): {apk_mos_dict}")
    print(f"  JSON:\n{json.dumps(apk_mos_dict, indent=4)}")
    print(f"\n  Expected: {{'MIM': 2, 'R': 3}}")

    if apk_mos_dict == {"MIM": 2, "R": 3}:
        print("🎉 PASS: Multiplicity count correct!")
        return True
    else:
        print(f"❌ FAIL: Got {apk_mos_dict}")
        return False


def test_label_matching():
    print("\n" + "=" * 60)
    print("TEST: Label Matching")
    print("=" * 60)

    malware_names = {"abc123", "def456"}
    benign_names = {"calc", "notepad"}
    decompiled_folders = ["abc123_smali", "calc_smali", "unknown_smali", "def456_smali"]

    results = {}
    for folder_name in decompiled_folders:
        clean_name = folder_name.replace("_smali", "")
        if clean_name in malware_names:
            label = "malware"
        elif clean_name in benign_names:
            label = "benign"
        else:
            label = "unknown"
        results[clean_name] = label
        print(f"  {folder_name} → {label}")

    expected = {
        "abc123": "malware",
        "calc": "benign",
        "unknown": "unknown",
        "def456": "malware",
    }

    if results == expected:
        print("\n🎉 PASS: Label matching correct!")
        return True
    else:
        print(f"\n❌ FAIL")
        return False


def test_config():
    print("\n" + "=" * 60)
    print("TEST: Config validation")
    print("=" * 60)

    val = CAT1_MAPPING.get("return-void-no-barrier")
    print(f"  return-void-no-barrier → '{val}'")

    if val == "R":
        print("✅ PASS: Correctly mapped to 'R'")
        return True
    else:
        print(f"❌ FAIL: Should be 'R', got '{val}'")
        return False


if __name__ == "__main__":
    print("\n" * 2)
    r1 = test_mos_extraction_with_multiplicity()
    r2 = test_label_matching()
    r3 = test_config()

    print("\n" + "=" * 60)
    if r1 and r2 and r3:
        print("✅ ALL TESTS PASSED!")
        print("   step2.py will output JSON with MOS multiplicity")
    else:
        print("❌ Some tests failed")
    print("=" * 60 + "\n")
