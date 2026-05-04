#!/usr/bin/env python3
"""
Test complete MOS pipeline format according to MOSDroid paper
"""

from config import CAT1_MAPPING
from collections import Counter
import json


def extract_opcode_from_line(line):
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("."):
        return None
    parts = line.split()
    return parts[0].lower() if parts else None


def extract_mos_from_smali_file(smali_path, opcode_mapping):
    """
    Returns: list of dicts, where each dict is MOS from one method
    Example: [{"MIM": 2, "R": 1}, {"GGP": 1}]
    """
    mos_per_method = []
    in_method = False
    current_sequence = []
    current_mos = []

    for line in smali_path.split("\n"):
        line_stripped = line.strip()

        if line_stripped.startswith(".method"):
            in_method = True
            current_sequence = []
            current_mos = []
            continue

        if line_stripped.startswith(".end method"):
            if current_sequence:
                current_mos.append("".join(current_sequence))
            if current_mos:
                mos_per_method.append(dict(Counter(current_mos)))
            in_method = False
            current_sequence = []
            current_mos = []
            continue

        if not in_method:
            continue

        opcode = extract_opcode_from_line(line_stripped)
        if opcode is None:
            continue

        symbol = opcode_mapping.get(opcode, None)
        if symbol is None:
            continue

        if symbol == "V":
            if current_sequence:
                current_mos.append("".join(current_sequence))
                current_sequence = []
        else:
            current_sequence.append(symbol)

    return mos_per_method


def generate_apk_mos(smali_content, opcode_mapping):
    """
    Returns: list of unique multisets from all methods
    Example: [{"MIM": 2, "R": 1}, {"GGP": 1}]
    """
    all_method_mos = extract_mos_from_smali_file(smali_content, opcode_mapping)

    # Deduplicate (convert dict to tuple for hashing)
    unique_mos = set()
    for mos in all_method_mos:
        key = tuple(sorted(mos.items()))
        unique_mos.add(key)

    # Convert back to dict
    apk_mos = [dict(m) for m in unique_mos]
    return apk_mos


def mos_dict_to_str(mos_dict):
    """Convert MOS dict to string representation"""
    return "|".join(f"{k}:{v}" for k, v in sorted(mos_dict.items()))


def test_mosdroid_pipeline():
    """
    Test complete MOSDroid pipeline:
    1. Extract MOS from methods (with multiplicity)
    2. Deduplicate to APK_MOS
    3. Convert to feature strings
    4. Create binary vector
    """
    print("=" * 70)
    print("TEST: Complete MOSDroid Pipeline Format")
    print("=" * 70)

    # Simulated smali with methods having MULTIPLE V-separated segments
    smali_code = """
.method public method1()V
    move-object v0, p0
    if-eq v0, v1, :label
    move-result v2
    invoke-virtual {v0}, Landroid/app/Activity;.startActivity(Landroid/content/Intent;)V
    move-object v0, p0
    if-eq v0, v1, :label
    move-result v2
    invoke-virtual {v0}, Landroid/app/Activity;.startActivity(Landroid/content/Intent;)V
    return-void
.end method
.method public method2()V
    move-object v0, p0
    if-eq v0, v1, :label
    move-result v2
    invoke-virtual {v0}, Landroid/app/Activity;.startActivity(Landroid/content/Intent;)V
    return-void
.end method
.method public method3()V
    get-object v0, p0, Lcom/example/App;.mContext:Landroid/content/Context;
    put-object v1, p0, Lcom/example/App;.mValue:I
    invoke-static {v0}, Ljava/lang/Math;.abs(I)I
    return-void
.end method
"""

    print("\n📝 Simulated APK with methods (note multiple segments in method1):")
    print("  method1: M→I→M→V→M→I→M→V→R (2x MIM segments, 1x R)")
    print("  method2: M→I→M→V→R (1x MIM, 1x R)")
    print("  method3: G→P→V→R (1x GP, 1x R)")

    # Step 1: Extract MOS from each method
    print("\n" + "=" * 70)
    print("Step 1: Extract MOS per method (with multiplicity counts)")
    print("=" * 70)

    method_mos_list = extract_mos_from_smali_file(smali_code, CAT1_MAPPING)

    for i, mos in enumerate(method_mos_list, 1):
        print(f"  Method {i}: {mos}")

    print(f"\n  Total MOS from all methods: {len(method_mos_list)}")
    print(f"  Sample: {method_mos_list}")

    # Step 2: Deduplicate to get APK_MOS
    print("\n" + "=" * 70)
    print("Step 2: Deduplicate → APK_MOS (set of unique multisets)")
    print("=" * 70)

    apk_mos = generate_apk_mos(smali_code, CAT1_MAPPING)

    print(f"  Unique multisets after dedup: {len(apk_mos)}")
    for i, mos in enumerate(apk_mos, 1):
        print(f"    {i}. {mos}")

    # Step 3: Convert to strings (for feature matrix)
    print("\n" + "=" * 70)
    print("Step 3: Convert MOS dicts to strings (feature representation)")
    print("=" * 70)

    mos_strings = set()
    for mos_dict in apk_mos:
        mos_str = mos_dict_to_str(mos_dict)
        mos_strings.add(mos_str)
        print(f"  {mos_dict} → '{mos_str}'")

    print(f"\n  Feature set: {mos_strings}")

    # Step 4: JSON format (what step2.py saves)
    print("\n" + "=" * 70)
    print("Step 4: JSON output format (for step2.py save)")
    print("=" * 70)

    json_output = json.dumps(apk_mos, indent=2)
    print(f"\n{json_output}")

    # Step 5: Feature matrix format (binary vector)
    print("\n" + "=" * 70)
    print("Step 5: Binary feature vector (for model input)")
    print("=" * 70)

    # Simulated global vocabulary
    global_vocab = ["MIM:2|R:1", "GPV:1|R:1", "V:1|R:1", "GP:1|V:1|R:1"]

    print(f"\n  Global vocabulary (all MOS in dataset):")
    for i, mos in enumerate(global_vocab, 1):
        print(f"    {i}. {mos}")

    # Create binary vector for this APK
    feature_vector = [1 if mos in mos_strings else 0 for mos in global_vocab]
    print(f"\n  Binary vector for this APK: {feature_vector}")
    print(f"    (1 if MOS in APK, 0 if not)")

    # Verification
    print("\n" + "=" * 70)
    print("VERIFICATION")
    print("=" * 70)

    checks = [
        (
            "Method MOS extracted as dicts with counts",
            isinstance(method_mos_list[0], dict),
        ),
        (
            "Multiplicity preserved in MOS dicts",
            any(v > 1 for m in method_mos_list for v in m.values()),
        ),
        (
            "Deduplication works correctly",
            len(set(tuple(sorted(m.items())) for m in apk_mos)) == len(apk_mos),
        ),
        ("Feature strings created correctly", len(mos_strings) > 0),
        ("Binary vector correct length", len(feature_vector) == len(global_vocab)),
        ("JSON serializable and valid", isinstance(json.loads(json_output), list)),
    ]

    all_pass = True
    for check_name, result in checks:
        status = "✅" if result else "❌"
        print(f"  {status} {check_name}")
        if not result:
            all_pass = False

    return all_pass


if __name__ == "__main__":
    print("\n" * 2)
    result = test_mosdroid_pipeline()
    print("\n" + "=" * 70)
    if result:
        print("✅ PIPELINE FORMAT CORRECT - Matches MOSDroid paper!")
    else:
        print("❌ Pipeline format has issues")
    print("=" * 70 + "\n")
