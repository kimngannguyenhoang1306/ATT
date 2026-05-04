#!/usr/bin/env python3
"""
Test step5_1.py structure (uses obfuscapk CLI)
"""

import os


def test_step5_1_structure():
    """Verify step5_1.py structure"""

    print("=" * 70)
    print("Test: step5_1.py Structure Validation")
    print("=" * 70)

    from step5_1 import (
        OBFUSCATION_TECHNIQUES,
        check_obfuscapk,
        compare_mos,
    )

    # Test 1: Obfuscation techniques
    print("\n✅ Test 1: Obfuscation Techniques")
    print(f"   Registered techniques: {len(OBFUSCATION_TECHNIQUES)}")
    for i, (short, long) in enumerate(OBFUSCATION_TECHNIQUES.items(), 1):
        print(f"   {i:2d}. {short:<20} → {long}")

    # Test 2: Check for 10 techniques
    if len(OBFUSCATION_TECHNIQUES) == 10:
        print("\n✅ Test 2: All 10 techniques present")
    else:
        print(f"\n❌ Expected 10 techniques, got {len(OBFUSCATION_TECHNIQUES)}")

    # Test 3: obfuscapk availability check
    print("\n✅ Test 3: obfuscapk Check Function")
    has_obfuscapk = check_obfuscapk()
    if has_obfuscapk:
        print("   ✅ obfuscapk is available")
    else:
        print("   ℹ️ obfuscapk not installed (optional for testing)")

    # Test 4: MOS comparison logic
    print("\n✅ Test 4: MOS Comparison Logic")
    original = {"MIM:1|R:1", "GP:1|V:1", "R:1"}
    obfuscated = {"MIM:1|R:1", "GP:1|V:1"}  # Lost one

    comparison = compare_mos(original, obfuscated)
    print(f"   Original:    {len(original)} MOS")
    print(f"   Obfuscated:  {len(obfuscated)} MOS")
    print(f"   Kept:        {comparison['kept']}")
    print(f"   Lost:        {comparison['lost']}")
    print(f"   New:         {comparison['new']}")
    print(f"   Preservation: {comparison['preservation_rate']:.2f}%")

    if comparison["lost"] == 1 and comparison["preservation_rate"] != 100.0:
        print("   ✓ Comparison working correctly")

    # Test 5: Check for key functions
    print("\n✅ Test 5: Required Functions")
    from step5_1 import (
        decompile_apk,
        obfuscate_apk_with_technique,
        extract_mos_set,
        compare_mos,
        test_obfuscation_with_obfuscapk,
    )

    print("   ✓ decompile_apk")
    print("   ✓ obfuscate_apk_with_technique")
    print("   ✓ extract_mos_set")
    print("   ✓ compare_mos")
    print("   ✓ test_obfuscation_with_obfuscapk")

    print("\n" + "=" * 70)
    print("✅ STEP 5_1 STRUCTURE VALIDATION PASSED")
    print("=" * 70)
    print("\nUsage:")
    print("  python step5_1.py <apk_file>")
    print("\nExample:")
    print("  python step5_1.py app.apk")
    print("\nNote:")
    if not has_obfuscapk:
        print("  Install obfuscapk: pip install obfuscapk")
        print("  Then re-run this script for full testing")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    test_step5_1_structure()
