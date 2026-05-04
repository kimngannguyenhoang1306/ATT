# MOSDroid Pipeline - Status Report

## ✅ Pipeline Architecture Complete

### Overview
The MOSDroid (Multiset of Opcode Sequences for Malware Detection) pipeline is now fully implemented with all core components and obfuscation resilience testing.

---

## 📊 Component Status

### Core Pipeline Components

| Component | Status | Description |
|-----------|--------|-------------|
| **config.py** | ✅ COMPLETE | Central config with CAT1 opcode mapping (95 opcodes → 6 symbols) |
| **step2.py** | ✅ COMPLETE | MOS extraction from decompiled APK SMALI files (JSON format with multiplicity) |
| **step3.py** | ✅ COMPLETE | Feature matrix builder (binary vectors from MOS) |
| **train.py** | ✅ COMPLETE | Model training (DNN + Random Forest + SVM ensemble) |
| **step5.py** | ✅ COMPLETE | Manual obfuscation resilience testing (10 techniques) |
| **step5_1.py** | ✅ COMPLETE | CLI-based obfuscation with obfuscapk tool (10 techniques) |

### Test Suites

| Test | Status | Coverage |
|------|--------|----------|
| **test_mosdroid_pipeline.py** | ✅ PASS | MOS extraction, multiplicity, deduplication, feature strings, binary vectors |
| **test_step5_obfuscation.py** | ✅ PASS | All 10 obfuscation techniques, pipeline structure, MOS comparison |
| **test_step5_1.py** | ✅ PASS | step5_1.py structure, obfuscapk integration framework, function imports |

---

## 🔧 Key Configurations

### Opcode Mapping (CAT1 - 6 Categories)
- **M (Move)**: Move operations - 15 opcodes
- **R (Return)**: Return operations - 3 opcodes  
- **I (If/Judgment)**: Conditional operations - 8 opcodes
- **V (Jump/Invoke)**: Call/Jump/Separator - 26 opcodes (V acts as segment delimiter)
- **G (Get)**: Field/Array get operations - 21 opcodes
- **P (Put)**: Field/Array put operations - 22 opcodes

**Total: 95 opcodes mapped to 6 categories**

### Data Flow
```
raw_apk/decompiled/{hash}_smali/
    ↓
step2.py: Extract MOS (Multiset per method)
    ↓
{hash}_{label}.json: Array of MOS dicts
    [{"MIM": 2, "R": 1}, {"R": 1, "GP": 1}]
    ↓
step3.py: Convert to feature strings
    "MIM:2|R:1", "GP:1|R:1"
    ↓
Binary feature vectors (1 if MOS present, 0 if absent)
    ↓
train.py: Train ensemble model
    ↓
Predictions: Malware or Benign
```

### Directory Structure
```
ATT/
├── config.py                      # Central configuration
├── step2.py                       # MOS extraction
├── step3.py                       # Feature matrix builder
├── train.py                       # Model training
├── step5.py                       # Manual obfuscation (10 techniques)
├── step5_1.py                     # CLI obfuscation with obfuscapk
├── test_mosdroid_pipeline.py      # Pipeline tests ✅ PASS
├── test_step5_obfuscation.py      # Obfuscation tests ✅ PASS
├── test_step5_1.py                # step5_1 tests ✅ PASS
├── raw_apk/
│   ├── decompiled/                # Decompiled APK SMALI files
│   ├── apk_mos/                   # Generated MOS JSON files
│   ├── malware/                   # Malware APK folders
│   └── benign/                    # Benign APK folders
├── models/                        # Trained model files
├── data/                          # Feature matrices
└── figs/                          # Visualizations
```

---

## 🧬 MOS Format Specification

### Level 1: Method-level MOS
Each method produces one multiset with opcode symbol frequencies:
```python
{"MIM": 2, "R": 1, "GP": 1}  # Dict with symbol counts
```

### Level 2: APK-level MOS (APK_MOS)
Deduplicates all method MOS to unique multisets:
```json
[
  {"MIM": 2, "R": 1, "GP": 1},
  {"R": 1},
  {"MIM": 1, "R": 1, "GP": 1}
]
```

### Level 3: Feature Strings
Converts MOS dicts to sorted string format for binary vectorization:
```python
"GP:1|MIM:2|R:1"  # Keys sorted alphabetically
```

### Level 4: Binary Features
Creates feature matrix for ML (1 if MOS string appears, 0 otherwise):
```
MOS_1    MOS_2    MOS_3    ...
  1        0        1      ...
  0        1        0      ...
```

---

## 🛡️ Obfuscation Resilience Testing

### 10 Obfuscation Techniques (MOSDroid Paper)

| # | Technique | step5.py | step5_1.py | obfuscapk CLI |
|---|-----------|----------|-----------|---------------|
| 1 | Junk Code | ✅ | ✅ | Nop |
| 2 | Class Rename | ✅ | ✅ | ClassRename |
| 3 | Method Rename | ✅ | ✅ | MethodRename |
| 4 | Field Rename | ✅ | ✅ | FieldRename |
| 5 | String Encryption | ✅ | ✅ | ConstStringEncryption |
| 6 | Control Flow | ✅ | ✅ | Goto |
| 7 | Reflection | ✅ | ✅ | Reflection |
| 8 | Call Indirection | ✅ | ✅ | CallIndirection |
| 9 | Dead Code | ✅ | ✅ | DebugRemoval |
| 10 | Reorder | ✅ | ✅ | Reorder |

### Metrics Calculated
- **Kept**: Number of original MOS preserved in obfuscated version
- **Lost**: Number of original MOS not found in obfuscated version
- **New**: Number of new MOS created by obfuscation
- **Preservation Rate**: (kept / original) × 100%

---

## 🚀 Usage Guide

### Phase 1: MOS Extraction
```bash
# Extract MOS from decompiled APK SMALI files
python step2.py

# Output: raw_apk/apk_mos/{apk_hash}_{label}.json
```

### Phase 2: Feature Matrix Building
```bash
# Build feature matrix from MOS
python step3.py

# Output: data/features_{label}.pkl
```

### Phase 3: Model Training
```bash
# Train ensemble model (DNN + RF + SVM)
python train.py

# Output: models/malware_detector.pkl
```

### Phase 4A: Manual Obfuscation Testing
```bash
# Test MOS resilience with manual obfuscation
python step5.py <decompiled_apk_path>

# Output: Preservation rate metrics for 10 techniques
```

### Phase 4B: CLI Obfuscation Testing (Recommended)
```bash
# Test MOS resilience with obfuscapk CLI tool
# First install: pip install obfuscapk
python step5_1.py <apk_file>

# Output: Preservation rate metrics with realistic obfuscation
```

---

## 🔍 Data Requirements

### Input: raw_apk/decompiled/
```
{hash}_smali/
├── AndroidManifest.xml
├── classes.dex
├── com/
│   └── example/
│       └── *.smali           # Smali source files
├── android/
├── androidx/
└── ...
```

### Input: raw_apk/malware/ and raw_apk/benign/
Folders containing original APK files (for obfuscation testing):
```
malware/
├── {hash1}/
├── {hash2}/
└── ...

benign/
├── {hash1}/
├── {hash2}/
└── ...
```

### Output: raw_apk/apk_mos/
```
{hash}_malware.json
{hash}_benign.json
```

Format:
```json
[
  {"MIM": 2, "R": 1},
  {"R": 1},
  ...
]
```

---

## ✅ Verification Checklist

### Ready for Testing
- [x] config.py - Opcode mapping verified (95→6)
- [x] step2.py - MOS extraction with multiplicity counts
- [x] step3.py - Feature matrix builder with string conversion
- [x] step5.py - All 10 manual obfuscation techniques
- [x] step5_1.py - obfuscapk CLI integration framework
- [x] All test suites passing

### Before Running
- [ ] Verify decompiled SMALI files exist in `raw_apk/decompiled/`
- [ ] Check APK files exist in `raw_apk/malware/` and `raw_apk/benign/`
- [ ] (Optional) Install obfuscapk: `pip install obfuscapk`

### After Extraction
- [ ] Verify JSON files generated in `raw_apk/apk_mos/`
- [ ] Check JSON format: `[{"SYMBOL": count}, ...]`
- [ ] Verify feature matrix in `data/features_*.pkl`

### After Training
- [ ] Model saved to `models/malware_detector.pkl`
- [ ] Accuracy metrics calculated and logged
- [ ] Test set predictions generated

### Obfuscation Testing
- [ ] Run step5.py or step5_1.py on sample APK
- [ ] Verify preservation rates calculated
- [ ] Compare resilience across 10 techniques

---

## 📋 Known Issues & Notes

### obfuscapk Installation
- **Issue**: obfuscapk may have dependencies on Android SDK
- **Solution**: Install via `pip install obfuscapk`
- **Fallback**: Use step5.py for manual obfuscation testing (doesn't require obfuscapk)

### Path Handling
- **Format**: Use forward slashes in paths (Windows compatible)
- **Absolute Paths**: Used throughout for clarity
- **Environment Variable**: `DECOMPILED_DIR` in config.py

### MOS Deduplication
- **Method**: Convert dict to sorted tuple, then set deduplication
- **Preservation**: Multiplicity kept at method level, deduplicated at APK level
- **Format**: JSON with multiplicity counts (not unique symbols)

### Label Assignment
- **Malware**: Folder name matches `malware/` directory name
- **Benign**: Folder name matches `benign/` directory name
- **Matching**: Based on APK hash directory name

---

## 🎯 Next Steps

1. **Verify Data Exists**
   ```bash
   ls raw_apk/decompiled/  # Should show {hash}_smali/ folders
   ls raw_apk/malware/     # Should show APK or hash folders
   ls raw_apk/benign/      # Should show APK or hash folders
   ```

2. **Run Pipeline**
   ```bash
   python step2.py         # Extract MOS
   python step3.py         # Build features
   python train.py         # Train model
   ```

3. **Test Obfuscation Resilience**
   ```bash
   # Option A: Manual (no dependencies)
   python step5.py raw_apk/decompiled/sample_smali/
   
   # Option B: CLI-based (recommended)
   pip install obfuscapk
   python step5_1.py sample.apk
   ```

4. **Generate Predictions**
   ```bash
   python run.py           # Use trained model for detection
   ```

---

## 📝 References

- **MOSDroid Paper**: Multiset of Opcode Sequences for Malware Detection
- **Opcode Mapping**: CAT1 (6 categories from 95 opcodes)
- **Framework**: scikit-learn, TensorFlow, pandas
- **Obfuscation Tool**: obfuscapk (https://github.com/ClaudiuGeorgiu/Obfuscapk)

---

**Last Updated**: 2024 (After step5_1.py completion and test validation)
**Status**: ✅ READY FOR TESTING
