# config.py

# ============ OPCODE MAPPING (Table 2 trong bài báo) ============

# Cat_1: 95 opcodes → 6 nhóm
CAT1_MAPPING = {
    # M — Move (13 opcodes)
    "move": "M",
    "move/from16": "M",
    "move/16": "M",
    "move-wide": "M",
    "move-wide/from16": "M",
    "move-wide/16": "M",
    "move-object": "M",
    "move-object/from16": "M",
    "move-object/16": "M",
    "move-result": "M",
    "move-result-wide": "M",
    "move-result-object": "M",
    "move-exception": "M",
    # R — Return (4 opcodes)
    "return-void": "R",
    "return": "R",
    "return-wide": "R",
    "return-object": "R",
    # I — Judgment/If (12 opcodes)
    "if-eq": "I",
    "if-ne": "I",
    "if-lt": "I",
    "if-ge": "I",
    "if-gt": "I",
    "if-le": "I",
    "if-eqz": "I",
    "if-nez": "I",
    "if-ltz": "I",
    "if-gez": "I",
    "if-gtz": "I",
    "if-lez": "I",
    # V — Jump/Invoke (18 opcodes) ← DẤU PHÂN CÁCH!
    "goto": "V",
    "goto/16": "V",
    "goto/32": "V",
    "invoke-virtual": "V",
    "invoke-super": "V",
    "invoke-direct": "V",
    "invoke-static": "V",
    "invoke-interface": "V",
    "invoke-virtual/range": "V",
    "invoke-super/range": "V",
    "invoke-direct/range": "V",
    "invoke-static/range": "V",
    "invoke-interface/range": "V",
    "invoke-polymorphic": "V",
    "invoke-polymorphic/range": "V",
    "invoke-custom": "V",
    "invoke-custom/range": "V",
    "return-void-no-barrier": "V",
    # G — Get/Read (24 opcodes)
    "aget": "G",
    "aget-wide": "G",
    "aget-object": "G",
    "aget-boolean": "G",
    "aget-byte": "G",
    "aget-char": "G",
    "aget-short": "G",
    "iget": "G",
    "iget-wide": "G",
    "iget-object": "G",
    "iget-boolean": "G",
    "iget-byte": "G",
    "iget-char": "G",
    "iget-short": "G",
    "sget": "G",
    "sget-wide": "G",
    "sget-object": "G",
    "sget-boolean": "G",
    "sget-byte": "G",
    "sget-char": "G",
    "sget-short": "G",
    "instance-of": "G",
    "array-length": "G",
    "filled-new-array": "G",
    # P — Put/Write (24 opcodes)
    "aput": "P",
    "aput-wide": "P",
    "aput-object": "P",
    "aput-boolean": "P",
    "aput-byte": "P",
    "aput-char": "P",
    "aput-short": "P",
    "iput": "P",
    "iput-wide": "P",
    "iput-object": "P",
    "iput-boolean": "P",
    "iput-byte": "P",
    "iput-char": "P",
    "iput-short": "P",
    "sput": "P",
    "sput-wide": "P",
    "sput-object": "P",
    "sput-boolean": "P",
    "sput-byte": "P",
    "sput-char": "P",
    "sput-short": "P",
    "filled-new-array/range": "P",
    "fill-array-data": "P",
    "new-array": "P",
}

# Paths
APK_DIR = "raw_apk/"
MALWARE_DIR = "raw_apk/malware/"
BENIGN_DIR = "raw_apk/benign/"
DECOMPILED_DIR = "data/decompiled/"
APK_MOS_DIR = "data/apk_mos/"
FEATURES_DIR = "data/features/"
MODELS_DIR = "models/"

# Feature selection
MIN_FREQUENCY = 0.01  # loại MOS xuất hiện < 1% apps
K_BEST = 500  # số features giữ lại

# Model parameters
DNN_CONFIG = {
    "layers": [256, 256, 128],
    "dropout": 0.2,
    "learning_rate": 0.001,
    "batch_size": 64,
    "epochs": 50,
    "patience": 10,
}

RF_CONFIG = {
    "n_estimators": 300,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
}

SVM_CONFIG = {
    "C": 0.0625,
    "max_iter": 5000,
    # bỏ 'kernel' vì LinearSVC không cần
}
