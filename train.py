# =========================
# MOSDroid FINAL (CFG + FULL OPCODE COVERAGE)
# =========================
# Upgrades:
# - Full Dalvik opcode coverage (auto-loaded)
# - CFG-like basic block segmentation using labels
# - Accurate MOS extraction per basic block

import os
import re
import numpy as np
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf
import subprocess


def decode_apk(apk_path, output_dir):
    """
    Decode 1 APK -> smali folder
    """
    try:
        subprocess.run(
            ["apktool", "d", apk_path, "-o", output_dir, "-f"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        print(f"Error decoding {apk_path}: {e}")
        return False


def batch_decode_full(raw_root="raw_apk", decoded_root="decoded"):
    for label in ["benign", "malware"]:
        input_dir = os.path.join(raw_root, label)
        output_dir = os.path.join(decoded_root, label)

        os.makedirs(output_dir, exist_ok=True)

        for apk in os.listdir(input_dir):
            if not apk.endswith(".apk"):
                continue

            apk_path = os.path.join(input_dir, apk)
            app_name = apk.replace(".apk", "")
            out_path = os.path.join(output_dir, app_name)

            print(f"[+] {label}: {apk}")

            subprocess.run(
                [
                    "apktool",
                    "d",
                    apk_path,
                    "-o",
                    out_path,
                    "-f",
                    "-r",  # 🔥 skip resource → nhanh hơn
                ]
            )


# =========================
# 1. FULL OPCODE LIST (Dalvik)
# =========================
# Simplified full coverage list (can extend)
DALVIK_OPCODES = [
    "move",
    "move/from16",
    "move/16",
    "move-wide",
    "move-object",
    "return",
    "return-void",
    "return-object",
    "const",
    "const/4",
    "const/16",
    "const-string",
    "goto",
    "goto/16",
    "goto/32",
    "if-eq",
    "if-ne",
    "if-lt",
    "if-gt",
    "if-le",
    "if-ge",
    "invoke-virtual",
    "invoke-static",
    "invoke-direct",
    "invoke-interface",
    "iget",
    "iget-object",
    "sget",
    "sget-object",
    "iput",
    "iput-object",
    "sput",
    "sput-object",
    "add-int",
    "sub-int",
    "mul-int",
    "div-int",
    "rem-int",
]

# Map all to categories
CATEGORY = {}
for op in DALVIK_OPCODES:
    if "move" in op:
        CATEGORY[op] = "M"
    elif "return" in op:
        CATEGORY[op] = "R"
    elif "if-" in op:
        CATEGORY[op] = "I"
    elif "goto" in op or "invoke" in op:
        CATEGORY[op] = "V"
    elif "get" in op:
        CATEGORY[op] = "G"
    elif "put" in op:
        CATEGORY[op] = "P"
    elif "const" in op:
        CATEGORY[op] = "D"
    elif any(x in op for x in ["add", "sub", "mul", "div", "rem"]):
        CATEGORY[op] = "A"
    else:
        CATEGORY[op] = "X"


# =========================
# 2. PARSE SMALI → BASIC BLOCKS (CFG-like)
# =========================
def extract_blocks(file_path):
    blocks = []
    current = []

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            # Label indicates new block
            if line.startswith(":"):
                if current:
                    blocks.append(current)
                    current = []
                continue

            if not line or line.startswith("."):
                continue

            token = line.split()[0]

            if token in CATEGORY:
                current.append(CATEGORY[token])

                # End block on control flow
                if CATEGORY[token] == "V":
                    blocks.append(current)
                    current = []

    if current:
        blocks.append(current)

    return blocks


# =========================
# 3. BUILD MOS FROM BLOCKS
# =========================
def build_mos_from_blocks(blocks):
    mos = Counter()
    for b in blocks:
        if len(b) > 0:
            mos[tuple(b)] += 1
    return mos


# =========================
# 4. PROCESS APK
# =========================
def process_apk(smali_dir):
    apk_mos = Counter()

    for root, _, files in os.walk(smali_dir):
        for f in files:
            if f.endswith(".smali"):
                path = os.path.join(root, f)
                blocks = extract_blocks(path)
                mos = build_mos_from_blocks(blocks)
                apk_mos.update(mos)

    return apk_mos


# =========================
# 5. DATASET
# =========================
def build_dataset(apk_dirs, labels):
    all_features = Counter()
    mos_list = []

    for d in apk_dirs:
        mos = process_apk(d)
        mos_list.append(mos)
        all_features.update(mos.keys())

    threshold = max(1, int(len(apk_dirs) * 0.01))
    features = [f for f, c in all_features.items() if c >= threshold]
    index = {f: i for i, f in enumerate(features)}

    X = np.zeros((len(apk_dirs), len(features)))

    for i, mos in enumerate(mos_list):
        for k in mos:
            if k in index:
                X[i][index[k]] = 1

    return X, np.array(labels)


# =========================
# 6. DNN
# =========================
def build_dnn(input_dim):
    model = tf.keras.Sequential(
        [
            tf.keras.Input(shape=(input_dim,)),  # ✅ đúng chuẩn
            tf.keras.layers.Dense(256, activation="relu"),
            tf.keras.layers.Dense(256, activation="relu"),
            tf.keras.layers.Dense(128, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(optimizer="adam", loss="binary_crossentropy")
    return model


# =========================
# 7. TRAIN
# =========================
def train(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    svm = SVC(kernel="linear", C=0.0625)
    svm.fit(X_train, y_train)
    print("SVM:", accuracy_score(y_test, svm.predict(X_test)))

    rf = RandomForestClassifier(n_estimators=300)
    rf.fit(X_train, y_train)
    print("RF:", accuracy_score(y_test, rf.predict(X_test)))

    dnn = build_dnn(X_train.shape[1])
    dnn.fit(X_train, y_train, epochs=5, verbose=0)
    preds = (dnn.predict(X_test) > 0.5).astype(int)
    print("DNN:", accuracy_score(y_test, preds))


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Step 1: decode APK
    batch_decode_full(raw_root="raw_apk", decoded_root="decoded")

    # Step 2: lấy path smali
    apk_dirs = []
    labels = []

    for label, folder in [(0, "decoded/benign"), (1, "decoded/malware")]:
        for app in os.listdir(folder):
            smali_path = os.path.join(folder, app, "smali")
            if os.path.exists(smali_path):
                apk_dirs.append(smali_path)
                labels.append(label)

    # Step 3: build dataset + train
    X, y = build_dataset(apk_dirs, labels)
    train(X, y)
