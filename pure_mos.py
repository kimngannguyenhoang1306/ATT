# =========================
# MOSDroid PURE (FINAL)
# =========================

import os
import re
import pickle
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report


# =========================
# CONFIG
# =========================
RAW_DIR = "raw_apk"
DECODED_DIR = "decoded"
CACHE_DIR = "mos_cache"
MAX_WORKERS = 4
MAX_METHODS_PER_APK = 2000
MAX_BLOCKS_PER_METHOD = 150

os.makedirs(CACHE_DIR, exist_ok=True)


# =========================
# OPCODE → CATEGORY
# =========================
CATEGORY = {}


def init_opcode():
    ops = [
        "move",
        "move/from16",
        "move/16",
        "move-wide",
        "move-object",
        "return",
        "return-void",
        "return-object",
        "throw",
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

    for op in ops:
        if "move" in op:
            CATEGORY[op] = "M"
        elif "return" in op or "throw" in op:
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


init_opcode()


# =========================
# APK DECODE
# =========================
def decode_apk(apk_path, out_dir):
    try:
        subprocess.run(
            ["apktool", "d", apk_path, "-o", out_dir, "-f", "-r"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except:
        return False


def batch_decode():
    tasks = []

    for label in ["benign", "malware"]:
        in_dir = os.path.join(RAW_DIR, label)
        out_dir = os.path.join(DECODED_DIR, label)
        os.makedirs(out_dir, exist_ok=True)

        for apk in os.listdir(in_dir):
            if not apk.endswith(".apk"):
                continue

            apk_path = os.path.join(in_dir, apk)
            out_path = os.path.join(out_dir, apk.replace(".apk", ""))

            if os.path.exists(out_path):
                continue

            tasks.append((apk_path, out_path))

    print(f"Decoding {len(tasks)} APKs...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(decode_apk, a, b) for a, b in tasks]
        for _ in tqdm(as_completed(futures), total=len(futures)):
            pass


# =========================
# SMALI PARSER (METHOD-LEVEL)
# =========================
REGISTER = re.compile(r"v\d+|p\d+")


def normalize(line):
    line = REGISTER.sub("vX", line)
    line = re.sub(r'".*?"', '"STR"', line)
    return line.strip()


def parse_smali_file(path):
    methods = []
    current_blocks = []
    current_block = []
    in_method = False

    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for raw in f:
                line = normalize(raw)

                if line.startswith(".method"):
                    in_method = True
                    current_blocks = []
                    current_block = []
                    continue

                if line.startswith(".end method"):
                    if current_block:
                        current_blocks.append(current_block)
                    if current_blocks:
                        methods.append(current_blocks)
                    in_method = False
                    continue

                if not in_method:
                    continue

                if line.startswith(":"):
                    if current_block:
                        current_blocks.append(current_block)
                    current_block = []
                    continue

                parts = line.split()
                if not parts:
                    continue

                op = parts[0]
                if op in CATEGORY:
                    current_block.append(CATEGORY[op])

        if current_block:
            current_blocks.append(current_block)
        if len(current_blocks) > MAX_BLOCKS_PER_METHOD:
            current_blocks = current_blocks[:MAX_BLOCKS_PER_METHOD]
        if current_blocks:
            methods.append(current_blocks)

    except:
        pass

    return methods


def parse_smali_dir(smali_dir):
    all_methods = []

    for root, _, files in os.walk(smali_dir):
        for f in files:
            if f.endswith(".smali"):
                methods = parse_smali_file(os.path.join(root, f))
                all_methods.extend(methods)

                if len(all_methods) >= MAX_METHODS_PER_APK:
                    return all_methods[:MAX_METHODS_PER_APK]

    return all_methods


# =========================
# MOS FEATURE (CORE)
# =========================
def encode_block(block):
    return "".join(block)


def extract_mos(smali_dir):
    cache_path = os.path.join(CACHE_DIR, f"{hash(smali_dir)}.pkl")

    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            return pickle.load(f)

    methods = parse_smali_dir(smali_dir)

    apk_counter = Counter()

    for method in methods:
        method_counter = Counter()

        for block in method:
            enc = encode_block(block)
            if enc:
                method_counter[enc] += 1

        # merge method → APK
        apk_counter.update(method_counter)

    with open(cache_path, "wb") as f:
        pickle.dump(apk_counter, f)

    return apk_counter


# =========================
# VECTORIZE
# =========================
def build_vocab(counters, max_features=3000, min_freq=2):
    total = Counter()
    for c in counters:
        total.update(c)

    items = [(k, v) for k, v in total.items() if v >= min_freq]
    items.sort(key=lambda x: -x[1])

    return {k: i for i, (k, _) in enumerate(items[:max_features])}


def vectorize(counter, vocab):
    vec = np.zeros(len(vocab))
    for k, v in counter.items():
        if k in vocab:
            vec[vocab[k]] = v
    return vec


# =========================
# BUILD DATASET
# =========================
def build_dataset():
    dirs, labels = [], []

    for label, folder in [(0, "benign"), (1, "malware")]:
        path = os.path.join(DECODED_DIR, folder)
        for app in os.listdir(path):
            smali = os.path.join(path, app, "smali")
            if os.path.exists(smali):
                dirs.append(smali)
                labels.append(label)

    print(f"Total samples: {len(dirs)}")

    train_idx, test_idx = train_test_split(
        list(range(len(dirs))),
        stratify=labels,
        test_size=0.2,
        random_state=42,
    )

    train_dirs = [dirs[i] for i in train_idx]
    test_dirs = [dirs[i] for i in test_idx]

    y_train = np.array([labels[i] for i in train_idx])
    y_test = np.array([labels[i] for i in test_idx])

    print("Extracting MOS...")

    train_counters = [extract_mos(d) for d in tqdm(train_dirs)]
    test_counters = [extract_mos(d) for d in tqdm(test_dirs)]

    vocab = build_vocab(train_counters)

    X_train = np.array([vectorize(c, vocab) for c in train_counters])
    X_test = np.array([vectorize(c, vocab) for c in test_counters])

    return X_train, X_test, y_train, y_test


# =========================
# TRAIN & EVAL
# =========================
def train_and_eval(X_train, X_test, y_train, y_test):
    print("\n=== SVM ===")
    svm = SVC(kernel="linear", probability=True)
    svm.fit(X_train, y_train)
    probs = svm.predict_proba(X_test)[:, 1]
    preds = (probs > 0.5).astype(int)

    print("Accuracy:", accuracy_score(y_test, preds))
    print("AUC:", roc_auc_score(y_test, probs))
    print(classification_report(y_test, preds))

    print("\n=== Random Forest ===")
    rf = RandomForestClassifier(n_estimators=200)
    rf.fit(X_train, y_train)
    probs = rf.predict_proba(X_test)[:, 1]
    preds = (probs > 0.5).astype(int)

    print("Accuracy:", accuracy_score(y_test, preds))
    print("AUC:", roc_auc_score(y_test, probs))
    print(classification_report(y_test, preds))


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    batch_decode()
    X_train, X_test, y_train, y_test = build_dataset()
    train_and_eval(X_train, X_test, y_train, y_test)
