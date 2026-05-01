import os
import re
import pickle
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import numpy as np
import networkx as nx
from tqdm import tqdm

from sklearn.model_selection import train_test_split
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfTransformer

# =========================
# CONFIG
# =========================
RAW_DIR = "raw_apk"
DECODED_DIR = "decoded"
CACHE_DIR = "mos_cache"
MAX_WORKERS = 4
K_GRAM = 2

os.makedirs(CACHE_DIR, exist_ok=True)


# =========================
# OPCODE CATEGORY (EXTENDED)
# =========================
def map_opcode(op):
    if op.startswith("move"):
        return "M"
    if op.startswith("return") or op == "throw":
        return "R"
    if op.startswith("if-"):
        return "I"
    if op.startswith("goto"):
        return "G"
    if op.startswith("invoke"):
        return "V"
    if "get" in op:
        return "G"
    if "put" in op:
        return "P"
    if op.startswith("const"):
        return "D"
    if any(x in op for x in ["add", "sub", "mul", "div", "rem"]):
        return "A"
    return "X"


# =========================
# NORMALIZE
# =========================
REGISTER = re.compile(r"v\d+|p\d+")


def normalize(line):
    line = REGISTER.sub("vX", line)
    line = re.sub(r'".*?"', '"STR"', line)
    return line.strip()


# =========================
# CFG PARSER
# =========================
def parse_smali_cfg(path):
    blocks = []
    edges = []
    current = []
    label_map = {}
    block_id = 0

    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            lines = [normalize(l) for l in f]

        for i, line in enumerate(lines):
            if line.startswith(":"):
                if current:
                    blocks.append(current)
                    block_id += 1
                    current = []
                label_map[line] = block_id
                continue

            parts = line.split()
            if not parts:
                continue

            op = parts[0]
            current.append(map_opcode(op))

            # edges
            if op.startswith("if-") and len(parts) > 1:
                edges.append((block_id, parts[-1]))
            elif op.startswith("goto") and len(parts) > 1:
                edges.append((block_id, parts[-1]))

        if current:
            blocks.append(current)

        # build graph
        G = nx.DiGraph()
        for i in range(len(blocks)):
            G.add_node(i)

        for src, label in edges:
            if label in label_map:
                G.add_edge(src, label_map[label])

        return blocks, G

    except:
        return [], nx.DiGraph()


# =========================
# K-GRAM ENCODING
# =========================
def kgram(block, k=2):
    seq = []
    for i in range(len(block) - k + 1):
        seq.append("".join(block[i : i + k]))
    return seq


# =========================
# MOS EXTRACTION
# =========================
def extract_mos(smali_dir):
    cache_path = os.path.join(CACHE_DIR, f"{hash(smali_dir)}.pkl")
    if os.path.exists(cache_path):
        return pickle.load(open(cache_path, "rb"))

    apk_counter = Counter()

    for root, _, files in os.walk(smali_dir):
        for f in files:
            if not f.endswith(".smali"):
                continue

            blocks, _ = parse_smali_cfg(os.path.join(root, f))

            for block in blocks:
                grams = kgram(block, K_GRAM)
                apk_counter.update(grams)

    pickle.dump(apk_counter, open(cache_path, "wb"))
    return apk_counter


# =========================
# VECTORIZE
# =========================
def build_vocab(counters, max_features=5000):
    total = Counter()
    for c in counters:
        total.update(c)

    items = total.most_common(max_features)
    return {k: i for i, (k, _) in enumerate(items)}


def vectorize(counter, vocab):
    vec = np.zeros(len(vocab))
    for k, v in counter.items():
        if k in vocab:
            vec[vocab[k]] = v
    return vec


# =========================
# DATASET
# =========================
def build_dataset():
    dirs, labels = [], []

    for label, folder in [(0, "benign"), (1, "malware")]:
        base = os.path.join(DECODED_DIR, folder)
        for app in os.listdir(base):
            smali = os.path.join(base, app, "smali")
            if os.path.exists(smali):
                dirs.append(smali)
                labels.append(label)

    train_idx, test_idx = train_test_split(
        list(range(len(dirs))), stratify=labels, test_size=0.2, random_state=42
    )

    train_dirs = [dirs[i] for i in train_idx]
    test_dirs = [dirs[i] for i in test_idx]

    y_train = np.array([labels[i] for i in train_idx])
    y_test = np.array([labels[i] for i in test_idx])

    train_counters = [extract_mos(d) for d in tqdm(train_dirs)]
    test_counters = [extract_mos(d) for d in tqdm(test_dirs)]

    vocab = build_vocab(train_counters)

    X_train = np.array([vectorize(c, vocab) for c in train_counters])
    X_test = np.array([vectorize(c, vocab) for c in test_counters])

    # TF-IDF
    tfidf = TfidfTransformer()
    X_train = tfidf.fit_transform(X_train).toarray()
    X_test = tfidf.transform(X_test).toarray()

    # Normalize
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, X_test, y_train, y_test


# =========================
# TRAIN
# =========================
def train_and_eval(X_train, X_test, y_train, y_test):
    print("=== SVM ===")
    svm = SVC(kernel="linear", probability=True)
    svm.fit(X_train, y_train)
    probs = svm.predict_proba(X_test)[:, 1]
    preds = (probs > 0.5).astype(int)

    print("Accuracy:", accuracy_score(y_test, preds))
    print("AUC:", roc_auc_score(y_test, probs))
    print(classification_report(y_test, preds))

    print("\n=== RF ===")
    rf = RandomForestClassifier(n_estimators=300)
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
    X_train, X_test, y_train, y_test = build_dataset()
    train_and_eval(X_train, X_test, y_train, y_test)
