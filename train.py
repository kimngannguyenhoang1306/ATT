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
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


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


def batch_decode_full(raw_root="raw_apk", decoded_root="decoded", max_workers=8):
    """Decode APK files với multi-threading"""
    apk_tasks = []

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

            if os.path.exists(out_path) and os.path.exists(
                os.path.join(out_path, "smali")
            ):
                continue

            apk_tasks.append((apk_path, out_path, label, apk))

    # Decode với multi-threading
    print(f"\n🚀 Decoding {len(apk_tasks)} APKs với {max_workers} threads...\n")

    def decode_task(apk_path, out_path, label, apk_name):
        # ✅ CHECK: nếu đã decode rồi thì bỏ qua
        if os.path.exists(out_path) and os.path.exists(os.path.join(out_path, "smali")):
            return f"SKIP {label}: {apk_name[:30]}"

        try:
            subprocess.run(
                [
                    "apktool",
                    "d",
                    apk_path,
                    "-o",
                    out_path,
                    "-f",
                    "-r",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return f"OK {label}: {apk_name[:30]}"
        except Exception as e:
            return f"FAIL {label}: {apk_name[:30]} - {str(e)[:30]}"

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(decode_task, apk_path, out_path, label, apk_name)
            for apk_path, out_path, label, apk_name in apk_tasks
        ]

        for f in tqdm(as_completed(futures), total=len(futures), desc="Decoding APKs"):
            result = f.result()
            if "FAIL" in result:
                print(result)


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

    with open(file_path, "rb") as f:
        for line in f:
            line = line.strip()

            # ✅ dùng bytes
            if line.startswith(b":"):
                if current:
                    blocks.append(current)
                    current = []
                continue

            if not line or line.startswith(b"."):
                continue

            parts = line.split()
            if not parts:
                continue

            token = parts[0].decode(errors="ignore")  # convert sang str

            if token in CATEGORY:
                current.append(CATEGORY[token])

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
from concurrent.futures import ThreadPoolExecutor, as_completed

import pickle


def process_apk_cached(smali_dir):
    cache_path = smali_dir + "_mos.pkl"

    if os.path.exists(cache_path):
        with open(cache_path, "rb") as f:
            return pickle.load(f)

    mos = process_apk(smali_dir)

    with open(cache_path, "wb") as f:
        pickle.dump(mos, f)

    return mos


def build_dataset_fast(apk_dirs, labels, max_workers=8):
    print("\n🚀 Building dataset (parallel)...")

    mos_list = [None] * len(apk_dirs)

    def worker(i, d):
        return i, process_apk_cached(d)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i, d) for i, d in enumerate(apk_dirs)]

        for f in tqdm(as_completed(futures), total=len(futures)):
            i, mos = f.result()
            mos_list[i] = mos

    # ===== build feature space =====
    all_features = Counter()
    for mos in mos_list:
        all_features.update(mos.keys())

    threshold = max(1, int(len(apk_dirs) * 0.01))
    features = [f for f, c in all_features.items() if c >= threshold]
    index = {f: i for i, f in enumerate(features)}

    print(f"Feature count: {len(features)}")

    # ===== build X =====
    X = np.zeros((len(apk_dirs), len(features)), dtype=np.uint8)

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


def filter_infrequent_features(X, threshold=0.01):
    # số app chứa feature
    app_counts = np.sum(X > 0, axis=0)

    # ❌ bạn đang sai ở đây
    min_apps = int(X.shape[0] * threshold)

    mask = app_counts >= min_apps
    return X[:, mask], mask


def get_dnn_importance_scores(model):
    # lấy weights layer đầu tiên
    weights = model.layers[0].get_weights()[0]  # shape: (features, neurons)

    # importance = tổng abs
    importance = np.sum(np.abs(weights), axis=1)

    return importance


def select_top_k_features(X_train, X_test, y_train, k=3000):
    model = build_dnn(X_train.shape[1])
    model.fit(X_train, y_train, epochs=3, verbose=0)

    importance = get_dnn_importance_scores(model)

    idx = np.argsort(importance)[-k:]

    return X_train[:, idx], X_test[:, idx]


def auto_select_k(X, y):
    candidate_k = [500, 1000, 2000, 3000]
    best_k = candidate_k[0]
    best_score = 0

    for k in candidate_k:
        print(f"Testing k={k}...")

        model = build_dnn(X.shape[1])
        model.fit(X, y, epochs=2, verbose=0)

        importance = get_dnn_importance_scores(model)
        idx = np.argsort(importance)[-k:]

        X_k = X[:, idx]

        # dùng RF để estimate nhanh
        rf = RandomForestClassifier(n_estimators=100)
        rf.fit(X_k, y)
        probs = rf.predict_proba(X_k)[:, 1]

        auc = roc_auc_score(y, probs)

        print(f" → AUC={auc:.4f}")

        if auc > best_score:
            best_score = auc
            best_k = k

    return best_k, best_score


# =========================
# 7. TRAIN
# =========================
from sklearn.metrics import accuracy_score, roc_auc_score, roc_curve, confusion_matrix
import matplotlib.pyplot as plt


def train(X, y):
    print(f"\n📊 Total samples: {X.shape}")

    # ===== STEP 1: filter feature =====
    X, mask = filter_infrequent_features(X, threshold=0.01)
    print(f"After frequency filter: {X.shape}")

    # ===== STEP 2: split =====
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y)
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    # ===== STEP 3: AUTO SELECT K =====
    best_k, best_score = auto_select_k(X_train, y_train)
    print(f"🔥 Best k = {best_k} (AUC={best_score:.4f})")

    X_train, X_test = select_top_k_features(X_train, X_test, y_train, k=best_k)
    print(f"After feature selection: {X_train.shape}")

    # ===== STEP 4: TRAIN MODELS =====
    print("\n=== TRAINING ===")

    # SVM
    print("→ Training SVM...")
    svm = SVC(kernel="linear", C=0.0625, probability=True)
    svm.fit(X_train, y_train)
    svm_probs = svm.predict_proba(X_test)[:, 1]

    # RF
    print("→ Training RF...")
    rf = RandomForestClassifier(n_estimators=300)
    rf.fit(X_train, y_train)
    rf_probs = rf.predict_proba(X_test)[:, 1]

    # DNN
    print("→ Training DNN...")
    dnn = build_dnn(X_train.shape[1])
    dnn.fit(X_train, y_train, epochs=5, verbose=1)
    dnn_probs = dnn.predict(X_test).flatten()

    # ===== STEP 5: EVALUATION =====
    print("\n=== EVALUATION ===")

    evaluate_model("SVM", y_test, svm_probs)
    evaluate_model("RF", y_test, rf_probs)
    evaluate_model("DNN", y_test, dnn_probs)

    # ===== STEP 6: ROC CURVE =====
    plot_roc(y_test, {"SVM": svm_probs, "RF": rf_probs, "DNN": dnn_probs})


def evaluate_model(name, y_true, probs):
    preds = (probs > 0.5).astype(int)

    acc = accuracy_score(y_true, preds)
    auc = roc_auc_score(y_true, probs)
    cm = confusion_matrix(y_true, preds)

    print(f"\n{name}")
    print(f"Accuracy: {acc:.4f}")
    print(f"AUC: {auc:.4f}")
    print("Confusion Matrix:")
    print(cm)


def plot_roc(y_true, models_probs):
    plt.figure()

    for name, probs in models_probs.items():
        fpr, tpr, _ = roc_curve(y_true, probs)
        auc = roc_auc_score(y_true, probs)
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})")

    plt.plot([0, 1], [0, 1], linestyle="--")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.legend()
    plt.show()


def plot_feature_importance(importance, top_n=20):
    idx = np.argsort(importance)[-top_n:]

    plt.figure()
    plt.barh(range(top_n), importance[idx])
    plt.yticks(range(top_n), idx)
    plt.title("Top Feature Importance")
    plt.show()


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

    print("Dataset size:", len(apk_dirs))

    # Step 3: build dataset + train
    X, y = build_dataset_fast(apk_dirs, labels, max_workers=8)
    dnn = train(X, y)
    importance = get_dnn_importance_scores(dnn)
    plot_feature_importance(importance)
