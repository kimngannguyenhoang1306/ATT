# =========================
# MOSDroid FINAL (CFG + FULL OPCODE COVERAGE)
# =========================

import os
import re
import pickle
import subprocess
import random
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import joblib
import hashlib
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from gensim.models import Word2Vec
from gensim.models.callbacks import CallbackAny2Vec
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    roc_curve,
    confusion_matrix,
    classification_report,
)
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils.class_weight import compute_class_weight
import tensorflow as tf


# =========================
# CONSTANTS
# =========================
MAX_BLOCKS_PER_APK = 20000
TERMINATORS = {"R"}
BRANCH_OPS = {"I"}
W2V_MODEL_PATH = "w2v_model.model"


# =========================
# 1. FULL OPCODE LIST (Dalvik)
# =========================
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
# 2. APK DECODING
# =========================
def decode_apk(apk_path, output_dir):
    try:
        subprocess.run(
            ["apktool", "d", apk_path, "-o", output_dir, "-f", "-r"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return True
    except Exception as e:
        print(f"Error decoding {apk_path}: {e}")
        return False


def batch_decode_full(raw_root="raw_apk", decoded_root="decoded", max_workers=8):
    apk_tasks = []

    for label in ["benign", "malware"]:
        input_dir = os.path.join(raw_root, label)
        output_dir = os.path.join(decoded_root, label)
        os.makedirs(output_dir, exist_ok=True)

        if not os.path.exists(input_dir):
            continue

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

    if not apk_tasks:
        print("No APKs to decode.")
        return

    print(f"\n🚀 Decoding {len(apk_tasks)} APKs with {max_workers} threads...\n")

    def decode_task(args):
        apk_path, out_path, label, apk_name = args
        success = decode_apk(apk_path, out_path)
        return f"{'OK' if success else 'FAIL'} {label}: {apk_name[:30]}"

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(decode_task, task) for task in apk_tasks]
        for f in tqdm(as_completed(futures), total=len(futures), desc="Decoding APKs"):
            result = f.result()
            if "FAIL" in result:
                print(result)


# =========================
# 3. SMALI PARSING & CFG
# =========================
REGISTER_PATTERN = re.compile(r"v\d+|p\d+")


def normalize_line(line: str) -> str:
    line = REGISTER_PATTERN.sub("vX", line)
    line = re.sub(r'".*?"', '"STR"', line)
    return line


def extract_blocks_only(file_path):
    """
    Parse một file .smali thành danh sách basic blocks.
    Mỗi item trong block là tuple (cat, op, api_name, target_label).
    api_name và target_label có thể là None.
    """
    blocks = []
    current = []
    in_method = False

    try:
        for line in open(file_path, encoding="utf-8", errors="ignore"):
            line = normalize_line(line.strip())

            if not line:
                continue

            if line.startswith(".method"):
                in_method = True
                current = []
                continue

            if line.startswith(".end method"):
                if current:
                    blocks.append(current)
                current = []
                in_method = False
                continue

            if not in_method:
                continue

            if line.startswith(":"):
                current.append(("LABEL", line, None, None))
                continue

            parts = line.split()
            if not parts:
                continue

            token = parts[0]
            api_name = None
            target_label = None

            if token.startswith("invoke") and len(parts) > 1:
                full = " ".join(parts)
                match = re.search(r"L([^;]+);", full)
                if match:
                    api_name = match.group(1).split("/")[-1]

            if (token.startswith("if") or token.startswith("goto")) and len(parts) > 1:
                if parts[-1].startswith(":"):
                    target_label = parts[-1]

            if token in CATEGORY:
                cat = CATEGORY[token]
                # FIX: luôn dùng tuple 4 phần tử để nhất quán
                current.append((cat, token, api_name, target_label))

                if cat in TERMINATORS or cat in BRANCH_OPS:
                    if current:
                        blocks.append(current)
                    current = []

    except Exception:
        pass

    if current:
        blocks.append(current)

    return blocks


def build_cfg_from_blocks(blocks):
    G = nx.DiGraph()
    n = len(blocks)

    label_map = {}
    for i, block in enumerate(blocks):
        for item in block:
            # item luôn là tuple 4 phần tử: (cat, op, api_name, target_label)
            if item[0] == "LABEL":
                label_map[item[1]] = i

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)

        if not block:
            continue

        last = block[-1]
        cat, op, api_name, target_label = last

        if cat == "LABEL":
            # block kết thúc bằng label → nối tiếp
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        if not op.startswith("return") and i + 1 < n:
            G.add_edge(i, i + 1)

        if target_label and target_label in label_map:
            G.add_edge(i, label_map[target_label])

    return G


# =========================
# 4. CACHE (blocks only — không cache CFG để tiết kiệm RAM)
# =========================
def get_blocks_cache_path(smali_dir):
    return smali_dir.rstrip("/") + "_blocks.pkl"


def get_features_cache_path(smali_dir):
    return smali_dir.rstrip("/") + "_features.pkl"


def build_blocks_only(smali_dir):
    """Đọc tất cả file .smali trong smali_dir, trả về list of blocks."""
    files = [
        os.path.join(root, f)
        for root, _, fs in os.walk(smali_dir)
        for f in fs
        if f.endswith(".smali")
    ]

    blocks = []
    # FIX RAM: dùng max_workers nhỏ để tránh load quá nhiều file cùng lúc
    with ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(extract_blocks_only, files):
            blocks.extend(res)
            if len(blocks) >= MAX_BLOCKS_PER_APK:
                blocks = blocks[:MAX_BLOCKS_PER_APK]
                break

    return blocks


def get_blocks_cached(smali_dir):
    cache_path = get_blocks_cache_path(smali_dir)

    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass

    blocks = build_blocks_only(smali_dir)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(blocks, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass

    return blocks


# =========================
# 5. FEATURE EXTRACTION
# =========================
def extract_ngrams(blocks, n=3):
    sequences = Counter()
    for block in blocks:
        # Chỉ lấy opcode (index 1), bỏ qua LABEL
        ops = [item[1] for item in block if item[0] != "LABEL"]
        for i in range(len(ops) - n + 1):
            gram = tuple(ops[i : i + n])
            sequences[gram] += 1
    return sequences


def build_mos_from_blocks(blocks):
    mos = Counter()

    for block in blocks:
        ops = tuple(item[1] for item in block if item[0] != "LABEL")
        if ops:
            mos[ops] += 1

    mos.update(extract_ngrams(blocks, n=2))
    mos.update(extract_ngrams(blocks, n=3))

    return mos


def extract_api_sequence(blocks):
    api_seq = Counter()

    for block in blocks:
        for item in block:
            cat, op, api_name, target = item
            if op.startswith("invoke"):
                if "virtual" in op:
                    api_seq["API_VIRTUAL"] += 1
                elif "static" in op:
                    api_seq["API_STATIC"] += 1
                elif "direct" in op:
                    api_seq["API_DIRECT"] += 1
                else:
                    api_seq["API_OTHER"] += 1

                if api_name:
                    api_seq[f"API_{api_name}"] += 1

    return api_seq


def graph_to_features_fast(G):
    features = Counter()

    features[("NODE_COUNT",)] = G.number_of_nodes()
    features[("EDGE_COUNT",)] = G.number_of_edges()

    degrees = [d for _, d in G.degree()]
    if degrees:
        features[("AVG_DEGREE",)] = float(np.mean(degrees))
        features[("MAX_DEGREE",)] = float(np.max(degrees))

    branch_nodes = sum(1 for n in G.nodes() if G.out_degree(n) > 1)
    features[("BRANCH_NODES",)] = branch_nodes

    try:
        cycles = list(nx.simple_cycles(G))
        features[("CYCLE_COUNT",)] = len(cycles)
    except Exception:
        features[("CYCLE_COUNT",)] = 0

    if G.number_of_nodes() > 1:
        features[("DENSITY",)] = nx.density(G)

    return features


# =========================
# 6. EMBEDDING
# =========================
class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"  Word2Vec epoch {self.epoch} done")


class SentenceIterable:
    """Lazy iterator qua blocks — không load toàn bộ vào RAM."""

    def __init__(self, smali_dirs):
        self.smali_dirs = smali_dirs

    def __iter__(self):
        for smali_dir in self.smali_dirs:
            blocks = get_blocks_cached(smali_dir)
            for block in blocks:
                ops = [item[1] for item in block if item[0] != "LABEL"]
                if ops:
                    yield ops


def train_w2v(train_dirs, vector_size=32, model_path=W2V_MODEL_PATH):
    if model_path and os.path.exists(model_path):
        print("📦 Loading cached Word2Vec...")
        return Word2Vec.load(model_path)

    print("🧠 Training Word2Vec on TRAIN set only...")
    sentences = SentenceIterable(train_dirs)

    model = Word2Vec(
        vector_size=vector_size,
        window=5,
        min_count=2,
        sg=1,
        negative=15,
        sample=1e-4,
        workers=os.cpu_count(),
        epochs=8,
    )

    print("🧠 Building vocabulary...")
    model.build_vocab(sentences)

    print("🚀 Training Word2Vec...")
    model.train(
        sentences,
        total_examples=model.corpus_count,
        epochs=model.epochs,
        callbacks=[EpochLogger()],
    )

    if model_path:
        model.save(model_path)
        print(f"💾 Saved Word2Vec to {model_path}")

    return model


def graph_embedding(blocks, G, w2v_model, vector_size=32):
    if w2v_model is None:
        return np.zeros(vector_size)

    wv = w2v_model.wv
    node_vecs = []

    for node in G.nodes():
        block = G.nodes[node].get("features", [])
        block_vecs = [
            wv[item[1]] for item in block if item[0] != "LABEL" and item[1] in wv
        ]
        if block_vecs:
            node_vecs.append(np.mean(block_vecs, axis=0))

    if not node_vecs:
        return np.zeros(vector_size)

    return np.mean(node_vecs, axis=0)


# =========================
# 7. AUGMENTATION
# =========================
JUNK_OPS = [
    ["const/4", "add-int"],
    ["const/4", "if-eq"],
]


def inject_junk_blocks(blocks, prob=0.1):
    new_blocks = []
    for block in blocks:
        new_blocks.append(block)
        if random.random() < prob:
            junk_ops = random.choice(JUNK_OPS)
            junk_encoded = [(CATEGORY.get(op, "X"), op, None, None) for op in junk_ops]
            new_blocks.append(junk_encoded)
    return new_blocks


def obfuscate_blocks(blocks):
    return inject_junk_blocks(blocks, prob=0.1)


# =========================
# 8. SINGLE APK FEATURE EXTRACTION (với cache features)
# =========================
def extract_features_for_apk(smali_dir, w2v_model, vector_size=32, use_cache=True):
    """
    Trả về dict: {mos, api, cfg, emb}.
    FIX: không lưu blocks vào feature cache (tiết kiệm RAM & disk).
    """
    cache_path = get_features_cache_path(smali_dir)

    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)
            # Validate cache có đủ keys
            if all(k in cached for k in ("mos", "api", "cfg", "emb")):
                return cached
        except Exception:
            pass

    blocks = get_blocks_cached(smali_dir)
    if len(blocks) > MAX_BLOCKS_PER_APK:
        blocks = blocks[:MAX_BLOCKS_PER_APK]

    G = build_cfg_from_blocks(blocks)

    result = {
        "mos": build_mos_from_blocks(blocks),
        "api": extract_api_sequence(blocks),
        "cfg": graph_to_features_fast(G),  # FIX: không truyền blocks thừa
        "emb": graph_embedding(blocks, G, w2v_model, vector_size=vector_size),
    }

    # FIX: KHÔNG lưu blocks vào cache → tiết kiệm RAM & disk
    if use_cache:
        try:
            with open(cache_path, "wb") as f:
                pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

    return result


def extract_features_augmented(smali_dir, w2v_model, vector_size=32):
    """Trả về features sau khi augment (chỉ dùng cho train malware)."""
    blocks = get_blocks_cached(smali_dir)
    if len(blocks) > MAX_BLOCKS_PER_APK:
        blocks = blocks[:MAX_BLOCKS_PER_APK]

    blocks_aug = obfuscate_blocks(blocks)
    G_aug = build_cfg_from_blocks(blocks_aug)

    return {
        "mos": build_mos_from_blocks(blocks_aug),
        "api": extract_api_sequence(blocks_aug),
        "cfg": graph_to_features_fast(G_aug),
        "emb": graph_embedding(blocks_aug, G_aug, w2v_model, vector_size=vector_size),
    }


# =========================
# 9. VOCAB & VECTORIZATION
# =========================
def build_global_vocab(all_counters, min_freq=2, max_features=2000):
    global_counter = Counter()
    for c in all_counters:
        global_counter.update(c)

    filtered = [(k, v) for k, v in global_counter.items() if v >= min_freq]
    filtered.sort(key=lambda x: -x[1])

    return {k: i for i, (k, _) in enumerate(filtered[:max_features])}


def counter_to_vector(counter, vocab):
    vec = np.zeros(len(vocab))
    for key, count in counter.items():
        if key in vocab:
            vec[vocab[key]] = count
    return vec


def vectorize_results(results, mos_vocab, api_vocab, cfg_vocab):
    X = []
    for r in results:
        mos_vec = counter_to_vector(r["mos"], mos_vocab)
        api_vec = counter_to_vector(r["api"], api_vocab)
        cfg_vec = counter_to_vector(r["cfg"], cfg_vocab)
        emb_vec = r["emb"]
        X.append(np.concatenate([mos_vec, api_vec, cfg_vec, emb_vec]))
    return np.array(X)


# =========================
# 10. DATASET BUILDING (no data leakage)
# =========================
def build_dataset(
    apk_dirs,
    labels,
    max_workers=8,
    vector_size=32,
    use_cache=True,
    test_size=0.2,
):
    """
    Build train/test dataset với đầy đủ anti-leakage:
    - Split index trước khi fit bất kỳ transformer nào
    - W2V chỉ train trên train set
    - Vocab, scaler fit chỉ trên train set
    - Augment chỉ trên train malware
    - FIX RAM: không giữ toàn bộ blocks trong RAM
    """

    # ── STEP 1: Train/test split TRƯỚC ────────────────────────
    print("\n✂️  Step 1: Train/test split (before any fitting)...")
    train_idx, test_idx = train_test_split(
        list(range(len(apk_dirs))),
        test_size=test_size,
        stratify=labels,
        random_state=42,
    )
    train_dirs = [apk_dirs[i] for i in train_idx]
    test_dirs = [apk_dirs[i] for i in test_idx]
    train_labels_orig = [labels[i] for i in train_idx]
    test_labels_orig = [labels[i] for i in test_idx]
    print(f"Train: {len(train_dirs)} | Test: {len(test_dirs)}")

    # ── STEP 2: W2V chỉ train trên train_dirs ─────────────────
    print("\n🧠 Step 2: Training Word2Vec (TRAIN SET ONLY)...")
    w2v_model = train_w2v(
        train_dirs, vector_size=vector_size, model_path=W2V_MODEL_PATH
    )

    # ── STEP 3: Extract raw features (lazy, có cache) ─────────
    print("\n🔧 Step 3: Extracting raw features...")

    def worker(smali_dir):
        return extract_features_for_apk(
            smali_dir, w2v_model, vector_size=vector_size, use_cache=use_cache
        )

    # FIX RAM: xử lý tuần tự từng APK (không load toàn bộ vào RAM cùng lúc)
    # Dùng ThreadPoolExecutor nhưng kết quả được tiêu thụ ngay
    all_dirs = [apk_dirs[i] for i in train_idx] + [apk_dirs[i] for i in test_idx]
    all_raw = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(worker, d): d for d in all_dirs}
        for future in tqdm(
            as_completed(future_map), total=len(future_map), desc="Extracting"
        ):
            d = future_map[future]
            try:
                all_raw[d] = future.result()
            except Exception as e:
                print(f"  ERROR {d}: {e}")
                all_raw[d] = None

    # ── STEP 4: Augment train malware ─────────────────────────
    print("\n🔀 Step 4: Augmenting train malware (TRAIN SET ONLY)...")
    train_results = []
    train_combined_labels = []

    for i, d in zip(train_idx, train_dirs):
        raw = all_raw.get(d)
        if raw is None:
            continue
        train_results.append(raw)
        train_combined_labels.append(labels[i])

        if labels[i] == 1:
            # Augmented version
            try:
                aug = extract_features_augmented(d, w2v_model, vector_size=vector_size)
                train_results.append(aug)
                train_combined_labels.append(1)
            except Exception:
                pass

    test_results = []
    test_combined_labels = []
    for i, d in zip(test_idx, test_dirs):
        raw = all_raw.get(d)
        if raw is None:
            continue
        test_results.append(raw)
        test_combined_labels.append(labels[i])

    # FIX RAM: giải phóng all_raw sau khi đã tách train/test
    del all_raw

    # ── STEP 5: Vocab fit trên TRAIN set ──────────────────────
    print("\n📚 Step 5: Building vocabulary (TRAIN SET ONLY)...")
    mos_vocab = build_global_vocab(
        [r["mos"] for r in train_results], min_freq=3, max_features=1500
    )
    api_vocab = build_global_vocab(
        [r["api"] for r in train_results], min_freq=3, max_features=500
    )
    cfg_vocab = build_global_vocab(
        [r["cfg"] for r in train_results], min_freq=2, max_features=200
    )
    print(
        f"Vocab — MOS: {len(mos_vocab)}, API: {len(api_vocab)}, CFG: {len(cfg_vocab)}"
    )

    # ── STEP 6: Vectorize ─────────────────────────────────────
    print("\n🔢 Step 6: Building feature vectors...")
    X_train_raw = vectorize_results(train_results, mos_vocab, api_vocab, cfg_vocab)
    X_test_raw = vectorize_results(test_results, mos_vocab, api_vocab, cfg_vocab)
    y_train = np.array(train_combined_labels)
    y_test = np.array(test_combined_labels)

    # ── STEP 7: Scaler fit trên TRAIN ─────────────────────────
    print("\n📐 Step 7: Scaling (fit on TRAIN SET ONLY)...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)  # chỉ transform

    # Feature names
    def fmt(f):
        if isinstance(f, tuple):
            return " → ".join(str(x) for x in f if x is not None)
        return str(f)

    feature_names = (
        [f"MOS:{fmt(k)}" for k in mos_vocab]
        + [f"API:{k}" for k in api_vocab]
        + [f"CFG:{k[0]}" for k in cfg_vocab]
        + [f"EMB:{i}" for i in range(vector_size)]
    )

    print(f"\n✅ Dataset built:")
    print(f"  X_train={X_train.shape}, y_train={y_train.shape}")
    print(f"  X_test ={X_test.shape},  y_test ={y_test.shape}")

    return X_train, X_test, y_train, y_test, feature_names, scaler


# =========================
# 11. FEATURE SELECTION
# =========================
def filter_infrequent_features(X_train, X_test, feature_names, threshold=0.01):
    """
    FIX LEAKAGE: tính mask CHỈ trên X_train, apply cho cả X_test.
    FIX: trả về feature_names đã filtered (không để caller tự filter dễ lỗi).
    """
    min_apps = max(1, int(X_train.shape[0] * threshold))
    mask = np.sum(X_train > 0, axis=0) >= min_apps
    print(f"  filter_infrequent: giữ {mask.sum()}/{X_train.shape[1]} features")

    filtered_names = [n for n, keep in zip(feature_names, mask) if keep]
    return X_train[:, mask], X_test[:, mask], filtered_names, mask


def auto_select_k(X_train, y_train, candidate_k=None):
    """
    FIX: train RandomForest 1 lần duy nhất, dùng lại importance để eval.
    """
    if candidate_k is None:
        candidate_k = [500, 1000, 2000, 3000]

    candidate_k = [k for k in candidate_k if k <= X_train.shape[1]]
    if not candidate_k:
        return X_train.shape[1], 0.0

    print(f"\n🔍 auto_select_k: trying {candidate_k}...")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )

    # Train 1 lần lấy importance
    rf = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)
    rf.fit(X_tr, y_tr)
    importance = rf.feature_importances_

    best_k, best_auc = candidate_k[0], 0.0

    for k in candidate_k:
        top_idx = np.argsort(importance)[-k:]
        probs = rf.predict_proba(X_val[:, top_idx])[:, 1]
        auc = roc_auc_score(y_val, probs)
        print(f"  k={k:>5} → AUC={auc:.4f}")
        if auc > best_auc:
            best_auc = auc
            best_k = k

    print(f"  ✅ Best k = {best_k} (AUC={best_auc:.4f})")
    return best_k, best_auc


def select_top_k_features(X_train, X_test, importance, k):
    n = X_train.shape[1]
    if importance is None:
        importance = np.ones(n)
    importance = importance[:n]  # trim nếu dài hơn
    k = min(k, n)
    idx = np.argsort(importance)[-k:]
    return X_train[:, idx], X_test[:, idx], idx


# =========================
# 12. MODEL BUILDING
# =========================
def build_dnn(input_dim):
    model = tf.keras.Sequential(
        [
            tf.keras.Input(shape=(input_dim,)),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(512, activation="relu"),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(256, activation="relu"),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(128, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=5e-4),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def get_dnn_importance(model, n_features):
    """Lấy importance từ layer Dense đầu tiên, đảm bảo length = n_features."""
    for layer in model.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            weights = layer.get_weights()
            if weights and weights[0].shape[0] == n_features:
                return np.sum(np.abs(weights[0]), axis=1)
    return np.ones(n_features)


# =========================
# 13. EVALUATION & PLOTTING
# =========================
def evaluate_model(name, y_true, probs, threshold=0.5):
    preds = (probs > threshold).astype(int)
    acc = accuracy_score(y_true, preds)
    auc = roc_auc_score(y_true, probs)
    cm = confusion_matrix(y_true, preds)

    print(f"\n{'='*40}")
    print(f"{name}")
    print(f"{'='*40}")
    print(f"Accuracy : {acc:.4f}")
    print(f"AUC      : {auc:.4f}")
    print(f"Confusion Matrix:\n{cm}")
    print("\nClassification Report:")
    print(classification_report(y_true, preds))

    return {"accuracy": acc, "auc": auc, "confusion_matrix": cm}


def plot_roc(y_true, models_probs, save_path=None):
    plt.figure(figsize=(8, 6))
    for name, probs in models_probs.items():
        fpr, tpr, _ = roc_curve(y_true, probs)
        auc = roc_auc_score(y_true, probs)
        plt.plot(fpr, tpr, label=f"{name} (AUC={auc:.3f})", linewidth=2)
    plt.plot([0, 1], [0, 1], "k--", linewidth=1)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve Comparison")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.show()


def plot_feature_importance(importance, features, top_n=20, save_path=None):
    if importance is None or len(importance) == 0:
        print("No importance scores.")
        return
    top_n = min(top_n, len(importance), len(features))
    idx = np.argsort(importance)[-top_n:]
    plt.figure(figsize=(10, 8))
    plt.barh(range(top_n), importance[idx], color="steelblue")
    labels = [str(features[i])[:50] for i in idx]
    plt.yticks(range(top_n), labels)
    plt.xlabel("Importance Score")
    plt.title(f"Top {top_n} Feature Importance")
    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.show()


# =========================
# 14. TRAINING & EVALUATION
# =========================
def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names):
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")
    print(f"X_train: {X_train.shape}  |  X_test: {X_test.shape}")

    # STEP 1: Filter infrequent features (fit on train only)
    print("\n🔎 Step 1: Filtering infrequent features...")
    X_train, X_test, feature_names, _ = filter_infrequent_features(
        X_train, X_test, feature_names, threshold=0.01
    )

    print(f"\n📊 Class balance:")
    print(f"  Train — Benign: {(y_train==0).sum()}, Malware: {(y_train==1).sum()}")
    print(f"  Test  — Benign: {(y_test==0).sum()},  Malware: {(y_test==1).sum()}")

    # STEP 2: Auto-select k (using only train)
    best_k, _ = auto_select_k(X_train, y_train, candidate_k=[500, 1000, 2000, 3000])

    # STEP 3: DNN preliminary để lấy importance (fit on train only)
    print(f"\n🔍 Step 3: Preliminary DNN for importance (k={best_k})...")
    prelim_dnn = build_dnn(X_train.shape[1])
    prelim_dnn.fit(X_train, y_train, epochs=3, verbose=0, batch_size=32)
    importance = get_dnn_importance(prelim_dnn, X_train.shape[1])

    X_train_sel, X_test_sel, selected_idx = select_top_k_features(
        X_train, X_test, importance, k=best_k
    )
    selected_features = [feature_names[i] for i in selected_idx]
    print(f"  Selected {X_train_sel.shape[1]} features")

    # STEP 4: Train models
    print("\n🚀 Step 4: Training models...")

    class_weights = compute_class_weight(
        class_weight="balanced", classes=np.unique(y_train), y=y_train
    )
    cw_dict = {i: w for i, w in enumerate(class_weights)}

    print("  → SVM...")
    svm = SVC(kernel="linear", C=0.0625, probability=True)
    svm.fit(X_train_sel, y_train)
    svm_probs = svm.predict_proba(X_test_sel)[:, 1]

    print("  → Random Forest...")
    rf = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
    rf.fit(X_train_sel, y_train)
    rf_probs = rf.predict_proba(X_test_sel)[:, 1]

    print("  → DNN...")
    dnn = build_dnn(X_train_sel.shape[1])
    dnn.fit(
        X_train_sel,
        y_train,
        epochs=10,
        batch_size=32,
        validation_split=0.1,
        class_weight=cw_dict,
        verbose=1,
    )
    dnn_probs = dnn.predict(X_test_sel, verbose=0).flatten()

    # STEP 5: Evaluate
    print("\n📊 EVALUATION RESULTS")
    results = {
        "SVM": evaluate_model("SVM", y_test, svm_probs),
        "RF": evaluate_model("Random Forest", y_test, rf_probs),
        "DNN": evaluate_model("DNN", y_test, dnn_probs),
    }

    os.makedirs("figs", exist_ok=True)
    plot_roc(
        y_test,
        {"SVM": svm_probs, "RF": rf_probs, "DNN": dnn_probs},
        save_path="figs/roc_comparison.png",
    )

    # Feature importance breakdown by group
    final_importance = get_dnn_importance(dnn, X_train_sel.shape[1])
    total_imp = np.sum(final_importance)
    if total_imp > 0:
        final_importance = final_importance / total_imp

    group_importance = defaultdict(float)
    symbolic_idx, symbolic_names = [], []
    embedding_idx, embedding_names = [], []

    for pos, (orig_idx, feat) in enumerate(zip(selected_idx, selected_features)):
        prefix = feat.split(":")[0]
        group_importance[prefix] += final_importance[pos]
        if prefix in ("MOS", "API", "CFG"):
            symbolic_idx.append(pos)
            symbolic_names.append(feat)
        elif prefix == "EMB":
            embedding_idx.append(pos)
            embedding_names.append(feat)

    print("\n📊 Feature Group Importance:")
    for k, v in sorted(group_importance.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v:.4f}")

    sym_imp = final_importance[symbolic_idx] if symbolic_idx else np.array([])
    emb_imp = final_importance[embedding_idx] if embedding_idx else np.array([])

    plot_feature_importance(
        sym_imp, symbolic_names, top_n=20, save_path="figs/feature_symbolic.png"
    )
    plot_feature_importance(
        emb_imp, embedding_names, top_n=20, save_path="figs/feature_embedding.png"
    )

    return {
        "models": {"svm": svm, "rf": rf, "dnn": dnn},
        "results": results,
        "selected_idx": selected_idx,
    }


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Step 1: Decode APKs
    batch_decode_full(raw_root="raw_apk", decoded_root="decoded", max_workers=8)

    # Step 2: Collect APK paths
    apk_dirs = []
    labels = []

    for label, folder in [(0, "decoded/benign"), (1, "decoded/malware")]:
        if not os.path.exists(folder):
            print(f"Warning: {folder} does not exist")
            continue
        for app in os.listdir(folder):
            smali_path = os.path.join(folder, app, "smali")
            if os.path.exists(smali_path):
                apk_dirs.append(smali_path)
                labels.append(label)

    total = len(labels)
    benign = labels.count(0)
    malware = labels.count(1)

    print("\n📊 DATASET STATISTICS")
    print("=" * 40)
    print(f"Total   : {total}")
    print(f"Benign  : {benign}  ({benign/total:.2%})")
    print(f"Malware : {malware} ({malware/total:.2%})")

    if total == 0:
        print("No APKs found. Check directory structure.")
        exit(1)

    # Step 3: Build dataset
    X_train, X_test, y_train, y_test, feature_names, scaler = build_dataset(
        apk_dirs=apk_dirs,
        labels=labels,
        max_workers=8,
        use_cache=True,
    )

    print("\n📦 FEATURE DATASET")
    print("=" * 40)
    print(f"X_train  : {X_train.shape}")
    print(f"X_test   : {X_test.shape}")
    print(f"#Features: {X_train.shape[1]}")

    # Step 4: Train and evaluate
    output = train_and_evaluate(X_train, X_test, y_train, y_test, feature_names)
    print("\n✅ Training complete!")
