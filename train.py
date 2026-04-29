# =========================
# MOSDroid FINAL (CFG + FULL OPCODE COVERAGE) - FIXED (NO DATA LEAKAGE)
# =========================

import os
import re
import pickle
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import joblib
import hashlib
import numpy as np
import networkx as nx
import matplotlib.pyplot as plt
from tqdm import tqdm
from gensim.models import Word2Vec
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, roc_auc_score, roc_curve, confusion_matrix
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
import tensorflow as tf


W2V_CACHE_PATH = "w2v_model.model"
MAX_BLOCKS_PER_APK = 20000
TERMINATORS = {"R"}
BRANCH_OPS = {"I"}


def save_w2v_model(model):
    model.save(W2V_CACHE_PATH)


def load_w2v_model():
    if os.path.exists(W2V_CACHE_PATH):
        return Word2Vec.load(W2V_CACHE_PATH)
    return None


def get_feature_cache_path(smali_dir):
    return smali_dir.rstrip("/") + "_features.pkl"


def process_apk_features_cached(smali_dir, w2v_model):
    cache_path = get_feature_cache_path(smali_dir)

    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass

    blocks = get_blocks_cached(smali_dir)
    G = build_cfg_from_blocks(blocks)
    result = process_single_apk(smali_dir, w2v_model, G, blocks)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(result, f)
    except Exception:
        pass

    return result


def get_cfg_cache_path(smali_dir):
    return smali_dir.rstrip("/") + "_cfg.pkl"


def build_cfg_cached(smali_dir, blocks):
    path = get_cfg_cache_path(smali_dir)

    if os.path.exists(path):
        with open(path, "rb") as f:
            return pickle.load(f)

    G = build_cfg_from_blocks(blocks)

    with open(path, "wb") as f:
        pickle.dump(G, f)

    return G


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
        if os.path.exists(out_path) and os.path.exists(os.path.join(out_path, "smali")):
            return f"SKIP {label}: {apk_name[:30]}"
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
                current.append(("LABEL", line))
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
                current.append((CATEGORY[token], token, api_name, target_label))

            cat = CATEGORY.get(token, "X")

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
            if isinstance(item, tuple) and item[0] == "LABEL":
                label_map[item[1]] = i

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)

        if not block:
            continue

        last = block[-1]

        if not isinstance(last, tuple):
            continue

        if len(last) == 4:
            cat, op, api_name, target_label = last
        else:
            cat, op = last[0], last[1]
            target_label = None

        if not op.startswith("return") and i + 1 < n:
            G.add_edge(i, i + 1)

        if target_label and target_label in label_map:
            G.add_edge(i, label_map[target_label])

    return G


def build_cfg_from_file(file_path):
    blocks = extract_blocks_only(file_path)
    G = build_cfg_from_blocks(blocks)
    return G, blocks


def get_blocks_cached(smali_dir):
    cache_path = smali_dir.rstrip("/") + "_blocks.pkl"

    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass

    blocks = build_blocks_only(smali_dir)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(blocks, f)
    except Exception:
        pass

    return blocks


def build_blocks_only(smali_dir):
    files = [
        os.path.join(root, f)
        for root, _, fs in os.walk(smali_dir)
        for f in fs
        if f.endswith(".smali")
    ]

    blocks = []

    with ThreadPoolExecutor(max_workers=4) as ex:
        for res in ex.map(extract_blocks_only, files):
            blocks.extend(res)

            if len(blocks) >= MAX_BLOCKS_PER_APK:
                blocks = blocks[:MAX_BLOCKS_PER_APK]
                break

    return blocks


def build_cfg_from_dir_fast(smali_dir, max_workers=8):
    files = [
        os.path.join(root, f)
        for root, _, fs in os.walk(smali_dir)
        for f in fs
        if f.endswith(".smali")
    ]

    def parse_single(f):
        return build_cfg_from_file(f)[1]

    blocks = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(parse_single, files):
            blocks.extend(res)
    return blocks


def build_cfg_from_dir(smali_dir):
    all_blocks = []
    combined_graph = nx.DiGraph()
    node_offset = 0

    for root, _, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue

            file_path = os.path.join(root, fname)
            G, blocks = build_cfg_from_file(file_path)

            all_blocks.extend(blocks)

            mapping = {n: n + node_offset for n in G.nodes()}
            G_relabeled = nx.relabel_nodes(G, mapping)
            combined_graph = nx.compose(combined_graph, G_relabeled)
            node_offset += len(G.nodes())

    return combined_graph, all_blocks


# =========================
# 4. FEATURE EXTRACTION
# =========================
def extract_ngrams(blocks, n=3):
    sequences = Counter()
    for block in blocks:
        for i in range(len(block) - n + 1):
            gram = tuple(block[i : i + n])
            sequences[gram] += 1
    return sequences


def build_mos_from_blocks(blocks):
    mos = Counter()

    for block in blocks:
        if block:
            mos[tuple(block)] += 1

    mos.update(extract_ngrams(blocks, n=2))
    mos.update(extract_ngrams(blocks, n=3))

    return mos


def extract_api_sequence(blocks):
    api_seq = Counter()

    for block in blocks:
        for item in block:
            if not isinstance(item, tuple):
                continue

            if len(item) == 4:
                cat, op, api_name, target = item
            elif len(item) == 3:
                cat, op, api_name = item
            else:
                continue

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


def graph_to_features_fast(G, blocks):
    features = Counter()

    features[("NODE_COUNT",)] = G.number_of_nodes()
    features[("EDGE_COUNT",)] = G.number_of_edges()

    degrees = [d for _, d in G.degree()]
    if degrees:
        features[("AVG_DEGREE",)] = np.mean(degrees)
        features[("MAX_DEGREE",)] = np.max(degrees)

    branch_nodes = sum(1 for n in G.nodes() if G.out_degree(n) > 1)
    features[("BRANCH_NODES",)] = branch_nodes

    try:
        cycles = list(nx.simple_cycles(G))
        features[("CYCLE_COUNT",)] = len(cycles)
    except:
        features[("CYCLE_COUNT",)] = 0

    if G.number_of_nodes() > 1:
        features[("DENSITY",)] = nx.density(G)

    return features


# =========================
# 5. EMBEDDING
# =========================
from gensim.models.callbacks import CallbackAny2Vec


class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"🧠 Word2Vec epoch {self.epoch} done")


def train_opcode_embedding(all_blocks, vector_size=32, model_path=None):
    """
    Train Word2Vec chỉ trên tập train blocks.
    Không bao giờ gọi hàm này với toàn bộ dataset.
    """
    if model_path and os.path.exists(model_path):
        print("📦 Loading cached Word2Vec...")
        return Word2Vec.load(model_path)

    class SentenceIterable:
        def __init__(self, blocks):
            self.blocks = blocks

        def __iter__(self):
            for block in self.blocks:
                if block:
                    yield [op[1] for op in block if isinstance(op, tuple)]

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

    sentences = SentenceIterable(all_blocks)

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


def encode_block(block, w2v_model, vector_size=32):
    if w2v_model is None or not block:
        return np.zeros(vector_size)

    vectors = []
    for op in block:
        key = op[1]
        if key in w2v_model.wv:
            vectors.append(w2v_model.wv[key])

    if not vectors:
        return np.zeros(vector_size)

    return np.mean(vectors, axis=0)


def graph_embedding(blocks, G, w2v_model, vector_size=32):
    if w2v_model is None:
        return np.zeros(vector_size)

    wv = w2v_model.wv
    node_vecs = []

    for node in G.nodes():
        block = G.nodes[node]["features"]

        block_vecs = []
        for op in block:
            key = op[1]
            if key in wv:
                block_vecs.append(wv[key])

        if block_vecs:
            node_vec = np.mean(block_vecs, axis=0)
            node_vecs.append(node_vec)

    if not node_vecs:
        return np.zeros(vector_size)

    return np.mean(node_vecs, axis=0)


# =========================
# 6. DATASET BUILDING
# =========================
def hash_dir(path):
    return hashlib.md5(path.encode()).hexdigest()


def save_dataset(cache_dir, X, y, feature_names, apk_dirs, scaler, apk_index=None):
    os.makedirs(cache_dir, exist_ok=True)

    np.save(os.path.join(cache_dir, "X.npy"), X)
    np.save(os.path.join(cache_dir, "y.npy"), y)

    joblib.dump(feature_names, os.path.join(cache_dir, "feature_names.pkl"))
    joblib.dump(scaler, os.path.join(cache_dir, "scaler.pkl"))

    if apk_index is None:
        apk_index = {hash_dir(p): p for p in apk_dirs}

    joblib.dump(apk_index, os.path.join(cache_dir, "apk_index.pkl"))

    print(f"💾 Dataset saved to {cache_dir}")


def load_dataset(cache_dir):
    X_path = os.path.join(cache_dir, "X.npy")
    y_path = os.path.join(cache_dir, "y.npy")

    if not os.path.exists(X_path):
        return None

    X = np.load(X_path)
    y = np.load(y_path)

    feature_names = joblib.load(os.path.join(cache_dir, "feature_names.pkl"))
    scaler = joblib.load(os.path.join(cache_dir, "scaler.pkl"))
    apk_index = joblib.load(os.path.join(cache_dir, "apk_index.pkl"))

    print(f"📂 Loaded dataset from {cache_dir}")
    return X, y, feature_names, apk_index, scaler


def update_dataset(
    cache_dir, apk_dirs, labels, build_dataset_fn, max_workers=8, use_cache=True
):
    cached = load_dataset(cache_dir)

    if cached is None:
        print("No cache found → building new dataset...")
        X, y, feature_names, scaler = build_dataset_fn(
            apk_dirs=apk_dirs,
            labels=labels,
            max_workers=max_workers,
            use_cache=use_cache,
        )
        save_dataset(cache_dir, X, y, feature_names, apk_dirs, scaler, apk_index=None)
        return X, y, feature_names, scaler

    X_old, y_old, feature_names, apk_index, scaler = cached

    new_apks = []
    new_labels = []

    for p, label in zip(apk_dirs, labels):
        if hash_dir(p) not in apk_index:
            new_apks.append(p)
            new_labels.append(label)

    print(f"🆕 New APKs found: {len(new_apks)}")

    if len(new_apks) == 0:
        return X_old, y_old, feature_names, scaler

    X_new, y_new, feature_names, scaler = build_dataset_fn(
        apk_dirs=new_apks,
        labels=new_labels,
        max_workers=max_workers,
        use_cache=use_cache,
    )

    X = np.vstack([X_old, X_new])
    y = np.concatenate([y_old, y_new])

    for p in new_apks:
        apk_index[hash_dir(p)] = p

    save_dataset(
        cache_dir, X, y, feature_names, list(apk_index.values()), scaler, apk_index
    )

    print("✅ Dataset updated successfully")

    return X, y, feature_names, scaler


def counter_to_vector_with_vocab(counter, vocab):
    vec = np.zeros(len(vocab))
    for key, count in counter.items():
        if key in vocab:
            vec[vocab[key]] = count
    return vec


def build_global_vocab(all_counters, min_freq=2, max_features=2000):
    global_counter = Counter()
    for c in all_counters:
        global_counter.update(c)

    filtered = [(k, v) for k, v in global_counter.items() if v >= min_freq]
    filtered.sort(key=lambda x: -x[1])

    vocab = {k: i for i, (k, _) in enumerate(filtered[:max_features])}
    return vocab


import random

JUNK_OPS = [
    ["const/4 v0, 0x1", "add-int v0, v0, v0"],
    ["const/4 v1, 0x0", "if-eq v1, v1, :label"],
]


def inject_junk_blocks(blocks, prob=0.3):
    new_blocks = []

    for block in blocks:
        new_blocks.append(block)

        if random.random() < prob:
            junk = random.choice(JUNK_OPS)

            junk_encoded = []
            for op_line in junk:
                op = op_line.split()[0]
                cat = CATEGORY.get(op, "X")
                junk_encoded.append((cat, op, None))

            new_blocks.append(junk_encoded)

    return new_blocks


def shuffle_blocks(blocks, prob=0.2):
    if random.random() < prob:
        random.shuffle(blocks)
    return blocks


def duplicate_blocks(blocks, prob=0.2):
    new_blocks = []
    for b in blocks:
        new_blocks.append(b)
        if random.random() < prob:
            new_blocks.append(b)
    return new_blocks


def obfuscate_blocks(blocks):
    blocks = inject_junk_blocks(blocks, prob=0.1)
    return blocks


def process_single_apk(smali_dir, w2v_model, G=None, blocks=None):
    if G is None or blocks is None:
        blocks = get_blocks_cached(smali_dir)
        G = build_cfg_from_blocks(blocks)

    if len(blocks) > MAX_BLOCKS_PER_APK:
        blocks = blocks[:MAX_BLOCKS_PER_APK]

    mos = build_mos_from_blocks(blocks)
    api = extract_api_sequence(blocks)
    cfg_feat = graph_to_features_fast(G, blocks)
    emb = graph_embedding(blocks, G, w2v_model)

    return {
        "mos": mos,
        "api": api,
        "cfg": cfg_feat,
        "emb": emb,
        "blocks": None,
    }


def process_apk_cached(smali_dir, w2v_model):
    cache_path = smali_dir.rstrip("/") + "_features.pkl"

    try:
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)

            blocks = cached["blocks"]
            G = build_cfg_from_blocks(blocks)

            return {
                "mos": cached["mos"],
                "api": cached["api"],
                "cfg": graph_to_features_fast(G, blocks),
                "blocks": blocks,
                "emb": cached["emb"],
            }
    except Exception:
        pass

    blocks = get_blocks_cached(smali_dir)
    result = process_single_apk(smali_dir, w2v_model, None, blocks)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(
                {
                    "mos": result["mos"],
                    "api": result["api"],
                    "cfg": result["cfg"],
                    "blocks": blocks,
                    "emb": result["emb"],
                },
                f,
            )
    except Exception:
        pass

    return result


class SentenceIterable:
    def __init__(self, apk_blocks):
        self.apk_blocks = apk_blocks

    def __iter__(self):
        for blocks in self.apk_blocks.values():
            for block in blocks:
                if block:
                    yield [op[1] for op in block if isinstance(op, tuple)]


def build_dataset(
    apk_dirs, labels, max_workers=8, vector_size=32, use_cache=True, test_size=0.2
):
    # =========================================================
    # FIX DATA LEAKAGE: split index TRƯỚC, rồi mới fit bất cứ
    # transformer nào (W2V, vocab, scaler, freq_mask)
    # =========================================================

    apk_blocks = {}

    print("\n📊 Step 1: Collecting blocks (ONE PASS ONLY)...")

    for smali_dir in tqdm(apk_dirs, desc="Scanning"):
        if use_cache:
            blocks = get_blocks_cached(smali_dir)
        else:
            blocks = build_blocks_only(smali_dir)
        apk_blocks[smali_dir] = blocks

    total_blocks = sum(len(b) for b in apk_blocks.values())
    print(f"Total blocks collected: {total_blocks}")

    # ----------------------------------------------------------
    # FIX LEAKAGE #1: Split index TRƯỚC khi train W2V
    # ----------------------------------------------------------
    print("\n✂️  Step 2: Train/test split indices (before any fitting)...")

    train_idx, test_idx = train_test_split(
        list(range(len(apk_dirs))),
        test_size=test_size,
        stratify=labels,
        random_state=42,
    )
    train_dirs = [apk_dirs[i] for i in train_idx]
    train_labels = [labels[i] for i in train_idx]
    test_dirs = [apk_dirs[i] for i in test_idx]
    test_labels = [labels[i] for i in test_idx]

    print(f"Train: {len(train_dirs)} | Test: {len(test_dirs)}")

    # ----------------------------------------------------------
    # FIX LEAKAGE #1: Word2Vec chỉ train trên train_dirs
    # ----------------------------------------------------------
    print("\n🧠 Step 3: Training Word2Vec (TRAIN SET ONLY)...")
    model_path = "w2v_model.model"

    if os.path.exists(model_path):
        w2v_model = Word2Vec.load(model_path)
        print("📦 Loaded cached Word2Vec")
    else:
        print("🧠 Training Word2Vec on TRAIN set only...")
        train_apk_blocks = {d: apk_blocks[d] for d in train_dirs}
        sentences = SentenceIterable(train_apk_blocks)

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
        )

        w2v_model = model
        w2v_model.save(model_path)

    # ----------------------------------------------------------
    # Extract raw features (không cần vocab ở bước này)
    # ----------------------------------------------------------
    print("\n🔧 Step 4: Extracting raw features from all APKs...")

    all_indices = list(range(len(apk_dirs)))
    raw_results = [None] * len(apk_dirs)

    def worker(idx):
        smali_dir = apk_dirs[idx]
        blocks = apk_blocks[smali_dir]
        G = build_cfg_from_blocks(blocks)

        mos = build_mos_from_blocks(blocks)
        api = extract_api_sequence(blocks)
        cfg_feat = graph_to_features_fast(G, blocks)
        emb = graph_embedding(blocks, G, w2v_model)

        return idx, {"mos": mos, "api": api, "cfg": cfg_feat, "emb": emb}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, i) for i in all_indices]
        for f in tqdm(
            as_completed(futures), total=len(futures), desc="Extracting features"
        ):
            idx, data = f.result()
            raw_results[idx] = data

    # ----------------------------------------------------------
    # Augment malware CHỈNH trên train set (không đụng test)
    # ----------------------------------------------------------
    print("\n🔀 Step 5: Augmenting train set (malware only)...")

    def worker_aug(idx):
        smali_dir = apk_dirs[idx]
        blocks = apk_blocks[smali_dir]
        blocks_aug = obfuscate_blocks(blocks)
        G_aug = build_cfg_from_blocks(blocks_aug)

        mos = build_mos_from_blocks(blocks_aug)
        api = extract_api_sequence(blocks_aug)
        cfg_feat = raw_results[idx]["cfg"]  # giữ CFG gốc
        emb = graph_embedding(blocks, G_aug, w2v_model)

        return idx, {"mos": mos, "api": api, "cfg": cfg_feat, "emb": emb}

    # Chỉ augment train malware
    train_malware_idx = [i for i in train_idx if labels[i] == 1]
    aug_results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker_aug, i) for i in train_malware_idx]
        for f in tqdm(as_completed(futures), total=len(futures), desc="Augmenting"):
            idx, data = f.result()
            aug_results[idx] = data

    # Tạo danh sách train: gốc + augmented malware
    train_results = []
    train_combined_labels = []

    for i in train_idx:
        train_results.append(raw_results[i])
        train_combined_labels.append(labels[i])
        if labels[i] == 1 and i in aug_results:
            train_results.append(aug_results[i])
            train_combined_labels.append(labels[i])

    test_results = [raw_results[i] for i in test_idx]
    test_combined_labels = [labels[i] for i in test_idx]

    # ----------------------------------------------------------
    # FIX LEAKAGE #2: Build vocab CHỈNH trên train_results
    # ----------------------------------------------------------
    print("\n📚 Step 6: Building global vocabulary (TRAIN SET ONLY)...")

    train_mos = [r["mos"] for r in train_results]
    train_api = [r["api"] for r in train_results]
    train_cfg = [r["cfg"] for r in train_results]

    mos_vocab = build_global_vocab(train_mos, min_freq=3, max_features=1500)
    api_vocab = build_global_vocab(train_api, min_freq=3, max_features=500)
    cfg_vocab = build_global_vocab(train_cfg, min_freq=2, max_features=200)

    print(
        f"Vocab sizes - MOS: {len(mos_vocab)}, API: {len(api_vocab)}, CFG: {len(cfg_vocab)}"
    )

    # ----------------------------------------------------------
    # Vectorize
    # ----------------------------------------------------------
    print("\n🔢 Step 7: Building feature vectors...")

    def vectorize(results):
        X = []
        for r in results:
            mos_vec = counter_to_vector_with_vocab(r["mos"], mos_vocab)
            api_vec = counter_to_vector_with_vocab(r["api"], api_vocab)
            cfg_vec = counter_to_vector_with_vocab(r["cfg"], cfg_vocab)
            emb_vec = r["emb"]
            combined = np.concatenate([mos_vec, api_vec, cfg_vec, emb_vec])
            X.append(combined)
        return np.array(X)

    X_train_raw = vectorize(train_results)
    X_test_raw = vectorize(test_results)
    y_train = np.array(train_combined_labels)
    y_test = np.array(test_combined_labels)

    # ----------------------------------------------------------
    # FIX LEAKAGE #3: StandardScaler fit CHỈNH trên train
    # ----------------------------------------------------------
    print("\n📐 Step 8: Scaling (fit on TRAIN SET ONLY)...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)  # chỉ transform, không fit

    def format_feature_name(f):
        if isinstance(f, tuple):
            parts = []
            for item in f:
                if isinstance(item, tuple):
                    if len(item) >= 2:
                        op = item[1]
                        if len(item) >= 3 and item[2]:
                            parts.append(f"{op}:{item[2]}")
                        else:
                            parts.append(op)
                else:
                    parts.append(str(item))
            return " → ".join(parts)
        return str(f)

    feature_names = (
        [f"MOS:{format_feature_name(k)}" for k in mos_vocab.keys()]
        + [f"API:{k}" for k in api_vocab.keys()]
        + [f"CFG:{k[0]}" for k in cfg_vocab.keys()]
        + [f"EMB:{i}" for i in range(vector_size)]
    )

    print(f"\n✅ Dataset built:")
    print(f"  X_train={X_train.shape}, y_train={y_train.shape}")
    print(f"  X_test={X_test.shape},  y_test={y_test.shape}")

    # Trả về cả train và test đã tách sẵn, scaler fit-only-train
    return X_train, X_test, y_train, y_test, feature_names, scaler


# =========================
# 7. MODEL BUILDING
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


def get_dnn_importance_scores(model):
    for layer in model.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            weights = layer.get_weights()
            if weights and len(weights[0].shape) == 2:
                return np.sum(np.abs(weights[0]), axis=1)
    return None


def select_top_k_features(X_train, X_test, importance, k=3000):
    n_features = X_train.shape[1]

    if importance is None:
        importance = np.ones(n_features)
    else:
        if len(importance) > n_features:
            importance = importance[:n_features]
        elif len(importance) < n_features:
            importance = np.concatenate(
                [importance, np.zeros(n_features - len(importance))]
            )

    k = min(k, n_features)
    idx = np.argsort(importance)[-k:]

    return X_train[:, idx], X_test[:, idx], idx


def filter_infrequent_features(X_train, X_test, threshold=0.002):
    """
    FIX LEAKAGE #4: tính frequency mask CHỈ trên X_train,
    sau đó apply cùng mask lên X_test.
    """
    app_counts = np.sum(X_train > 0, axis=0)
    min_apps = max(1, int(X_train.shape[0] * threshold))
    mask = app_counts >= min_apps
    print(
        f"  filter_infrequent_features: giữ {mask.sum()}/{X_train.shape[1]} features (threshold={threshold})"
    )
    return X_train[:, mask], X_test[:, mask], mask


def auto_select_k(X_train, y_train, candidate_k=None):
    if candidate_k is None:
        candidate_k = [500, 1000, 2000, 3000]

    candidate_k = [k for k in candidate_k if k <= X_train.shape[1]]
    if not candidate_k:
        candidate_k = [X_train.shape[1]]

    print(f"\n🔍 auto_select_k: thử {candidate_k}...")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )

    rf = RandomForestClassifier(n_estimators=200)
    rf.fit(X_tr, y_tr)
    importance = rf.feature_importances_

    n_features = X_tr.shape[1]
    if importance is not None:
        if len(importance) > n_features:
            importance = importance[:n_features]
        elif len(importance) < n_features:
            importance = np.concatenate(
                [importance, np.zeros(n_features - len(importance))]
            )

    best_k = candidate_k[0]
    best_auc = 0.0

    for k in candidate_k:
        idx = np.argsort(importance)[-k:] if importance is not None else np.arange(k)

        rf_val = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
        rf_val.fit(X_tr[:, idx], y_tr)
        probs = rf_val.predict_proba(X_val[:, idx])[:, 1]
        auc = roc_auc_score(y_val, probs)

        print(f"  k={k:>5} → AUC={auc:.4f}")

        if auc > best_auc:
            best_auc = auc
            best_k = k

    print(f"  ✅ Best k = {best_k} (AUC={best_auc:.4f})")
    return best_k, best_auc


# =========================
# 8. TRAINING & EVALUATION
# =========================
from sklearn.metrics import classification_report


def evaluate_model(name, y_true, probs, threshold=0.5):
    preds = (probs > threshold).astype(int)

    acc = accuracy_score(y_true, preds)
    auc = roc_auc_score(y_true, probs)
    cm = confusion_matrix(y_true, preds)

    print(f"\n{'='*40}")
    print(f"{name}")
    print(f"{'='*40}")
    print(f"Accuracy: {acc:.4f}")
    print(f"AUC:      {auc:.4f}")
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
    if importance is None:
        print("No importance scores available.")
        return

    top_n = min(top_n, len(importance), len(features))
    idx = np.argsort(importance)[-top_n:]

    plt.figure(figsize=(10, 8))
    plt.barh(range(top_n), importance[idx], color="steelblue")

    def shorten(s, max_len=50):
        return s if len(s) <= max_len else s[:50] + "..."

    labels = [shorten(str(features[i])) for i in idx]
    plt.yticks(range(top_n), labels)
    plt.xlabel("Importance Score")
    plt.title(f"Top {top_n} Feature Importance")
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.show()


def train_and_evaluate(X_train, X_test, y_train, y_test, feature_names, scaler=None):
    """
    Nhận vào X_train/X_test đã tách sẵn (không split lại ở đây).
    Mọi fitting chỉ dùng X_train / y_train.
    """
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")
    print(f"X_train: {X_train.shape}  |  X_test: {X_test.shape}")

    # STEP 1: Lọc feature xuất hiện quá ít (fit on train only)
    print("\n🔎 Step 1: Filtering infrequent features (TRAIN SET ONLY)...")
    X_train, X_test, freq_mask = filter_infrequent_features(
        X_train, X_test, threshold=0.01
    )
    print("\n🔎 FEATURE FILTERING")
    print("=" * 40)
    print(f"Before: {len(feature_names)} features")
    feature_names = [f for f, keep in zip(feature_names, freq_mask) if keep]
    print(f"After : {X_train.shape[1]} features")

    print("\n📊 TRAIN / TEST SPLIT")
    print("=" * 40)
    print(f"Train samples: {len(y_train)}")
    print(f"Test samples : {len(y_test)}")
    print(f"Train class balance:")
    print(f"  Benign : {(y_train==0).sum()}")
    print(f"  Malware: {(y_train==1).sum()}")
    print(f"Test class balance:")
    print(f"  Benign : {(y_test==0).sum()}")
    print(f"  Malware: {(y_test==1).sum()}")

    # STEP 2: Tự động chọn k (chỉ dùng X_train / y_train)
    best_k, _ = auto_select_k(X_train, y_train, candidate_k=[500, 1000, 2000, 3000])

    # STEP 3: Feature selection bằng DNN importance (fit on X_train only)
    print(f"\n🔍 Step 3: Feature selection (k={best_k}, TRAIN ONLY)...")
    prelim_dnn = build_dnn(X_train.shape[1])
    prelim_dnn.fit(X_train, y_train, epochs=3, verbose=0, batch_size=32)
    importance = get_dnn_importance_scores(prelim_dnn)

    X_train_sel, X_test_sel, selected_idx = select_top_k_features(
        X_train, X_test, importance, k=best_k
    )
    print(f"Selected {X_train_sel.shape[1]} features")

    # STEP 4: Train models
    print("\n🚀 Step 4: Training models...")

    print("→ Training SVM...")
    svm = SVC(kernel="linear", C=0.0625, probability=True)
    svm.fit(X_train_sel, y_train)
    svm_probs = svm.predict_proba(X_test_sel)[:, 1]

    print("→ Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=300, n_jobs=-1, random_state=42)
    rf.fit(X_train_sel, y_train)
    rf_probs = rf.predict_proba(X_test_sel)[:, 1]

    print("→ Training DNN...")
    from sklearn.utils.class_weight import compute_class_weight

    class_weights = compute_class_weight(
        class_weight="balanced", classes=np.unique(y_train), y=y_train
    )
    class_weight_dict = {i: w for i, w in enumerate(class_weights)}

    dnn = build_dnn(X_train_sel.shape[1])
    dnn.fit(
        X_train_sel,
        y_train,
        epochs=10,
        batch_size=32,
        validation_split=0.1,
        class_weight=class_weight_dict,
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

    selected_features = [feature_names[i] for i in selected_idx]

    # Feature Importance
    importance = get_dnn_importance_scores(dnn)
    final_importance = importance[: len(selected_idx)]
    final_importance = final_importance / np.sum(final_importance)

    from collections import defaultdict

    group_importance = defaultdict(float)

    for i, feat in enumerate(selected_features):
        if feat.startswith("API"):
            group_importance["API"] += final_importance[i]
        elif feat.startswith("MOS"):
            group_importance["MOS"] += final_importance[i]
        elif feat.startswith("CFG"):
            group_importance["CFG"] += final_importance[i]
        elif feat.startswith("EMB"):
            group_importance["EMB"] += final_importance[i]

    print("\n📊 Feature Group Importance:")
    for k, v in group_importance.items():
        print(f"{k}: {v:.4f}")

    symbolic_idx = []
    embedding_idx = []

    for i, f in zip(selected_idx, selected_features):
        if f.startswith("MOS") or f.startswith("API") or f.startswith("CFG"):
            symbolic_idx.append(i)
        elif f.startswith("EMB"):
            embedding_idx.append(i)

    importance = importance[: len(selected_idx)]

    idx_map = {feat_idx: pos for pos, feat_idx in enumerate(selected_idx)}

    sym_features = [feature_names[i] for i in symbolic_idx]
    sym_importance = [importance[idx_map[i]] for i in symbolic_idx]

    emb_features = [feature_names[i] for i in embedding_idx]
    emb_importance = [importance[idx_map[i]] for i in embedding_idx]

    plot_feature_importance(
        np.array(sym_importance),
        sym_features,
        top_n=20,
        save_path="figs/feature_symbolic.png",
    )
    plot_feature_importance(
        np.array(emb_importance),
        emb_features,
        top_n=20,
        save_path="figs/feature_embedding.png",
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
    print(f"Total samples : {total}")
    print(f"Benign        : {benign} ({benign/total:.2%})")
    print(f"Malware       : {malware} ({malware/total:.2%})")

    if len(apk_dirs) == 0:
        print("No APKs found. Please check the directory structure.")
        exit(1)

    # Step 3: Build dataset (trả về train/test đã tách sẵn, không leak)
    X_train, X_test, y_train, y_test, feature_names, scaler = build_dataset(
        apk_dirs=apk_dirs,
        labels=labels,
        max_workers=8,
        use_cache=True,
    )

    print("\n📦 FEATURE DATASET")
    print("=" * 40)
    print(f"X_train : {X_train.shape}")
    print(f"X_test  : {X_test.shape}")
    print(f"#Features: {X_train.shape[1]}")

    # Step 4: Train and evaluate
    output = train_and_evaluate(
        X_train, X_test, y_train, y_test, feature_names, scaler=scaler
    )

    print("\n✅ Training complete!")
