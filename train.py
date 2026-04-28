# =========================
# MOSDroid FINAL (CFG + FULL OPCODE COVERAGE) - COMPLETE
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


W2V_CACHE_PATH = f"w2v_model.model"


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
        except:
            pass

    blocks = get_blocks_cached(smali_dir)
    G = build_cfg_from_blocks(blocks)
    result = process_single_apk(smali_dir, w2v_model, G, blocks)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(result, f)
    except:
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
    blocks, current = [], []
    try:
        for line in open(file_path, encoding="utf-8", errors="ignore"):
            line = normalize_line(line.strip())
            if not line or line.startswith("."):
                continue
            if line.startswith(":"):
                if current:
                    blocks.append(current)
                    current = []
                continue
            token = line.split()[0]
            if token in CATEGORY:
                current.append(CATEGORY[token])
            if "goto" in token or "if-" in token or "return" in token:
                if current:
                    blocks.append(current)
                    current = []
        if current:
            blocks.append(current)
    except Exception:
        pass
    return blocks


def build_cfg_from_blocks(blocks):
    G = nx.DiGraph()

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)
        if i + 1 < len(blocks):
            G.add_edge(i, i + 1)

    return G


def build_cfg_from_file(file_path):
    """Build CFG từ một file smali."""
    G = nx.DiGraph()
    blocks = []
    current = []

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return G, blocks

    for line in lines:
        line = normalize_line(line.strip())

        if not line or line.startswith("."):
            continue

        if line.startswith(":"):
            if current:
                blocks.append(current)
                current = []
            continue

        parts = line.split()
        if not parts:
            continue

        token = parts[0]
        if token in CATEGORY:
            current.append(CATEGORY[token])

        if "goto" in token or "if-" in token or "return" in token:
            if current:
                blocks.append(current)
                current = []

    if current:
        blocks.append(current)

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)
        if i + 1 < len(blocks):
            G.add_edge(i, i + 1)

    return G, blocks


def get_blocks_cached(smali_dir):
    cache_path = smali_dir.rstrip("/") + "_blocks.pkl"

    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                return pickle.load(f)
        except:
            pass  # nếu cache lỗi thì fallback

    # nếu chưa có cache → parse
    blocks = build_blocks_only(smali_dir)

    try:
        with open(cache_path, "wb") as f:
            pickle.dump(blocks, f)
    except:
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
    return blocks


def build_cfg_from_dir_fast(smali_dir, max_workers=8):
    files = [
        os.path.join(root, f)
        for root, _, fs in os.walk(smali_dir)
        for f in fs
        if f.endswith(".smali")
    ]

    def parse_single(f):
        return build_cfg_from_file(f)[1]  # chỉ cần list block

    blocks = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for res in ex.map(parse_single, files):
            blocks.extend(res)
    return blocks


def build_cfg_from_dir(smali_dir):
    """Build CFG từ toàn bộ thư mục smali."""
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
        for op in block:
            if op == "V":
                api_seq["API_CALL"] += 1
    return api_seq


# def graph_to_features(G):
#     features = Counter()

#     for _, data in G.nodes(data=True):
#         block = data.get("features", [])
#         if block:
#             features[tuple(block)] += 1

#     features[("EDGE_COUNT",)] = G.number_of_edges()
#     features[("NODE_COUNT",)] = G.number_of_nodes()

#     return features


def graph_to_features_fast(blocks):
    features = Counter()

    for block in blocks:
        if block:
            features[tuple(block)] += 1

    features[("EDGE_COUNT",)] = len(blocks) - 1
    features[("NODE_COUNT",)] = len(blocks)

    return features


# =========================
# 5. EMBEDDING
# =========================
from gensim.models import Word2Vec
from gensim.models.callbacks import CallbackAny2Vec
import os


class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"🧠 Word2Vec epoch {self.epoch} done")


def train_opcode_embedding(all_blocks, vector_size=32, model_path=None):
    """
    Optimized Word2Vec:
    - streaming corpus (không build list sentences)
    - skip-gram + negative sampling tuned
    - subsampling opcode phổ biến
    - optional cache model
    """
    # ===== CACHE =====
    if model_path and os.path.exists(model_path):
        print("📦 Loading cached Word2Vec...")
        return Word2Vec.load(model_path)

    # ===== STREAMING CORPUS =====
    class SentenceIterable:
        def __init__(self, blocks):
            self.blocks = blocks

        def __iter__(self):
            for block in self.blocks:
                if block:
                    yield [str(op) for op in block]

    # ===== MODEL =====
    model = Word2Vec(
        vector_size=vector_size,
        window=5,
        min_count=2,
        sg=1,  # skip-gram (giữ semantic opcode tốt hơn CBOW)
        negative=15,  # tăng stability embedding malware patterns
        sample=1e-4,  # subsampling opcode phổ biến (move, const,...)
        workers=os.cpu_count(),
        epochs=1,
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
        key = str(op)
        if key in w2v_model.wv:
            vectors.append(w2v_model.wv[key])

    if not vectors:
        return np.zeros(vector_size)

    return np.mean(vectors, axis=0)


# def graph_embedding(G, op_cache, vector_size=32):
#     if G.number_of_nodes() == 0:
#         return np.zeros(vector_size)

#     vecs = []

#     for _, data in G.nodes(data=True):
#         for op in data.get("features", []):
#             if op in op_cache:
#                 vecs.append(op_cache[op])

#     if not vecs:
#         return np.zeros(vector_size)

#     return np.mean(vecs, axis=0)


def graph_embedding(blocks, w2v_model, vector_size=32):
    if w2v_model is None:
        return np.zeros(vector_size)

    vecs = []
    wv = w2v_model.wv  # cache

    import random

    sampled_blocks = blocks if len(blocks) <= 5000 else random.sample(blocks, 5000)

    for block in sampled_blocks:
        for op in block:
            key = str(op)
            if key in wv:
                vecs.append(wv[key])

    if not vecs:
        return np.zeros(vector_size)

    return np.mean(vecs, axis=0)


# =========================
# 6. DATASET BUILDING
# =========================
def hash_dir(path):
    """Tạo ID duy nhất cho mỗi APK (smali folder)."""
    return hashlib.md5(path.encode()).hexdigest()


def save_dataset(cache_dir, X, y, feature_names, apk_dirs):
    os.makedirs(cache_dir, exist_ok=True)

    np.save(os.path.join(cache_dir, "X.npy"), X)
    np.save(os.path.join(cache_dir, "y.npy"), y)

    joblib.dump(feature_names, os.path.join(cache_dir, "feature_names.pkl"))
    # joblib.dump(scaler, os.path.join(cache_dir, "scaler.pkl"))

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
    # scaler = joblib.load(os.path.join(cache_dir, "scaler.pkl"))
    apk_index = joblib.load(os.path.join(cache_dir, "apk_index.pkl"))

    print(f"📂 Loaded dataset from {cache_dir}")
    return X, y, feature_names, apk_index


def update_dataset(
    cache_dir, apk_dirs, labels, build_dataset_fn, max_workers=8, use_cache=True
):
    """
    - Load dataset cũ
    - Chỉ process APK mới
    - Merge lại
    """

    cached = load_dataset(cache_dir)

    if cached is None:
        print("No cache found → building new dataset...")
        X, y, feature_names = build_dataset_fn(
            apk_dirs=apk_dirs,
            labels=labels,
            max_workers=max_workers,
            use_cache=use_cache,
        )
        save_dataset(cache_dir, X, y, feature_names, apk_dirs)
        return X, y, feature_names

    X_old, y_old, feature_names, apk_index = cached

    # APK mới
    new_apks = []
    new_labels = []

    for p, label in zip(apk_dirs, labels):
        if hash_dir(p) not in apk_index:
            new_apks.append(p)
            new_labels.append(label)

    print(f"🆕 New APKs found: {len(new_apks)}")

    if len(new_apks) == 0:
        return X_old, y_old, feature_names

    # build dataset cho APK mới
    X_new, y_new, feature_names = build_dataset_fn(
        apk_dirs=new_apks,
        labels=new_labels,
        max_workers=max_workers,
        use_cache=use_cache,
    )

    # merge
    X = np.vstack([X_old, X_new])
    y = np.concatenate([y_old, y_new])

    # update index
    for p in new_apks:
        apk_index[hash_dir(p)] = p

    # save lại
    save_dataset(cache_dir, X, y, feature_names, list(apk_index.values()))

    print("✅ Dataset updated successfully")

    return X, y, feature_names


def counter_to_vector_with_vocab(counter, vocab, default_size=2000):
    """Convert Counter thành vector dựa trên vocabulary cố định."""
    vec = np.zeros(len(vocab))
    for key, count in counter.items():
        if key in vocab:
            vec[vocab[key]] = count
    return vec


def build_global_vocab(all_counters, min_freq=2, max_features=2000):
    """Build vocabulary từ tất cả counters."""
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
            junk_encoded = [CATEGORY.get(op.split()[0], "X") for op in junk]
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
            new_blocks.append(b)  # duplicate
    return new_blocks


def obfuscate_blocks(blocks):
    blocks = inject_junk_blocks(blocks, prob=0.3)
    blocks = duplicate_blocks(blocks, prob=0.2)
    blocks = shuffle_blocks(blocks, prob=0.1)
    return blocks


def process_single_apk(smali_dir, w2v_model, G=None, blocks=None):
    if G is None or blocks is None:
        blocks = get_blocks_cached(smali_dir)
        G = build_cfg_from_blocks(blocks)

    # blocks = obfuscate_blocks(blocks)
    if len(blocks) > 20000:
        blocks = blocks[:20000]

    mos = build_mos_from_blocks(blocks)
    api = extract_api_sequence(blocks)
    cfg_feat = graph_to_features_fast(blocks)
    emb = graph_embedding(blocks, w2v_model)

    return {
        "mos": mos,
        "api": api,
        "cfg": cfg_feat,
        "emb": emb,
        "blocks": blocks,
    }


def process_apk_cached(smali_dir, w2v_model):
    cache_path = smali_dir.rstrip("/") + "_features.pkl"

    try:
        if os.path.exists(cache_path):
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)

            blocks = cached["blocks"]

            return {
                "mos": cached["mos"],
                "api": cached["api"],
                "cfg": cached["cfg"],
                "blocks": blocks,
                "emb": cached["emb"],
            }

    except Exception:
        pass

    # rebuild full
    blocks = get_blocks_cached(smali_dir)
    # G = build_cfg_from_blocks(blocks)

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


def build_dataset(
    apk_dirs, labels, max_workers=8, vector_size=32, use_cache=True, test_size=0.2
):
    """
    Build dataset với proper vocabulary handling.
    use_cache=True sẽ dùng process_apk_cached thay vì process_single_apk.
    """
    apk_blocks = {}
    all_blocks = []

    print("\n📊 Step 1: Collecting blocks (ONE PASS ONLY)...")

    for smali_dir in tqdm(apk_dirs, desc="Scanning"):
        if use_cache:
            blocks = get_blocks_cached(smali_dir)
        else:
            blocks = build_blocks_only(smali_dir)
        apk_blocks[smali_dir] = blocks
        all_blocks.extend(blocks)

    print(f"Total blocks collected: {len(all_blocks)}")

    print("\n🧠 Step 2: Training Word2Vec embedding...")
    import hashlib

    def hash_blocks(all_blocks):
        return hashlib.md5(
            " ".join([" ".join(map(str, b)) for b in all_blocks]).encode()
        ).hexdigest()

    # def get_w2v_cache_path(all_blocks, vector_size):
    #         h = hashlib.md5(
    #             (" ".join([" ".join(map(str, b)) for b in all_blocks])).encode()
    #         ).hexdigest()

    #         return f"w2v_{vector_size}_{h}.model"

    #     corpus_hash = hash_blocks(all_blocks)
    #     model_path = model_path = get_w2v_cache_path(all_blocks, vector_size)

    model_path = f"w2v_model.model"

    if os.path.exists(model_path):
        w2v_model = Word2Vec.load(model_path)
        print("📦 Loaded cached Word2Vec")
    else:
        print("🧠 Training Word2Vec...")
        w2v_model = train_opcode_embedding(
            all_blocks, vector_size, model_path=model_path
        )
        w2v_model.save(model_path)

    print("\n🔧 Step 3: Extracting features from all APKs...")

    results = []
    aug_results = []

    def worker(idx, smali_dir):
        data = process_apk_cached(smali_dir, w2v_model)

        # 🔥 CHỈ augment khi build dataset
        blocks_aug = obfuscate_blocks(data["blocks"])

        mos = build_mos_from_blocks(blocks_aug)
        api = extract_api_sequence(blocks_aug)
        cfg = graph_to_features_fast(blocks_aug)
        emb = graph_embedding(blocks_aug, w2v_model)

        data_aug = {
            "mos": mos,
            "api": api,
            "cfg": cfg,
            "emb": emb,
        }

        return idx, data, data_aug

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(worker, i, d) for i, d in enumerate(apk_dirs)]
        for f in tqdm(as_completed(futures), total=len(futures), desc="Processing"):
            idx, original, augmented = f.result()
            results.append(original)
            aug_results.append(augmented)

    results = results + aug_results
    labels = labels + labels

    print("\n📚 Step 4: Building global vocabulary...")

    all_mos = [r["mos"] for r in results]
    all_api = [r["api"] for r in results]
    all_cfg = [r["cfg"] for r in results]

    mos_vocab = build_global_vocab(all_mos, min_freq=2, max_features=1500)
    api_vocab = build_global_vocab(all_api, min_freq=1, max_features=200)
    cfg_vocab = build_global_vocab(all_cfg, min_freq=1, max_features=300)

    print(
        f"Vocab sizes - MOS: {len(mos_vocab)}, API: {len(api_vocab)}, CFG: {len(cfg_vocab)}"
    )

    print("\n🔢 Step 5: Building feature vectors...")

    X = []
    for r in results:
        mos_vec = counter_to_vector_with_vocab(r["mos"], mos_vocab)
        api_vec = counter_to_vector_with_vocab(r["api"], api_vocab)
        cfg_vec = counter_to_vector_with_vocab(r["cfg"], cfg_vocab)
        emb_vec = r["emb"]

        combined = np.concatenate([mos_vec, api_vec, cfg_vec, emb_vec])
        X.append(combined)

    X = np.array(X)
    y = np.array(labels)

    feature_names = (
        list(mos_vocab.keys())
        + list(api_vocab.keys())
        + list(cfg_vocab.keys())
        + [f"emb_{i}" for i in range(vector_size)]
    )

    print(f"\n✅ Dataset built: X={X.shape}, y={y.shape}")

    return X, y, feature_names


# =========================
# 7. MODEL BUILDING
# =========================
def build_dnn(input_dim):
    model = tf.keras.Sequential(
        [
            tf.keras.Input(shape=(input_dim,)),
            tf.keras.layers.BatchNormalization(),  # 🔥 ADD THIS FIRST
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
        optimizer=tf.keras.optimizers.Adam(learning_rate=5e-4),  # giảm LR
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def get_dnn_importance_scores(model):
    """
    Get feature importance từ first Dense layer weights.
    Tìm layer Dense đầu tiên có weight matrix 2D để đảm bảo đúng layer.
    """
    for layer in model.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            weights = layer.get_weights()
            if weights and len(weights[0].shape) == 2:
                return np.sum(np.abs(weights[0]), axis=1)
    return None


def select_top_k_features(X_train, X_test, importance, k=3000):
    """Select top k features based on importance scores."""
    if importance is None:
        importance = np.ones(X_train.shape[1])

    importance = importance[: X_train.shape[1]]  # FIX mismatch safety

    k = min(k, X_train.shape[1])
    idx = np.argsort(importance)[-k:]

    return X_train[:, idx], X_test[:, idx], idx


# ✅ BỔ SUNG: Lọc feature xuất hiện quá ít trong dataset
def filter_infrequent_features(X, threshold=0.01):
    """
    Loại bỏ các feature xuất hiện trong ít hơn `threshold * n_samples` APK.
    Giúp giảm noise và overfitting từ các feature rất hiếm.

    Args:
        X: feature matrix (n_samples, n_features)
        threshold: tỉ lệ tối thiểu số APK phải có feature (mặc định 1%)
    Returns:
        X_filtered: ma trận đã lọc
        mask: boolean mask các feature được giữ lại
    """
    app_counts = np.sum(X > 0, axis=0)  # số APK chứa mỗi feature
    min_apps = max(1, int(X.shape[0] * threshold))
    mask = app_counts >= min_apps
    print(
        f"  filter_infrequent_features: giữ {mask.sum()}/{X.shape[1]} features (threshold={threshold})"
    )
    return X[:, mask], mask


# ✅ BỔ SUNG: Tự động chọn k tối ưu cho feature selection
def auto_select_k(X_train, y_train, candidate_k=None):
    """
    Thử các giá trị k khác nhau, dùng RF để ước lượng nhanh AUC trên train set,
    trả về k cho AUC cao nhất.

    Args:
        X_train: feature matrix tập train
        y_train: nhãn tập train
        candidate_k: danh sách k cần thử (mặc định [500, 1000, 2000, 3000])
    Returns:
        best_k (int), best_auc (float)
    """
    if candidate_k is None:
        candidate_k = [500, 1000, 2000, 3000]

    # Giới hạn k không vượt quá số feature thực tế
    candidate_k = [k for k in candidate_k if k <= X_train.shape[1]]
    if not candidate_k:
        candidate_k = [X_train.shape[1]]

    print(f"\n🔍 auto_select_k: thử {candidate_k}...")

    # Train DNN nhanh 1 lần để lấy importance
    prelim = build_dnn(X_train.shape[1])
    prelim.fit(
        X_train, y_train, epochs=10, batch_size=32, validation_split=0.2, verbose=0
    )
    importance = get_dnn_importance_scores(prelim)

    best_k = candidate_k[0]
    best_auc = 0.0

    for k in candidate_k:
        idx = np.argsort(importance)[-k:] if importance is not None else np.arange(k)
        X_k = X_train[:, idx]

        X_tr, X_val, y_tr, y_val = train_test_split(
            X_train, y_train, test_size=0.2, stratify=y_train
        )

        rf = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
        rf.fit(X_tr[:, idx], y_tr)
        probs = rf.predict_proba(X_val[:, idx])[:, 1]
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

    # 🔥 THÊM DÒNG NÀY
    print("\nClassification Report:")
    print(classification_report(y_true, preds))


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

    labels = [str(features[i])[:40] for i in idx]
    plt.yticks(range(top_n), labels)
    plt.xlabel("Importance Score")
    plt.title(f"Top {top_n} Feature Importance")
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.show()


def train_and_evaluate(X, y, feature_names, test_size=0.2):
    """
    Pipeline đầy đủ:
      1. filter_infrequent_features  ← ✅ bổ sung
      2. train/test split
      3. auto_select_k               ← ✅ bổ sung
      4. select_top_k_features
      5. Train SVM / RF / DNN
      6. Evaluate + plot
    """
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")
    print(f"Dataset shape: {X.shape}")

    # ✅ STEP 1: Lọc feature xuất hiện quá ít
    print("\n🔎 Step 1: Filtering infrequent features...")
    X, freq_mask = filter_infrequent_features(X, threshold=0.01)
    print("\n🔎 FEATURE FILTERING")
    print("=" * 40)
    print(f"Before: {len(feature_names)} features")
    # Cập nhật feature_names theo mask
    feature_names = [f for f, keep in zip(feature_names, freq_mask) if keep]
    print(f"After : {X.shape[1]} features")

    # STEP 2: Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=42
    )
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
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

    # ✅ STEP 3: Tự động chọn k
    best_k, _ = auto_select_k(X_train, y_train, candidate_k=[500, 1000, 2000, 3000])

    # STEP 4: Feature selection dùng DNN importance + best_k
    print(f"\n🔍 Step 4: Feature selection (k={best_k})...")
    prelim_dnn = build_dnn(X_train.shape[1])
    prelim_dnn.fit(X_train, y_train, epochs=3, verbose=0, batch_size=32)
    importance = get_dnn_importance_scores(prelim_dnn)

    X_train_sel, X_test_sel, selected_idx = select_top_k_features(
        X_train, X_test, importance, k=best_k
    )
    print(f"Selected {X_train_sel.shape[1]} features")

    # STEP 5: Train models
    print("\n🚀 Step 5: Training models...")

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
        class_weight=class_weight_dict,  # 🔥 ADD THIS
        verbose=1,
    )
    dnn_probs = dnn.predict(X_test_sel, verbose=0).flatten()

    # STEP 6: Evaluate
    print("\n📊 EVALUATION RESULTS")
    results = {
        "SVM": evaluate_model("SVM", y_test, svm_probs),
        "RF": evaluate_model("Random Forest", y_test, rf_probs),
        "DNN": evaluate_model("DNN", y_test, dnn_probs),
    }

    # Plot
    plot_roc(y_test, {"SVM": svm_probs, "RF": rf_probs, "DNN": dnn_probs})

    selected_features = [
        feature_names[i] for i in selected_idx if i < len(feature_names)
    ]
    dnn_importance = get_dnn_importance_scores(dnn)
    plot_feature_importance(dnn_importance, selected_features, top_n=20)

    return {
        "models": {"svm": svm, "rf": rf, "dnn": dnn},
        "results": results,
        "selected_idx": selected_idx,
    }


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Step 1: Decode APKs (bỏ comment nếu cần)
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

    # Step 3: Build dataset (use_cache=True để tận dụng pkl cache)
    X, y, feature_names = update_dataset(
        cache_dir="dataset_cache",
        apk_dirs=apk_dirs,
        labels=labels,
        build_dataset_fn=build_dataset,
        max_workers=8,
        use_cache=True,
    )

    print("\n📦 FEATURE DATASET")
    print("=" * 40)
    print(f"Feature shape : {X.shape}")
    print(f"#Features     : {X.shape[1]}")
    print(f"#Samples      : {X.shape[0]}")

    # Step 4: Train and evaluate
    output = train_and_evaluate(X, y, feature_names)

    print("\n✅ Training complete!")
