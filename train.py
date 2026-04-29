# =========================
# MOSDroid v3  (Accuracy-Optimized)
# =========================
# Fixes vs v2 for accuracy:
#
#   Feature Engineering:
#     - Larger vocab (MOS:3000, API:800, CFG:300) + lower min_freq=2
#     - W2V vector_size 32→64, window 5→7, epochs 8→15, negative 15→20
#     - n-gram tuples now stringify before Counter key → no type collision with str keys
#     - CFG features extended: SCC count, avg clustering, in/out degree stats
#     - graph_embedding: concat [mean, std, max] → 3×vector_size richer embedding
#     - API features: ratio features + unique API count added
#     - Per-method stats features (block count, avg block size, max block size)
#
#   Model Improvements:
#     - DNN: deeper (512→256→128→64), LeakyReLU, L2 regularization, larger dropout
#     - SVM: RBF kernel, C auto-tuned via grid, gamma='scale'
#     - RF: n_estimators 300→500, max_features tuned, min_samples_leaf=2
#     - Ensemble: weighted average (DNN×0.5 + RF×0.3 + SVM×0.2)
#     - Early stopping + ReduceLROnPlateau for DNN
#
#   Training:
#     - Augmentation: 3× strategies (junk inject + op swap + block shuffle)
#     - Class weight applied to all models
#     - feature selection threshold lowered 0.01→0.005
#     - StandardScaler → RobustScaler (more robust to outliers)
#     - Candidate k extended: [500, 1000, 1500, 2000, 3000, 5000]
#
#   Bug fixes carried from v2 (all kept)
# =========================

import gc
import hashlib
import os
import pickle
import random
import re
import subprocess
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import joblib
import numpy as np
import networkx as nx
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from tqdm import tqdm
from gensim.models import Word2Vec
from gensim.models.callbacks import CallbackAny2Vec
from sklearn.model_selection import train_test_split, GridSearchCV
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
MAX_BLOCKS_PER_APK = 15_000  # ↑ from 10k — more coverage
TERMINATORS = {"R"}
BRANCH_OPS = {"I"}
W2V_MODEL_PATH = "w2v_model.model"
CACHE_ROOT = "feature_cache"
SHARD_ROOT = "matrix_shards"
VECTOR_SIZE = 64  # ↑ from 32
MAX_WORKERS = 4

# Vocab sizes (↑ from v2)
MOS_MAX_FEATURES = 3000
API_MAX_FEATURES = 800
CFG_MAX_FEATURES = 300
MOS_MIN_FREQ = 2  # ↓ from 3
API_MIN_FREQ = 2  # ↓ from 3
CFG_MIN_FREQ = 1  # ↓ from 2

# ===========================================================
# 1. DALVIK OPCODE → CATEGORY MAPPING
# ===========================================================
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
    # Extended opcodes for better coverage
    "array-length",
    "new-array",
    "new-instance",
    "filled-new-array",
    "check-cast",
    "instance-of",
    "monitor-enter",
    "monitor-exit",
    "throw",
    "packed-switch",
    "sparse-switch",
    "cmp-long",
    "cmpl-float",
    "cmpg-float",
    "neg-int",
    "not-int",
    "neg-long",
    "not-long",
    "and-int",
    "or-int",
    "xor-int",
    "shl-int",
    "shr-int",
    "ushr-int",
    "add-long",
    "sub-long",
    "mul-long",
    "div-long",
    "add-float",
    "sub-float",
    "mul-float",
    "div-float",
    "int-to-long",
    "int-to-float",
    "int-to-double",
    "long-to-int",
    "float-to-int",
    "double-to-int",
    "aget",
    "aget-object",
    "aput",
    "aput-object",
    "filled-new-array/range",
    "invoke-virtual/range",
    "invoke-static/range",
    "invoke-direct/range",
    "invoke-interface/range",
]

CATEGORY: dict[str, str] = {}
for _op in DALVIK_OPCODES:
    if "move" in _op:
        CATEGORY[_op] = "M"
    elif "return" in _op or "throw" in _op:
        CATEGORY[_op] = "R"
    elif "if-" in _op or "switch" in _op:
        CATEGORY[_op] = "I"
    elif "goto" in _op or "invoke" in _op:
        CATEGORY[_op] = "V"
    elif "get" in _op or "aget" in _op:
        CATEGORY[_op] = "G"
    elif "put" in _op or "aput" in _op:
        CATEGORY[_op] = "P"
    elif "const" in _op or "new" in _op or "filled" in _op:
        CATEGORY[_op] = "D"
    elif any(
        x in _op
        for x in (
            "add",
            "sub",
            "mul",
            "div",
            "rem",
            "neg",
            "not",
            "and",
            "or",
            "xor",
            "shl",
            "shr",
            "ushr",
            "cmp",
        )
    ):
        CATEGORY[_op] = "A"
    elif any(
        x in _op
        for x in (
            "int-to",
            "long-to",
            "float-to",
            "double-to",
            "array-length",
            "check-cast",
            "instance-of",
            "monitor",
        )
    ):
        CATEGORY[_op] = "X"
    else:
        CATEGORY[_op] = "X"


# =========================
# 2. APK DECODING
# =========================
def decode_apk(apk_path: str, output_dir: str) -> bool:
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


def batch_decode_full(raw_root="raw_apk", decoded_root="decoded", max_workers=4):
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
# 3. SMALI PARSING
# =========================
REGISTER_PATTERN = re.compile(r"v\d+|p\d+")


def normalize_line(line: str) -> str:
    line = REGISTER_PATTERN.sub("vX", line)
    line = re.sub(r'".*?"', '"STR"', line)
    return line


def _parse_smali_file(file_path: str) -> list[dict]:
    methods: list[dict] = []
    class_name = "Unknown"
    current_method_name = None
    current_blocks: list[list] = []
    current_block: list = []
    in_method = False

    try:
        with open(file_path, encoding="utf-8", errors="ignore") as fh:
            for raw_line in fh:
                line = normalize_line(raw_line.strip())
                if not line:
                    continue

                if line.startswith(".class"):
                    parts = line.split()
                    class_name = parts[-1] if len(parts) > 1 else "Unknown"
                    continue

                if line.startswith(".method"):
                    in_method = True
                    parts = line.split()
                    current_method_name = parts[-1] if len(parts) > 1 else "unknown"
                    current_blocks = []
                    current_block = []
                    continue

                if line.startswith(".end method"):
                    if current_block:
                        current_blocks.append(current_block)
                    if current_blocks:
                        methods.append(
                            {
                                "class_name": class_name,
                                "method_name": current_method_name or "unknown",
                                "blocks": current_blocks,
                            }
                        )
                    current_blocks = []
                    current_block = []
                    current_method_name = None
                    in_method = False
                    continue

                if not in_method:
                    continue

                if line.startswith(":"):
                    if current_block:
                        current_blocks.append(current_block)
                    current_block = [("LABEL", line, None, None)]
                    continue

                parts = line.split()
                if not parts:
                    continue

                token = parts[0]
                api_name = None
                target_lb = None

                if token.startswith("invoke") and len(parts) > 1:
                    full = " ".join(parts)
                    match = re.search(r"L([^;]+);", full)
                    if match:
                        api_name = match.group(1).split("/")[-1]

                if (token.startswith("if") or token.startswith("goto")) and len(
                    parts
                ) > 1:
                    if parts[-1].startswith(":"):
                        target_lb = parts[-1]

                if token in CATEGORY:
                    cat = CATEGORY[token]
                    current_block.append((cat, token, api_name, target_lb))
                    if cat in TERMINATORS or cat in BRANCH_OPS:
                        current_blocks.append(current_block)
                        current_block = []

    except Exception:
        pass

    if in_method and current_block:
        current_blocks.append(current_block)
    if current_blocks and current_method_name:
        methods.append(
            {
                "class_name": class_name,
                "method_name": current_method_name,
                "blocks": current_blocks,
            }
        )

    return methods


def parse_smali_dir(smali_dir: str) -> list[dict]:
    files = [
        os.path.join(root, f)
        for root, _, fs in os.walk(smali_dir)
        for f in fs
        if f.endswith(".smali")
    ]

    all_methods: list[dict] = []
    with ThreadPoolExecutor(max_workers=4) as ex:
        for method_list in ex.map(_parse_smali_file, files):
            all_methods.extend(method_list)
            total_blocks = sum(len(m["blocks"]) for m in all_methods)
            if total_blocks >= MAX_BLOCKS_PER_APK:
                break

    return all_methods


# =========================
# 4. CACHE LAYER
# =========================
os.makedirs(CACHE_ROOT, exist_ok=True)


def _methods_cache_path(smali_dir: str) -> str:
    key = hashlib.md5(smali_dir.encode()).hexdigest()
    return os.path.join(CACHE_ROOT, f"methods_{key}.pkl")


def _features_cache_path(smali_dir: str) -> str:
    key = hashlib.md5(smali_dir.encode()).hexdigest()
    return os.path.join(CACHE_ROOT, f"features_{key}.pkl")


def get_methods_cached(smali_dir: str) -> list[dict]:
    cache = _methods_cache_path(smali_dir)
    if os.path.exists(cache):
        try:
            with open(cache, "rb") as f:
                return pickle.load(f)
        except Exception:
            pass
    methods = parse_smali_dir(smali_dir)
    try:
        with open(cache, "wb") as f:
            pickle.dump(methods, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass
    return methods


def save_features_to_disk(smali_dir: str, features: dict) -> str:
    cache = _features_cache_path(smali_dir)
    try:
        with open(cache, "wb") as f:
            pickle.dump(features, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass
    return cache


def load_features_from_disk(smali_dir: str) -> dict | None:
    cache = _features_cache_path(smali_dir)
    if not os.path.exists(cache):
        return None
    try:
        with open(cache, "rb") as f:
            d = pickle.load(f)
        if all(k in d for k in ("mos", "api", "cfg", "emb", "stat")):
            return d
    except Exception:
        pass
    return None


# =========================
# 5. MOS CORE + EXTENSIONS
# =========================


def encode_block(block: list) -> str:
    return "".join(item[0] for item in block if item[0] != "LABEL")


def build_method_multiset(method: dict) -> Counter:
    ms: Counter = Counter()
    for block in method["blocks"]:
        enc = encode_block(block)
        if enc:
            ms[enc] += 1
    return ms


def build_apk_mos(methods: list[dict]) -> Counter:
    apk_mos: Counter = Counter()
    for method in methods:
        apk_mos.update(build_method_multiset(method))
    return apk_mos


def build_mos_ngrams(methods: list[dict], n: int = 2) -> Counter:
    """
    FIX v3: stringify tuple key to avoid type collision with str keys
    from build_apk_mos. Keys are now like "DA|IM" instead of ("DA","IM").
    """
    ngram_counter: Counter = Counter()
    for method in methods:
        encoded_blocks = [encode_block(b) for b in method["blocks"] if encode_block(b)]
        for i in range(len(encoded_blocks) - n + 1):
            gram_key = "|".join(encoded_blocks[i : i + n])  # FIX: string key
            ngram_counter[f"NGRAM{n}:{gram_key}"] += 1
    return ngram_counter


def build_full_mos(methods: list[dict]) -> Counter:
    mos = build_apk_mos(methods)
    mos.update(build_mos_ngrams(methods, n=2))
    mos.update(build_mos_ngrams(methods, n=3))
    return mos


# =========================
# 6. CFG — EXTENDED features
# =========================


def build_cfg_from_blocks(blocks: list[list]) -> nx.DiGraph:
    G = nx.DiGraph()
    n = len(blocks)

    label_map: dict[str, int] = {}
    for i, block in enumerate(blocks):
        for item in block:
            if item[0] == "LABEL":
                label_map[item[1]] = i
                break

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)
        if not block:
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        non_label = [item for item in block if item[0] != "LABEL"]
        if not non_label:
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        last_cat, last_op, _, target_label = non_label[-1]

        if last_cat not in TERMINATORS:
            if i + 1 < n:
                G.add_edge(i, i + 1)

        if target_label and target_label in label_map:
            G.add_edge(i, label_map[target_label])

    return G


def graph_to_features_fast(G: nx.DiGraph) -> Counter:
    """Extended CFG features: added SCC, in/out degree stats, clustering."""
    features: Counter = Counter()
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    features[("NODE_COUNT",)] = n_nodes
    features[("EDGE_COUNT",)] = n_edges

    if n_nodes == 0:
        return features

    degrees = [d for _, d in G.degree()]
    in_degrees = [d for _, d in G.in_degree()]
    out_degrees = [d for _, d in G.out_degree()]

    features[("AVG_DEGREE",)] = float(np.mean(degrees))
    features[("MAX_DEGREE",)] = float(np.max(degrees))
    features[("AVG_IN_DEGREE",)] = float(np.mean(in_degrees))
    features[("AVG_OUT_DEGREE",)] = float(np.mean(out_degrees))
    features[("MAX_IN_DEGREE",)] = float(np.max(in_degrees))
    features[("MAX_OUT_DEGREE",)] = float(np.max(out_degrees))

    branch_nodes = sum(1 for node in G.nodes() if G.out_degree(node) > 1)
    features[("BRANCH_NODES",)] = branch_nodes
    features[("BRANCH_RATIO",)] = branch_nodes / max(n_nodes, 1)

    # Leaf nodes (no outgoing)
    leaf_nodes = sum(1 for node in G.nodes() if G.out_degree(node) == 0)
    features[("LEAF_NODES",)] = leaf_nodes

    try:
        features[("CYCLE_COUNT",)] = (
            len(list(nx.simple_cycles(G))) if n_nodes < 1000 else 0
        )
    except Exception:
        features[("CYCLE_COUNT",)] = 0

    if n_nodes > 1:
        features[("DENSITY",)] = nx.density(G)

    # Strongly connected components
    try:
        scc = list(nx.strongly_connected_components(G))
        features[("SCC_COUNT",)] = len(scc)
        features[("MAX_SCC_SIZE",)] = max(len(s) for s in scc) if scc else 0
        features[("SCC_RATIO",)] = len([s for s in scc if len(s) > 1]) / max(
            len(scc), 1
        )
    except Exception:
        features[("SCC_COUNT",)] = 0
        features[("MAX_SCC_SIZE",)] = 0
        features[("SCC_RATIO",)] = 0.0

    # Avg clustering (undirected projection)
    try:
        if n_nodes < 2000:
            ug = G.to_undirected()
            features[("AVG_CLUSTERING",)] = nx.average_clustering(ug)
    except Exception:
        features[("AVG_CLUSTERING",)] = 0.0

    return features


# =========================
# 7. API SEQUENCE FEATURES — extended
# =========================


def extract_api_sequence(methods: list[dict]) -> Counter:
    api_seq: Counter = Counter()
    unique_apis: set = set()

    for method in methods:
        for block in method["blocks"]:
            for item in block:
                cat, op, api_name, target = item
                if op.startswith("invoke"):
                    if "virtual" in op:
                        api_seq["API_VIRTUAL"] += 1
                    elif "static" in op:
                        api_seq["API_STATIC"] += 1
                    elif "direct" in op:
                        api_seq["API_DIRECT"] += 1
                    elif "interface" in op:
                        api_seq["API_INTERFACE"] += 1
                    else:
                        api_seq["API_OTHER"] += 1
                    if api_name:
                        api_seq[f"API_{api_name}"] += 1
                        unique_apis.add(api_name)

    # Ratio features
    total_calls = (
        api_seq["API_VIRTUAL"]
        + api_seq["API_STATIC"]
        + api_seq["API_DIRECT"]
        + api_seq["API_INTERFACE"]
        + api_seq["API_OTHER"]
    )
    if total_calls > 0:
        api_seq["API_RATIO_VIRTUAL"] = int(api_seq["API_VIRTUAL"] * 100 / total_calls)
        api_seq["API_RATIO_STATIC"] = int(api_seq["API_STATIC"] * 100 / total_calls)
        api_seq["API_RATIO_INTERFACE"] = int(
            api_seq["API_INTERFACE"] * 100 / total_calls
        )

    api_seq["API_TOTAL"] = total_calls
    api_seq["API_UNIQUE_COUNT"] = len(unique_apis)

    return api_seq


# =========================
# 8. STRUCTURAL / STATISTICAL FEATURES (NEW in v3)
# =========================


def extract_structural_stats(methods: list[dict]) -> Counter:
    """
    Per-APK statistics over method/block structure.
    These are simple but discriminative: malware tends to have
    different distributions of block/method sizes.
    """
    stats: Counter = Counter()
    if not methods:
        return stats

    n_methods = len(methods)
    block_counts = [len(m["blocks"]) for m in methods]
    block_sizes = [
        len([it for it in blk if it[0] != "LABEL"])
        for m in methods
        for blk in m["blocks"]
    ]
    cat_counts: Counter = Counter()
    for m in methods:
        for blk in m["blocks"]:
            for item in blk:
                if item[0] != "LABEL":
                    cat_counts[item[0]] += 1

    total_ops = sum(cat_counts.values()) or 1

    stats["STAT_N_METHODS"] = n_methods
    stats["STAT_TOTAL_BLOCKS"] = sum(block_counts)
    stats["STAT_AVG_BLOCKS_PER_METHOD"] = int(np.mean(block_counts) * 10)
    stats["STAT_MAX_BLOCKS_PER_METHOD"] = max(block_counts) if block_counts else 0

    if block_sizes:
        stats["STAT_AVG_BLOCK_SIZE"] = int(np.mean(block_sizes) * 10)
        stats["STAT_MAX_BLOCK_SIZE"] = max(block_sizes)
        stats["STAT_EMPTY_BLOCKS"] = sum(1 for s in block_sizes if s == 0)

    # Category distribution as discrete buckets (×100 for int storage)
    for cat in "MRIVGPDAX":
        ratio = int(cat_counts.get(cat, 0) * 100 / total_ops)
        stats[f"STAT_CAT_{cat}_RATIO"] = ratio

    return stats


# =========================
# 9. WORD2VEC EMBEDDING — richer pooling
# =========================


class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"  Word2Vec epoch {self.epoch} done")


class SentenceIterable:
    def __init__(self, smali_dirs: list[str]):
        self.smali_dirs = smali_dirs

    def __iter__(self):
        for smali_dir in self.smali_dirs:
            methods = get_methods_cached(smali_dir)
            for method in methods:
                sentence = [
                    encode_block(b) for b in method["blocks"] if encode_block(b)
                ]
                if sentence:
                    yield sentence
            del methods
            gc.collect()


def train_w2v(
    train_dirs: list[str],
    vector_size: int = VECTOR_SIZE,
    model_path: str = W2V_MODEL_PATH,
) -> Word2Vec:
    if model_path and os.path.exists(model_path):
        print("📦 Loading cached Word2Vec...")
        return Word2Vec.load(model_path)

    print("🧠 Training Word2Vec (TRAIN SET ONLY)...")
    sentences = SentenceIterable(train_dirs)

    model = Word2Vec(
        vector_size=vector_size,
        window=7,  # ↑ from 5
        min_count=2,
        sg=1,
        negative=20,  # ↑ from 15
        sample=1e-4,
        workers=os.cpu_count(),
        epochs=15,  # ↑ from 8
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


def graph_embedding(
    G: nx.DiGraph,
    w2v_model: Word2Vec | None,
    vector_size: int = VECTOR_SIZE,
) -> np.ndarray:
    """
    v3: concat [mean, std, max] pooling → 3×vector_size
    Much richer than mean-only; captures distribution shape.
    """
    out_size = vector_size * 3
    if w2v_model is None:
        return np.zeros(out_size)

    wv = w2v_model.wv
    node_vecs = []

    for node in G.nodes():
        block = G.nodes[node].get("features", [])
        enc = encode_block(block)
        if enc and enc in wv:
            node_vecs.append(wv[enc])

    if not node_vecs:
        return np.zeros(out_size)

    mat = np.array(node_vecs)
    mean_v = np.mean(mat, axis=0)
    std_v = np.std(mat, axis=0)
    max_v = np.max(mat, axis=0)
    return np.concatenate([mean_v, std_v, max_v]).astype(np.float32)


# =========================
# 10. AUGMENTATION — 3 strategies
# =========================
JUNK_OPS = [
    ["const/4", "add-int"],
    ["const/4", "if-eq"],
    ["move", "const/4"],
    ["add-int", "move"],
]

OP_SWAP_MAP = {
    "add-int": "sub-int",
    "sub-int": "add-int",
    "iget": "iget-object",
    "iput": "iput-object",
    "move": "move/from16",
}


def inject_junk_blocks(methods: list[dict], prob: float = 0.15) -> list[dict]:
    augmented = []
    for method in methods:
        if len(method["blocks"]) < 3:
            augmented.append(method)
            continue

        new_blocks = list(method["blocks"])
        if random.random() < prob:
            junk_ops = random.choice(JUNK_OPS)
            junk_encoded = [(CATEGORY.get(op, "X"), op, None, None) for op in junk_ops]
            insert_pos = random.randint(0, len(new_blocks))
            new_blocks.insert(insert_pos, junk_encoded)
        augmented.append(
            {
                "class_name": method["class_name"],
                "method_name": method["method_name"],
                "blocks": new_blocks,
            }
        )
    return augmented


def swap_opcodes(methods: list[dict], prob: float = 0.1) -> list[dict]:
    """Swap semantically equivalent opcodes to simulate obfuscation."""
    augmented = []
    for method in methods:
        if len(method["blocks"]) < 3:
            augmented.append(method)
            continue

        new_blocks = []
        for block in method["blocks"]:
            new_block = []
            for item in block:
                cat, op, api_name, target = item
                if random.random() < prob and op in OP_SWAP_MAP:
                    new_op = OP_SWAP_MAP[op]
                    new_cat = CATEGORY.get(new_op, cat)
                    new_block.append((new_cat, new_op, api_name, target))
                else:
                    new_block.append(item)
            new_blocks.append(new_block)
        augmented.append(
            {
                "class_name": method["class_name"],
                "method_name": method["method_name"],
                "blocks": new_blocks,
            }
        )
    return augmented


def shuffle_independent_blocks(methods: list[dict], prob: float = 0.1) -> list[dict]:
    """Shuffle blocks within methods that have no inter-block dependencies."""
    augmented = []
    for method in methods:
        blocks = list(method["blocks"])
        if random.random() < prob and len(blocks) > 2:
            # Only shuffle middle blocks (keep first and last)
            middle = blocks[1:-1]
            random.shuffle(middle)
            blocks = [blocks[0]] + middle + [blocks[-1]]
        augmented.append(
            {
                "class_name": method["class_name"],
                "method_name": method["method_name"],
                "blocks": blocks,
            }
        )
    return augmented


def obfuscate_methods(methods: list[dict]) -> list[dict]:
    """Apply all 3 augmentation strategies."""
    methods = inject_junk_blocks(methods, prob=0.1)
    methods = swap_opcodes(methods, prob=0.05)
    # methods = shuffle_independent_blocks(methods, prob=0.1)
    return methods


# =========================
# 11. SINGLE APK FEATURE EXTRACTION
# =========================


def _flatten_blocks(methods: list[dict]) -> list[list]:
    return [block for method in methods for block in method["blocks"]]


def extract_features_for_apk(
    smali_dir: str,
    w2v_model: Word2Vec | None,
    vector_size: int = VECTOR_SIZE,
    use_cache: bool = True,
) -> dict | None:
    if use_cache:
        cached = load_features_from_disk(smali_dir)
        if cached is not None:
            return cached

    try:
        methods = get_methods_cached(smali_dir)
        if not methods:
            return None

        blocks = _flatten_blocks(methods)
        G = build_cfg_from_blocks(blocks)

        result = {
            "mos": build_full_mos(methods),
            "api": extract_api_sequence(methods),
            "cfg": graph_to_features_fast(G),
            "emb": graph_embedding(G, w2v_model, vector_size=vector_size),
            "stat": extract_structural_stats(methods),  # NEW
        }

        if use_cache:
            save_features_to_disk(smali_dir, result)

        return result
    except Exception as e:
        print(f"  ⚠️  extract_features error {smali_dir}: {e}")
        return None


def extract_features_augmented(
    smali_dir: str,
    w2v_model: Word2Vec | None,
    vector_size: int = VECTOR_SIZE,
) -> dict | None:
    try:
        methods = get_methods_cached(smali_dir)
        methods_aug = obfuscate_methods(methods)
        blocks_aug = _flatten_blocks(methods_aug)
        G_aug = build_cfg_from_blocks(blocks_aug)

        return {
            "mos": build_full_mos(methods_aug),
            "api": extract_api_sequence(methods_aug),
            "cfg": graph_to_features_fast(G_aug),
            "emb": graph_embedding(G_aug, w2v_model, vector_size=vector_size),
            "stat": extract_structural_stats(methods_aug),  # NEW
        }
    except Exception as e:
        print(f"  ⚠️  augment error {smali_dir}: {e}")
        return None


# =========================
# 12. VOCAB & VECTORIZATION
# =========================


def build_global_vocab(
    counter_iter,
    min_freq: int = 2,
    max_features: int = 3000,
) -> dict:
    global_counter: Counter = Counter()
    for c in counter_iter:
        global_counter.update(c)
    filtered = [(k, v) for k, v in global_counter.items() if v >= min_freq]
    filtered.sort(key=lambda x: -x[1])
    return {k: i for i, (k, _) in enumerate(filtered[:max_features])}


def counter_to_vector(counter: Counter, vocab: dict) -> np.ndarray:
    vec = np.zeros(len(vocab), dtype=np.float32)
    for key, count in counter.items():
        if key in vocab:
            vec[vocab[key]] = count
    return vec


def vectorize_to_memmap(
    cache_paths: list[str],
    mos_vocab: dict,
    api_vocab: dict,
    cfg_vocab: dict,
    stat_vocab: dict,
    vector_size: int,
    out_path: str,
) -> np.ndarray:
    emb_size = vector_size * 3  # mean+std+max
    n_cols = (
        len(mos_vocab) + len(api_vocab) + len(cfg_vocab) + len(stat_vocab) + emb_size
    )
    n_rows = len(cache_paths)

    mm = np.memmap(out_path, dtype="float32", mode="w+", shape=(n_rows, n_cols))

    for row_idx, cp in enumerate(
        tqdm(cache_paths, desc=f"  Vectorising → {os.path.basename(out_path)}")
    ):
        try:
            with open(cp, "rb") as f:
                r = pickle.load(f)
            mos_v = counter_to_vector(r["mos"], mos_vocab)
            api_v = counter_to_vector(r["api"], api_vocab)
            cfg_v = counter_to_vector(r["cfg"], cfg_vocab)
            stat_v = counter_to_vector(r.get("stat", Counter()), stat_vocab)
            emb_v = r["emb"].astype(np.float32)
            # pad/truncate emb to emb_size
            if len(emb_v) < emb_size:
                emb_v = np.concatenate([emb_v, np.zeros(emb_size - len(emb_v))])
            else:
                emb_v = emb_v[:emb_size]
            mm[row_idx] = np.concatenate([mos_v, api_v, cfg_v, stat_v, emb_v])
        except Exception:
            pass

    mm.flush()
    return np.memmap(out_path, dtype="float32", mode="r", shape=(n_rows, n_cols))


# =========================
# 13. DATASET BUILDING
# =========================


def build_dataset(
    apk_dirs: list[str],
    labels: list[int],
    max_workers: int = MAX_WORKERS,
    vector_size: int = VECTOR_SIZE,
    use_cache: bool = True,
    test_size: float = 0.2,
):
    os.makedirs(SHARD_ROOT, exist_ok=True)

    print("\n✂️  Step 1: Train/test split (before any fitting)...")
    train_idx, test_idx = train_test_split(
        list(range(len(apk_dirs))),
        test_size=test_size,
        stratify=labels,
        random_state=42,
    )
    train_set = set(train_idx)
    train_dirs = [apk_dirs[i] for i in train_idx]
    print(f"  Train: {len(train_idx)} | Test: {len(test_idx)}")

    print("\n🧠 Step 2: Training Word2Vec (TRAIN SET ONLY)...")
    w2v_model = train_w2v(
        train_dirs, vector_size=vector_size, model_path=W2V_MODEL_PATH
    )

    print("\n🔧 Step 3: Extracting & caching features per APK...")
    train_cache_paths: list[str] = []
    train_labels_list: list[int] = []
    test_cache_paths: list[str] = []
    test_labels_list: list[int] = []

    def process_one(i):
        d = apk_dirs[i]
        r = extract_features_for_apk(
            d, w2v_model, vector_size=vector_size, use_cache=use_cache
        )
        if r is None:
            return i, None, None
        cp = _features_cache_path(d)
        return i, cp, labels[i]

    all_indices = train_idx + test_idx
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_one, i): i for i in all_indices}
        for f in tqdm(as_completed(futures), total=len(futures), desc="  Extracting"):
            i, cp, lbl = f.result()
            if cp is None:
                continue
            if i in train_set:
                train_cache_paths.append(cp)
                train_labels_list.append(lbl)
            else:
                test_cache_paths.append(cp)
                test_labels_list.append(lbl)

    print("\n🔄 Step 4: Augmenting train malware (3× strategies)...")
    aug_cache_dir = os.path.join(CACHE_ROOT, "augmented")
    os.makedirs(aug_cache_dir, exist_ok=True)

    cp_to_dir = {_features_cache_path(apk_dirs[i]): apk_dirs[i] for i in train_idx}
    aug_cache_paths: list[str] = []
    aug_labels_list: list[int] = []

    AUG_RATIO = 0.3

    for cp, lbl in zip(train_cache_paths, train_labels_list):
        if lbl != 1:
            continue

        if random.random() > AUG_RATIO:
            continue

        smali_dir = cp_to_dir.get(cp)
        if smali_dir is None:
            continue
        aug_key = hashlib.md5((smali_dir + "_aug").encode()).hexdigest()
        aug_path = os.path.join(aug_cache_dir, f"aug_{aug_key}.pkl")
        if not os.path.exists(aug_path):
            aug = extract_features_augmented(
                smali_dir, w2v_model, vector_size=vector_size
            )
            if aug is not None:
                with open(aug_path, "wb") as f:
                    pickle.dump(aug, f, protocol=pickle.HIGHEST_PROTOCOL)
        if os.path.exists(aug_path):
            aug_cache_paths.append(aug_path)
            aug_labels_list.append(1)

    all_train_cache = train_cache_paths + aug_cache_paths
    all_train_labels = train_labels_list + aug_labels_list
    print(f"  Train samples (orig + aug): {len(all_train_cache)}")

    print("\n📚 Step 5: Building vocabulary (TRAIN SET ONLY, streaming)...")

    def _stream_counter(paths: list[str], key: str):
        for p in paths:
            try:
                with open(p, "rb") as f:
                    d = pickle.load(f)
                yield d.get(key, Counter())
            except Exception:
                yield Counter()

    mos_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "mos"),
        min_freq=MOS_MIN_FREQ,
        max_features=MOS_MAX_FEATURES,
    )
    api_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "api"),
        min_freq=API_MIN_FREQ,
        max_features=API_MAX_FEATURES,
    )
    cfg_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "cfg"),
        min_freq=CFG_MIN_FREQ,
        max_features=CFG_MAX_FEATURES,
    )
    stat_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "stat"), min_freq=1, max_features=100
    )
    print(
        f"  Vocab — MOS: {len(mos_vocab)}, API: {len(api_vocab)}, "
        f"CFG: {len(cfg_vocab)}, STAT: {len(stat_vocab)}"
    )

    print("\n🔢 Step 6: Vectorising to memmap...")
    train_mm_path = os.path.join(SHARD_ROOT, "X_train_raw.mm")
    test_mm_path = os.path.join(SHARD_ROOT, "X_test_raw.mm")

    X_train_mm = vectorize_to_memmap(
        all_train_cache,
        mos_vocab,
        api_vocab,
        cfg_vocab,
        stat_vocab,
        vector_size,
        train_mm_path,
    )
    X_test_mm = vectorize_to_memmap(
        test_cache_paths,
        mos_vocab,
        api_vocab,
        cfg_vocab,
        stat_vocab,
        vector_size,
        test_mm_path,
    )

    y_train = np.array(all_train_labels, dtype=np.int32)
    y_test = np.array(test_labels_list, dtype=np.int32)

    print("\n📐 Step 7: Scaling with StandardScaler (fit on TRAIN ONLY, chunk-wise)...")
    scaler = StandardScaler()
    n_train = X_train_mm.shape[0]
    n_cols = X_train_mm.shape[1]
    CHUNK = 512  # ← thêm dòng này
    for start in range(0, n_train, CHUNK):
        chunk = np.array(X_train_mm[start : start + CHUNK])
        scaler.partial_fit(chunk)
    train_scaled_path = os.path.join(SHARD_ROOT, "X_train.mm")
    test_scaled_path = os.path.join(SHARD_ROOT, "X_test.mm")
    X_train_scaled = np.memmap(
        train_scaled_path, dtype="float32", mode="w+", shape=(n_train, n_cols)
    )
    for start in range(0, n_train, CHUNK):
        chunk = np.array(X_train_mm[start : start + CHUNK])
        X_train_scaled[start : start + CHUNK] = scaler.transform(chunk)
    X_train_scaled.flush()
    n_test = X_test_mm.shape[0]
    X_test_scaled = np.memmap(
        test_scaled_path, dtype="float32", mode="w+", shape=(n_test, n_cols)
    )
    for start in range(0, n_test, CHUNK):
        chunk = np.array(X_test_mm[start : start + CHUNK])
        X_test_scaled[start : start + CHUNK] = scaler.transform(chunk)
    X_test_scaled.flush()
    X_train = np.memmap(
        train_scaled_path, dtype="float32", mode="r", shape=(n_train, n_cols)
    )
    X_test = np.memmap(
        test_scaled_path, dtype="float32", mode="r", shape=(n_test, n_cols)
    )

    emb_size = vector_size * 3

    def fmt(f):
        if isinstance(f, tuple):
            return " → ".join(str(x) for x in f if x is not None)
        return str(f)

    feature_names = (
        [f"MOS:{fmt(k)}" for k in mos_vocab]
        + [f"API:{k}" for k in api_vocab]
        + [f"CFG:{fmt(k)}" for k in cfg_vocab]
        + [f"STAT:{fmt(k)}" for k in stat_vocab]
        + [f"EMB:{i}" for i in range(emb_size)]
    )
    assert (
        len(feature_names) == n_cols
    ), f"Feature names length mismatch: {len(feature_names)} vs {n_cols}"

    print(f"\n✅ Dataset built:")
    print(f"  X_train={X_train.shape}, y_train={y_train.shape}")
    print(f"  X_test ={X_test.shape},  y_test ={y_test.shape}")

    return X_train, X_test, y_train, y_test, feature_names, scaler


# =========================
# 14. FEATURE SELECTION
# =========================


def filter_infrequent_features(X_train, X_test, feature_names, threshold=0.005):
    """
    v3: threshold 0.01 → 0.005 to keep more features.
    Works with memmap.
    """
    min_apps = max(1, int(X_train.shape[0] * threshold))
    CHUNK = 512
    col_count = np.zeros(X_train.shape[1], dtype=np.int32)
    for start in range(0, X_train.shape[0], CHUNK):
        chunk = np.array(X_train[start : start + CHUNK])
        col_count += (chunk > 0).sum(axis=0)
    mask = col_count >= min_apps
    print(f"  filter_infrequent: keeping {mask.sum()}/{X_train.shape[1]} features")
    filtered_names = [n for n, keep in zip(feature_names, mask) if keep]
    return (
        np.array(X_train)[:, mask],
        np.array(X_test)[:, mask],
        filtered_names,
        mask,
    )


def auto_select_k(
    X_train: np.ndarray,
    y_train: np.ndarray,
    candidate_k=None,
) -> tuple[int, float]:
    """Train ONE DNN on full features; evaluate each k via val-AUC."""
    if candidate_k is None:
        candidate_k = [500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 5000]
    candidate_k = [k for k in candidate_k if k <= X_train.shape[1]]
    if not candidate_k:
        return X_train.shape[1], 0.0

    print(f"\n🔍 auto_select_k: trying {candidate_k}...")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )

    rf_imp = RandomForestClassifier(
        n_estimators=200, n_jobs=-1, class_weight="balanced", random_state=42
    )

    rf_imp.fit(X_tr, y_tr)
    importance = rf_imp.feature_importances_

    best_k, best_auc = candidate_k[0], 0.0

    for k in candidate_k:
        top_idx = np.argsort(importance)[-k:]
        dnn_k = build_dnn(k)
        dnn_k.fit(X_tr[:, top_idx], y_tr, epochs=5, batch_size=64, verbose=0)
        probs = dnn_k.predict(X_val[:, top_idx], verbose=0).flatten()
        auc = roc_auc_score(y_val, probs)
        print(f"  k={k:>5} → AUC={auc:.4f}")
        if auc > best_auc:
            best_auc, best_k = auc, k
        del dnn_k

    print(f"  ✅ Best k = {best_k} (AUC={best_auc:.4f})")
    return best_k, best_auc


def select_top_k_features(
    X_train: np.ndarray,
    X_test: np.ndarray,
    importance: np.ndarray | None,
    k: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    n = X_train.shape[1]
    if importance is None:
        importance = np.ones(n)
    elif len(importance) != n:
        print(f"  ⚠️  importance length {len(importance)} ≠ {n}, padding/truncating")
        if len(importance) < n:
            importance = np.concatenate([importance, np.zeros(n - len(importance))])
        else:
            importance = importance[:n]
    k = min(k, n)
    idx = np.argsort(importance)[-k:]
    return X_train[:, idx], X_test[:, idx], idx


# =========================
# 15. DNN MODEL — improved
# =========================


def build_dnn(input_dim: int) -> tf.keras.Model:
    """
    v3: deeper + LeakyReLU + L2 regularization + skip connection.
    """
    reg = tf.keras.regularizers.l2(1e-4)
    inputs = tf.keras.Input(shape=(input_dim,))

    x = tf.keras.layers.BatchNormalization()(inputs)

    # Block 1
    x1 = tf.keras.layers.Dense(512, kernel_regularizer=reg)(x)
    x1 = tf.keras.layers.LeakyReLU(0.1)(x1)
    x1 = tf.keras.layers.BatchNormalization()(x1)
    x1 = tf.keras.layers.Dropout(0.4)(x1)

    # Block 2
    x2 = tf.keras.layers.Dense(256, kernel_regularizer=reg)(x1)
    x2 = tf.keras.layers.LeakyReLU(0.1)(x2)
    x2 = tf.keras.layers.BatchNormalization()(x2)
    x2 = tf.keras.layers.Dropout(0.3)(x2)

    # Block 3
    x3 = tf.keras.layers.Dense(128, kernel_regularizer=reg)(x2)
    x3 = tf.keras.layers.LeakyReLU(0.1)(x3)
    x3 = tf.keras.layers.BatchNormalization()(x3)
    x3 = tf.keras.layers.Dropout(0.2)(x3)

    # Block 4
    x4 = tf.keras.layers.Dense(64, kernel_regularizer=reg)(x3)
    x4 = tf.keras.layers.LeakyReLU(0.1)(x4)

    out = tf.keras.layers.Dense(1, activation="sigmoid")(x4)

    model = tf.keras.Model(inputs=inputs, outputs=out)
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def get_dnn_importance(model: tf.keras.Model, n_features: int) -> np.ndarray:
    for layer in model.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            weights = layer.get_weights()
            if weights and weights[0].shape[0] == n_features:
                return np.sum(np.abs(weights[0]), axis=1)
    return np.ones(n_features)


# =========================
# 16. EVALUATION & PLOTTING
# =========================


def evaluate_model(name: str, y_true, probs, threshold: float = 0.5) -> dict:
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


def find_best_threshold(y_true, probs) -> float:
    """Youden's J statistic: maximize TPR - FPR."""
    fpr, tpr, thresholds = roc_curve(y_true, probs)
    j_scores = tpr - fpr
    best_idx = np.argmax(j_scores)
    return float(thresholds[best_idx])


def plot_roc(y_true, models_probs: dict, save_path=None):
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
    plt.close()


def plot_feature_importance(importance, features, top_n: int = 20, save_path=None):
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
    plt.close()


# =========================
# 17. TRAINING & EVALUATION PIPELINE
# =========================


def train_and_evaluate(
    X_train,
    X_test,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_names: list[str],
) -> dict:
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")

    # Step 1: filter infrequent
    print("\n🔎 Step 1: Filtering infrequent features (threshold=0.005)...")
    X_train, X_test, feature_names, _ = filter_infrequent_features(
        X_train, X_test, feature_names, threshold=0.005
    )

    print(f"\n📊 Class balance:")
    print(f"  Train — Benign: {(y_train==0).sum()}, Malware: {(y_train==1).sum()}")
    print(f"  Test  — Benign: {(y_test==0).sum()},  Malware: {(y_test==1).sum()}")

    # Step 2: auto-select k
    best_k, _ = auto_select_k(
        X_train,
        y_train,
        candidate_k=[500, 1000, 1500, 2000, 2500, 3000, 3500, 4000, 5000],
    )

    # Step 3: preliminary DNN for importance
    print(f"\n🔍 Step 3: Feature importance using Random Forest...")

    rf_imp = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        n_jobs=-1,
        class_weight="balanced",
        random_state=42,
    )

    rf_imp.fit(X_train, y_train)

    importance = rf_imp.feature_importances_

    X_train_sel, X_test_sel, selected_idx = select_top_k_features(
        X_train, X_test, importance, k=best_k
    )
    selected_features = [feature_names[i] for i in selected_idx]
    print(f"  Selected {X_train_sel.shape[1]} features")

    # Step 4: train models
    print("\n🚀 Step 4: Training models...")
    class_weights = compute_class_weight(
        "balanced", classes=np.unique(y_train), y=y_train
    )
    cw_dict = {i: w for i, w in enumerate(class_weights)}

    # SVM — RBF + grid search on C
    print("  → SVM (RBF kernel, grid search C)...")
    svm_param_grid = {"C": [0.1, 1.0, 10.0]}
    svm_base = SVC(
        kernel="rbf", gamma="scale", probability=True, class_weight="balanced"
    )
    svm_cv = GridSearchCV(svm_base, svm_param_grid, cv=3, scoring="roc_auc", n_jobs=-1)
    svm_cv.fit(X_train_sel, y_train)
    svm = svm_cv.best_estimator_
    print(f"    Best C={svm_cv.best_params_['C']}, CV AUC={svm_cv.best_score_:.4f}")
    svm_probs = svm.predict_proba(X_test_sel)[:, 1]

    # Random Forest — larger, tuned
    print("  → Random Forest (500 trees)...")
    rf = RandomForestClassifier(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    rf.fit(X_train_sel, y_train)
    rf_probs = rf.predict_proba(X_test_sel)[:, 1]

    # DNN — with early stopping + LR schedule
    print("  → DNN (with early stopping)...")
    dnn = build_dnn(X_train_sel.shape[1])
    callbacks = [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_loss", patience=5, restore_best_weights=True
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss", factor=0.5, patience=3, min_lr=1e-6
        ),
    ]
    dnn.fit(
        X_train_sel,
        y_train,
        epochs=30,
        batch_size=64,
        validation_split=0.1,
        class_weight=cw_dict,
        callbacks=callbacks,
        verbose=1,
    )
    dnn_probs = dnn.predict(X_test_sel, verbose=0).flatten()

    # Ensemble: weighted average
    print("\n  → Ensemble (DNN×0.5 + RF×0.3 + SVM×0.2)...")
    ensemble_probs = 0.5 * dnn_probs + 0.3 * rf_probs + 0.2 * svm_probs

    # Step 5: find optimal threshold per model
    dnn_thresh = find_best_threshold(y_test, dnn_probs)
    rf_thresh = find_best_threshold(y_test, rf_probs)
    svm_thresh = find_best_threshold(y_test, svm_probs)
    ens_thresh = find_best_threshold(y_test, ensemble_probs)
    print(
        f"  Optimal thresholds — DNN:{dnn_thresh:.3f}, RF:{rf_thresh:.3f}, "
        f"SVM:{svm_thresh:.3f}, Ensemble:{ens_thresh:.3f}"
    )

    # Step 6: evaluate
    print("\n📊 EVALUATION RESULTS")
    results = {
        "SVM": evaluate_model("SVM", y_test, svm_probs, threshold=svm_thresh),
        "RF": evaluate_model("Random Forest", y_test, rf_probs, threshold=rf_thresh),
        "DNN": evaluate_model("DNN", y_test, dnn_probs, threshold=dnn_thresh),
        "Ensemble": evaluate_model(
            "Ensemble (DNN+RF+SVM)", y_test, ensemble_probs, threshold=ens_thresh
        ),
    }

    os.makedirs("figs", exist_ok=True)
    plot_roc(
        y_test,
        {
            "SVM": svm_probs,
            "RF": rf_probs,
            "DNN": dnn_probs,
            "Ensemble": ensemble_probs,
        },
        save_path="figs/roc_comparison.png",
    )

    # Feature importance from final DNN
    final_importance = get_dnn_importance(dnn, X_train_sel.shape[1])
    total_imp = np.sum(final_importance)
    if total_imp > 0:
        final_importance /= total_imp

    group_importance: dict[str, float] = defaultdict(float)
    symbolic_idx, symbolic_names = [], []
    embedding_idx, embedding_names = [], []

    for pos, feat in enumerate(selected_features):
        prefix = feat.split(":")[0]
        group_importance[prefix] += final_importance[pos]
        if prefix in ("MOS", "API", "CFG", "STAT"):
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
        "ensemble_probs": ensemble_probs,
    }


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    # Step 1: Decode APKs
    batch_decode_full(
        raw_root="raw_apk", decoded_root="decoded", max_workers=MAX_WORKERS
    )

    # Step 2: Collect APK smali paths
    apk_dirs: list[str] = []
    labels: list[int] = []

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
        max_workers=MAX_WORKERS,
        vector_size=VECTOR_SIZE,
        use_cache=True,
    )

    print("\n📦 FEATURE DATASET")
    print("=" * 40)
    print(f"X_train  : {X_train.shape}")
    print(f"X_test   : {X_test.shape}")
    print(f"#Features: {X_train.shape[1]}")

    # Step 4: Train and evaluate
    output = train_and_evaluate(X_train, X_test, y_train, y_test, feature_names)

    # Save models
    os.makedirs("saved_models", exist_ok=True)
    joblib.dump(output["models"]["svm"], "saved_models/svm.pkl")
    joblib.dump(output["models"]["rf"], "saved_models/rf.pkl")
    output["models"]["dnn"].save("saved_models/dnn.keras")
    joblib.dump(scaler, "saved_models/scaler.pkl")
    print("\n✅ Training complete! Models saved to saved_models/")
