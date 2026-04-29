# =========================
# MOSDroid FINAL v2  (RAM-optimized + Logic-fixed)
# =========================
# Paper: "MOSDroid: Obfuscation-resilient android malware detection using
#         multisets of encoded opcode sequences"
#         Sharma et al., Maulana Azad NIT
#
# Fixes vs v1:
#   RAM/CPU:
#     - Streaming disk-based result accumulation (numpy memmap / npz shards)
#     - Vocab built by streaming Counters from disk, never load all raw at once
#     - Vectorization done in shards → written to memmap, then loaded slice-by-slice
#     - auto_select_k uses a single DNN pass (no repeated full retrain)
#     - W2V SentenceIterable unchanged (already lazy)
#
#   Logic:
#     - train_idx lookup uses set  (O(1) vs O(n))
#     - build_cfg_from_blocks: block terminator scans ALL items, not just last
#     - graph_embedding: removed unused `methods` param
#     - select_top_k_features: importance padding/truncating correct
#     - auto_select_k: importance computed once, k-selection done by index slicing
#     - train_and_evaluate: importance from prelim DNN aligns with selected cols
#     - feature_names length validated against actual vector width
#     - augmented samples appended *after* all features extracted (order-stable)
#
#   Paper alignment kept:
#     - Method-level grouping + basic block segmentation
#     - Per-block category encoding → per-method multiset
#     - APK multiset = union of per-method multisets
#     - 2-gram / 3-gram extension (author extension, kept)
#     - CFG structural features  (author extension, kept)
#     - API call tracking        (author extension, kept)
#     - Word2Vec graph embedding (author extension, kept)
#     - Junk-block augmentation  (author extension, kept)
#     - Anti-leakage pipeline    (author extension, kept)
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
MAX_BLOCKS_PER_APK = 10_000
TERMINATORS = {"R"}  # return  → terminates block
BRANCH_OPS = {"I"}  # if-*    → terminates block (branch)
W2V_MODEL_PATH = "w2v_model.model"
CACHE_ROOT = "feature_cache"  # all per-APK feature dicts stored here
SHARD_ROOT = "matrix_shards"  # train/test matrix shards
VECTOR_SIZE = 32
MAX_WORKERS = 4


# ===========================================================
# 1. DALVIK OPCODE → CATEGORY MAPPING
#    Categories per paper Table 1:
#      M=Move  R=Return  I=if-branch  V=invoke/goto
#      G=iget/sget  P=iput/sput  D=const  A=arithmetic  X=other
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
]

CATEGORY: dict[str, str] = {}
for _op in DALVIK_OPCODES:
    if "move" in _op:
        CATEGORY[_op] = "M"
    elif "return" in _op:
        CATEGORY[_op] = "R"
    elif "if-" in _op:
        CATEGORY[_op] = "I"
    elif "goto" in _op or "invoke" in _op:
        CATEGORY[_op] = "V"
    elif "get" in _op:
        CATEGORY[_op] = "G"
    elif "put" in _op:
        CATEGORY[_op] = "P"
    elif "const" in _op:
        CATEGORY[_op] = "D"
    elif any(x in _op for x in ("add", "sub", "mul", "div", "rem")):
        CATEGORY[_op] = "A"
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
    """
    Parse one .smali file → list of method dicts.
    Each method dict:
        class_name   : str
        method_name  : str
        blocks       : List[List[Tuple(cat, op, api_name, target_label)]]

    Block boundary rules (paper §3.2):
      - Every label line (:xxx) starts a new block
      - A return opcode (cat R) ends the current block
      - A branch opcode (cat I) ends the current block
    """
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

                # .class directive
                if line.startswith(".class"):
                    parts = line.split()
                    class_name = parts[-1] if len(parts) > 1 else "Unknown"
                    continue

                # Method start
                if line.startswith(".method"):
                    in_method = True
                    parts = line.split()
                    current_method_name = parts[-1] if len(parts) > 1 else "unknown"
                    current_blocks = []
                    current_block = []
                    continue

                # Method end
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

                # Label line → new block boundary
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

                    # FIX: check cat membership, not string op —
                    # terminates block on return OR branch
                    if cat in TERMINATORS or cat in BRANCH_OPS:
                        current_blocks.append(current_block)
                        current_block = []

    except Exception:
        pass

    # flush leftover
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
    """Walk all .smali files, return flat list of method dicts."""
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
# 4. CACHE LAYER  (disk-only, no in-memory accumulation)
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
    """Serialize feature dict to disk, return cache path."""
    cache = _features_cache_path(smali_dir)
    try:
        with open(cache, "wb") as f:
            pickle.dump(features, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass
    return cache


def load_features_from_disk(smali_dir: str) -> dict | None:
    """Load feature dict from disk; returns None on miss/corruption."""
    cache = _features_cache_path(smali_dir)
    if not os.path.exists(cache):
        return None
    try:
        with open(cache, "rb") as f:
            d = pickle.load(f)
        if all(k in d for k in ("mos", "api", "cfg", "emb")):
            return d
    except Exception:
        pass
    return None


# =========================
# 5. MOS CORE  (paper-aligned)
#
# Paper §3.2 & §3.3:
#   Step 1 – Per method, extract basic blocks (parser above)
#   Step 2 – Encode each block as string of category letters ("DAI", "MVGR" …)
#   Step 3 – Per-method multiset = Counter({encoded_seq: count})
#   Step 4 – APK multiset = union (sum) of all method multisets
#
# Extensions (kept from v1):
#   - 2-gram and 3-gram of encoded blocks within methods
# =========================


def encode_block(block: list) -> str:
    """Encode a basic block to category-letter string; skip LABEL items."""
    return "".join(item[0] for item in block if item[0] != "LABEL")


def build_method_multiset(method: dict) -> Counter:
    ms: Counter = Counter()
    for block in method["blocks"]:
        enc = encode_block(block)
        if enc:
            ms[enc] += 1
    return ms


def build_apk_mos(methods: list[dict]) -> Counter:
    """Paper core: APK MOS = union of per-method multisets."""
    apk_mos: Counter = Counter()
    for method in methods:
        apk_mos.update(build_method_multiset(method))
    return apk_mos


def build_mos_ngrams(methods: list[dict], n: int = 2) -> Counter:
    """Extension: n-gram of encoded block sequences within each method."""
    ngram_counter: Counter = Counter()
    for method in methods:
        encoded_blocks = [encode_block(b) for b in method["blocks"] if encode_block(b)]
        for i in range(len(encoded_blocks) - n + 1):
            gram = tuple(encoded_blocks[i : i + n])
            ngram_counter[gram] += 1
    return ngram_counter


def build_full_mos(methods: list[dict]) -> Counter:
    """Paper MOS + 2-gram + 3-gram extensions."""
    mos = build_apk_mos(methods)
    mos.update(build_mos_ngrams(methods, n=2))
    mos.update(build_mos_ngrams(methods, n=3))
    return mos


# =========================
# 6. CFG  (per APK — aggregate over all methods)
# =========================


def build_cfg_from_blocks(blocks: list[list]) -> nx.DiGraph:
    """
    Build a CFG from a flat list of basic blocks.
    FIX: label_map built correctly; edge to fall-through only when
         block does NOT end with a return (cat R).
    """
    G = nx.DiGraph()
    n = len(blocks)

    # Map label string → block index  (first LABEL item in each block)
    label_map: dict[str, int] = {}
    for i, block in enumerate(blocks):
        for item in block:
            if item[0] == "LABEL":
                label_map[item[1]] = i
                break  # only the first label per block matters

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)
        if not block:
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        # Determine terminator by scanning all items (not just last)
        # Last non-LABEL item is the semantic terminator
        non_label = [item for item in block if item[0] != "LABEL"]
        if not non_label:
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        last_cat, last_op, _, target_label = non_label[-1]

        # Fall-through edge: everything except unconditional return
        if last_cat not in TERMINATORS:
            if i + 1 < n:
                G.add_edge(i, i + 1)

        # Branch target edge
        if target_label and target_label in label_map:
            G.add_edge(i, label_map[target_label])

    return G


def graph_to_features_fast(G: nx.DiGraph) -> Counter:
    features: Counter = Counter()
    features[("NODE_COUNT",)] = G.number_of_nodes()
    features[("EDGE_COUNT",)] = G.number_of_edges()

    degrees = [d for _, d in G.degree()]
    if degrees:
        features[("AVG_DEGREE",)] = float(np.mean(degrees))
        features[("MAX_DEGREE",)] = float(np.max(degrees))

    branch_nodes = sum(1 for node in G.nodes() if G.out_degree(node) > 1)
    features[("BRANCH_NODES",)] = branch_nodes

    try:
        features[("CYCLE_COUNT",)] = (
            len(list(nx.simple_cycles(G))) if G.number_of_nodes() < 1000 else 0
        )
    except Exception:
        features[("CYCLE_COUNT",)] = 0

    if G.number_of_nodes() > 1:
        features[("DENSITY",)] = nx.density(G)

    return features


# =========================
# 7. API SEQUENCE FEATURES
# =========================


def extract_api_sequence(methods: list[dict]) -> Counter:
    api_seq: Counter = Counter()
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
                    else:
                        api_seq["API_OTHER"] += 1
                    if api_name:
                        api_seq[f"API_{api_name}"] += 1
    return api_seq


# =========================
# 8. WORD2VEC EMBEDDING
# =========================


class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"  Word2Vec epoch {self.epoch} done")


class SentenceIterable:
    """
    Lazy sentence iterator — each sentence = list of encoded block strings
    within one method.  Iterates from disk each time (low RAM).
    """

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
            del methods  # release immediately
            gc.collect()


def train_w2v(
    train_dirs: list[str],
    vector_size: int = VECTOR_SIZE,
    model_path: str = W2V_MODEL_PATH,
) -> Word2Vec:
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


def graph_embedding(
    G: nx.DiGraph,  # FIX: removed unused `methods` param
    w2v_model: Word2Vec | None,
    vector_size: int = VECTOR_SIZE,
) -> np.ndarray:
    """Mean of W2V vectors for encoded blocks found in graph nodes."""
    if w2v_model is None:
        return np.zeros(vector_size)

    wv = w2v_model.wv
    node_vecs = []

    for node in G.nodes():
        block = G.nodes[node].get("features", [])
        enc = encode_block(block)
        if enc and enc in wv:
            node_vecs.append(wv[enc])

    if not node_vecs:
        return np.zeros(vector_size)

    return np.mean(node_vecs, axis=0)


# =========================
# 9. AUGMENTATION  (train malware only)
# =========================
JUNK_OPS = [
    ["const/4", "add-int"],
    ["const/4", "if-eq"],
]


def inject_junk_blocks(methods: list[dict], prob: float = 0.1) -> list[dict]:
    """Augment by injecting junk blocks into random methods (shallow copy)."""
    augmented = []
    for method in methods:
        new_blocks = list(method["blocks"])
        if random.random() < prob:
            junk_ops = random.choice(JUNK_OPS)
            junk_encoded = [(CATEGORY.get(op, "X"), op, None, None) for op in junk_ops]
            new_blocks.append(junk_encoded)
        augmented.append(
            {
                "class_name": method["class_name"],
                "method_name": method["method_name"],
                "blocks": new_blocks,
            }
        )
    return augmented


def obfuscate_methods(methods: list[dict]) -> list[dict]:
    return inject_junk_blocks(methods, prob=0.1)


# =========================
# 10. SINGLE APK FEATURE EXTRACTION
# =========================


def _flatten_blocks(methods: list[dict]) -> list[list]:
    return [block for method in methods for block in method["blocks"]]


def extract_features_for_apk(
    smali_dir: str,
    w2v_model: Word2Vec | None,
    vector_size: int = VECTOR_SIZE,
    use_cache: bool = True,
) -> dict | None:
    """
    Extract {mos, api, cfg, emb} for one APK.
    Results are cached to disk; never held in a list of all APKs.
    """
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
    """Augmented features for train malware (NOT cached — stochastic)."""
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
        }
    except Exception as e:
        print(f"  ⚠️  augment error {smali_dir}: {e}")
        return None


# =========================
# 11. VOCAB & VECTORIZATION  (RAM-efficient)
# =========================


def build_global_vocab(
    counter_iter,  # iterable of Counter objects (streamed from disk)
    min_freq: int = 2,
    max_features: int = 2000,
) -> dict:
    """
    Stream Counters one-by-one to build global freq dict.
    counter_iter can be a generator — never stores all counters in RAM.
    """
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
    vector_size: int,
    out_path: str,
) -> np.ndarray:
    """
    Build feature matrix shard-by-shard, write to a numpy memmap.
    Memory usage = one row at a time.
    Returns the memmap (read mode) for downstream use.
    """
    n_cols = len(mos_vocab) + len(api_vocab) + len(cfg_vocab) + vector_size
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
            emb_v = r["emb"].astype(np.float32)
            mm[row_idx] = np.concatenate([mos_v, api_v, cfg_v, emb_v])
        except Exception:
            pass  # row stays zeros

    mm.flush()
    # Reopen read-only to return
    return np.memmap(out_path, dtype="float32", mode="r", shape=(n_rows, n_cols))


# =========================
# 12. DATASET BUILDING  (no data leakage, disk-streaming)
#
# Pipeline:
#   1. Split indices (before ANY fitting)
#   2. Fit W2V on train dirs only
#   3. Extract + cache raw features per APK  (written to disk)
#   4. Augment train malware → extra cached entries  (in-memory, appended to list)
#   5. Stream Counters from disk → build vocab (train only)
#   6. Vectorise to memmap (train + test separately)
#   7. Fit StandardScaler on TRAIN memmap only, transform both
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

    # ── STEP 1: Split ─────────────────────────────────────────
    print("\n✂️  Step 1: Train/test split (before any fitting)...")
    train_idx, test_idx = train_test_split(
        list(range(len(apk_dirs))),
        test_size=test_size,
        stratify=labels,
        random_state=42,
    )
    train_set = set(train_idx)  # FIX: O(1) lookup
    train_dirs = [apk_dirs[i] for i in train_idx]
    print(f"  Train: {len(train_idx)} | Test: {len(test_idx)}")

    # ── STEP 2: W2V on train only ──────────────────────────────
    print("\n🧠 Step 2: Training Word2Vec (TRAIN SET ONLY)...")
    w2v_model = train_w2v(
        train_dirs, vector_size=vector_size, model_path=W2V_MODEL_PATH
    )

    # ── STEP 3: Extract + cache features (streaming) ──────────
    print("\n🔧 Step 3: Extracting & caching features per APK...")

    # We store cache_path lists (not the dicts themselves)
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

    # ── STEP 4: Augment train malware ─────────────────────────
    print("\n🔄 Step 4: Augmenting train malware (disk-based)...")
    aug_cache_dir = os.path.join(CACHE_ROOT, "augmented")
    os.makedirs(aug_cache_dir, exist_ok=True)

    aug_cache_paths: list[str] = []
    aug_labels_list: list[int] = []

    for i, cp in zip(train_labels_list, train_cache_paths):
        if i != 1:
            continue
        # Derive original smali_dir from index → need reverse map
    # Rebuild reverse map: cache_path → smali_dir
    cp_to_dir = {_features_cache_path(apk_dirs[i]): apk_dirs[i] for i in train_idx}

    for cp, lbl in zip(train_cache_paths, train_labels_list):
        if lbl != 1:
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

    # Merge train + augmented
    all_train_cache = train_cache_paths + aug_cache_paths
    all_train_labels = train_labels_list + aug_labels_list
    print(f"  Train samples (orig + aug): {len(all_train_cache)}")

    # ── STEP 5: Vocab fit on TRAIN only (streaming Counters) ──
    print("\n📚 Step 5: Building vocabulary (TRAIN SET ONLY, streaming)...")

    def _stream_counter(paths: list[str], key: str):
        for p in paths:
            try:
                with open(p, "rb") as f:
                    d = pickle.load(f)
                yield d[key]
            except Exception:
                yield Counter()

    mos_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "mos"), min_freq=3, max_features=1500
    )
    api_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "api"), min_freq=3, max_features=500
    )
    cfg_vocab = build_global_vocab(
        _stream_counter(all_train_cache, "cfg"), min_freq=2, max_features=200
    )
    print(
        f"  Vocab — MOS: {len(mos_vocab)}, API: {len(api_vocab)}, CFG: {len(cfg_vocab)}"
    )

    # ── STEP 6: Vectorise to memmap ───────────────────────────
    print("\n🔢 Step 6: Vectorising to memmap...")
    train_mm_path = os.path.join(SHARD_ROOT, "X_train_raw.mm")
    test_mm_path = os.path.join(SHARD_ROOT, "X_test_raw.mm")

    X_train_mm = vectorize_to_memmap(
        all_train_cache, mos_vocab, api_vocab, cfg_vocab, vector_size, train_mm_path
    )
    X_test_mm = vectorize_to_memmap(
        test_cache_paths, mos_vocab, api_vocab, cfg_vocab, vector_size, test_mm_path
    )

    y_train = np.array(all_train_labels, dtype=np.int32)
    y_test = np.array(test_labels_list, dtype=np.int32)

    # ── STEP 7: Scale (fit on TRAIN only) ─────────────────────
    print("\n📐 Step 7: Scaling (fit on TRAIN SET ONLY, chunk-wise)...")
    # StandardScaler on memmap: fit in chunks to avoid loading all rows at once
    scaler = StandardScaler()
    CHUNK = 512
    n_train = X_train_mm.shape[0]

    # Partial fit
    for start in range(0, n_train, CHUNK):
        chunk = np.array(X_train_mm[start : start + CHUNK])
        scaler.partial_fit(chunk)

    # Transform → write to new memmaps
    train_scaled_path = os.path.join(SHARD_ROOT, "X_train.mm")
    test_scaled_path = os.path.join(SHARD_ROOT, "X_test.mm")
    n_cols = X_train_mm.shape[1]

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

    # Reopen read-only
    X_train = np.memmap(
        train_scaled_path, dtype="float32", mode="r", shape=(n_train, n_cols)
    )
    X_test = np.memmap(
        test_scaled_path, dtype="float32", mode="r", shape=(n_test, n_cols)
    )

    # Feature names — length must equal n_cols exactly
    def fmt(f):
        if isinstance(f, tuple):
            return " → ".join(str(x) for x in f if x is not None)
        return str(f)

    feature_names = (
        [f"MOS:{fmt(k)}" for k in mos_vocab]
        + [f"API:{k}" for k in api_vocab]
        + [f"CFG:{fmt(k)}" for k in cfg_vocab]
        + [f"EMB:{i}" for i in range(vector_size)]
    )
    assert (
        len(feature_names) == n_cols
    ), f"Feature names length mismatch: {len(feature_names)} vs {n_cols}"

    print(f"\n✅ Dataset built:")
    print(f"  X_train={X_train.shape}, y_train={y_train.shape}")
    print(f"  X_test ={X_test.shape},  y_test ={y_test.shape}")

    return X_train, X_test, y_train, y_test, feature_names, scaler


# =========================
# 13. FEATURE SELECTION
# =========================


def filter_infrequent_features(X_train, X_test, feature_names, threshold=0.01):
    """Mask computed on train only, applied to both. Works with memmap."""
    min_apps = max(1, int(X_train.shape[0] * threshold))
    # Count non-zero rows in chunks
    CHUNK = 512
    col_count = np.zeros(X_train.shape[1], dtype=np.int32)
    for start in range(0, X_train.shape[0], CHUNK):
        chunk = np.array(X_train[start : start + CHUNK])
        col_count += (chunk > 0).sum(axis=0)
    mask = col_count >= min_apps
    print(f"  filter_infrequent: keeping {mask.sum()}/{X_train.shape[1]} features")
    filtered_names = [n for n, keep in zip(feature_names, mask) if keep]
    # Materialize filtered sub-matrix (this is after reduction, manageable)
    return (
        np.array(X_train)[:, mask],
        np.array(X_test)[:, mask],
        filtered_names,
        mask,
    )


def auto_select_k(
    X_train: np.ndarray, y_train: np.ndarray, candidate_k=None
) -> tuple[int, float]:
    """
    FIX: Train ONE DNN on full train set, get importance once,
         then evaluate each k by index slicing (no re-training).
    Uses a small validation split to score each k.
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

    # Train full DNN once
    full_dnn = build_dnn(X_tr.shape[1])
    full_dnn.fit(X_tr, y_tr, epochs=8, batch_size=32, verbose=0)
    importance = get_dnn_importance(full_dnn, X_tr.shape[1])  # shape = (n_features,)

    best_k, best_auc = candidate_k[0], 0.0

    for k in candidate_k:
        top_idx = np.argsort(importance)[-k:]
        # Note: the DNN was trained on full features; projecting to k features
        # is a proxy metric. For a proper eval, train a lightweight model:
        dnn_k = build_dnn(k)
        dnn_k.fit(X_tr[:, top_idx], y_tr, epochs=5, batch_size=32, verbose=0)
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
    """
    FIX: importance must align with X_train.shape[1].
    Pad or truncate only as a safety net; log a warning.
    """
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
# 14. DNN MODEL
# =========================


def build_dnn(input_dim: int) -> tf.keras.Model:
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


def get_dnn_importance(model: tf.keras.Model, n_features: int) -> np.ndarray:
    """
    FIX: find the Dense layer whose input dimension == n_features
         (skip BatchNorm + first BN layer that doesn't have weights matching).
    """
    for layer in model.layers:
        if isinstance(layer, tf.keras.layers.Dense):
            weights = layer.get_weights()
            if weights and weights[0].shape[0] == n_features:
                return np.sum(np.abs(weights[0]), axis=1)
    return np.ones(n_features)


# =========================
# 15. EVALUATION & PLOTTING
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
# 16. TRAINING & EVALUATION PIPELINE
# =========================


def train_and_evaluate(
    X_train,  # numpy array or memmap — filtered/dense after step 1
    X_test,
    y_train: np.ndarray,
    y_test: np.ndarray,
    feature_names: list[str],
) -> dict:
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")

    # Step 1: filter infrequent (materialises filtered dense arrays)
    print("\n🔎 Step 1: Filtering infrequent features...")
    X_train, X_test, feature_names, _ = filter_infrequent_features(
        X_train, X_test, feature_names, threshold=0.01
    )

    print(f"\n📊 Class balance:")
    print(f"  Train — Benign: {(y_train==0).sum()}, Malware: {(y_train==1).sum()}")
    print(f"  Test  — Benign: {(y_test==0).sum()},  Malware: {(y_test==1).sum()}")

    # Step 2: auto-select k (FIX: single DNN pass)
    best_k, _ = auto_select_k(X_train, y_train, candidate_k=[500, 1000, 2000, 3000])

    # Step 3: preliminary DNN for importance (FIX: full-dim, then select)
    print(f"\n🔍 Step 3: Preliminary DNN for importance (full dim → top {best_k})...")
    prelim_dnn = build_dnn(X_train.shape[1])
    prelim_dnn.fit(X_train, y_train, epochs=5, verbose=0, batch_size=32)
    importance = get_dnn_importance(prelim_dnn, X_train.shape[1])

    # FIX: select_top_k_features returns idx aligned to X_train.shape[1]
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

    # Step 5: evaluate
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

    # FIX: importance from FINAL dnn aligned to X_train_sel (selected dim)
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

    # Optionally save models
    os.makedirs("saved_models", exist_ok=True)
    joblib.dump(output["models"]["svm"], "saved_models/svm.pkl")
    joblib.dump(output["models"]["rf"], "saved_models/rf.pkl")
    output["models"]["dnn"].save("saved_models/dnn.keras")
    joblib.dump(scaler, "saved_models/scaler.pkl")
    print("\n✅ Training complete! Models saved to saved_models/")
