# =========================
# MOSDroid FINAL (Paper-aligned MOS Core + CFG + API + Embedding)
# =========================
# Fixes aligned with paper:
#   "MOSDroid: Obfuscation-resilient android malware detection using
#    multisets of encoded opcode sequences"
#   Sharma et al., Maulana Azad NIT
#
# MOS core now correctly implements:
#   1. Method-level grouping (class → method → blocks)
#   2. Per-method basic block segmentation
#   3. Opcode → category encoding per block  (e.g. "MVGR")
#   4. Per-method multiset of encoded sequences
#   5. APK-level multiset = union of all method multisets
#
# Author extensions (kept as-is):
#   - CFG structural features (node/edge count, degree, cycles, density)
#   - API call type tracking
#   - Word2Vec graph embedding
#   - Data augmentation (junk block injection for malware)
#   - Anti-leakage pipeline (split → W2V → vocab → scaler all fit on train only)
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
TERMINATORS = {"R"}  # return  → terminates block
BRANCH_OPS = {"I"}  # if-*    → terminates block (branch)
W2V_MODEL_PATH = "w2v_model.model"

# ===========================================================
# 1. FULL OPCODE LIST (Dalvik) + CATEGORY MAPPING
#    Categories follow paper Table 1:
#      M = Move,  R = Return,  I = if-branch,
#      V = invoke/goto (Visit),  G = iget/sget,
#      P = iput/sput,  D = const (Data),
#      A = arithmetic,  X = other
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
    elif any(x in _op for x in ["add", "sub", "mul", "div", "rem"]):
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
# 3. SMALI PARSING
#    Returns method-level structure:
#      List[MethodInfo] where MethodInfo is a dict:
#        {
#          "class_name": str,
#          "method_name": str,
#          "blocks": List[List[Tuple(cat, op, api_name, target_label)]]
#        }
# =========================
REGISTER_PATTERN = re.compile(r"v\d+|p\d+")


def normalize_line(line: str) -> str:
    line = REGISTER_PATTERN.sub("vX", line)
    line = re.sub(r'".*?"', '"STR"', line)
    return line


def _parse_smali_file(file_path: str) -> list[dict]:
    """
    Parse một .smali file thành danh sách method dicts.
    Mỗi method dict:
        class_name   : str  (tên class từ .class directive)
        method_name  : str
        blocks       : List[List[Tuple(cat, op, api_name, target_label)]]
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

                # ── .class directive ───────────────────────────────────
                if line.startswith(".class"):
                    parts = line.split()
                    class_name = parts[-1] if len(parts) > 1 else "Unknown"
                    continue

                # ── Method start ───────────────────────────────────────
                if line.startswith(".method"):
                    in_method = True
                    parts = line.split()
                    current_method_name = parts[-1] if len(parts) > 1 else "unknown"
                    current_blocks = []
                    current_block = []
                    continue

                # ── Method end ─────────────────────────────────────────
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

                # ── Label line → new block boundary ───────────────────
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

                    # Block boundary: return or branch
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
    """
    Walk tất cả .smali files trong smali_dir,
    trả về flat list of method dicts.
    """
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
            # Giới hạn tổng số blocks để tránh OOM
            total_blocks = sum(len(m["blocks"]) for m in all_methods)
            if total_blocks >= MAX_BLOCKS_PER_APK:
                break

    return all_methods


# =========================
# 4. MOS CORE  (paper-aligned)
#
# Paper §3.2 & §3.3:
#   Step 1 – For each method, extract basic blocks (done in parser above)
#   Step 2 – Encode each block as a string of category letters
#             e.g. [const/4, add-int, if-eq] → "DAI"
#   Step 3 – Build per-method MULTISET = Counter({encoded_seq: count})
#   Step 4 – APK multiset = union of all method multisets
#             (key = encoded_seq, value = total count across methods)
#
# Additionally we keep 2-gram and 3-gram of encoded blocks (extension).
# =========================


def encode_block(block: list) -> str:
    """
    Encode một basic block thành chuỗi category letters.
    Bỏ qua LABEL items. Trả về "" nếu block rỗng.
    """
    return "".join(item[0] for item in block if item[0] != "LABEL")


def build_method_multiset(method: dict) -> Counter:
    """
    Tạo multiset (Counter) cho một method.
    Keys là encoded block strings (e.g. "MVGR", "DAI").
    """
    ms: Counter = Counter()
    for block in method["blocks"]:
        enc = encode_block(block)
        if enc:
            ms[enc] += 1
    return ms


def build_apk_mos(methods: list[dict]) -> Counter:
    """
    Paper core: APK-level MOS = union (sum) of per-method multisets.
    Key  = encoded block sequence string
    Val  = total occurrence count across all methods
    """
    apk_mos: Counter = Counter()
    for method in methods:
        apk_mos.update(build_method_multiset(method))
    return apk_mos


def build_mos_ngrams(methods: list[dict], n: int = 2) -> Counter:
    """
    Extension: n-gram of encoded block sequences within each method.
    For each method, treat the list of encoded blocks as a sentence,
    extract n-grams of encoded blocks, count them.
    """
    ngram_counter: Counter = Counter()
    for method in methods:
        encoded_blocks = [encode_block(b) for b in method["blocks"] if encode_block(b)]
        for i in range(len(encoded_blocks) - n + 1):
            gram = tuple(encoded_blocks[i : i + n])
            ngram_counter[gram] += 1
    return ngram_counter


def build_full_mos(methods: list[dict]) -> Counter:
    """
    Combines:
      1. APK-level MOS (paper core)        → keys are str
      2. 2-gram of encoded blocks           → keys are tuple
      3. 3-gram of encoded blocks           → keys are tuple
    """
    mos = build_apk_mos(methods)
    mos.update(build_mos_ngrams(methods, n=2))
    mos.update(build_mos_ngrams(methods, n=3))
    return mos


# =========================
# 5. CFG  (per APK — aggregate over all methods)
# =========================


def build_cfg_from_blocks(blocks: list[list]) -> nx.DiGraph:
    """
    Build a CFG from a flat list of basic blocks.
    Used for graph-level structural features.
    """
    G = nx.DiGraph()
    n = len(blocks)

    label_map: dict[str, int] = {}
    for i, block in enumerate(blocks):
        for item in block:
            if item[0] == "LABEL":
                label_map[item[1]] = i

    for i, block in enumerate(blocks):
        G.add_node(i, features=block)
        if not block:
            continue

        last = block[-1]
        cat, op, api_name, target_label = last

        if cat == "LABEL":
            if i + 1 < n:
                G.add_edge(i, i + 1)
            continue

        if not op.startswith("return") and i + 1 < n:
            G.add_edge(i, i + 1)
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
        features[("CYCLE_COUNT",)] = len(list(nx.simple_cycles(G)))
    except Exception:
        features[("CYCLE_COUNT",)] = 0

    if G.number_of_nodes() > 1:
        features[("DENSITY",)] = nx.density(G)

    return features


# =========================
# 6. API SEQUENCE FEATURES
# =========================


def extract_api_sequence(methods: list[dict]) -> Counter:
    """
    Extract API-call statistics from method-level structure.
    Counts invoke types and specific class names.
    """
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
# 7. CACHE  (method-level)
# =========================


def _methods_cache_path(smali_dir: str) -> str:
    return smali_dir.rstrip("/") + "_methods.pkl"


def _features_cache_path(smali_dir: str) -> str:
    return smali_dir.rstrip("/") + "_features.pkl"


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


# =========================
# 8. WORD2VEC EMBEDDING
#    Sentence = sequence of encoded blocks within a method
#    (paper: block-level opcode sequence as word)
# =========================


class EpochLogger(CallbackAny2Vec):
    def __init__(self):
        self.epoch = 0

    def on_epoch_end(self, model):
        self.epoch += 1
        print(f"  Word2Vec epoch {self.epoch} done")


class SentenceIterable:
    """
    Lazy sentence iterator for Word2Vec.
    Each 'sentence' = list of encoded block strings within one method.
    This preserves method-level context.
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


def train_w2v(
    train_dirs: list[str], vector_size: int = 32, model_path: str = W2V_MODEL_PATH
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
    methods: list[dict],
    G: nx.DiGraph,
    w2v_model: Word2Vec | None,
    vector_size: int = 32,
) -> np.ndarray:
    """
    Build graph embedding using W2V vectors of encoded blocks.
    Each node in G corresponds to a block; look up its encoded string in W2V.
    """
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
# 9. AUGMENTATION
#    Inject junk blocks (for train malware only, as extension)
# =========================
JUNK_OPS = [
    ["const/4", "add-int"],
    ["const/4", "if-eq"],
]


def inject_junk_blocks(methods: list[dict], prob: float = 0.1) -> list[dict]:
    """
    Augment by injecting junk blocks into random methods.
    Returns new list of method dicts (shallow copy + modified blocks).
    """
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
    """Flatten all blocks from all methods into a single list (for CFG)."""
    return [block for method in methods for block in method["blocks"]]


def extract_features_for_apk(
    smali_dir: str,
    w2v_model: Word2Vec | None,
    vector_size: int = 32,
    use_cache: bool = True,
) -> dict:
    """
    Extract {mos, api, cfg, emb} for one APK.
    MOS now correctly uses per-method multisets (paper-aligned).
    """
    cache_path = _features_cache_path(smali_dir)

    if use_cache and os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                cached = pickle.load(f)
            if all(k in cached for k in ("mos", "api", "cfg", "emb")):
                return cached
        except Exception:
            pass

    methods = get_methods_cached(smali_dir)
    blocks = _flatten_blocks(methods)
    G = build_cfg_from_blocks(blocks)

    result = {
        "mos": build_full_mos(methods),  # ← paper-aligned MOS
        "api": extract_api_sequence(methods),
        "cfg": graph_to_features_fast(G),
        "emb": graph_embedding(methods, G, w2v_model, vector_size=vector_size),
    }

    if use_cache:
        try:
            with open(cache_path, "wb") as f:
                pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            pass

    return result


def extract_features_augmented(
    smali_dir: str,
    w2v_model: Word2Vec | None,
    vector_size: int = 32,
) -> dict:
    """Features after augmentation (train malware only)."""
    methods = get_methods_cached(smali_dir)
    methods_aug = obfuscate_methods(methods)
    blocks_aug = _flatten_blocks(methods_aug)
    G_aug = build_cfg_from_blocks(blocks_aug)

    return {
        "mos": build_full_mos(methods_aug),
        "api": extract_api_sequence(methods_aug),
        "cfg": graph_to_features_fast(G_aug),
        "emb": graph_embedding(methods_aug, G_aug, w2v_model, vector_size=vector_size),
    }


# =========================
# 11. VOCAB & VECTORIZATION
# =========================


def build_global_vocab(
    all_counters: list[Counter], min_freq: int = 2, max_features: int = 2000
) -> dict:
    global_counter: Counter = Counter()
    for c in all_counters:
        global_counter.update(c)

    filtered = [(k, v) for k, v in global_counter.items() if v >= min_freq]
    filtered.sort(key=lambda x: -x[1])

    return {k: i for i, (k, _) in enumerate(filtered[:max_features])}


def counter_to_vector(counter: Counter, vocab: dict) -> np.ndarray:
    vec = np.zeros(len(vocab))
    for key, count in counter.items():
        if key in vocab:
            vec[vocab[key]] = count
    return vec


def vectorize_results(
    results: list[dict], mos_vocab: dict, api_vocab: dict, cfg_vocab: dict
) -> np.ndarray:
    X = []
    for r in results:
        mos_vec = counter_to_vector(r["mos"], mos_vocab)
        api_vec = counter_to_vector(r["api"], api_vocab)
        cfg_vec = counter_to_vector(r["cfg"], cfg_vocab)
        emb_vec = r["emb"]
        X.append(np.concatenate([mos_vec, api_vec, cfg_vec, emb_vec]))
    return np.array(X)


# =========================
# 12. DATASET BUILDING (no data leakage)
# =========================


def build_dataset(
    apk_dirs: list[str],
    labels: list[int],
    max_workers: int = 8,
    vector_size: int = 32,
    use_cache: bool = True,
    test_size: float = 0.2,
):
    """
    Full anti-leakage pipeline:
      1. Split indices first
      2. Fit W2V on train set only
      3. Extract raw features (cached)
      4. Augment train malware only
      5. Fit vocab + scaler on train set only
      6. Vectorize
    """
    # ── STEP 1: Split before any fitting ──────────────────────
    print("\n✂️  Step 1: Train/test split (before any fitting)...")
    train_idx, test_idx = train_test_split(
        list(range(len(apk_dirs))),
        test_size=test_size,
        stratify=labels,
        random_state=42,
    )
    train_dirs = [apk_dirs[i] for i in train_idx]
    print(f"Train: {len(train_idx)} | Test: {len(test_idx)}")

    # ── STEP 2: W2V on train only ──────────────────────────────
    print("\n🧠 Step 2: Training Word2Vec (TRAIN SET ONLY)...")
    w2v_model = train_w2v(
        train_dirs, vector_size=vector_size, model_path=W2V_MODEL_PATH
    )

    # ── STEP 3: Raw feature extraction ────────────────────────
    print("\n🔧 Step 3: Extracting raw features...")

    def worker(smali_dir):
        return extract_features_for_apk(
            smali_dir, w2v_model, vector_size=vector_size, use_cache=use_cache
        )

    all_dirs = [apk_dirs[i] for i in train_idx] + [apk_dirs[i] for i in test_idx]
    all_raw: dict[str, dict | None] = {}

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
    train_results: list[dict] = []
    train_combined_labels: list[int] = []

    for i, d in zip(train_idx, train_dirs):
        raw = all_raw.get(d)
        if raw is None:
            continue
        train_results.append(raw)
        train_combined_labels.append(labels[i])

        if labels[i] == 1:
            try:
                aug = extract_features_augmented(d, w2v_model, vector_size=vector_size)
                train_results.append(aug)
                train_combined_labels.append(1)
            except Exception:
                pass

    test_results: list[dict] = []
    test_combined_labels: list[int] = []
    for i, d in zip(test_idx, [apk_dirs[j] for j in test_idx]):
        raw = all_raw.get(d)
        if raw is None:
            continue
        test_results.append(raw)
        test_combined_labels.append(labels[i])

    del all_raw  # free RAM

    # ── STEP 5: Vocab fit on TRAIN only ───────────────────────
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

    # ── STEP 6: Vectorize ──────────────────────────────────────
    print("\n🔢 Step 6: Building feature vectors...")
    X_train_raw = vectorize_results(train_results, mos_vocab, api_vocab, cfg_vocab)
    X_test_raw = vectorize_results(test_results, mos_vocab, api_vocab, cfg_vocab)
    y_train = np.array(train_combined_labels)
    y_test = np.array(test_combined_labels)

    # ── STEP 7: Scaler fit on TRAIN only ──────────────────────
    print("\n📐 Step 7: Scaling (fit on TRAIN SET ONLY)...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_test = scaler.transform(X_test_raw)

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
# 13. FEATURE SELECTION
# =========================


def filter_infrequent_features(X_train, X_test, feature_names, threshold=0.01):
    """Mask computed on train only, applied to both."""
    min_apps = max(1, int(X_train.shape[0] * threshold))
    mask = np.sum(X_train > 0, axis=0) >= min_apps
    print(f"  filter_infrequent: keeping {mask.sum()}/{X_train.shape[1]} features")
    filtered_names = [n for n, keep in zip(feature_names, mask) if keep]
    return X_train[:, mask], X_test[:, mask], filtered_names, mask


def auto_select_k(X_train, y_train, candidate_k=None):
    if candidate_k is None:
        candidate_k = [500, 1000, 2000, 3000]
    candidate_k = [k for k in candidate_k if k <= X_train.shape[1]]
    if not candidate_k:
        return X_train.shape[1], 0.0

    print(f"\n🔍 auto_select_k (DNN): trying {candidate_k}...")

    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.2, stratify=y_train, random_state=42
    )

    # 👉 Train DNN once
    dnn = build_dnn(X_tr.shape[1])
    dnn.fit(X_tr, y_tr, epochs=5, batch_size=32, verbose=0)

    importance = get_dnn_importance(dnn, X_tr.shape[1])

    best_k, best_auc = candidate_k[0], 0.0

    for k in candidate_k:
        top_idx = np.argsort(importance)[-k:]

        # 👉 Train DNN lại với k features
        dnn_k = build_dnn(k)
        dnn_k.fit(X_tr[:, top_idx], y_tr, epochs=5, batch_size=32, verbose=0)

        probs = dnn_k.predict(X_val[:, top_idx], verbose=0).flatten()
        auc = roc_auc_score(y_val, probs)

        print(f"  k={k:>5} → AUC={auc:.4f}")

        if auc > best_auc:
            best_auc, best_k = auc, k

    print(f"  ✅ Best k = {best_k} (AUC={best_auc:.4f})")
    return best_k, best_auc


def select_top_k_features(X_train, X_test, importance, k):
    n = X_train.shape[1]
    importance = importance[:n] if importance is not None else np.ones(n)
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
    plt.show()


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
    plt.show()


# =========================
# 16. TRAINING & EVALUATION PIPELINE
# =========================


def train_and_evaluate(
    X_train, X_test, y_train, y_test, feature_names: list[str]
) -> dict:
    print(f"\n{'='*60}")
    print("TRAINING AND EVALUATION")
    print(f"{'='*60}")
    print(f"X_train: {X_train.shape}  |  X_test: {X_test.shape}")

    # Step 1: filter infrequent (train only)
    print("\n🔎 Step 1: Filtering infrequent features...")
    X_train, X_test, feature_names, _ = filter_infrequent_features(
        X_train, X_test, feature_names, threshold=0.01
    )

    print(f"\n📊 Class balance:")
    print(f"  Train — Benign: {(y_train==0).sum()}, Malware: {(y_train==1).sum()}")
    print(f"  Test  — Benign: {(y_test==0).sum()},  Malware: {(y_test==1).sum()}")

    # Step 2: auto-select k
    best_k, _ = auto_select_k(X_train, y_train, candidate_k=[500, 1000, 2000, 3000])

    # Step 3: preliminary DNN for importance
    print(f"\n🔍 Step 3: Preliminary DNN for importance (k={best_k})...")
    prelim_dnn = build_dnn(X_train.shape[1])
    prelim_dnn.fit(X_train, y_train, epochs=3, verbose=0, batch_size=32)
    importance = get_dnn_importance(prelim_dnn, X_train.shape[1])

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

    final_importance = get_dnn_importance(dnn, X_train_sel.shape[1])
    total_imp = np.sum(final_importance)
    if total_imp > 0:
        final_importance /= total_imp

    group_importance: dict[str, float] = defaultdict(float)
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
