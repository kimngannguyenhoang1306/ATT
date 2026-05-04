# step4_train_evaluate.py
import numpy as np
import pandas as pd
import pickle
import os
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
from tensorflow import keras
from config import FEATURES_DIR, MODELS_DIR, K_BEST, RF_CONFIG, SVM_CONFIG
import matplotlib.pyplot as plt


# ═══════════════════════════════════════════════
# PHẦN 1: XÂY DỰNG DNN
# ═══════════════════════════════════════════════
def build_dnn(input_dim):
    """
    Xây dựng DNN theo Figure 2 bài báo:
    Input → Dense(256) → Dropout → Dense(256)
    → Dropout → Dense(128) → Dropout → Output(1)
    """
    model = keras.Sequential(
        [
            keras.layers.Input(shape=(input_dim,)),
            keras.layers.Dense(256, activation="relu"),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(256, activation="relu"),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(128, activation="relu"),
            keras.layers.Dropout(0.2),
            keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


# ═══════════════════════════════════════════════
# PHẦN 2: CHỌN FEATURES QUAN TRỌNG (SelectKBest)
# ═══════════════════════════════════════════════
def select_k_best_features(X_train, y_train, k):
    """
    Theo Section 4.4 bài báo:
    1. Train DNN nhỏ
    2. Lấy weights layer đầu tiên
    3. Tính importance = tổng |weights| mỗi feature
    4. Chọn K features quan trọng nhất
    """
    print(f"    Đang chọn {k} features quan trọng nhất...")

    # Train DNN nhỏ để tính importance
    dnn_fs = build_dnn(X_train.shape[1])
    dnn_fs.fit(X_train, y_train, epochs=10, batch_size=32, verbose=0)

    # Lấy weights layer đầu tiên (shape: n_features × 256)
    first_layer_weights = dnn_fs.layers[0].get_weights()[0]

    # Tính importance = tổng |weights| theo từng feature
    importance = np.sum(np.abs(first_layer_weights), axis=1)

    # Chọn K index có importance cao nhất
    top_k_indices = np.argsort(importance)[-k:]

    return top_k_indices


# ═══════════════════════════════════════════════
# PHẦN 3: ĐÁNH GIÁ MODEL
# ═══════════════════════════════════════════════
def evaluate_model(y_true, y_pred, y_prob, model_name):
    """
    Tính 4 metrics theo bài báo:
    - Accuracy : tổng số đoán đúng / tổng số APK
    - F1-Score : cân bằng precision và recall
    - AUC      : khả năng phân biệt malware/benign
    - FPR      : tỉ lệ app lành bị báo nhầm là malware
    """
    acc = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    auc = roc_auc_score(y_true, y_prob)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    print(f"    [{model_name}]")
    print(f"      Accuracy : {acc*100:.2f}%")
    print(f"      F1-Score : {f1*100:.2f}%")
    print(f"      AUC      : {auc*100:.2f}%")
    print(f"      FPR      : {fpr:.4f}")

    return {"accuracy": acc, "f1": f1, "auc": auc, "fpr": fpr}


# ═══════════════════════════════════════════════
# PHẦN 4: CHẠY EXPERIMENT CHÍNH
# ═══════════════════════════════════════════════
def run_experiment(df):
    """
    5-fold Cross Validation với 3 models:
    SVM, Random Forest, DNN
    """
    X = df.drop("label", axis=1).values.astype(np.float32)
    y = df["label"].values
    feature_names = list(df.drop("label", axis=1).columns)

    print(f"  Dataset : {X.shape[0]} APKs × {X.shape[1]} features")
    print(f"  Malware : {int(y.sum())}")
    print(f"  Benign  : {int((y==0).sum())}")

    # 5-fold vì dataset nhỏ (391 APK)
    # Stratified = đảm bảo tỉ lệ malware/benign đều trong mỗi fold
    N_FOLDS = 5
    skf = StratifiedKFold(n_splits=N_FOLDS, shuffle=True, random_state=42)
    all_results = {"SVM": [], "RF": [], "DNN": []}

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        print(f"\n{'='*45}")
        print(f"FOLD {fold+1}/{N_FOLDS}")
        print(f"  Train: {len(train_idx)} APKs | Test: {len(test_idx)} APKs")
        print(
            f"  Train malware: {int(y[train_idx].sum())} | "
            f"Train benign: {int((y[train_idx]==0).sum())}"
        )

        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        # ── SelectKBest ──────────────────────────────────
        # Chỉ dùng train set để chọn features
        # → Tránh data leakage (test set không được nhìn vào)
        selected_idx = select_k_best_features(X_train, y_train, k=K_BEST)
        X_train_sel = X_train[:, selected_idx]
        X_test_sel = X_test[:, selected_idx]
        print(f"    Features sau SelectKBest: {X_train_sel.shape[1]}")
        print(f"\n  Kết quả Fold {fold+1}:")

        # ── SVM ──────────────────────────────────────────
        svm = LinearSVC(C=SVM_CONFIG["C"], max_iter=SVM_CONFIG["max_iter"])
        svm.fit(X_train_sel, y_train)
        svm_pred = svm.predict(X_test_sel)
        svm_prob = svm.decision_function(X_test_sel)
        res = evaluate_model(y_test, svm_pred, svm_prob, "SVM")
        all_results["SVM"].append(res)

        # ── Random Forest ─────────────────────────────────
        rf = RandomForestClassifier(
            n_estimators=RF_CONFIG["n_estimators"],
            max_depth=RF_CONFIG["max_depth"],
            random_state=42,
            n_jobs=-1,
        )
        rf.fit(X_train_sel, y_train)
        rf_pred = rf.predict(X_test_sel)
        rf_prob = rf.predict_proba(X_test_sel)[:, 1]
        res = evaluate_model(y_test, rf_pred, rf_prob, "RF")
        all_results["RF"].append(res)

        # ── DNN ───────────────────────────────────────────
        dnn = build_dnn(X_train_sel.shape[1])
        early_stop = keras.callbacks.EarlyStopping(
            patience=10, restore_best_weights=True, monitor="val_loss"
        )
        dnn.fit(
            X_train_sel,
            y_train,
            validation_split=0.1,
            epochs=50,
            batch_size=32,
            callbacks=[early_stop],
            verbose=0,
        )
        dnn_prob = dnn.predict(X_test_sel, verbose=0).flatten()
        dnn_pred = (dnn_prob >= 0.5).astype(int)
        res = evaluate_model(y_test, dnn_pred, dnn_prob, "DNN")
        all_results["DNN"].append(res)

    # ── Kết quả trung bình ────────────────────────────────
    print(f"\n{'='*45}")
    print("KẾT QUẢ TRUNG BÌNH (5-fold CV):")
    print(f"{'='*45}")

    best_model_name = None
    best_auc = 0

    for model_name, results in all_results.items():
        avg_acc = np.mean([r["accuracy"] for r in results])
        avg_f1 = np.mean([r["f1"] for r in results])
        avg_auc = np.mean([r["auc"] for r in results])
        avg_fpr = np.mean([r["fpr"] for r in results])

        print(f"\n  {model_name}:")
        print(f"    Accuracy : {avg_acc*100:.2f}%")
        print(f"    F1-Score : {avg_f1*100:.2f}%")
        print(f"    AUC      : {avg_auc*100:.2f}%")
        print(f"    FPR      : {avg_fpr:.4f}")

        # Theo dõi model tốt nhất theo AUC
        if avg_auc > best_auc:
            best_auc = avg_auc
            best_model_name = model_name

    print(f"\n  ✅ Model tốt nhất: {best_model_name} (AUC={best_auc*100:.2f}%)")

    return all_results, best_model_name, feature_names, X, y


# ═══════════════════════════════════════════════
# PHẦN 5: LƯU MODEL ĐỂ DÙNG SAU
# ═══════════════════════════════════════════════
def save_final_model(X, y, feature_names, best_model_name):
    """
    Train lại với TOÀN BỘ dataset
    → Lưu model ra file để dùng predict.py

    Tại sao train lại?
    Trong cross-validation, mỗi fold chỉ train
    trên 80% data. Bây giờ train lại với 100%
    → Model mạnh hơn để dùng thật
    """
    print(f"\n{'='*45}")
    print(f"LƯU MODEL: Train lại với 100% data...")
    print(f"{'='*45}")

    os.makedirs(MODELS_DIR, exist_ok=True)

    # SelectKBest trên toàn bộ data
    selected_idx = select_k_best_features(X, y, k=K_BEST)
    X_final = X[:, selected_idx]
    print(f"  Features đã chọn: {X_final.shape[1]}")

    # Train model tốt nhất
    print(f"  Đang train {best_model_name}...")

    if best_model_name == "RF":
        final_model = RandomForestClassifier(
            n_estimators=RF_CONFIG["n_estimators"],
            max_depth=RF_CONFIG["max_depth"],
            random_state=42,
            n_jobs=-1,
        )
        final_model.fit(X_final, y)

    elif best_model_name == "SVM":
        final_model = LinearSVC(C=SVM_CONFIG["C"], max_iter=SVM_CONFIG["max_iter"])
        final_model.fit(X_final, y)

    elif best_model_name == "DNN":
        final_model = build_dnn(X_final.shape[1])
        final_model.fit(X_final, y, epochs=50, batch_size=32, verbose=0)

    # Lưu tất cả thông tin cần thiết vào 1 file
    model_data = {
        "model": final_model,  # model đã train
        "model_name": best_model_name,  # tên model
        "selected_idx": selected_idx,  # 500 index features
        "feature_names": feature_names,  # tên 33,372 MOS
        "k_best": K_BEST,  # số features
    }

    save_path = os.path.join(MODELS_DIR, "best_model.pkl")
    with open(save_path, "wb") as f:
        pickle.dump(model_data, f)

    print(f"  ✅ Đã lưu model tại: {save_path}")
    print(f"  Dùng predict.py để test APK mới!")


def save_metrics_fig(all_results):
    models = ["SVM", "RF", "DNN"]

    accs, f1s, aucs, fprs = [], [], [], []

    for m in models:
        r = all_results[m]
        accs.append(np.mean([x["accuracy"] for x in r]))
        f1s.append(np.mean([x["f1"] for x in r]))
        aucs.append(np.mean([x["auc"] for x in r]))
        fprs.append(np.mean([x["fpr"] for x in r]))

    x = np.arange(len(models))

    # Accuracy
    plt.figure()
    plt.bar(x, accs)
    plt.xticks(x, models)
    plt.ylabel("Accuracy")
    plt.title("Model Accuracy")
    plt.savefig(os.path.join(FIG_DIR, "accuracy.png"))
    plt.close()

    # F1
    plt.figure()
    plt.bar(x, f1s)
    plt.xticks(x, models)
    plt.ylabel("F1 Score")
    plt.title("Model F1 Score")
    plt.savefig(os.path.join(FIG_DIR, "f1.png"))
    plt.close()

    # AUC
    plt.figure()
    plt.bar(x, aucs)
    plt.xticks(x, models)
    plt.ylabel("AUC")
    plt.title("Model AUC")
    plt.savefig(os.path.join(FIG_DIR, "auc.png"))
    plt.close()

    # FPR
    plt.figure()
    plt.bar(x, fprs)
    plt.xticks(x, models)
    plt.ylabel("FPR")
    plt.title("Model False Positive Rate")
    plt.savefig(os.path.join(FIG_DIR, "fpr.png"))
    plt.close()

    print(f"📊 Saved figures to: {FIG_DIR}/")


# ═══════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 45)
    print("STEP 4: Train & Evaluate Models")
    print("=" * 45)

    FIG_DIR = "figs"
    os.makedirs(FIG_DIR, exist_ok=True)

    # Load feature matrix
    print("\nĐang load feature matrix...")
    df = pd.read_csv(os.path.join(FEATURES_DIR, "feature_matrix.csv"), index_col=0)

    # Chạy experiment
    all_results, best_model_name, feature_names, X, y = run_experiment(df)

    # Lưu model tốt nhất
    save_final_model(X, y, feature_names, best_model_name)

    save_metrics_fig(all_results)

    print("\n✅ Hoàn thành Step 4!")
    print("   Chạy predict.py để test APK mới:")
    print("   python3 predict.py <đường_dẫn_APK>")
