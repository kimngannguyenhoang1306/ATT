# MOSDroid Step 4 - Model Parameters & Hyperparameters

## Feature Selection Parameters

```
K_BEST = 2000  # Số features chọn sau khi filter bằng DNN importance
MIN_FREQUENCY = 0.01  # Loại MOS xuất hiện < 1% apps (0.01 = 1%)
```

---

## Model 1: DNN (Deep Neural Network)

### Architecture
```
Input(features=K_BEST=2000)
  ↓
Dense(256, activation=ReLU)
  ↓
Dropout(0.2)
  ↓
Dense(256, activation=ReLU)
  ↓
Dropout(0.2)
  ↓
Dense(128, activation=ReLU)
  ↓
Dropout(0.2)
  ↓
Output(1, activation=Sigmoid)  [Binary classification]
```

### Hyperparameters

| Parameter | Value | Ý nghĩa |
|-----------|-------|---------|
| **layers** | [256, 256, 128] | 3 hidden layers với 256→256→128 units |
| **dropout** | 0.2 | 20% dropout để tránh overfitting |
| **activation** | ReLU | Rectified Linear Unit |
| **learning_rate** | 0.001 | Learning rate của Adam optimizer |
| **batch_size** | 32 | Train 32 samples cùng lúc |
| **epochs** | 50 | Train tối đa 50 epochs |
| **patience** | 10 | Early stopping nếu không improve sau 10 epochs |
| **optimizer** | Adam | Adaptive Moment Estimation |
| **loss** | binary_crossentropy | Loss function cho binary classification |
| **metrics** | accuracy | Evaluation metric |

### Công thức tính
```
Output = Sigmoid(Dense_128_output)

Sigmoid(x) = 1 / (1 + e^(-x))  # Output ∈ [0,1]
- Output > 0.5 → Malware (class 1)
- Output ≤ 0.5 → Benign (class 0)
```

---

## Model 2: Random Forest (RF)

### Hyperparameters

| Parameter | Value | Ý nghĩa |
|-----------|-------|---------|
| **n_estimators** | 100 | Số trees trong forest |
| **max_depth** | 25 | Độ sâu tối đa của mỗi tree |
| **min_samples_split** | 2 | Min samples cần để split node |
| **min_samples_leaf** | 1 | Min samples cần tại leaf node |
| **criterion** | gini (mặc định) | Gini impurity |
| **random_state** | (không fix) | Random tree selection |

### Công thức tính
```
RF_prediction = majority_vote(tree1, tree2, ..., tree100)

Gini impurity = 1 - Σ(p_i)^2  # p_i = tỉ lệ class i
```

### Ưu điểm
- Xử lý non-linear relationships tốt
- Có feature importance (dùng cho visualization)
- Ít overfitting hơn single tree

---

## Model 3: SVM (Support Vector Machine)

### Hyperparameters

| Parameter | Value | Ý nghĩa |
|-----------|-------|---------|
| **C** | 0.0625 | Regularization strength (0.0625 = 1/16) |
| **max_iter** | 5000 | Max iterations để tìm optimal boundary |
| **kernel** | linear | Linear decision boundary |
| **dual** | True (mặc định) | Solve dual problem |
| **class_weight** | balanced (có thể) | Cân bằng class không cân xứng |

### Công thức tính
```
Linear SVC: w·x + b = 0

Decision: f(x) = sign(w·x + b)
- f(x) > 0  → Malware (class 1)
- f(x) ≤ 0  → Benign (class 0)

Loss (hinge loss): L = Σ max(0, 1 - y_i(w·x_i + b)) + λ||w||²
```

### Regularization
```
C = 0.0625 = 1/16  → Mạnh regularization
- Ít overfitting
- Đơn giản hơn
- Có thể underfitting

Cao C → Ít regularization → Complex model
Thấp C → Mạnh regularization → Simple model
```

---

## Training Configuration

### Cross-Validation Strategy
```
StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
```
- **5-fold**: Chia data thành 5 phần
- **Stratified**: Giữ tỉ lệ malware/benign trong mỗi fold
- **Shuffle**: Xáo trộn trước khi chia
- **random_state=42**: Reproducible results

### Training Process
```
For each fold:
  1. Train DNN: 50 epochs với early stopping (patience=10)
  2. Train RF: 100 trees, max_depth=25
  3. Train SVM: Linear kernel, C=0.0625
  4. Evaluate trên validation fold
  5. Tính metrics: Accuracy, F1, AUC, FPR

Average metrics across 5 folds
```

---

## Comparison of Models

| Aspect | DNN | RF | SVM |
|--------|-----|----|----|
| **Complexity** | High | Medium | Low |
| **Training Time** | Slow | Fast | Medium |
| **Interpretability** | Black box | Medium | Medium |
| **Non-linear** | ✅ Yes | ✅ Yes | ❌ No (linear) |
| **Feature Importance** | ❌ Difficult | ✅ Yes | ❌ No |
| **Overfitting Risk** | High | Medium | Low |
| **Hyperparameter Tuning** | Complex | Easy | Easy |

---

## Output Metrics (Step 4)

After training & evaluation, step4 computes:

```
For each model:
  - Accuracy: TP+TN / (TP+TN+FP+FN)  →  0-1 (0-100%)
  - F1-Score: 2*Precision*Recall / (Precision+Recall)  →  0-1 (0-100%)
  - AUC: Area Under ROC Curve  →  0-1 (0-100%)
  - FPR: False Positive Rate = FP/(FP+TN)  →  0-1
```

---

## Summary Table

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 4 MODEL CONFIGURATION SUMMARY                         │
├─────────────────────────────────────────────────────────────┤
│ Feature Selection: K_BEST = 2000 features                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│ 1️⃣  DNN (Deep Neural Network)                             │
│    - Layers: 256 → 256 → 128 → 1                          │
│    - Dropout: 0.2 after each hidden layer                 │
│    - Learning rate: 0.001 (Adam optimizer)                │
│    - Batch size: 32                                       │
│    - Epochs: 50 (with early stopping, patience=10)        │
│                                                             │
│ 2️⃣  RF (Random Forest)                                    │
│    - Trees: 100                                           │
│    - Max depth: 25                                        │
│    - Min samples split: 2                                 │
│    - Min samples leaf: 1                                  │
│                                                             │
│ 3️⃣  SVM (Support Vector Machine - Linear)                │
│    - C (regularization): 0.0625 (strong regularization)  │
│    - Kernel: Linear                                       │
│    - Max iterations: 5000                                 │
│                                                             │
│ Evaluation: 5-Fold StratifiedKFold Cross-Validation      │
│ Metrics: Accuracy, F1-Score, AUC, FPR                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## References

- **DNN Architecture**: Figure 2 in MOSDroid paper
- **RF Parameters**: Tuned for malware detection
- **SVM Config**: Linear kernel for interpretability + speed
- **K_BEST**: 2000 features từ 3000+ candidates
- **Cross-Validation**: Standard 5-fold stratified approach

---

## How to Modify

To change parameters, edit `config.py`:

```python
# Change DNN
DNN_CONFIG = {
    "layers": [512, 256, 128],  # Deeper network
    "dropout": 0.3,             # More dropout
    "learning_rate": 0.0005,    # Lower learning rate
    "batch_size": 64,           # Larger batch
    "epochs": 100,              # More epochs
    "patience": 15,
}

# Change RF
RF_CONFIG = {
    "n_estimators": 200,        # More trees
    "max_depth": 30,            # Deeper trees
    "min_samples_split": 5,     # Higher threshold
    "min_samples_leaf": 2,
}

# Change SVM
SVM_CONFIG = {
    "C": 0.125,                 # Weaker regularization
    "max_iter": 10000,
}

# Change K_BEST
K_BEST = 3000  # Select more features
```

Then run: `python step4.py`
