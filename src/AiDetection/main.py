import glob
import json
import os

import joblib
import numpy as np
import pandas as pd
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# 1. Find all CSV files
csv_files = glob.glob("src/archive/*.csv")
print(f"Found {len(csv_files)} files")

df_list = []
for f in csv_files:
    print(f"Loading {f} ...")
    df = pd.read_csv(f, low_memory=False)
    df_list.append(df)

df = pd.concat(df_list, ignore_index=True)
print(f"Total rows: {len(df)}")

# 2. Auto‑detect label column (case‑insensitive, trim spaces)
possible_label_names = ["Label", "label", "Attack", "attack", " Label", " attack"]
label_col = None
for col in df.columns:
    col_clean = col.strip()
    if col_clean in [name.strip() for name in possible_label_names]:
        label_col = col
        break
if label_col is None:
    raise KeyError(
        f"Could not find label column. Available columns: {df.columns.tolist()[:20]}..."
    )

print(f"Using label column: '{label_col}'")

# 3. Drop rows where label is missing
df = df.dropna(subset=[label_col])

# 4. Drop non‑feature columns (common metadata)
drop_cols = ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Protocol"]
for col in drop_cols:
    if col in df.columns:
        df = df.drop(columns=[col])

# 5. Separate features and labels
X = df.drop(columns=[label_col])
y = df[label_col]

# 6. Clean infinite / NaN values
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

# 7. Encode labels: BENIGN = 0, any attack = 1
y_binary = (y != "BENIGN").astype(int)
print(f"Attack samples: {y_binary.sum()} / {len(y_binary)}")

# 8. Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
)

# 9. Standardize
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 10. Train Random Forest
model = RandomForestClassifier(
    n_estimators=100, max_depth=20, random_state=42, n_jobs=-1, class_weight="balanced"
)
model.fit(X_train_scaled, y_train)

# 11. Evaluate
y_pred = model.predict(X_test_scaled)
print(classification_report(y_test, y_pred))

# 12. Save artifacts
os.makedirs("models", exist_ok=True)
joblib.dump(scaler, "models/scaler.pkl")
joblib.dump(model, "models/rf_model.pkl")

with open("models/feature_columns.txt", "w") as f:
    f.write("\n".join(X.columns.tolist()))

scaler_params = {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist()}
with open("models/scaler.json", "w") as f:
    json.dump(scaler_params, f)

# 13. Convert to ONNX
initial_type = [("float_input", FloatTensorType([None, X_train.shape[1]]))]
onnx_model = convert_sklearn(
    model, initial_types=initial_type, options={id(model): {"zipmap": False}}
)
with open("models/ids_model.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

# made the color green hehehehe
print("\033[92mModel and scaler saved to models/\033[0m")
