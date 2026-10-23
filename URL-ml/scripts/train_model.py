import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load cleaned dataset
data = pd.read_csv("../data/cleaned_data.csv")

# Separate features and label
X = data.drop(columns=['url', 'label'])
y = data['label']

print("Feature columns:", X.columns)

# Split dataset
from sklearn.model_selection import GroupShuffleSplit

# Group by DOMAIN (IMPORTANT)
data['domain_group'] = data['url'].apply(lambda x: x.split('/')[2] if '//' in x else x)

groups = data['domain_group']

gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)

train_idx, test_idx = next(gss.split(X, y, groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]
# Normalize features (VERY IMPORTANT for ML)
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("Training data shape:", X_train.shape)
print("Testing data shape:", X_test.shape)

print("✅ Data prepared successfully")


# 🔥 TRAIN MODEL
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# 📊 Evaluate
y_pred = model.predict(X_test)

print("\n================ MODEL RESULTS ================\n")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))