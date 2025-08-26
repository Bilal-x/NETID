import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
import joblib

# List of NSL-KDD feature names (41 features + 1 label + difficulty)
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
    'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
    'root_shell','su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label',          # Attack label
    'difficulty'      # Difficulty level as an integer
]

def load_preprocess_data(train_path, test_path):
    # Load datasets
    train_df = pd.read_csv(train_path, names=columns)
    test_df = pd.read_csv(test_path, names=columns)

    # Encode categorical columns
    categorical_cols = ['protocol_type', 'service', 'flag']
    encoder = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
    train_df[categorical_cols] = encoder.fit_transform(train_df[categorical_cols])
    test_df[categorical_cols] = encoder.transform(test_df[categorical_cols])

    # Debug print dtypes
    print("Data types before scaling (train):")
    print(train_df.dtypes)

    # Columns to scale (numeric features excluding categorical and labels)
    numeric_cols = [col for col in train_df.columns if col not in ['label', 'difficulty'] + categorical_cols]
    print("Numeric columns to scale:", numeric_cols)

    scaler = StandardScaler()
    train_df[numeric_cols] = scaler.fit_transform(train_df[numeric_cols])
    test_df[numeric_cols] = scaler.transform(test_df[numeric_cols])

    return train_df, test_df, scaler, encoder

def train_model(train_df):
    # Separate features and labels
    X_train = train_df.drop(['label', 'difficulty'], axis=1)
    y_train = train_df['label']

    # Train Random Forest Classifier
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    return model

if __name__ == "__main__":
    train_file = '../data/KDDTrain+.txt'
    test_file = '../data/KDDTest+.txt'

    # Load and preprocess data
    train_df, test_df, scaler, encoder = load_preprocess_data(train_file, test_file)
    print(f"Training data shape: {train_df.shape}")
    print(f"Test data shape: {test_df.shape}")
    print(train_df.head())

    # Train model
    model = train_model(train_df)

    # Save scaler, encoder, and model in models folder
    joblib.dump(scaler, '../models/scaler.joblib')
    joblib.dump(encoder, '../models/encoder.joblib')
    joblib.dump(model, '../models/model.joblib')

    print("Scaler, encoder, and model saved successfully.")
