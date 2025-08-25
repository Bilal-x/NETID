import pandas as pd
from sklearn.preprocessing import OrdinalEncoder, StandardScaler

# List of NSL-KDD feature names (41 features + 1 label)
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
    train_df = pd.read_csv(train_path, names=columns)
    test_df = pd.read_csv(test_path, names=columns)

    categorical_cols = ['protocol_type', 'service', 'flag']
    encoder = OrdinalEncoder(handle_unknown='use_encoded_value', unknown_value=-1)
    train_df[categorical_cols] = encoder.fit_transform(train_df[categorical_cols])
    test_df[categorical_cols] = encoder.transform(test_df[categorical_cols])

    # DEBUG: print dtypes of columns before scaling
    print("Data types before scaling (train):")
    print(train_df.dtypes[categorical_cols + [c for c in train_df.columns if c not in categorical_cols]])

    numeric_cols = [col for col in train_df.columns if col not in ['label'] + categorical_cols]
    print("Numeric columns to scale:", numeric_cols)

    scaler = StandardScaler()
    train_df[numeric_cols] = scaler.fit_transform(train_df[numeric_cols])
    test_df[numeric_cols] = scaler.transform(test_df[numeric_cols])

    return train_df, test_df



if __name__ == "__main__":
    train_file = '../data/KDDTrain+.txt'
    test_file = '../data/KDDTest+.txt'
    train_df, test_df = load_preprocess_data(train_file, test_file)
    print(f"Training data shape: {train_df.shape}")
    print(f"Test data shape: {test_df.shape}")
    print(train_df.head())
