from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import preprocessing  # Import your preprocessing module

def train_intrusion_model():
    # Load preprocessed data
    train_df, test_df = preprocessing.load_preprocess_data('../data/KDDTrain+.txt', '../data/KDDTest+.txt')
    
    # Separate features and labels
    X_train = train_df.drop('label', axis=1)
    y_train = train_df['label']
    X_test = test_df.drop('label', axis=1)
    y_test = test_df['label']
    
    # Train Random Forest Classifier
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    # Predict on test set
    y_pred = clf.predict(X_test)
    
    # Print classification report
    print("Classification Report:\n", classification_report(y_test, y_pred))
    
    return clf

if __name__ == "__main__":
    model = train_intrusion_model()
