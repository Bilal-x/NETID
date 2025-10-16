from scapy.all import sniff
from src.realtime.feature_extractor import extract_features
from src.preprocessing import preprocess_features
import joblib
import warnings
warnings.filterwarnings("ignore",category=UserWarning)
# Shared list for storing live results
live_results = []

model = joblib.load('models/model.joblib')
scaler = joblib.load('models/scaler.joblib')
encoder = joblib.load('models/encoder.joblib')

def predict_packet(packet):
    features = extract_features(packet)
    if features is not None:
        try:
            X = preprocess_features(features,encoder, scaler)
            pred = model.predict([X])[0]
            
            # Format the result for display
            result_text = f"Packet Prediction: {'Intrusion' if pred == 1 else 'Normal'} | Features: {features[:5]}..."
            
            # Add to shared results list (for Dash to read)
            live_results.append(result_text)
            
            # Also print to terminal (optional, for debugging)
            print(result_text)
            
        except Exception as e:
            error_msg = f"Error processing packet: {str(e)}"
            live_results.append(error_msg)
            print(error_msg)

def start_live_capture():
    global live_results
    # Clear previous results when starting new capture
    live_results = []
    print("Starting live packet sniffing (Ctrl+C to stop)...")
    sniff(prn=predict_packet, store=False)

if __name__ == '__main__':
    start_live_capture()
