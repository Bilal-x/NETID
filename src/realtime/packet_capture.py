import threading
from scapy.all import sniff
from src.realtime.feature_extractor import extract_features
from src.preprocessing import preprocess_features
from src.realtime.prevention import simulate_block_action, log_prevention_action
import joblib
import warnings

warnings.filterwarnings("ignore", category=UserWarning)

live_results = []

model = joblib.load('models/model.joblib')
scaler = joblib.load('models/scaler.joblib')
encoder = joblib.load('models/encoder.joblib')

stop_sniff_event = threading.Event()

def predict_packet(packet):
    features = extract_features(packet)
    if features is not None:
        try:
            X = preprocess_features(features, encoder, scaler)
            pred = model.predict([X])[0]
            result_text = f"Packet Prediction: {'Intrusion' if pred != 'normal' else 'Normal'} | Features: {features[:5]}..."
            if pred != 'normal':
                prevention_success = simulate_block_action(packet)
                if prevention_success:
                    result_text += " | ACTION: IP BLOCKED"
                else:
                    result_text += " | ACTION: BLOCK FAILED"
            live_results.append(result_text)
            print(result_text)
        except Exception as e:
            error_msg = f"Error processing packet: {str(e)}"
            live_results.append(error_msg)
            print(error_msg)

def sniff_with_stop(*args, **kwargs):
    sniff(prn=kwargs.get('prn'), store=kwargs.get('store', False), stop_filter=lambda x: stop_sniff_event.is_set())

def start_capture_thread():
    stop_sniff_event.clear()
    log_prevention_action("Starting live packet sniffing with prevention enabled")
    print("Starting live packet sniffing (use stop_capture to stop)...")
    capture_thread = threading.Thread(target=sniff_with_stop, kwargs={'prn': predict_packet, 'store': False})
    capture_thread.start()
    return capture_thread

def stop_capture():
    stop_sniff_event.set()
    log_prevention_action("Stopping live packet sniffing")
    print("Stopping live packet sniffing...")

if __name__ == '__main__':
    thread = start_capture_thread()
    # Example: To stop capture after 10 seconds (for demonstration)
    # import time
    # time.sleep(10)
    # stop_capture()
    # thread.join()
