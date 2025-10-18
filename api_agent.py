import pandas as pd
import joblib
from datetime import datetime
import sys
import shap
from flask import Flask, request, jsonify
from sklearn.model_selection import train_test_split # <-- Import added


print("---Initializing the IDS Agent ---")


agent_model = None
explainer = None


MODEL_FILE = 'ids_agent_model.joblib'
LOG_FILE = 'security_alerts_api.log'
DECISION_THRESHOLD = 0.3


REFERENCE_COLUMNS = [
    'network_packet_size', 'login_attempts', 'session_duration',
    'ip_reputation_score', 'failed_logins', 'unusual_time_access',
    'protocol_type_TCP', 'protocol_type_UDP', 'encryption_used_DES',
    'encryption_used_None', 'browser_type_Edge', 'browser_type_Firefox',
    'browser_type_Safari', 'browser_type_Unknown'
]


def load_models():
    """Loads the AI model and properly initializes the SHAP explainer."""
    global agent_model, explainer
    try:
        agent_model = joblib.load(MODEL_FILE)
        print(f"AI brain '{MODEL_FILE}' loaded successfully.")

        print("Initializing SHAP explainer with background data...")
        df = pd.read_csv("the_dataset.csv")
        df['encryption_used'] = df['encryption_used'].fillna('None')
        df_processed = df.drop('session_id', axis=1)
        categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
        df_processed = pd.get_dummies(df_processed, columns=categorical_cols, drop_first=True)
        df_processed = df_processed.astype(int)
        
        X = df_processed.drop('attack_detected', axis=1)
        y = df_processed['attack_detected']
        X_train, _, _, _ = train_test_split(X, y, test_size=0.2, random_state=42)
        
        
        explainer = shap.TreeExplainer(agent_model, X_train)
        print("SHAP Explainer is ready.")

    except FileNotFoundError:
        print(f"FATAL ERROR: Model file '{MODEL_FILE}' not found. Cannot start agent.")
        sys.exit()

def analyze_data(session_data):
    """The core logic: analyzes data, gets an explanation, logs, and returns a result."""
    features_df = pd.DataFrame([session_data])[REFERENCE_COLUMNS]
    prediction = agent_model.predict(features_df)[0]
    attack_probability = agent_model.predict_proba(features_df)[:, 1][0]
    is_threat = attack_probability >= DECISION_THRESHOLD
    
    explanation = "N/A (Confidence below threshold)"
    if is_threat:
        shap_values = explainer(features_df)
        top_features = pd.Series(shap_values.values[0], index=features_df.columns).abs().nlargest(3)
        explanation_parts = [f"'{feature}'" for feature, _ in top_features.items()]
        explanation = "Key factors: " + ", ".join(explanation_parts)
        log_incident(session_data, attack_probability, explanation)
        
    response = {
        'is_threat': bool(is_threat),
        'threat_confidence': float(attack_probability),
        'prediction_explanation': explanation
    }
    return response

def log_incident(session_data, attack_prob, explanation):
    """Logs the details of a detected threat to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] - ALERT: Threat Detected via API\n"
        f"  - Confidence Score: {attack_prob:.2%}\n"
        f"  - AI Explanation: {explanation}\n"
        f"  - Full Data Received: {session_data}\n"
        f"----------------------------------------------------\n"
    )
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(log_entry)


app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    """The main API endpoint."""
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    session_data = request.get_json()
    
    if not all(col in session_data for col in REFERENCE_COLUMNS):
        return jsonify({"error": f"Missing features. Please provide all: {REFERENCE_COLUMNS}"}), 400

    result = analyze_data(session_data)
    
    return jsonify(result)


if __name__ == "__main__":
    load_models()
    app.run(host='0.0.0.0', port=5000, debug=False) 
