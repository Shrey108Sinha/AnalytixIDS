#AnalytixIDS
# ML-Based Intrusion Detection System with Explainable AI

A production-ready Flask API for real-time network threat detection using machine learning and explainable AI (XAI). This project demonstrates end-to-end ML engineering, from model training to API deployment with interpretability.

## Overview

This system analyzes network session data to identify potential security threats with explainable predictions. It uses a fine-tuned XGBoost classifier optimized for high recall (catching threats) while maintaining precision to minimize false alarms.

**Key Achievement**: Model achieves 99%+ threat detection confidence with interpretable explanations via SHAP.

## Features

- **Real-time Threat Detection**: Analyzes network sessions via REST API with sub-millisecond response times
- **Explainable AI (XAI)**: SHAP integration provides human-readable explanations for every threat detection
- **Production Architecture**: Microservice design with structured logging, error handling, and JSON APIs
- **Optimized for Security**: Decision threshold tuned to 0.3 (vs. default 0.5) to prioritize threat recall
- **Automated Incident Logging**: Detailed security alerts logged with confidence scores and evidence

## Architecture

```
Training Phase 
├── Data preprocessing & one-hot encoding
├── Model comparison (Decision Tree → Random Forest → XGBoost)
├── Threshold optimization (recall vs. precision trade-off)
└── Model serialization → ids_agent_model.joblib

Inference Phase (Flask API)
├── Load pre-trained model & SHAP explainer
├── Receive session data via POST /analyze
├── Generate predictions & SHAP explanations
└── Log incidents to security_alerts_api.log
```

## Requirements

- Python 3.8+
- Flask, scikit-learn, XGBoost, SHAP, pandas, joblib
- See `requirements.txt` for full dependencies

## Setup

1. **Clone and navigate:**
   ```bash
   git clone 
   cd AnalytixIDS
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## ⚡ Quick Start

**Terminal 1** - Start the API server:
```bash
python api_agent.py
```

**Terminal 2** - Run client tests:
```bash
python client.py
```

**Output**:
- JSON threat assessments in terminal
- Detailed incident logs in `security_alerts_api.log`

## 📡 API Endpoint

### POST `/analyze`

Analyzes a network session and returns threat assessment.

**Request:**
```json
{
    "network_packet_size": 850,
    "login_attempts": 9,
    "session_duration": 120.5,
    "ip_reputation_score": 0.2,
    "failed_logins": 4,
    "unusual_time_access": 1,
    "protocol_type_TCP": 1,
    "protocol_type_UDP": 0,
    "encryption_used_DES": 1,
    "encryption_used_None": 0,
    "browser_type_Edge": 1,
    "browser_type_Firefox": 0,
    "browser_type_Safari": 0,
    "browser_type_Unknown": 0
}
```

**Response:**
```json
{
    "is_threat": true,
    "threat_confidence": 0.9999,
    "prediction_explanation": "Key factors: 'failed_logins', 'login_attempts', 'browser_type_Edge'"
}
```

## Model Performance

| Aspect | Details |
|--------|---------|
| **Algorithm** | XGBoost with class weight balancing |
| **Decision Threshold** | 0.3 (tuned for high recall) |
| **Key Features** | Failed logins, login attempts, IP reputation, session duration |
| **Explainability** | SHAP TreeExplainer with top-3 feature attribution |

## How It Works

1. **Data arrives** at `/analyze` endpoint as JSON
2. **Model predicts** threat probability using XGBoost
3. **If threat detected** (confidence ≥ 0.3):
   - SHAP calculates feature importance
   - Top 3 contributing factors extracted
   - Incident logged with explanation
4. **Response** returned with threat flag, confidence, and explanation

## Project Structure

```
.
├── Training_Notebook.ipynb       # ML training & model selection
├── api_agent.py                  # Flask API server
├── client.py                     # Test client
├── ids_agent_model.joblib        # Serialized trained model
├── security_alerts_api.log       # Incident log
└── requirements.txt              # Dependencies
```

## Technical Decisions

- **XGBoost over alternatives**: Superior performance on imbalanced classification
- **0.3 threshold tuning**: Prioritizes threat detection (recall) for security use case
- **SHAP explanations**: Builds trust in predictions; critical for security systems
- **API design**: Stateless microservice for scalability and easy integration

## Learning Outcomes

This project demonstrates:
- End-to-end ML pipeline (data → training → deployment)
- Model evaluation and threshold optimization
- API design and error handling
- ML interpretability and explainable AI
- Security-focused ML engineering

## Future Enhancements

- Drift detection for model performance monitoring
- Adaptive threshold based on false positive feedback
- Temporal feature engineering for session pattern analysis
- Real-time model retraining pipeline
- Integration with SIEM systems

## Notes

- Ensure `the_dataset.csv` is in the project root before running training
- Model requires all 14 features for predictions (no partial data accepted)
- Log file grows with each threat detected; implement rotation for production
