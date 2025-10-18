import requests
import json


API_URL = "http://127.0.0.1:5000/analyze"


suspicious_session = {
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


normal_session = {
    "network_packet_size": 200,
    "login_attempts": 1,
    "session_duration": 1800.0,
    "ip_reputation_score": 0.8,
    "failed_logins": 0,
    "unusual_time_access": 0,
    "protocol_type_TCP": 1,
    "protocol_type_UDP": 0,
    "encryption_used_DES": 0,
    "encryption_used_None": 0,
    "browser_type_Edge": 0,
    "browser_type_Firefox": 1,
    "browser_type_Safari": 0,
    "browser_type_Unknown": 0
}

def check_session(session_data, description):
    """Sends session data to the API and prints the response."""
    print(f"--- Analyzing {description} Session ---")
    try:
        response = requests.post(API_URL, json=session_data)
        response.raise_for_status() 
        
        result = response.json()
        print("Agent Response:")
        print(json.dumps(result, indent=2))
        
    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the agent API: {e}")
    print("-" * 30)

if __name__ == "__main__":
    check_session(suspicious_session, "Suspicious")
    check_session(normal_session, "Normal")
