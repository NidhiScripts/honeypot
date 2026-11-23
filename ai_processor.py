import time
import os
import threading
import json
import datetime
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

# --- CONFIGURATION ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("Error: GEMINI_API_KEY not found in environment variables. Please set it in .env file.")
    exit(1)

MODEL_NAME = "models/gemini-3-flash-preview"

# --- RELATIVE LOG PATHS ---
COWRIE_PATH = "cowrie/var/log/cowrie/cowrie.log"
SNARE_PATH  = "snare/snare.log"
AI_LOG_PATH = "ai_analysis.json"

# --- RATE LIMIT CONFIGURATION ---
# Safety buffer: 1 request every 15 seconds (4 calls/min)
MIN_SECONDS_BETWEEN_CALLS = 15
last_api_call_time = 0
api_lock = threading.Lock()

def setup_client():
    """Configures the new GenAI Client."""
    if "PASTE_YOUR" in GEMINI_API_KEY:
        print("ERROR: Please insert your Gemini API Key in the script.")
        exit(1)
    
    return genai.Client(api_key=GEMINI_API_KEY)

def safe_generate_content(client, prompt):
    """
    Thread-safe wrapper with rate limiting and retry logic.
    """
    global last_api_call_time
    
    with api_lock:
        # 1. Enforce delay
        current_time = time.time()
        time_since_last = current_time - last_api_call_time
        
        if time_since_last < MIN_SECONDS_BETWEEN_CALLS:
            sleep_needed = MIN_SECONDS_BETWEEN_CALLS - time_since_last
            print(f"    [Rate Limit] Sleeping {sleep_needed:.1f}s...")
            time.sleep(sleep_needed)

        # 2. Try API call
        retries = 0
        MAX_RETRIES = 5
        
        while retries < MAX_RETRIES:
            try:
                response = client.models.generate_content(
                    model=MODEL_NAME,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        # Disable safety filters specifically for security logs
                        safety_settings=[
                            types.SafetySetting(
                                category="HARM_CATEGORY_DANGEROUS_CONTENT",
                                threshold="BLOCK_NONE"
                            ),
                            types.SafetySetting(
                                category="HARM_CATEGORY_HATE_SPEECH",
                                threshold="BLOCK_NONE"
                            ),
                            types.SafetySetting(
                                category="HARM_CATEGORY_HARASSMENT",
                                threshold="BLOCK_NONE"
                            ),
                            types.SafetySetting(
                                category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                                threshold="BLOCK_NONE"
                            ),
                        ]
                    )
                )
                last_api_call_time = time.time()
                return response
            except Exception as e:
                error_str = str(e)
                if "429" in error_str:
                    print(f"    [!] Quota Exceeded. Waiting 60s...")
                    time.sleep(60)
                    continue
                elif "503" in error_str or "502" in error_str or "500" in error_str:
                    wait_time = 5 * (2 ** retries)  # Exponential backoff: 5, 10, 20, 40, 80
                    print(f"    [!] Server Error ({e}). Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    retries += 1
                    continue
                else:
                    print(f"    [!] API Error: {e}")
                    return None
        return None

def analyze_log(client, source_type, log_line):
    """Filters logs to prevent duplicates and sends to Gemini."""
    
    # --- COWRIE FILTER ---
    # Only process lines with actual commands (ignores connection/disconnection noise)
    if source_type == "Cowrie" and "CMD:" not in log_line:
        return

    # --- SNARE FILTER ---
    # Snare logs the request twice: once as 'snare.server' and once as 'aiohttp.access'.
    # We IGNORE 'aiohttp.access' because it's just a generic web log.
    # We KEEP 'snare.server' because it contains the full path and attack payload.
    if source_type == "Snare" and "aiohttp.access" in log_line:
        return

    if not log_line.strip():
        return

    prompt = (
        f"You are a security analyst. Analyze this {source_type} log. "
        f"Format: [Event] - [Intent] - [Severity]. Keep it very brief. Give a description of the attack, latest examples of such attack and how to defend against it.\n\n"
        f"Log: {log_line}"
    )

    response = safe_generate_content(client, prompt)
    
    if response:
        analysis_text = response.text.strip()
        print(f"\n>>> [ {source_type.upper()} ALERT ]")
        print(f"Log: {log_line.strip()[:80]}...") 
        print(f"Analysis: {analysis_text}")
        print("-" * 40)

        # Extract Severity
        severity = "Unknown"
        if "Severity] High" in analysis_text or "[High]" in analysis_text:
            severity = "High"
        elif "Severity] Medium" in analysis_text or "[Medium]" in analysis_text:
            severity = "Medium"
        elif "Severity] Low" in analysis_text or "[Low]" in analysis_text:
            severity = "Low"

        # Write to JSON Logs for Visualization
        try:
            entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "honeypot_source": source_type,
                "raw_log": log_line.strip(),
                "severity": severity,
                "analysis": analysis_text
            }
            with open(AI_LOG_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[!] Error writing to AI log: {e}")

def monitor_file(client, relative_path, source_type):
    """Tails a file."""
    full_path = os.path.abspath(relative_path)
    print(f"[*] Monitor starting: {source_type}")
    
    while not os.path.exists(full_path):
        print(f"    Waiting for file: {relative_path}")
        time.sleep(10)

    print(f"[+] {source_type} active.")

    with open(full_path, "r", encoding='utf-8', errors='ignore') as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(1)
                continue
            analyze_log(client, source_type, line)

if __name__ == "__main__":
    # Check for new library
    try:
        from google import genai
    except ImportError:
        print("Error: New SDK missing. Run: pip install -U google-genai")
        exit(1)

    client = setup_client()
    print(f"[+] System Online. Using {MODEL_NAME}")
    print(f"[+] Rate Limit: 1 request every {MIN_SECONDS_BETWEEN_CALLS}s")

    targets = [
        (COWRIE_PATH, "Cowrie"),
        (SNARE_PATH, "Snare")
    ]

    for path, name in targets:
        t = threading.Thread(target=monitor_file, args=(client, path, name))
        t.daemon = True
        t.start()

    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping.")