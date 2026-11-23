# HoneyGen: AI-Powered Honeypot Monitoring System

A comprehensive honeypot ecosystem allowing for the capture, logging, and AI-driven analysis of SSH and Web attacks. This project integrates industry-standard honeypots (**Cowrie**, **Snare/Tanner**) with modern **Generative AI** (Google Gemini) for real-time threat intelligence, visualized through an **ELK Stack**.

## 🏗 System Architecture

### 1. **SSH/Telnet Honeypot: [Cowrie](https://github.com/cowrie/cowrie)**
*   Simulates a vulnerable Linux shell.
*   Captures attacker credentials, command history, and file downloads.
*   Outputs logs to `cowrie/var/log/cowrie/cowrie.json`.

### 2. **Web Honeypot: [Snare & Tanner](https://github.com/mushorg/snare)**
*   **Snare**: The edge sensor that emulates a web server. It clones legitimate websites to fool attackers.
*   **Tanner**: The backend "brain" that classifies events and manages sessions.
*   Outputs logs to `/tmp/tanner_report.json`.

### 3. **AI Threat Analyst: `ai_processor.py`**
*   A custom Python engine connecting to **Google Gemini**.
*   Tails live logs from Cowrie and Snare.
*   **Analysis**: Determines intent (e.g., "Botnet Recruitment", "Credential Stuffing"), tools used, and threat severity.
*   **Action**: Enriches raw logs with human-readable descriptions and defense strategies.
*   Outputs structured analysis to `ai_analysis.json`.

### 4. **Visualization: The ELK Stack**
*   **Filebeat**: Ships logs from all three sources (Cowrie, Tanner, AI).
*   **Elasticsearch**: Indexes the data for fast searching.
*   **Kibana**: Provides a dashboard to visualize attack trends, geolocation, and AI insights.

---

## 🚀 Prerequisites

*   **OS**: macOS (Intel or Apple Silicon) / Linux.
*   **Python**: 3.10+
*   **Docker Desktop**: Required for the ELK stack.
*   **Google Gemini API Key**: For the AI processor.

---

## 🛠 Installation & Setup

### 1. Environment Setup
Clone the repository and set up the Python environment for the root scripts.

```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install python-dotenv google-genai
```

### 2. Configuration
Create a `.env` file in the root directory to store your API key:

```bash
echo "GEMINI_API_KEY=your_actual_api_key_here" > .env
```

### 3. Log Preparation
Ensure the log files exist so Docker permissions are handled correctly.

```bash
# Basic log file creation
touch ai_analysis.json
touch /tmp/tanner_report.json
chmod 644 ai_analysis.json
```

---

## ▶️ Running the System

### Step 1: Start the ELK Stack (Visualization)
This spins up Elasticsearch, Kibana, and Filebeat in the background.

```bash
docker compose -f docker-compose-elk.yml up -d
```
*   **Kibana Dashboard**: [http://localhost:5601](http://localhost:5601)

### Step 2: Start Cowrie (SSH Honeypot)
```bash
cd cowrie
source cowrie-env/bin/activate
cowrie start
```

### Step 3: Start Snare & Tanner (Web Honeypot)
*From the root directory, open two new terminals:*

**Terminal A (Tanner - The Brain):**
```bash
cd tanner
# activate your tanner env if applicable
tanner
```

**Terminal B (Snare - The Sensor):**
```bash
cd snare
# activate your snare env if applicable
sudo snare # Requires sudo for port 80 binding usually
```

### Step 4: Start the AI Processor
This script must be running to generate the AI insights in Kibana.

```bash
# In Root Directory
source .venv/bin/activate
python ai_processor.py
```

---

## 📊 Visualizing Data

1.  Open **Kibana** at [http://localhost:5601](http://localhost:5601).
2.  Navigate to **Stack Management** > **Index Patterns**.
3.  Create an index pattern for `filebeat-*`.
4.  Select `@timestamp` as the time field.
5.  Go to **Discover** to see your logs.

### Filters to Use
*   **SSH Attacks**: `event_source: "cowrie"`
*   **Web Attacks**: `event_source: "tanner"`
*   **AI Insights**: `event_source: "gemini_ai"`

---

## 📁 Project Structure

```
.
├── ai_processor.py          # Main AI Analysis Script
├── ai_analysis.json         # Output of AI Analysis (ingested by ELK)
├── docker-compose-elk.yml   # Docker services for Visualization
├── filebeat.yml             # Log shipper configuration
├── .env                     # API Keys (GitIgnored)
├── cowrie/                  # SSH Honeypot Folder
├── snare/                   # Web Honeypot Sensor
└── tanner/                  # Web Honeypot Brain
```
