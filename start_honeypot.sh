#!/bin/bash

# Definition of the project root
PROJECT_ROOT=$(pwd)

echo "Starting HoneyGen Ecosystem..."
echo "Project Root: $PROJECT_ROOT"

# Function to run a command in a NEW TERMINAL WINDOW
run_in_new_window() {
    local cmd="cd \"$PROJECT_ROOT\"; $1"
    
    osascript - "$cmd" <<EOF
    on run argv
        tell application "Terminal"
            activate
            -- 'do script' by itself creates a new window automatically
            do script (item 1 of argv)
        end tell
    end run
EOF
}

# 1. Start Cowrie (SSH)
echo "Starting Cowrie..."
run_in_new_window "cd cowrie; source cowrie-env/bin/activate; cowrie start; echo 'Cowrie Started (Backgrounded)'"

# 2. Start Tanner (Brain)
echo "Starting Tanner..."
run_in_new_window "cd tanner; source tanner-env/bin/activate; tanner"

echo "Waiting 10s for Tanner to initialize..."
sleep 10

# 3. Start Snare (Sensor)
echo "Starting Snare..."
SNARE_CMD="cd snare; source snare-env/bin/activate; snare --port 8080 --page-dir \"$(pwd)/snare/manual_site\" --tanner localhost --index-page /"
run_in_new_window "$SNARE_CMD"

# 4. Start AI Processor
echo "Starting AI Processor..."
run_in_new_window "source .venv/bin/activate; python ai_processor.py"

echo "All systems initialized."