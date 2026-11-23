# Kibana Visualization Status

## ✅ Fixed Issues

### 1. Filebeat Configuration
- **Problem**: Path mismatch - Filebeat was looking for `/logs/cowrie/cowrie.json` but docker mounted the folder
- **Fix**: Changed to `/logs/cowrie/*.json` to match all JSON files in the directory
- **Status**: ✅ Working - 11 Cowrie events flowing

### 2. Visualization Types
- **Problem**: "Unknown visualization type" for line chart (not supported in Kibana 7.17)
- **Fix**: Changed from `line` to `area` chart type
- **Status**: ✅ Fixed

### 3. Index Pattern References
- **Problem**: Visualizations referenced deleted index pattern
- **Fix**: Recreated visualizations with correct index pattern ID: `d4190a60-f69b-11f0-bd7d-75457bbc1500`
- **Status**: ✅ Fixed

## 📊 Current Data Status

```bash
Cowrie Events:    11 events (SSH honeypot)
AI Analysis:      34 events (Gemini threat analysis)
Tanner Events:    0 events (needs Tanner to be running)
```

## 🗺️ Visualizations

### 1. HoneyGen - Threat Severity Timeline
- **Type**: Area chart (stacked)
- **Query**: `event_source: gemini_ai`
- **Shows**: High/Medium/Low severity threats over time
- **ID**: `6ffcceb0-f69e-11f0-bd7d-75457bbc1500`

### 2. HoneyGen - Attacker Origins Map
- **Type**: Coordinate map
- **Query**: `event_source: (cowrie OR tanner)`
- **Field**: `geoip.location`
- **Shows**: Geographic distribution of attackers
- **ID**: `70908330-f69e-11f0-bd7d-75457bbc1500`
- **Note**: Will only show data for non-local IP addresses (not 127.0.0.1)

## 🚀 Next Steps

1. **Get Real Attacker Data**: 
   - Current logs only have 127.0.0.1 (localhost)
   - To see GeoIP map: Expose honeypots publicly (see PUBLIC_EXPOSURE_GUIDE.md)
   
2. **Restart AI Processor** (currently stopped):
   ```bash
   cd /Users/suraj/Documents/Suraj/Projects/honeypot
   source .venv/bin/activate
   python ai_processor.py &
   ```

3. **Start Tanner** (to get HTTP honeypot data):
   - Use the `start_honeypot.sh` script or run manually

4. **Access Kibana**:
   - URL: http://localhost:5601
   - Go to: Visualize Library
   - Or create a Dashboard and add both visualizations

## 🔧 Commands

### Check Data Flow
```bash
# Count events by source
curl -s 'http://localhost:9200/filebeat-*/_count?q=event_source:cowrie'
curl -s 'http://localhost:9200/filebeat-*/_count?q=event_source:gemini_ai'
curl -s 'http://localhost:9200/filebeat-*/_count?q=event_source:tanner'

# Check Filebeat status
docker logs filebeat --tail 20

# Restart Filebeat if needed
docker restart filebeat
```

### Recreate Visualizations
```bash
./setup_kibana_visualizations.sh
```
