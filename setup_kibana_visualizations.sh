#!/bin/bash

# Script to recreate Kibana visualizations with correct index pattern
# Run this whenever visualizations show "index pattern missing" error

KIBANA_URL="http://localhost:5601"
ELASTICSEARCH_URL="http://localhost:9200"

echo "=========================================="
echo "Recreating Kibana Visualizations"
echo "=========================================="
echo ""

# Wait for services
echo "[1/4] Checking services..."
until curl -s "$ELASTICSEARCH_URL" > /dev/null 2>&1; do
    echo "  Waiting for Elasticsearch..."
    sleep 2
done
until curl -s "$KIBANA_URL/api/status" > /dev/null 2>&1; do
    echo "  Waiting for Kibana..."
    sleep 2
done
echo "  ✓ Services ready"

# Get current index pattern ID
echo ""
echo "[2/4] Getting current index pattern..."
INDEX_PATTERN_ID=$(curl -s "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&search_fields=title&search=filebeat-*" \
  -H 'kbn-xsrf: true' | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -z "$INDEX_PATTERN_ID" ]; then
    echo "  ✗ No index pattern found. Creating one..."
    INDEX_PATTERN_RESPONSE=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/index-pattern" \
      -H 'kbn-xsrf: true' \
      -H 'Content-Type: application/json' \
      -d '{
      "attributes": {
        "title": "filebeat-*",
        "timeFieldName": "@timestamp"
      }
    }')
    INDEX_PATTERN_ID=$(echo $INDEX_PATTERN_RESPONSE | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
fi
echo "  ✓ Index Pattern ID: $INDEX_PATTERN_ID"

# Delete old broken visualizations
echo ""
echo "[3/4] Removing old visualizations..."
curl -X DELETE "$KIBANA_URL/api/saved_objects/visualization/5ab9ae00-f69a-11f0-bd7d-75457bbc1500" \
  -H 'kbn-xsrf: true' > /dev/null 2>&1
curl -X DELETE "$KIBANA_URL/api/saved_objects/visualization/5adaca90-f69a-11f0-bd7d-75457bbc1500" \
  -H 'kbn-xsrf: true' > /dev/null 2>&1
echo "  ✓ Old visualizations removed"

# Create new visualizations
echo ""
echo "[4/4] Creating fresh visualizations..."

# Threat Severity Timeline (Updated to use 'severity' field if available, else fallback to analysis text)
TIMELINE_ID=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d "{
  \"attributes\": {
    \"title\": \"HoneyGen - Threat Severity Timeline\",
    \"visState\": \"{\\\"title\\\":\\\"HoneyGen - Threat Severity Timeline\\\",\\\"type\\\":\\\"area\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"date_histogram\\\",\\\"params\\\":{\\\"field\\\":\\\"@timestamp\\\",\\\"timeRange\\\":{\\\"from\\\":\\\"now-24h\\\",\\\"to\\\":\\\"now\\\"},\\\"useNormalizedEsInterval\\\":true,\\\"scaleMetricValues\\\":false,\\\"interval\\\":\\\"auto\\\",\\\"drop_partials\\\":false,\\\"min_doc_count\\\":1,\\\"extended_bounds\\\":{}},\\\"schema\\\":\\\"segment\\\"},{\\\"id\\\":\\\"3\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"filters\\\",\\\"params\\\":{\\\"filters\\\":[{\\\"input\\\":{\\\"query\\\":\\\"severity:High OR analysis:*High*\\\",\\\"language\\\":\\\"kuery\\\"},\\\"label\\\":\\\"High Severity\\\"},{\\\"input\\\":{\\\"query\\\":\\\"severity:Medium OR analysis:*Medium*\\\",\\\"language\\\":\\\"kuery\\\"},\\\"label\\\":\\\"Medium Severity\\\"},{\\\"input\\\":{\\\"query\\\":\\\"severity:Low OR analysis:*Low*\\\",\\\"language\\\":\\\"kuery\\\"},\\\"label\\\":\\\"Low Severity\\\"}]},\\\"schema\\\":\\\"group\\\"}],\\\"params\\\":{\\\"type\\\":\\\"area\\\",\\\"grid\\\":{\\\"categoryLines\\\":false},\\\"categoryAxes\\\":[{\\\"id\\\":\\\"CategoryAxis-1\\\",\\\"type\\\":\\\"category\\\",\\\"position\\\":\\\"bottom\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"filter\\\":true,\\\"truncate\\\":100},\\\"title\\\":{}}],\\\"valueAxes\\\":[{\\\"id\\\":\\\"ValueAxis-1\\\",\\\"name\\\":\\\"LeftAxis-1\\\",\\\"type\\\":\\\"value\\\",\\\"position\\\":\\\"left\\\",\\\"show\\\":true,\\\"style\\\":{},\\\"scale\\\":{\\\"type\\\":\\\"linear\\\",\\\"mode\\\":\\\"normal\\\"},\\\"labels\\\":{\\\"show\\\":true,\\\"rotate\\\":0,\\\"filter\\\":false,\\\"truncate\\\":100},\\\"title\\\":{\\\"text\\\":\\\"Count\\\"}}],\\\"seriesParams\\\":[{\\\"show\\\":true,\\\"type\\\":\\\"area\\\",\\\"mode\\\":\\\"stacked\\\",\\\"data\\\":{\\\"label\\\":\\\"Count\\\",\\\"id\\\":\\\"1\\\"},\\\"valueAxis\\\":\\\"ValueAxis-1\\\",\\\"drawLinesBetweenPoints\\\":true,\\\"lineWidth\\\":2,\\\"interpolate\\\":\\\"linear\\\",\\\"showCircles\\\":true}],\\\"addTooltip\\\":true,\\\"addLegend\\\":true,\\\"legendPosition\\\":\\\"right\\\",\\\"times\\\":[],\\\"addTimeMarker\\\":false,\\\"thresholdLine\\\":{\\\"show\\\":false,\\\"value\\\":10,\\\"width\\\":1,\\\"style\\\":\\\"full\\\",\\\"color\\\":\\\"#E7664C\\\"}}}\",
    \"uiStateJSON\": \"{}\",
    \"description\": \"Timeline showing AI-detected threat severity over time\",
    \"version\": 1,
    \"kibanaSavedObjectMeta\": {
      \"searchSourceJSON\": \"{\\\"index\\\":\\\"$INDEX_PATTERN_ID\\\",\\\"query\\\":{\\\"query\\\":\\\"event_source: gemini_ai\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[]}\"
    }
  }
}" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "  ✓ Threat Severity Timeline created (ID: $TIMELINE_ID)"

# Attacker Origins Map
MAP_ID=$(curl -s -X POST "$KIBANA_URL/api/saved_objects/visualization" \
  -H 'kbn-xsrf: true' \
  -H 'Content-Type: application/json' \
  -d "{
  \"attributes\": {
    \"title\": \"HoneyGen - Attacker Origins Map\",
    \"visState\": \"{\\\"title\\\":\\\"HoneyGen - Attacker Origins Map\\\",\\\"type\\\":\\\"tile_map\\\",\\\"aggs\\\":[{\\\"id\\\":\\\"1\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"count\\\",\\\"params\\\":{},\\\"schema\\\":\\\"metric\\\"},{\\\"id\\\":\\\"2\\\",\\\"enabled\\\":true,\\\"type\\\":\\\"geohash_grid\\\",\\\"params\\\":{\\\"field\\\":\\\"geoip.location\\\",\\\"autoPrecision\\\":true,\\\"precision\\\":2,\\\"useGeocentroid\\\":true,\\\"isFilteredByCollar\\\":true,\\\"mapZoom\\\":2,\\\"mapCenter\\\":[0,0]},\\\"schema\\\":\\\"segment\\\"}],\\\"params\\\":{\\\"colorSchema\\\":\\\"Yellow to Red\\\",\\\"mapType\\\":\\\"Scaled Circle Markers\\\",\\\"isDesaturated\\\":true,\\\"addTooltip\\\":true,\\\"heatClusterSize\\\":1.5,\\\"legendPosition\\\":\\\"bottomright\\\",\\\"mapZoom\\\":2,\\\"mapCenter\\\":[0,0],\\\"wms\\\":{\\\"enabled\\\":false,\\\"options\\\":{\\\"format\\\":\\\"image/png\\\",\\\"transparent\\\":true}}}}\",
    \"uiStateJSON\": \"{\\\"mapZoom\\\":2,\\\"mapCenter\\\":[0,0]}\",
    \"description\": \"World map showing geographic distribution of attackers\",
    \"version\": 1,
    \"kibanaSavedObjectMeta\": {
      \"searchSourceJSON\": \"{\\\"index\\\":\\\"$INDEX_PATTERN_ID\\\",\\\"query\\\":{\\\"query\\\":\\\"event_source: (cowrie OR tanner)\\\",\\\"language\\\":\\\"kuery\\\"},\\\"filter\\\":[]}\"
    }
  }
}" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

echo "  ✓ Attacker Origins Map created (ID: $MAP_ID)"

echo ""
echo "=========================================="
echo "✓ Visualizations Recreated Successfully"
echo "=========================================="
echo ""
echo "Go to Kibana > Visualize Library to see them"
echo ""
