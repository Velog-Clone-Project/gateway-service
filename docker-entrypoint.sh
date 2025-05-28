#!/bin/bash

echo "Waiting for config-service..."
/wait-for-it.sh config-service:8888 --timeout=60 --strict -- echo "config-service is up"

echo "Waiting for discovery-service..."
/wait-for-it.sh discovery-service:8761 --timeout=60 --strict -- echo "discovery-service is up"

echo "Starting gateway-service"
exec java -jar app.jar