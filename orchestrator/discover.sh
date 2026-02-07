#!/bin/bash

# Start orchestrator in background
/usr/local/bin/orchestrator -config /etc/orchestrator/orchestrator.conf.json http &
ORCHESTRATOR_PID=$!

# Wait for orchestrator to be ready
sleep 30

# Run discovery
echo "Running instance discovery..."
/usr/local/bin/orchestrator -c discover -i mysql-master:3306 -config /etc/orchestrator/orchestrator.conf.json
/usr/local/bin/orchestrator -c discover -i mysql-slave1:3306 -config /etc/orchestrator/orchestrator.conf.json  
/usr/local/bin/orchestrator -c discover -i mysql-slave2:3306 -config /etc/orchestrator/orchestrator.conf.json

echo "Discovery completed"

# Keep orchestrator running
wait $ORCHESTRATOR_PID