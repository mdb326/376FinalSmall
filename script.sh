#!/usr/bin/env bash

set -e

make myMulti

./myMultiserver &
SERVER_PID=$!

sleep 1

./myMulticlient
./myMulticlient

./myMulticlient > final_client_output.txt 2>&1

kill $SERVER_PID

echo "Final client output saved to final_client_output.txt"