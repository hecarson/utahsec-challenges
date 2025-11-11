#!/bin/sh

SERVER_PID=$(cat server-pid.txt)
echo $SERVER_PID
kill $SERVER_PID
rm server-pid.txt
