#!/bin/sh

socat -dd TCP-LISTEN:51478,fork,reuseaddr EXEC:"python chal.py" 2> log.txt &
echo $! | tee server-pid.txt
