#!/bin/bash

export FLASK_SECRET_KEY=$(xxd -p -l 16 /dev/urandom)
export ADMIN_PW=$(xxd -p -l 16 /dev/urandom)

trap 'kill $READ_TICKETS_PID' EXIT

python init_db.py
python read_tickets.py &
READ_TICKETS_PID=$!
gunicorn -w 4 -b 0.0.0.0:10000 "main:app"
