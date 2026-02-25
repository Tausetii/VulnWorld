#!/bin/bash

APP_DIR="/home/ec2-user/VulnWorld"
LOG_FILE="$APP_DIR/log.txt"
PYTHON="/usr/bin/python3.12"

echo "==== Deploy started at $(date) ===="

cd $APP_DIR || exit 1

echo "Pulling latest code..."
git pull --rebase

echo "Stopping existing app..."
pkill -f "python3.12 main.py" || true
pkill -f "gunicorn" || true

sleep 2

echo "Installing dependencies..."
$PYTHON -m pip install -r requirements.txt

echo "Starting application..."

# OPTION 1: Flask direct (what you're using)
nohup $PYTHON main.py > $LOG_FILE 2>&1 &

# OPTION 2 (recommended): Gunicorn
# nohup gunicorn -w 3 -b 0.0.0.0:5000 main:app > $LOG_FILE 2>&1 &

echo "App started."
echo "==== Deploy finished ===="