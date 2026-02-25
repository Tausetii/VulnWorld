#!/bin/bash

APP_DIR="/home/ec2-user/VulnWorld"
BRANCH="main"

echo "==== Deploy started at $(date) ===="

cd $APP_DIR || exit 1

echo "Fetching latest changes..."
git fetch origin

echo "Resetting local changes..."
git reset --hard origin/$BRANCH
git clean -fd

echo "Stopping existing app..."
pkill -f "python3.12 main.py" || true
pkill -f "gunicorn" || true

chmod +x run.sh

sleep 2

echo "Installing dependencies..."
python3.12 -m pip install -r requirements.txt

echo "Starting app..."
nohup python3.12 main.py > log.txt 2>&1 &

echo "==== Deploy finished ===="