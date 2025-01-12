#!/bin/bash

# Define the old and new strings
OLD_STRING="Last Update: 1/12/2025 Ver. 0.16.2 RC 1"
NEW_STRING="Last Update: 1/12/2025 Ver. 0.16.2 RC 1"

# Specify the directory to search (default is the current directory)
SEARCH_DIR="."

# Find and update files
echo "Updating files in $SEARCH_DIR..."
find "$SEARCH_DIR" -type f -exec sed -i "s|$OLD_STRING|$NEW_STRING|g" {} \;

echo "Update complete."
