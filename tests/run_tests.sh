#!/usr/bin/env bash
set -e

echo "=========================================================="
echo " RUNNING TRUST TEST SUITE"
echo "=========================================================="

echo -e "\n[1/3] Running Python Scoring Unit Tests..."
python3 tests/test_scoring.py

echo -e "\n[2/3] Running Node.js Detector & Bundle Tests..."
node tests/test_detectors.js

echo -e "\n[3/3] Testing Standalone HTML Re-bundler..."
python3 bundle_standalone.py

echo -e "\n=========================================================="
echo " ✓ ALL TESTS PASSED SUCCESSFULLY!"
echo "=========================================================="
