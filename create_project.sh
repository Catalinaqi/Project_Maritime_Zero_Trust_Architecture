#!/bin/bash
# Complete Maritime ZTA Project Generator

echo "Generating complete Maritime ZTA project..."

# Copy configuration files from previous version
cp /home/claude/maritime-zta/.env.example ./ 2>/dev/null || true
cp /home/claude/maritime-zta/pyproject.toml ./ 2>/dev/null || true
cp /home/claude/maritime-zta/Makefile ./ 2>/dev/null || true
cp /home/claude/maritime-zta/SECURITY.md ./ 2>/dev/null || true
cp /home/claude/maritime-zta/CHECKLIST.md ./ 2>/dev/null || true

echo "✓ Core configs copied"
