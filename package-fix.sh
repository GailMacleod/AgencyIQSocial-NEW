#!/bin/bash

# Quick Package Fix Script - Clears npm cache corruption
echo "🔧 Quick NPM Cache Fix"
echo "====================="

# Clear all npm caches
npm cache clean --force
rm -rf ~/.npm 2>/dev/null || true
rm -rf /tmp/.npm 2>/dev/null || true

# Remove corrupted global packages directory
rm -rf /home/runner/workspace/.config/npm 2>/dev/null || true

# Configure npm to use temp cache
npm config set cache /tmp/.npm-cache
npm config set update-notifier false

echo "✅ NPM cache cleared - ready for deployment"
echo "Now try deploying again through Replit's Deploy button"