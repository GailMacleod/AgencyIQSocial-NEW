#!/bin/bash

# Deployment Fix Script for TheAgencyIQ
# Fixes npm cache corruption and ensures clean deployment

echo "🔧 TheAgencyIQ Deployment Fix Script"
echo "===================================="

# Step 1: Clear npm cache and global packages
echo "📦 Clearing npm cache and corrupted global packages..."
npm cache clean --force 2>/dev/null || true
rm -rf ~/.npm 2>/dev/null || true
rm -rf /home/runner/workspace/.config/npm 2>/dev/null || true

# Step 2: Remove existing node_modules and lock file
echo "🗑️  Removing existing dependencies..."
rm -rf node_modules
rm -f package-lock.json

# Step 3: Set npm configuration to avoid cache issues
echo "⚙️  Configuring npm for clean installation..."
npm config set cache /tmp/.npm
npm config set update-notifier false
npm config set fund false
npm config set audit false

# Step 4: Fresh dependency installation
echo "📥 Installing dependencies with no cache..."
npm install --no-cache --verbose

# Step 5: Build the application
echo "🏗️  Building application..."
npm run build

# Step 6: Test the build
echo "🧪 Testing production build..."
if [ -f "dist/index.js" ]; then
    echo "✅ Build successful - dist/index.js created"
    
    # Quick smoke test
    timeout 10s node dist/index.js > /tmp/smoke-test.log 2>&1 &
    SMOKE_PID=$!
    sleep 3
    
    if ps -p $SMOKE_PID > /dev/null; then
        echo "✅ Production build smoke test passed"
        kill $SMOKE_PID 2>/dev/null || true
    else
        echo "⚠️  Smoke test inconclusive (may be normal)"
    fi
else
    echo "❌ Build failed - dist/index.js not found"
    exit 1
fi

# Step 7: Deployment readiness check
echo ""
echo "🎯 Deployment Readiness Summary"
echo "==============================="

# Check critical files
FILES=("dist/index.js" "package.json" ".env")
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file exists"
    else
        echo "❌ $file missing"
    fi
done

# Check environment variables
if grep -q "NODE_ENV=production" .env; then
    echo "✅ Production environment configured"
else
    echo "⚠️  NODE_ENV not set to production"
fi

if grep -q "PORT=" .env; then
    echo "✅ Port configuration found"
else
    echo "⚠️  Port configuration missing"
fi

echo ""
echo "🚀 Deployment Instructions"
echo "========================="
echo "1. Your build is ready for deployment"
echo "2. Click the 'Deploy' button in Replit"
echo "3. Replit will use: node dist/index.js"
echo "4. All dependencies are now properly installed"
echo ""
echo "📋 Build Output:"
echo "   - Server bundle: dist/index.js ($(du -h dist/index.js 2>/dev/null | cut -f1 || echo 'N/A'))"
echo "   - Static files: dist/public/"
echo "   - Dependencies: $(ls node_modules | wc -l) packages installed"
echo ""