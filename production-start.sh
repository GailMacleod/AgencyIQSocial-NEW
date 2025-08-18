#!/bin/bash
# Production startup script for TheAgencyIQ (Vite-free deployment)

echo "🚀 TheAgencyIQ Production Startup"
echo "=================================="

# Check if build exists
if [ ! -f "dist/index.js" ]; then
    echo "📦 Building application first..."
    node build-simple.js
fi

# Set production environment
export NODE_ENV=production
export PORT=${PORT:-5000}

echo "🌍 Environment: $NODE_ENV"
echo "🔌 Port: $PORT"
echo "📂 Build size: $(du -h dist/index.js | cut -f1)"

# Start the production server
echo "🎯 Starting TheAgencyIQ production server..."
node dist/index.js