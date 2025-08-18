#!/bin/bash
# TheAgencyIQ Production Startup Script
# Bypasses npm corruption and starts the working production server

echo "🚀 Starting TheAgencyIQ Production Server..."
echo "📅 $(date)"
echo "🔧 Bypassing npm corruption with direct Node.js execution"
echo ""

# Check if database connection is available
if [ -n "$DATABASE_URL" ]; then
    echo "✅ Database connection available"
else
    echo "❌ Database connection missing"
    exit 1
fi

# Start the production server
echo "🎯 Starting production server on port ${PORT:-5000}..."
node server/final-production-server.js