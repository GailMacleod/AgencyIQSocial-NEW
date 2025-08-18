#!/bin/bash

# Quick Rollback Deployment Script for TheAgencyIQ
# Usage: ./scripts/quick-rollback.sh [snapshot_id]

set -e

echo "🔄 TheAgencyIQ Quick Rollback System"
echo "======================================"

# Check if snapshot ID is provided
if [ $# -eq 0 ]; then
    echo "📋 Available snapshots:"
    node scripts/rollback-system.js list
    echo ""
    echo "Usage: $0 <snapshot_id>"
    echo "Example: $0 snapshot_2025-07-11_11-30-00"
    exit 1
fi

SNAPSHOT_ID="$1"

echo "🔍 Validating snapshot: $SNAPSHOT_ID"

# Check if snapshot exists
if ! node scripts/rollback-system.js list | grep -q "$SNAPSHOT_ID"; then
    echo "❌ Snapshot not found: $SNAPSHOT_ID"
    echo "📋 Available snapshots:"
    node scripts/rollback-system.js list
    exit 1
fi

echo "⚠️  ROLLBACK WARNING"
echo "==================="
echo "This will:"
echo "• Restore database to snapshot state"
echo "• Restore critical application files"
echo "• Create backup of current state"
echo "• Restart the application"
echo ""
echo "Snapshot: $SNAPSHOT_ID"
echo ""

# Prompt for confirmation
read -p "Are you sure you want to proceed? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Rollback cancelled"
    exit 1
fi

echo "🔄 Starting rollback process..."

# Create pre-rollback snapshot
echo "📦 Creating pre-rollback backup..."
BACKUP_ID=$(node scripts/rollback-system.js create "Pre-rollback backup $(date)" | grep "Created snapshot:" | cut -d' ' -f3)
echo "✅ Backup created: $BACKUP_ID"

# Stop application (if running)
echo "🛑 Stopping application..."
if pgrep -f "npm run dev" > /dev/null; then
    pkill -f "npm run dev" || true
    sleep 2
fi

# Execute rollback
echo "🔄 Executing rollback to $SNAPSHOT_ID..."
node scripts/rollback-system.js rollback "$SNAPSHOT_ID"

echo "🔄 Rollback process completed"
echo "=============================="
echo "✅ Database restored"
echo "✅ Code files restored"
echo "📦 Backup created: $BACKUP_ID"
echo ""
echo "🚀 Restarting application..."

# Restart application
npm run dev &
sleep 3

echo "✅ Application restarted"
echo "🌐 Visit: http://localhost:5000"
echo ""
echo "📋 Rollback Summary:"
echo "• Rolled back to: $SNAPSHOT_ID"
echo "• Backup created: $BACKUP_ID"
echo "• Application status: Running"
echo ""
echo "🔍 To verify rollback:"
echo "• Check database state"
echo "• Test application functionality"
echo "• Review restored files"
echo ""
echo "⚠️  If issues occur, rollback to backup: $BACKUP_ID"