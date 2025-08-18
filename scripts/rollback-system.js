#!/usr/bin/env node

/**
 * COMPREHENSIVE ROLLBACK SYSTEM FOR THEAGENCYIQ
 * Creates snapshots and enables rollback to previous stable states
 */

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class RollbackSystem {
  constructor() {
    this.snapshotDir = path.join(__dirname, '../snapshots');
    this.configFile = path.join(this.snapshotDir, 'rollback-config.json');
    this.maxSnapshots = 10;
    
    this.ensureDirectoryExists();
  }

  ensureDirectoryExists() {
    if (!fs.existsSync(this.snapshotDir)) {
      fs.mkdirSync(this.snapshotDir, { recursive: true });
    }
  }

  /**
   * Create a comprehensive snapshot of the current application state
   */
  async createSnapshot(description = 'Manual snapshot') {
    const timestamp = new Date().toISOString();
    const snapshotId = this.generateSnapshotId(timestamp);
    
    console.log(`🔄 Creating snapshot: ${snapshotId}`);
    
    const snapshot = {
      id: snapshotId,
      timestamp,
      description,
      database: await this.createDatabaseSnapshot(),
      codeState: await this.createCodeStateSnapshot(),
      configuration: await this.createConfigurationSnapshot(),
      userState: await this.createUserStateSnapshot(),
      platformConnections: await this.createPlatformConnectionsSnapshot(),
      posts: await this.createPostsSnapshot()
    };

    // Save snapshot metadata
    const snapshotFile = path.join(this.snapshotDir, `${snapshotId}.json`);
    fs.writeFileSync(snapshotFile, JSON.stringify(snapshot, null, 2));
    
    // Update rollback config
    await this.updateRollbackConfig(snapshot);
    
    // Cleanup old snapshots
    await this.cleanupOldSnapshots();
    
    console.log(`✅ Snapshot created: ${snapshotId}`);
    console.log(`📝 Description: ${description}`);
    return snapshotId;
  }

  /**
   * Create database snapshot using pg_dump
   */
  async createDatabaseSnapshot() {
    const dumpFile = path.join(this.snapshotDir, `db_${Date.now()}.sql`);
    
    try {
      // Use environment database URL if available
      const dbUrl = process.env.DATABASE_URL;
      if (dbUrl) {
        execSync(`pg_dump "${dbUrl}" > "${dumpFile}"`, { stdio: 'inherit' });
        return { file: dumpFile, size: fs.statSync(dumpFile).size };
      }
      return { error: 'DATABASE_URL not available' };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Create code state snapshot (critical files)
   */
  async createCodeStateSnapshot() {
    const criticalFiles = [
      'server/routes.ts',
      'server/storage.ts',
      'server/PostQuotaService.ts',
      'shared/schema.ts',
      'client/src/pages/subscription.tsx',
      'client/src/pages/intelligent-schedule.tsx',
      'client/src/pages/connect-platforms.tsx',
      'package.json',
      'replit.md'
    ];

    const codeState = {};
    
    for (const file of criticalFiles) {
      if (fs.existsSync(file)) {
        codeState[file] = {
          content: fs.readFileSync(file, 'utf8'),
          hash: this.calculateFileHash(file),
          size: fs.statSync(file).size
        };
      }
    }
    
    return codeState;
  }

  /**
   * Create configuration snapshot
   */
  async createConfigurationSnapshot() {
    const configFiles = [
      '.env',
      'vite.config.ts',
      'tsconfig.json',
      'tailwind.config.ts',
      'drizzle.config.ts'
    ];

    const config = {};
    
    for (const file of configFiles) {
      if (fs.existsSync(file)) {
        // Don't store sensitive data, just metadata
        config[file] = {
          exists: true,
          hash: this.calculateFileHash(file),
          size: fs.statSync(file).size
        };
      }
    }
    
    return config;
  }

  /**
   * Create user state snapshot from database
   */
  async createUserStateSnapshot() {
    try {
      const { db } = await import('../server/db.js');
      const { users } = await import('../shared/schema.js');
      
      const userCount = await db.select().from(users);
      
      return {
        totalUsers: userCount.length,
        subscriptionBreakdown: this.calculateSubscriptionBreakdown(userCount),
        lastUpdated: new Date().toISOString()
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Create platform connections snapshot
   */
  async createPlatformConnectionsSnapshot() {
    try {
      const { db } = await import('../server/db.js');
      const { platformConnections } = await import('../shared/schema.js');
      
      const connections = await db.select().from(platformConnections);
      
      return {
        totalConnections: connections.length,
        platformBreakdown: this.calculatePlatformBreakdown(connections),
        activeConnections: connections.filter(c => c.isActive).length
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Create posts snapshot
   */
  async createPostsSnapshot() {
    try {
      const { db } = await import('../server/db.js');
      const { post_schedule } = await import('../shared/schema.js');
      
      const posts = await db.select().from(post_schedule);
      
      return {
        totalPosts: posts.length,
        statusBreakdown: this.calculatePostStatusBreakdown(posts),
        lastGenerated: new Date().toISOString()
      };
    } catch (error) {
      return { error: error.message };
    }
  }

  /**
   * Rollback to a specific snapshot
   */
  async rollbackToSnapshot(snapshotId) {
    console.log(`🔄 Rolling back to snapshot: ${snapshotId}`);
    
    const snapshotFile = path.join(this.snapshotDir, `${snapshotId}.json`);
    
    if (!fs.existsSync(snapshotFile)) {
      throw new Error(`Snapshot not found: ${snapshotId}`);
    }
    
    const snapshot = JSON.parse(fs.readFileSync(snapshotFile, 'utf8'));
    
    // Create a backup of current state before rollback
    const backupId = await this.createSnapshot('Pre-rollback backup');
    
    try {
      // Restore database
      if (snapshot.database && snapshot.database.file) {
        await this.restoreDatabase(snapshot.database.file);
      }
      
      // Restore code state
      if (snapshot.codeState) {
        await this.restoreCodeState(snapshot.codeState);
      }
      
      console.log(`✅ Rollback completed to snapshot: ${snapshotId}`);
      console.log(`📦 Backup created before rollback: ${backupId}`);
      
      return { success: true, snapshotId, backupId };
    } catch (error) {
      console.error(`❌ Rollback failed: ${error.message}`);
      throw error;
    }
  }

  /**
   * Restore database from snapshot
   */
  async restoreDatabase(dumpFile) {
    const dbUrl = process.env.DATABASE_URL;
    if (!dbUrl) {
      throw new Error('DATABASE_URL not available for restore');
    }
    
    if (!fs.existsSync(dumpFile)) {
      throw new Error(`Database dump file not found: ${dumpFile}`);
    }
    
    console.log('🔄 Restoring database...');
    execSync(`psql "${dbUrl}" < "${dumpFile}"`, { stdio: 'inherit' });
    console.log('✅ Database restored');
  }

  /**
   * Restore code state from snapshot
   */
  async restoreCodeState(codeState) {
    console.log('🔄 Restoring code state...');
    
    for (const [filePath, fileData] of Object.entries(codeState)) {
      if (fileData.content) {
        // Create directory if it doesn't exist
        const dir = path.dirname(filePath);
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
        
        // Restore file content
        fs.writeFileSync(filePath, fileData.content);
        console.log(`✅ Restored: ${filePath}`);
      }
    }
  }

  /**
   * List available snapshots
   */
  listSnapshots() {
    const config = this.loadRollbackConfig();
    return config.snapshots || [];
  }

  /**
   * Delete a specific snapshot
   */
  deleteSnapshot(snapshotId) {
    const snapshotFile = path.join(this.snapshotDir, `${snapshotId}.json`);
    
    if (fs.existsSync(snapshotFile)) {
      fs.unlinkSync(snapshotFile);
      
      // Update config
      const config = this.loadRollbackConfig();
      config.snapshots = config.snapshots.filter(s => s.id !== snapshotId);
      this.saveRollbackConfig(config);
      
      console.log(`🗑️ Deleted snapshot: ${snapshotId}`);
    }
  }

  /**
   * Helper methods
   */
  generateSnapshotId(timestamp) {
    return `snapshot_${timestamp.replace(/[:.]/g, '-').replace('T', '_').slice(0, 19)}`;
  }

  calculateFileHash(filePath) {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('md5').update(content).digest('hex');
  }

  calculateSubscriptionBreakdown(users) {
    return users.reduce((acc, user) => {
      const plan = user.subscription_plan || 'none';
      acc[plan] = (acc[plan] || 0) + 1;
      return acc;
    }, {});
  }

  calculatePlatformBreakdown(connections) {
    return connections.reduce((acc, conn) => {
      acc[conn.platform] = (acc[conn.platform] || 0) + 1;
      return acc;
    }, {});
  }

  calculatePostStatusBreakdown(posts) {
    return posts.reduce((acc, post) => {
      acc[post.status] = (acc[post.status] || 0) + 1;
      return acc;
    }, {});
  }

  updateRollbackConfig(snapshot) {
    const config = this.loadRollbackConfig();
    
    if (!config.snapshots) {
      config.snapshots = [];
    }
    
    config.snapshots.push({
      id: snapshot.id,
      timestamp: snapshot.timestamp,
      description: snapshot.description
    });
    
    // Sort by timestamp (newest first)
    config.snapshots.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    this.saveRollbackConfig(config);
  }

  loadRollbackConfig() {
    if (fs.existsSync(this.configFile)) {
      return JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
    }
    return {};
  }

  saveRollbackConfig(config) {
    fs.writeFileSync(this.configFile, JSON.stringify(config, null, 2));
  }

  cleanupOldSnapshots() {
    const config = this.loadRollbackConfig();
    
    if (config.snapshots && config.snapshots.length > this.maxSnapshots) {
      const toDelete = config.snapshots.slice(this.maxSnapshots);
      
      toDelete.forEach(snapshot => {
        this.deleteSnapshot(snapshot.id);
      });
    }
  }
}

// CLI Interface
if (import.meta.url === `file://${process.argv[1]}`) {
  const rollback = new RollbackSystem();
  const command = process.argv[2];
  const arg = process.argv[3];

  switch (command) {
    case 'create':
      rollback.createSnapshot(arg || 'Manual snapshot from CLI')
        .then(id => console.log(`Created snapshot: ${id}`))
        .catch(console.error);
      break;
      
    case 'list':
      const snapshots = rollback.listSnapshots();
      console.log('\n📋 Available Snapshots:');
      snapshots.forEach(s => {
        console.log(`  ${s.id} - ${s.timestamp} - ${s.description}`);
      });
      break;
      
    case 'rollback':
      if (!arg) {
        console.error('Please provide snapshot ID');
        process.exit(1);
      }
      rollback.rollbackToSnapshot(arg)
        .then(result => console.log(`Rollback completed: ${result.snapshotId}`))
        .catch(console.error);
      break;
      
    case 'delete':
      if (!arg) {
        console.error('Please provide snapshot ID');
        process.exit(1);
      }
      rollback.deleteSnapshot(arg);
      break;
      
    default:
      console.log(`
Usage: node scripts/rollback-system.js <command> [args]

Commands:
  create [description]     - Create a new snapshot
  list                     - List all snapshots
  rollback <snapshot-id>   - Rollback to a specific snapshot
  delete <snapshot-id>     - Delete a specific snapshot

Examples:
  node scripts/rollback-system.js create "Before major update"
  node scripts/rollback-system.js list
  node scripts/rollback-system.js rollback snapshot_2025-07-11_11-30-00
  node scripts/rollback-system.js delete snapshot_2025-07-11_11-30-00
      `);
  }
}

export default RollbackSystem;