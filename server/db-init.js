/**
 * Database Initialization and Connection Management
 * Proper Drizzle ORM setup with PostgreSQL connection pooling
 */

import { neonConfig, Pool } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from 'ws';
import * as schema from '@shared/schema';

// Configure Neon for serverless environment
neonConfig.webSocketConstructor = ws;

class DatabaseManager {
  constructor() {
    this.pool = null;
    this.db = null;
    this.isConnected = false;
  }

  async initialize() {
    try {
      console.log('🔗 Initializing PostgreSQL connection...');
      
      if (!process.env.DATABASE_URL) {
        throw new Error('DATABASE_URL environment variable is required');
      }

      // Create connection pool
      this.pool = new Pool({ 
        connectionString: process.env.DATABASE_URL,
        max: 20, // Maximum connections in pool
        idleTimeoutMillis: 30000, // Close idle connections after 30s
        connectionTimeoutMillis: 10000, // Connection timeout 10s
      });

      // Initialize Drizzle ORM with schema
      this.db = drizzle(this.pool, { 
        schema,
        logger: process.env.NODE_ENV === 'development' 
      });

      // Test connection
      await this.testConnection();
      
      this.isConnected = true;
      console.log('✅ PostgreSQL connection established successfully');
      console.log(`🔗 Database URL: ${process.env.DATABASE_URL.replace(/:[^:@]*@/, ':****@')}`);
      
      return this.db;
    } catch (error) {
      console.error('❌ Database initialization failed:', error);
      throw error;
    }
  }

  async testConnection() {
    try {
      // Simple query to test connection
      const result = await this.db.execute('SELECT NOW() as current_time');
      console.log(`🕐 Database connection test successful: ${result.rows[0]?.current_time}`);
      
      // Ensure sessions table exists
      await this.db.execute(`
        CREATE TABLE IF NOT EXISTS sessions (
          sid VARCHAR PRIMARY KEY,
          sess JSONB NOT NULL,
          expire TIMESTAMP NOT NULL
        );
        CREATE INDEX IF NOT EXISTS IDX_session_expire ON sessions(expire);
      `);
      console.log('✅ Sessions table ready');
      
    } catch (error) {
      console.error('❌ Database connection test failed:', error);
      throw new Error(`Database connection failed: ${error.message}`);
    }
  }

  getDatabase() {
    if (!this.isConnected || !this.db) {
      throw new Error('Database not initialized. Call initialize() first.');
    }
    return this.db;
  }

  async closeConnection() {
    if (this.pool) {
      try {
        await this.pool.end();
        console.log('🔒 Database connection closed');
      } catch (error) {
        console.error('❌ Error closing database connection:', error);
      }
    }
  }

  // Health check for database
  async healthCheck() {
    try {
      if (!this.isConnected) {
        return { status: 'disconnected', error: 'Database not initialized' };
      }
      
      const startTime = Date.now();
      await this.db.execute('SELECT 1');
      const responseTime = Date.now() - startTime;
      
      return {
        status: 'healthy',
        responseTime: `${responseTime}ms`,
        connectionPool: {
          total: this.pool.totalCount || 0,
          idle: this.pool.idleCount || 0,
          waiting: this.pool.waitingCount || 0
        }
      };
    } catch (error) {
      return {
        status: 'error',
        error: error.message
      };
    }
  }
}

// Create singleton instance
const dbManager = new DatabaseManager();

export { dbManager };

// Export for backward compatibility
export const db = new Proxy({}, {
  get(target, prop) {
    const database = dbManager.getDatabase();
    return database[prop];
  }
});