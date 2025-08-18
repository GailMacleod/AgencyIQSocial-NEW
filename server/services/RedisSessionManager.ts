import { createClient } from 'redis';
import type { Request, Response, NextFunction } from 'express';

export class RedisSessionManager {
  private client: any = null;
  private isConnected = false;

  async initialize() {
    try {
      // Try Redis connection first
      if (process.env.REDIS_URL) {
        this.client = createClient({
          url: process.env.REDIS_URL,
          socket: {
            connectTimeout: 5000,
            lazyConnect: true
          }
        });

        this.client.on('error', (err: any) => {
          console.log('🔴 Redis connection error:', err.message);
          this.isConnected = false;
        });

        await this.client.connect();
        this.isConnected = true;
        console.log('✅ Redis session store connected');
        return true;
      }
    } catch (error) {
      console.log('⚠️ Redis unavailable, using PostgreSQL fallback');
      this.isConnected = false;
    }
    return false;
  }

  // Auto-save generation state to prevent mid-gen drops
  async saveGenerationState(userId: number, generationId: string, state: any) {
    const key = `gen_state:${userId}:${generationId}`;
    const data = {
      ...state,
      timestamp: new Date().toISOString(),
      userId,
      generationId
    };

    if (this.isConnected && this.client) {
      try {
        await this.client.setEx(key, 1800, JSON.stringify(data)); // 30 min TTL
        console.log(`💾 Generation state saved: ${key}`);
      } catch (error) {
        console.log('⚠️ Redis save failed, using DB fallback');
        await this.saveToDatabase(key, data);
      }
    } else {
      await this.saveToDatabase(key, data);
    }
  }

  async getGenerationState(userId: number, generationId: string) {
    const key = `gen_state:${userId}:${generationId}`;
    
    if (this.isConnected && this.client) {
      try {
        const data = await this.client.get(key);
        if (data) {
          console.log(`📥 Generation state restored: ${key}`);
          return JSON.parse(data);
        }
      } catch (error) {
        console.log('⚠️ Redis get failed, checking DB fallback');
      }
    }

    return await this.getFromDatabase(key);
  }

  async clearGenerationState(userId: number, generationId: string) {
    const key = `gen_state:${userId}:${generationId}`;
    
    if (this.isConnected && this.client) {
      try {
        await this.client.del(key);
      } catch (error) {
        console.log('⚠️ Redis delete failed');
      }
    }

    await this.clearFromDatabase(key);
  }

  // Database fallback for generation state
  private async saveToDatabase(key: string, data: any) {
    try {
      const Database = require('@replit/database');
      const db = new Database();
      await db.set(key, data, { EX: 1800 });
      console.log(`💾 Generation state saved to DB: ${key}`);
    } catch (error) {
      console.log('❌ DB fallback save failed:', error.message);
    }
  }

  private async getFromDatabase(key: string) {
    try {
      const Database = require('@replit/database');
      const db = new Database();
      const data = await db.get(key);
      if (data) {
        console.log(`📥 Generation state restored from DB: ${key}`);
        return data;
      }
    } catch (error) {
      console.log('⚠️ DB fallback get failed:', error.message);
    }
    return null;
  }

  private async clearFromDatabase(key: string) {
    try {
      const Database = require('@replit/database');
      const db = new Database();
      await db.delete(key);
    } catch (error) {
      console.log('⚠️ DB fallback delete failed:', error.message);
    }
  }

  // Session persistence middleware
  static createSessionMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Auto-save session state every request
      if (req.session && req.session.userId) {
        const sessionData = {
          userId: req.session.userId,
          userEmail: req.session.userEmail,
          lastActivity: new Date().toISOString(),
          generationContext: req.session.generationContext || null
        };

        // Store session backup
        req.session.backup = sessionData;
      }
      next();
    };
  }
}

export const redisSessionManager = new RedisSessionManager();