/**
 * Drizzle ORM Migration Validator
 * Ensures migrations run on startup and handles database errors gracefully
 */

import { db } from './db.js';
import { eq } from 'drizzle-orm';

class MigrationValidator {
  constructor() {
    this.migrationAttempts = 0;
    this.maxRetries = 3;
  }

  /**
   * Run migrations on startup with error handling
   */
  async runStartupMigrations() {
    try {
      console.log('🔄 Checking database migrations...');
      
      // Check if database is accessible
      await this.validateDatabaseConnection();
      
      // Run pending migrations
      await this.executeMigrations();
      
      // Validate critical tables exist
      await this.validateCriticalTables();
      
      console.log('✅ Database migrations completed successfully');
      return { success: true, message: 'Database ready' };

    } catch (error) {
      console.error('❌ Database migration failed:', error.message);
      
      if (this.migrationAttempts < this.maxRetries) {
        this.migrationAttempts++;
        console.log(`🔄 Retrying migrations (attempt ${this.migrationAttempts}/${this.maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, 2000));
        return this.runStartupMigrations();
      }

      throw new Error(`Database migration failed after ${this.maxRetries} attempts: ${error.message}`);
    }
  }

  /**
   * Validate database connection
   */
  async validateDatabaseConnection() {
    try {
      // Simple connection test
      const result = await db.execute('SELECT 1 as test');
      console.log('✅ Database connection validated');
      return true;
    } catch (error) {
      throw new Error(`Database connection failed: ${error.message}`);
    }
  }

  /**
   * Execute pending migrations
   */
  async executeMigrations() {
    try {
      // Import migration runner
      const { migrate } = await import('drizzle-orm/postgres-js/migrator');
      
      // Run migrations
      await migrate(db, { migrationsFolder: './drizzle' });
      console.log('✅ Migrations executed successfully');
      
    } catch (error) {
      // Handle migration errors gracefully
      if (error.message.includes('no pending migrations')) {
        console.log('✅ No pending migrations found');
        return;
      }
      throw error;
    }
  }

  /**
   * Validate critical tables exist for video generation
   */
  async validateCriticalTables() {
    try {
      const { users, platformConnections, posts } = await import('../shared/schema');
      
      // Test critical table access
      const tableTests = [
        { name: 'users', table: users },
        { name: 'platform_connections', table: platformConnections },
        { name: 'posts', table: posts }
      ];

      for (const test of tableTests) {
        try {
          await db.select().from(test.table).limit(1);
          console.log(`✅ Table ${test.name} accessible`);
        } catch (tableError) {
          throw new Error(`Critical table ${test.name} not accessible: ${tableError.message}`);
        }
      }

    } catch (error) {
      throw new Error(`Table validation failed: ${error.message}`);
    }
  }

  /**
   * Safe video URI storage with error handling
   */
  async saveVideoUri(videoId, userId, videoUri, metadata = {}) {
    try {
      const { posts } = await import('../shared/schema');
      
      // Prepare video data
      const videoData = {
        id: videoId,
        userId: userId,
        videoUrl: videoUri,
        platform: metadata.platform || 'youtube',
        status: 'generated',
        metadata: JSON.stringify({
          duration: metadata.duration || 8,
          aspectRatio: metadata.aspectRatio || '16:9',
          quality: metadata.quality || '720p',
          generatedAt: new Date().toISOString(),
          veoGenerated: true
        }),
        createdAt: new Date(),
        updatedAt: new Date()
      };

      // Insert with error handling
      const result = await db.insert(posts)
        .values(videoData)
        .onConflictDoUpdate({
          target: posts.id,
          set: {
            videoUrl: videoData.videoUrl,
            metadata: videoData.metadata,
            updatedAt: videoData.updatedAt
          }
        })
        .returning();

      console.log(`✅ Video URI saved to database: ${videoId}`);
      return result[0];

    } catch (error) {
      console.error('❌ Failed to save video URI:', error.message);
      
      // Return error but don't fail the video generation
      return {
        success: false,
        error: error.message,
        videoId: videoId,
        fallbackStorage: true
      };
    }
  }

  /**
   * Safe video retrieval with error handling
   */
  async getVideoByUri(videoUri) {
    try {
      const { posts } = await import('../shared/schema');
      
      const video = await db.select()
        .from(posts)
        .where(eq(posts.videoUrl, videoUri))
        .limit(1);

      return video[0] || null;

    } catch (error) {
      console.error('❌ Failed to retrieve video:', error.message);
      return null;
    }
  }

  /**
   * Safe user data retrieval for video generation
   */
  async getUserForVideo(userId) {
    try {
      const { users } = await import('../shared/schema');
      
      const user = await db.select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

      if (!user[0]) {
        throw new Error(`User ${userId} not found`);
      }

      return user[0];

    } catch (error) {
      console.error('❌ Failed to retrieve user for video:', error.message);
      throw error;
    }
  }
}

// Export singleton instance
const migrationValidator = new MigrationValidator();

export default migrationValidator;
export { MigrationValidator };