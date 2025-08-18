import { db } from "../db";
import { users, posts, postSchedule, postLedger, platformConnections, brandPurpose } from "@shared/schema";
import { eq, and } from "drizzle-orm";
import axios from "axios";

export class DataCleanupService {
  /**
   * Comprehensive user data cleanup service
   * Safely removes all user data across all tables and revokes external OAuth tokens
   */
  
  static async performCompleteDataCleanup(userId: number, userEmail: string) {
    console.log(`🧹 Starting comprehensive data cleanup for user ${userId} (${userEmail})`);
    
    const cleanupResults = {
      platformConnectionsRevoked: 0,
      postsDeleted: 0,
      schedulesDeleted: 0,
      ledgerEntriesDeleted: 0,
      brandPurposeDeleted: false,
      oauthTokensRevoked: [],
      errors: []
    };
    
    try {
      // Step 1: Revoke all OAuth tokens and close platform connections
      const connections = await db.select()
        .from(platformConnections)
        .where(eq(platformConnections.userId, userId));
      
      for (const connection of connections) {
        try {
          console.log(`🔌 Revoking ${connection.platform} OAuth token (ID: ${connection.id})`);
          
          // Revoke OAuth token from platform API
          await this.revokeOAuthToken(connection.platform, connection.accessToken);
          
          // Deactivate and nullify connection
          await db.update(platformConnections)
            .set({ 
              isActive: false,
              accessToken: null,
              refreshToken: null,
              expiresAt: null
            })
            .where(eq(platformConnections.id, connection.id));
          
          cleanupResults.platformConnectionsRevoked++;
          cleanupResults.oauthTokensRevoked.push({
            platform: connection.platform,
            username: connection.platformUsername,
            status: 'revoked'
          });
          
          console.log(`✅ ${connection.platform} OAuth token revoked successfully`);
        } catch (error) {
          console.error(`❌ Failed to revoke ${connection.platform} OAuth token:`, error);
          cleanupResults.errors.push(`Failed to revoke ${connection.platform} OAuth token: ${error.message}`);
          
          // Force deactivate connection even if revocation fails
          await db.update(platformConnections)
            .set({ 
              isActive: false,
              accessToken: null,
              refreshToken: null,
              expiresAt: null
            })
            .where(eq(platformConnections.id, connection.id));
        }
      }
      
      // Step 2: Delete all posts
      const userPosts = await db.select()
        .from(posts)
        .where(eq(posts.userId, userId));
      
      if (userPosts.length > 0) {
        await db.delete(posts).where(eq(posts.userId, userId));
        cleanupResults.postsDeleted = userPosts.length;
        console.log(`✅ Deleted ${userPosts.length} posts`);
      }
      
      // Step 3: Delete post schedules
      const schedules = await db.select()
        .from(postSchedule)
        .where(eq(postSchedule.userId, userId.toString()));
      
      if (schedules.length > 0) {
        await db.delete(postSchedule).where(eq(postSchedule.userId, userId.toString()));
        cleanupResults.schedulesDeleted = schedules.length;
        console.log(`✅ Deleted ${schedules.length} post schedules`);
      }
      
      // Step 4: Delete post ledger entries
      const ledgerEntries = await db.select()
        .from(postLedger)
        .where(eq(postLedger.userId, userId.toString()));
      
      if (ledgerEntries.length > 0) {
        await db.delete(postLedger).where(eq(postLedger.userId, userId.toString()));
        cleanupResults.ledgerEntriesDeleted = ledgerEntries.length;
        console.log(`✅ Deleted ${ledgerEntries.length} post ledger entries`);
      }
      
      // Step 5: Delete brand purpose data
      const brandPurposeData = await db.select()
        .from(brandPurpose)
        .where(eq(brandPurpose.userId, userId));
      
      if (brandPurposeData.length > 0) {
        await db.delete(brandPurpose).where(eq(brandPurpose.userId, userId));
        cleanupResults.brandPurposeDeleted = true;
        console.log(`✅ Deleted brand purpose data`);
      }
      
      console.log(`🧹 Data cleanup completed successfully for user ${userId}:`, cleanupResults);
      return cleanupResults;
      
    } catch (error) {
      console.error(`❌ Data cleanup failed for user ${userId}:`, error);
      cleanupResults.errors.push(`Data cleanup failed: ${error.message}`);
      throw error;
    }
  }
  
  /**
   * Revoke OAuth token from platform API
   */
  private static async revokeOAuthToken(platform: string, accessToken: string) {
    if (!accessToken) {
      console.log(`⚠️ No access token to revoke for ${platform}`);
      return;
    }
    
    const platformEndpoints = {
      facebook: 'https://graph.facebook.com/me/permissions',
      instagram: 'https://graph.facebook.com/me/permissions', // Instagram uses Facebook Graph API
      linkedin: 'https://www.linkedin.com/oauth/v2/revoke',
      x: 'https://api.twitter.com/2/oauth2/revoke',
      youtube: 'https://oauth2.googleapis.com/revoke'
    };

    const endpoint = platformEndpoints[platform as keyof typeof platformEndpoints];
    if (!endpoint) {
      throw new Error(`No revocation endpoint configured for platform: ${platform}`);
    }

    try {
      let response;
      
      switch (platform) {
        case 'facebook':
        case 'instagram':
          // Facebook/Instagram: DELETE to revoke permissions
          response = await axios.delete(endpoint, {
            params: { access_token: accessToken },
            timeout: 10000
          });
          break;
          
        case 'linkedin':
          // LinkedIn: POST with token parameter
          response = await axios.post(endpoint, null, {
            params: { token: accessToken },
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10000
          });
          break;
          
        case 'x':
          // X (Twitter): POST with token parameter
          response = await axios.post(endpoint, 
            `token=${accessToken}`,
            {
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              timeout: 10000
            }
          );
          break;
          
        case 'youtube':
          // YouTube (Google): POST with token parameter
          response = await axios.post(endpoint, null, {
            params: { token: accessToken },
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 10000
          });
          break;
          
        default:
          throw new Error(`Unsupported platform for token revocation: ${platform}`);
      }
      
      console.log(`✅ OAuth token revoked for ${platform}:`, response.status);
      return true;
    } catch (error: any) {
      console.error(`❌ Failed to revoke OAuth token for ${platform}:`, error.response?.data || error.message);
      throw error;
    }
  }
  
  /**
   * Emergency cleanup - deactivate all connections without OAuth revocation
   * Use when OAuth revocation fails but we still need to clean up database
   */
  static async emergencyDataCleanup(userId: number, userEmail: string) {
    console.log(`🚨 Emergency data cleanup for user ${userId} (${userEmail})`);
    
    try {
      // Force deactivate all platform connections
      await db.update(platformConnections)
        .set({ 
          isActive: false,
          accessToken: null,
          refreshToken: null,
          expiresAt: null
        })
        .where(eq(platformConnections.userId, userId));
      
      // Delete all user data
      await db.delete(posts).where(eq(posts.userId, userId));
      await db.delete(postSchedule).where(eq(postSchedule.userId, userId.toString()));
      await db.delete(postLedger).where(eq(postLedger.userId, userId.toString()));
      await db.delete(brandPurpose).where(eq(brandPurpose.userId, userId));
      
      console.log(`🚨 Emergency cleanup completed for user ${userId}`);
      return { success: true, method: 'emergency' };
    } catch (error) {
      console.error(`❌ Emergency cleanup failed for user ${userId}:`, error);
      throw error;
    }
  }
}