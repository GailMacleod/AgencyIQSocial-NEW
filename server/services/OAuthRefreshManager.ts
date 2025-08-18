import { db } from '../db';
import { platformConnections } from '../../shared/schema';
import { eq, and } from 'drizzle-orm';

export class OAuthRefreshManager {
  // Auto-refresh tokens before expiry to prevent mid-gen drops
  static async refreshTokenIfNeeded(userId: number, platform: string): Promise<boolean> {
    try {
      console.log(`🔄 Checking token refresh for ${platform} user ${userId}...`);

      const [connection] = await db.select()
        .from(platformConnections)
        .where(and(
          eq(platformConnections.userId, userId.toString()),
          eq(platformConnections.platform, platform)
        ));

      if (!connection || !connection.accessToken) {
        console.log(`⚠️ No connection found for ${platform}`);
        return false;
      }

      // Check if token expires within 1 hour
      const expiryTime = new Date(connection.expiresAt || 0);
      const oneHourFromNow = new Date(Date.now() + 60 * 60 * 1000);
      
      if (expiryTime > oneHourFromNow) {
        console.log(`✅ Token valid for ${platform}, expires: ${expiryTime.toISOString()}`);
        return true;
      }

      console.log(`⏰ Token expiring soon for ${platform}, refreshing...`);
      return await this.refreshPlatformToken(connection);

    } catch (error) {
      console.error(`❌ Token refresh check failed for ${platform}:`, error);
      return false;
    }
  }

  // Platform-specific refresh implementations
  private static async refreshPlatformToken(connection: any): Promise<boolean> {
    const platform = connection.platform;

    try {
      switch (platform) {
        case 'facebook':
        case 'instagram':
          return await this.refreshFacebookToken(connection);
        
        case 'linkedin':
          return await this.refreshLinkedInToken(connection);
        
        case 'x':
          return await this.refreshXToken(connection);
        
        default:
          console.log(`⚠️ No refresh handler for platform: ${platform}`);
          return false;
      }
    } catch (error) {
      console.error(`❌ Token refresh failed for ${platform}:`, error);
      return false;
    }
  }

  // Facebook/Instagram token refresh
  private static async refreshFacebookToken(connection: any): Promise<boolean> {
    try {
      const refreshUrl = `https://graph.facebook.com/v18.0/oauth/access_token`;
      const params = new URLSearchParams({
        grant_type: 'fb_exchange_token',
        client_id: process.env.FACEBOOK_APP_ID!,
        client_secret: process.env.FACEBOOK_APP_SECRET!,
        fb_exchange_token: connection.accessToken
      });

      const response = await fetch(`${refreshUrl}?${params}`, {
        method: 'GET'
      });

      if (!response.ok) {
        throw new Error(`Facebook refresh failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.access_token) {
        // Update connection with new token
        const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
        
        await db.update(platformConnections)
          .set({
            accessToken: data.access_token,
            expiresAt: expiresAt,
            updatedAt: new Date()
          })
          .where(eq(platformConnections.id, connection.id));

        console.log(`✅ Facebook token refreshed, expires: ${expiresAt.toISOString()}`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('❌ Facebook token refresh failed:', error);
      return false;
    }
  }

  // LinkedIn token refresh
  private static async refreshLinkedInToken(connection: any): Promise<boolean> {
    try {
      if (!connection.refreshToken) {
        console.log('⚠️ No refresh token available for LinkedIn');
        return false;
      }

      const refreshUrl = 'https://www.linkedin.com/oauth/v2/accessToken';
      const params = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: connection.refreshToken,
        client_id: process.env.LINKEDIN_CLIENT_ID!,
        client_secret: process.env.LINKEDIN_CLIENT_SECRET!
      });

      const response = await fetch(refreshUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: params
      });

      if (!response.ok) {
        throw new Error(`LinkedIn refresh failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.access_token) {
        const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
        
        await db.update(platformConnections)
          .set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token || connection.refreshToken,
            expiresAt: expiresAt,
            updatedAt: new Date()
          })
          .where(eq(platformConnections.id, connection.id));

        console.log(`✅ LinkedIn token refreshed, expires: ${expiresAt.toISOString()}`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('❌ LinkedIn token refresh failed:', error);
      return false;
    }
  }

  // X (Twitter) token refresh
  private static async refreshXToken(connection: any): Promise<boolean> {
    try {
      // X OAuth 2.0 PKCE flow refresh
      if (!connection.refreshToken) {
        console.log('⚠️ No refresh token available for X');
        return false;
      }

      const refreshUrl = 'https://api.x.com/2/oauth2/token';
      const params = new URLSearchParams({
        refresh_token: connection.refreshToken,
        grant_type: 'refresh_token',
        client_id: process.env.X_CLIENT_ID!
      });

      const auth = Buffer.from(`${process.env.X_CLIENT_ID}:${process.env.X_CLIENT_SECRET}`).toString('base64');

      const response = await fetch(refreshUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${auth}`
        },
        body: params
      });

      if (!response.ok) {
        throw new Error(`X refresh failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.access_token) {
        const expiresAt = new Date(Date.now() + (data.expires_in * 1000));
        
        await db.update(platformConnections)
          .set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token || connection.refreshToken,
            expiresAt: expiresAt,
            updatedAt: new Date()
          })
          .where(eq(platformConnections.id, connection.id));

        console.log(`✅ X token refreshed, expires: ${expiresAt.toISOString()}`);
        return true;
      }

      return false;
    } catch (error) {
      console.error('❌ X token refresh failed:', error);
      return false;
    }
  }

  // Auto-guide JTBD with Queensland prompts
  static async autoGuideJTBD(userId: number, businessData?: any): Promise<any> {
    try {
      console.log(`🎯 Auto-guiding JTBD for Queensland business user ${userId}...`);

      const qldPrompts = {
        heat_escape: {
          jtbd: "Get relief from Queensland heat through smart automation",
          painPoint: "Overwhelmed by manual work in sweltering conditions",
          desiredState: "Cool, efficient operations that run themselves",
          qldContext: "Brisbane summer, Ekka season efficiency needs"
        },
        growth_scale: {
          jtbd: "Scale Queensland business without burning out",
          painPoint: "Stuck managing every detail personally",
          desiredState: "Thriving business with systematic growth",
          qldContext: "Gold Coast tourism boom, Byron Bay expansion"
        },
        local_authority: {
          jtbd: "Become the go-to Queensland industry expert",
          painPoint: "Lost in crowded Sydney/Melbourne noise",
          desiredState: "Recognized as Queensland's premier authority",
          qldContext: "Local networks, Sunshine Coast influence"
        },
        customer_loyalty: {
          jtbd: "Transform customers into Queensland advocates",
          painPoint: "One-off transactions, no repeat business",
          desiredState: "Loyal community that refers consistently",
          qldContext: "Community-focused, local referral networks"
        }
      };

      // Auto-detect JTBD based on business context
      let selectedJTBD = qldPrompts.heat_escape; // Default fallback

      if (businessData?.industry?.includes('tourism') || businessData?.location?.includes('Gold Coast')) {
        selectedJTBD = qldPrompts.growth_scale;
      } else if (businessData?.industry?.includes('consulting') || businessData?.services?.includes('expert')) {
        selectedJTBD = qldPrompts.local_authority;
      } else if (businessData?.industry?.includes('service') || businessData?.business_type?.includes('local')) {
        selectedJTBD = qldPrompts.customer_loyalty;
      }

      console.log(`🎯 Selected JTBD: ${selectedJTBD.jtbd}`);
      return selectedJTBD;

    } catch (error) {
      console.error('❌ JTBD auto-guide failed:', error);
      return null;
    }
  }

  // Check all user tokens and refresh as needed
  static async refreshAllUserTokens(userId: number): Promise<boolean> {
    const platforms = ['facebook', 'instagram', 'linkedin', 'x'];
    const results = await Promise.all(
      platforms.map(platform => this.refreshTokenIfNeeded(userId, platform))
    );

    const successCount = results.filter(success => success).length;
    console.log(`🔄 Token refresh summary: ${successCount}/${platforms.length} successful`);
    
    return successCount > 0;
  }
}