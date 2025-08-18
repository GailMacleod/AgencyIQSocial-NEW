import { storage } from './storage';

export class OAuthFix {
  
  static async getReconnectionInstructions(userId: number): Promise<{
    status: string;
    immediate_actions: string[];
    platform_issues: {
      facebook: { issue: string; solution: string; url: string };
      linkedin: { issue: string; solution: string; url: string };
      twitter: { issue: string; solution: string; url: string };
      instagram: { issue: string; solution: string; url: string };
    };
    step_by_step: string[];
  }> {
    
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://app.theagencyiq.com' 
      : 'http://localhost:5000';

    return {
      status: "CRITICAL: All platforms require OAuth reconnection with proper permissions",
      immediate_actions: [
        "1. Reconnect Facebook with pages_manage_posts permission",
        "2. Reconnect LinkedIn with fresh access token", 
        "3. Upgrade X/Twitter to OAuth 2.0",
        "4. Replace Instagram demo tokens with business account"
      ],
      platform_issues: {
        facebook: {
          issue: "Invalid OAuth access token - token expired or lacks posting permissions",
          solution: "Reconnect with pages_manage_posts, pages_read_engagement, and publish_actions permissions",
          url: `${baseUrl}/auth/facebook/reconnect`
        },
        linkedin: {
          issue: "Access token expired",
          solution: "Reconnect LinkedIn account with w_member_social permission",
          url: `${baseUrl}/auth/linkedin`
        },
        twitter: {
          issue: "OAuth 1.0a incompatible with current posting API",
          solution: "Upgrade to OAuth 2.0 with tweet.write permission",
          url: `${baseUrl}/auth/twitter`
        },
        instagram: {
          issue: "Demo tokens cannot post to real Instagram accounts",
          solution: "Connect Instagram Business account via Facebook Graph API",
          url: `${baseUrl}/auth/facebook`
        }
      },
      step_by_step: [
        "1. Click 'Reconnect Platform' for each platform below",
        "2. Grant ALL requested permissions during OAuth flow",
        "3. For Facebook: Select your business pages when prompted",
        "4. For Instagram: Ensure you have a Business account linked to Facebook",
        "5. Test posting after reconnection",
        "6. Verify all 50 approved posts can publish successfully"
      ]
    };
  }

  static async simulateWorkingPost(platform: string, content: string): Promise<{
    platform: string;
    success: boolean;
    postId?: string;
    error?: string;
    demo_note?: string;
  }> {
    // Simulate what would happen with proper OAuth connections
    switch (platform) {
      case 'facebook':
        return {
          platform: 'facebook',
          success: true,
          postId: 'demo_fb_12345',
          demo_note: 'This would work with proper pages_manage_posts permission'
        };
      case 'linkedin':
        return {
          platform: 'linkedin', 
          success: true,
          postId: 'demo_li_67890',
          demo_note: 'This would work with valid w_member_social token'
        };
      case 'x':
        return {
          platform: 'x',
          success: true,
          postId: 'demo_x_54321',
          demo_note: 'This would work with OAuth 2.0 tweet.write permission'
        };
      default:
        return {
          platform,
          success: false,
          error: 'Platform not configured'
        };
    }
  }

  static getRequiredPermissions(): {
    facebook: string[];
    linkedin: string[];
    twitter: string[];
  } {
    return {
      facebook: [
        'public_profile',
        'pages_manage_posts', // Required for posting to pages
        'pages_read_engagement', // Required for analytics
        'pages_show_list' // Required to list pages
      ],
      linkedin: [
        'r_liteprofile', // Basic profile info
        'r_emailaddress', // Email access
        'w_member_social' // Required for posting
      ],
      twitter: [
        'tweet.read', // Read tweets
        'tweet.write', // Required for posting tweets
        'users.read' // Read user profile
      ]
    };
  }
}