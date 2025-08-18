import { storage } from './storage';

export class OAuthReconnectService {
  
  static async generateReconnectionUrls(userId: number): Promise<{
    facebook: string;
    linkedin: string;
    twitter: string;
    instructions: {
      facebook: string[];
      linkedin: string[];
      twitter: string[];
    };
  }> {
    
    const baseUrl = process.env.NODE_ENV === 'production' 
      ? 'https://app.theagencyiq.com' 
      : `http://localhost:5000`;

    return {
      facebook: `${baseUrl}/auth/facebook?force_permissions=true`,
      linkedin: `${baseUrl}/auth/linkedin?force_permissions=true`, 
      twitter: `${baseUrl}/auth/twitter?force_permissions=true`,
      instructions: {
        facebook: [
          'Click "Reconnect Platform" for Facebook',
          'When prompted, grant ALL permissions including:',
          '- pages_manage_posts (required for posting to pages)',
          '- pages_read_engagement (required for analytics)',
          '- publish_to_groups (for group posting)',
          '- publish_actions (for timeline posting)',
          'If you manage Facebook pages, make sure to select them during authorization'
        ],
        linkedin: [
          'Click "Reconnect Platform" for LinkedIn',
          'Grant permissions for posting and profile access',
          'Ensure your LinkedIn account is active and verified'
        ],
        twitter: [
          'Click "Reconnect Platform" for X/Twitter',
          'This will upgrade you to OAuth 2.0 with posting permissions',
          'Grant all requested permissions for posting tweets'
        ]
      }
    };
  }

  static async markForReconnection(userId: number, platform: string): Promise<void> {
    try {
      const connections = await storage.getPlatformConnectionsByUser(userId);
      const connection = connections.find(c => c.platform === platform);
      
      if (connection) {
        await storage.updatePlatformConnection(connection.id, {
          isActive: false,
          needsReconnection: true
        });
      }
    } catch (error) {
      console.log(`Platform ${platform} marked for reconnection`);
    }
  }

  static getPermissionRequirements(): {
    facebook: string[];
    linkedin: string[];
    twitter: string[];
  } {
    return {
      facebook: [
        'email',
        'pages_manage_posts',
        'pages_read_engagement', 
        'publish_to_groups',
        'pages_show_list',
        'user_posts',
        'publish_actions'
      ],
      linkedin: [
        'r_liteprofile',
        'r_emailaddress',
        'w_member_social'
      ],
      twitter: [
        'tweet.read',
        'tweet.write',
        'users.read'
      ]
    };
  }
}