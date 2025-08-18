import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { OAuthRefreshService } from '../../server/oauth-refresh-service';

describe('OAuthRefreshService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('validateAndRefreshConnection', () => {
    it('should validate X platform connection', async () => {
      const result = await OAuthRefreshService.validateAndRefreshConnection(1, 'x');
      expect(result).toHaveProperty('isValid');
      expect(result).toHaveProperty('platform');
      expect(result.platform).toBe('x');
    });

    it('should handle invalid platform gracefully', async () => {
      const result = await OAuthRefreshService.validateAndRefreshConnection(1, 'invalid');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Unknown platform');
    });

    it('should require valid user ID', async () => {
      const result = await OAuthRefreshService.validateAndRefreshConnection(0, 'x');
      expect(result.isValid).toBe(false);
      expect(result.error).toContain('Invalid user ID');
    });
  });

  describe('refreshTokens', () => {
    it('should refresh X platform tokens', async () => {
      const mockConnection = {
        userId: 1,
        platform: 'x',
        accessToken: 'old-token',
        refreshToken: 'refresh-token',
        expiresAt: new Date(Date.now() - 1000), // expired
      };

      const result = await OAuthRefreshService.refreshTokens(mockConnection);
      expect(result).toHaveProperty('success');
      expect(result).toHaveProperty('connection');
    });

    it('should handle refresh failures gracefully', async () => {
      const mockConnection = {
        userId: 1,
        platform: 'x',
        accessToken: 'invalid-token',
        refreshToken: 'invalid-refresh',
        expiresAt: new Date(Date.now() - 1000),
      };

      const result = await OAuthRefreshService.refreshTokens(mockConnection);
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });
});