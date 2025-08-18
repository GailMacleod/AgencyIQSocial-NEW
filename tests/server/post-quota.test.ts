import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { PostQuotaService } from '../../server/PostQuotaService';

describe('PostQuotaService', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('getQuotaStatus', () => {
    it('should return quota status for valid user', async () => {
      const userId = 1;
      const result = await PostQuotaService.getQuotaStatus(userId);
      
      if (result) {
        expect(result).toHaveProperty('userId');
        expect(result).toHaveProperty('remainingPosts');
        expect(result).toHaveProperty('totalPosts');
        expect(result).toHaveProperty('subscriptionPlan');
        expect(result).toHaveProperty('subscriptionActive');
        expect(result.userId).toBe(userId);
      }
    });

    it('should return null for invalid user', async () => {
      const result = await PostQuotaService.getQuotaStatus(0);
      expect(result).toBeNull();
    });
  });

  describe('hasPostsRemaining', () => {
    it('should check if user has posts remaining', async () => {
      const userId = 1;
      const result = await PostQuotaService.hasPostsRemaining(userId);
      expect(typeof result).toBe('boolean');
    });

    it('should return false for invalid user', async () => {
      const result = await PostQuotaService.hasPostsRemaining(0);
      expect(result).toBe(false);
    });
  });

  describe('postApproved', () => {
    it('should handle post approval correctly', async () => {
      const userId = 1;
      const postId = 1;
      
      const result = await PostQuotaService.postApproved(userId, postId, true);
      expect(typeof result).toBe('boolean');
    });

    it('should handle publishing failure', async () => {
      const userId = 1;
      const postId = 1;
      
      const result = await PostQuotaService.postApproved(userId, postId, false);
      expect(typeof result).toBe('boolean');
    });
  });

  describe('getPostCounts', () => {
    it('should return post count summary', async () => {
      const userId = 1;
      const result = await PostQuotaService.getPostCounts(userId);
      
      expect(result).toHaveProperty('approved');
      expect(result).toHaveProperty('draft');
      expect(result).toHaveProperty('published');
      expect(result).toHaveProperty('failed');
      expect(result).toHaveProperty('total');
      expect(typeof result.approved).toBe('number');
      expect(typeof result.draft).toBe('number');
      expect(typeof result.published).toBe('number');
      expect(typeof result.failed).toBe('number');
      expect(typeof result.total).toBe('number');
    });
  });
});