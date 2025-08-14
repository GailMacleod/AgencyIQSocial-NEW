// post-scheduler.ts
import { storage } from './storage';
import { PostQuotaService } from './PostQuotaService';

export default {
  async post(content: string, platform: string, userId: number) {
    const quota = await PostQuotaService.getQuotaStatus(userId);
    if (quota.remainingPosts <= 0) throw new Error('Quota exceeded');
    const limits = { facebook: 35, instagram: 100, linkedin: 100, youtube: 6, x: 2400 };
    const daily = await storage.countDailyPosts(userId, platform);
    if (daily >= limits[platform]) throw new Error(`Daily limit reached for ${platform}`);
    const post = await storage.createPost({ content, platform, userId, status: 'scheduled' });
    await PostQuotaService.deductPost(userId, post.id);
    return { success: true, postId: post.id };
  },
};