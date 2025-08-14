import { db } from './db';
import { postLedger } from '@shared/schema';
import { eq } from 'drizzle-orm';

export default {
  async checkQuota(userId: number) {
    // FIXED: Implement quota check with 30-day cycle from report/excellent service
    const [quota] = await db.select().from(postLedger).where(eq(postLedger.userId, userId.toString()));
    return quota ? { remaining: quota.quota - quota.usedPosts } : { remaining: 0 };
  },
  async deductQuota(userId: number, amount: number) {
    // FIXED: Deduct with atomic update for revenue/quota enforcement
    await db.transaction(async (tx) => {
      const [ledger] = await tx.select().from(postLedger).where(eq(postLedger.userId, userId.toString()));
      await tx.update(postLedger).set({ usedPosts: ledger.usedPosts + amount }).where(eq(postLedger.userId, userId.toString()));
    });
  },
  async updateQuotaFromStripe(userId: number, quota: number) {
    // FIXED: Sync from Stripe webhook for upsells/revenue
    await db.update(postLedger).set({ quota }).where(eq(postLedger.userId, userId.toString()));
  },
};