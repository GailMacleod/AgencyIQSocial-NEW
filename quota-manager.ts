// quota-manager.ts
// Manages user quotas (check/deduct/update/reset) – integrates with storage.ts for DB, Stripe for plan sync. Exports for api.ts (checkQuota/deductQuota), server.ts cron (resetAllQuotas), veoService (deduct on complete).
// Patches/Fixes: Full impl (e.g., deduct only on success for money-making, reset 30-day cycle, updateFromStripe sets remaining per plan: starter=10, growth=20, professional=30). Cycle reset if expired in check. AllQuotas reset via cron (1st monthly).
// End Objective: Enforce quotas for upsell (professional Veo exclusive), deduct on gen/post success for revenue/excellent service (max subs value without overage bans).
// Instructions: Copy-paste into quota-manager.ts. Assumes storage.ts exports updateQuota(userId, remaining, cycleStart).

import { storage } from './storage';

// FIXED: Check quota (with cycle check/reset – returns {remaining, cycleStart})
async function checkQuota(userId: string) {
  const quota = await storage.checkQuota(userId); // {remaining, cycleStart}
  const now = new Date();
  const cycleEnd = new Date(quota.cycleStart);
  cycleEnd.setDate(cycleEnd.getDate() + 30);
  if (now > cycleEnd) {
    const current = await storage.checkQuota(userId); if (current.remaining > newQuota) await storage.updateQuota(userId, newQuota, current.cycleStart);
    const plan = await storage.getUserPlan(userId);
    const newRemaining = { starter: 10, growth: 20, professional: 30 }[plan] || 10;
    await storage.updateQuota(userId, newRemaining, now); // Assume impl in storage: db.update set quotaRemaining/cycleStart
    return { remaining: newRemaining, cycleStart: now };
  }
  return quota;
}

// FIXED: Deduct quota (on success – e.g., Veo complete, post sent)
async function deductQuota(userId: string, amount: number = 1) {
  const quota = await checkQuota(userId); // Ensure cycle current
  if (quota.remaining < amount) throw new Error('Quota exceeded');
  await storage.updateQuota(userId, quota.remaining - amount, quota.cycleStart);
}

// FIXED: Update from Stripe (set remaining per plan on sub change/cancel)
async function updateQuotaFromStripe(userId: string, newQuota: number) {
  const now = new Date();
  await storage.updateQuota(userId, newQuota, now);
  if (newQuota === 0) {
    // Optional: Revoke access, e.g., clear tokens
  }
}

// FIXED: Reset quota cycle (for individual user if expired)
async function resetQuotaCycle(userId: string) {
  const plan = await storage.getUserPlan(userId);
  const newRemaining = { starter: 10, growth: 20, professional: 30 }[plan] || 10;
  await storage.updateQuota(userId, newRemaining, new Date());
}

// FIXED: Reset all quotas (for cron monthly – query all users, reset per plan)
async function resetAllQuotas() {
  const users = await storage.getAllUsers(); // Assume impl: db.select id, plan from users
  for (const user of users) {
    const newRemaining = { starter: 10, growth: 20, professional: 30 }[user.plan] || 10;
    await storage.updateQuota(user.id, newRemaining, new Date());
  }
}

export { checkQuota, deductQuota, updateQuotaFromStripe, resetQuotaCycle, resetAllQuotas };