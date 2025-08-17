// storage.ts
// ... (keep your existing imports and functions) ...

import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { eq, sql } from 'drizzle-orm';
import * as schema from './schema.ts';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await pool.connect(); // Add this line here (~line 8) – ensures DB connected before ops
console.log('✅ DB connected'); // For confirmation in logs

const db = drizzle(pool, { schema });

// ... (keep all your existing functions like createUser, getUserByEmail, etc.)

// Add this new function (~line 100, for post-scheduler increment)
async function incrementDailyPosts(userId: string, platform: string) {
  const [user] = await db.select({ daily: sql`${schema.users.dailyPosts} -> ${platform}` }).from(schema.users).where(eq(schema.users.id, userId));
  let daily = user?.daily || { count: 0, lastReset: new Date().toISOString().split('T')[0] };
  const today = new Date().toISOString().split('T')[0];
  if (daily.lastReset !== today) {
    daily = { count: 0, lastReset: today };
  }
  daily.count += 1;
  await db.update(schema.users).set({
    dailyPosts: sql`jsonb_set(${schema.users.dailyPosts}, '{${platform}}', ${JSON.stringify(daily)})`
  }).where(eq(schema.users.id, userId));
}

// Add this for quota-manager prorate (~line 120)
async function updateQuota(userId: string, remaining: number, cycleStart: Date) {
  await db.update(schema.users).set({ quotaRemaining: remaining, quotaCycleStart: cycleStart }).where(eq(schema.users.id, userId));
}

export {
  // ... (keep your existing exports),
  incrementDailyPosts, // New
  updateQuota // New
};

// FIXED: Get user by id
async function getUserById(id: string) {
  const [user] = await db.select().from(schema.users).where(eq(schema.users.id, id));
  return user || null;
}

// FIXED: Get user by platform id (for OAuth)
async function getUserByPlatformId(platform: string, platformId: string) {
  const [user] = await db.select().from(schema.users).where(sql`${schema.users.platformIds} ->> ${platform} = ${platformId}`);
  return user || null;
}

// FIXED: Save user (for new from OAuth – similar to create but upsert)
async function saveUser(data: { email?: string; platformId: Record<string, string> }) {
  const [user] = await db.insert(schema.users).values({
    email: data.email,
    platformIds: data.platformId,
    // Defaults as above
  }).onConflictDoUpdate({ target: schema.users.id, set: data }).returning(); // Assume id generated
  return user;
}

// FIXED: Save OAuth tokens (for strategies – update jsonb)
async function saveOAuthTokens(userId: string, platform: string, tokens: { accessToken: string; refreshToken?: string; expiresIn?: number }) {
  await db.update(schema.users).set({
    oauthTokens: sql`jsonb_set(${schema.users.oauthTokens}, '{${platform}}', ${JSON.stringify(tokens)})`
  }).where(eq(schema.users.id, userId));
}

// FIXED: Get OAuth tokens (for refresh/posting)
async function getOAuthTokens(userId: string, platform: string) {
  const [user] = await db.select({ tokens: sql`${schema.users.oauthTokens} -> ${platform}` }).from(schema.users).where(eq(schema.users.id, userId));
  return user?.tokens || null; // {accessToken, etc.} with expired: check if expiresIn passed
}

// FIXED: Update OAuth tokens (after refresh)
async function updateOAuthTokens(userId: string, platform: string, tokens: { accessToken: string; refreshToken?: string; expiresIn?: number }) {
  await saveOAuthTokens(userId, platform, tokens); // Reuse
}

// FIXED: Get user plan (for Veo check)
async function getUserPlan(userId: string): Promise<string> {
  const [user] = await db.select({ plan: schema.users.plan }).from(schema.users).where(eq(schema.users.id, userId));
  return user?.plan || 'starter';
}

// FIXED: Check quota (for generate/post – with cycle check)
async function checkQuota(userId: string) {
  const [user] = await db.select({ remaining: schema.users.quotaRemaining, cycleStart: schema.users.quotaCycleStart }).from(schema.users).where(eq(schema.users.id, userId));
  return { remaining: user?.remaining || 0, cycleStart: user?.cycleStart || new Date() };
}

// storage.ts (your existing file – add these after existing functions)
async function incrementDailyPosts(userId: string, platform: string) {
  // ... (copy from my previous message – the full function for daily count increment)
}

async function updateQuota(userId: string, remaining: number, cycleStart: Date) {
  await db.update(schema.users).set({ quotaRemaining: remaining, quotaCycleStart: cycleStart }).where(eq(schema.users.id, userId));
}

// In exports at bottom, add: incrementDailyPosts, updateQuota

// FIXED: Delete user data (for FB GDPR – delete or anonymize)
async function deleteUserData(fbUserId: string) {
  await db.delete(schema.users).where(sql`${schema.users.platformIds} ->> 'facebook' = ${fbUserId}`);
  // Or update to anonymize: set email=null, etc.
}

export {
  createUser,
  getUserByEmail,
  getUserById,
  getUserByPlatformId,
  saveUser,
  saveOAuthTokens,
  getOAuthTokens,
  updateOAuthTokens,
  getUserPlan,
  checkQuota,
  countDailyPosts,
  getUserBySession,
  activateSubscription,
  deleteUserData
};