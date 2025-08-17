// storage.ts
// Full patched version with all fixes applied:
// - Removed duplicate declaration of incrementDailyPosts (causing SyntaxError on load – deep search shows from copy-paste error; kept one instance ~line 100 with jsonb_set for daily post limits in auto-posting).
// - Kept pool.connect ~line 9 for DB init/log '✅ DB connected'.
// - Kept all other functions (createUser ~line 15, getUserByEmail ~line 30, etc., updateQuota ~line 120 for prorate in quota-manager).
// - Architecture Note: This abstracts Drizzle DB ops (users/sessions tables from schema.ts) for persistence (e.g., user create/get for onboarding/OAuth, token saves for posting/revoke, quota checks for gen, daily posts for auto-posting limits to max subscriber posts without bans/excellent service). Imported in api.ts/authModule/quota-manager/post-scheduler.
// - Regarding saving/commit: Saving the file in your editor (e.g., VS Code Ctrl+S) updates local, but to commit for Git/Vercel deploy, run `git add server/storage.ts && git commit -m "Fixed duplicate incrementDailyPosts in storage.ts" && git push origin main` from root terminal after saving. If changes not reflecting (e.g., old error persists), check git status for modified files – if not listed, file may not be saved or in wrong dir; restart terminal/editor to reload.
// - No other breaks in this file from deep search – aligns with goal for data persistence in onboarding/OAuth/gen/posting/quota management.

// Imports (with .ts if ESM – assume already patched)
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { eq, sql } from 'drizzle-orm';
import * as schema from './schema.ts'; // With .ts for ESM/Vercel

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await pool.connect(); // Ensures DB connected
console.log('✅ DB connected');

const db = drizzle(pool, { schema });

// Create user (for onboarding – returns {id, ...})
async function createUser(data: { email: string; hashedPassword: string; phone: string }) {
  const [user] = await db.insert(schema.users).values({
    email: data.email,
    hashedPassword: data.hashedPassword,
    phone: data.phone,
    plan: 'starter', // Default, update via Stripe
    quotaRemaining: 10, // Starter quota
    quotaCycleStart: new Date(),
    oauthTokens: {},
    platformIds: {},
    dailyPosts: {}
  }).returning();
  return user;
}

// Get user by email (uniqueness check)
async function getUserByEmail(email: string) {
  const [user] = await db.select().from(schema.users).where(eq(schema.users.email, email));
  return user || null;
}

// Get user by id
async function getUserById(id: string) {
  const [user] = await db.select().from(schema.users).where(eq(schema.users.id, id));
  return user || null;
}

// Get user by platform id (for OAuth)
async function getUserByPlatformId(platform: string, platformId: string) {
  const [user] = await db.select().from(schema.users).where(sql`${schema.users.platformIds} ->> ${platform} = ${platformId}`);
  return user || null;
}

// Save user (for new from OAuth – similar to create but upsert)
async function saveUser(data: { email?: string; platformId: Record<string, string> }) {
  const [user] = await db.insert(schema.users).values({
    email: data.email,
    platformIds: data.platformId,
    // Defaults as above
  }).onConflictDoUpdate({ target: schema.users.id, set: data }).returning(); // Assume id generated
  return user;
}

// Save OAuth tokens (for strategies – update jsonb)
async function saveOAuthTokens(userId: string, platform: string, tokens: { accessToken: string; refreshToken?: string; expiresIn?: number }) {
  await db.update(schema.users).set({
    oauthTokens: sql`jsonb_set(${schema.users.oauthTokens}, '{${platform}}', ${JSON.stringify(tokens)})`
  }).where(eq(schema.users.id, userId));
}

// Get OAuth tokens (for refresh/posting)
async function getOAuthTokens(userId: string, platform: string) {
  const [user] = await db.select({ tokens: sql`${schema.users.oauthTokens} -> ${platform}` }).from(schema.users).where(eq(schema.users.id, userId));
  return user?.tokens || null; // {accessToken, etc.} with expired: check if expiresIn passed
}

// Update OAuth tokens (after refresh)
async function updateOAuthTokens(userId: string, platform: string, tokens: { accessToken: string; refreshToken?: string; expiresIn?: number }) {
  await saveOAuthTokens(userId, platform, tokens); // Reuse
}

// Get user plan (for Veo check)
async function getUserPlan(userId: string): Promise<string> {
  const [user] = await db.select({ plan: schema.users.plan }).from(schema.users).where(eq(schema.users.id, userId));
  return user?.plan || 'starter';
}

// Check quota (for generate/post – with cycle check)
async function checkQuota(userId: string) {
  const [user] = await db.select({ remaining: schema.users.quotaRemaining, cycleStart: schema.users.quotaCycleStart }).from(schema.users).where(eq(schema.users.id, userId));
  return { remaining: user?.remaining || 0, cycleStart: user?.cycleStart || new Date() };
}

// Count daily posts (for auto-posting limits – jsonb {platform: {count: int, lastReset: date}})
async function countDailyPosts(userId: string, platform: string): Promise<number> {
  const [user] = await db.select({ daily: sql`${schema.users.dailyPosts} -> ${platform}` }).from(schema.users).where(eq(schema.users.id, userId));
  const daily = user?.daily || { count: 0, lastReset: new Date().toISOString().split('T')[0] };
  const today = new Date().toISOString().split('T')[0];
  if (daily.lastReset !== today) {
    daily.count = 0;
    daily.lastReset = today;
    await db.update(schema.users).set({
      dailyPosts: sql`jsonb_set(${schema.users.dailyPosts}, '{${platform}}', ${JSON.stringify(daily)})`
    }).where(eq(schema.users.id, userId));
  }
  return daily.count;
}

// Increment daily posts (for auto-posting success – update jsonb)
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

// Get user by session (for recovery – assume sessions table with sid, userId)
async function getUserBySession(sid: string) {
  const [sess] = await db.select({ userId: schema.sessions.userId }).from(schema.sessions).where(eq(schema.sessions.sid, sid));
  if (sess?.userId) {
    return await getUserById(sess.userId);
  }
  return null;
}

// Activate subscription (from Stripe webhook – set plan/remaining)
async function activateSubscription(userId: string, subId: string) {
  await db.update(schema.users).set({ stripeSubId: subId, plan: 'starter', quotaRemaining: 10 }).where(eq(schema.users.id, userId));
}

// Delete user data (for FB GDPR – delete or anonymize)
async function deleteUserData(fbUserId: string) {
  await db.delete(schema.users).where(sql`${schema.users.platformIds} ->> 'facebook' = ${fbUserId}`);
  // Or update to anonymize: set email=null, etc.
}

// Update quota (for prorate/reset)
async function updateQuota(userId: string, remaining: number, cycleStart: Date) {
  await db.update(schema.users).set({ quotaRemaining: remaining, quotaCycleStart: cycleStart }).where(eq(schema.users.id, userId));
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
  incrementDailyPosts, // Single instance here
  getUserBySession,
  activateSubscription,
  deleteUserData,
  updateQuota
};