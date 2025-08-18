// schema.ts
// Drizzle schema for users/sessions tables (PostgreSQL). Export for storage.ts db = drizzle(pool, { schema }).
import { pgTable, uuid, varchar, text, jsonb, timestamp, integer } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).unique().notNull(),
  hashedPassword: text('hashed_password').notNull(),
  phone: varchar('phone', { length: 20 }),
  plan: varchar('plan', { length: 20 }).default('starter'),
  quotaRemaining: integer('quota_remaining').default(10),
  quotaCycleStart: timestamp('quota_cycle_start').defaultNow(),
  oauthTokens: jsonb('oauth_tokens').default({}),
  platformIds: jsonb('platform_ids').default({}),
  dailyPosts: jsonb('daily_posts').default({}),
  stripeSubId: varchar('stripe_sub_id', { length: 255 }),
});

export const sessions = pgTable('sessions', {
  sid: varchar('sid', { length: 255 }).primaryKey(),
  userId: uuid('user_id').references(() => users.id),
  data: jsonb('data').default({}),
  expires: timestamp('expires'),
});