// schema.ts
// Drizzle schema for users/sessions tables (PostgreSQL). Export for storage.ts db = drizzle(pool, { schema }).
import { pgTable, uuid, varchar, text, jsonb, timestamp, integer } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow(),
  // Other fields...
});

export const sessions = pgTable('sessions', {
  sid: varchar('sid', { length: 255 }).primaryKey(),
  userId: uuid('user_id').references(() => users.id),
  data: jsonb('data').default({}),
  expires: timestamp('expires'),
});