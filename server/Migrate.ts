// migrate.ts
import { db } from './storage';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
(async () => {
  await migrate(db, { migrationsFolder: './drizzle' }); // Create /server/drizzle if not
  console.log('✅ Migrations run');
})();