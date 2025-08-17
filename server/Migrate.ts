// migrate.ts (~line 1 – add .ts extension)
import { db } from './storage.ts'; // Change to this

// Rest unchanged
(async () => {
  await migrate(db, { migrationsFolder: './drizzle' });
  console.log('✅ Migrations run');
})();