/**
 * Direct Database Connection Test
 * Tests PostgreSQL connection without external dependencies
 */

import { spawn } from 'child_process';
import { writeFileSync, readFileSync } from 'fs';

console.log('🔍 Testing direct database connection...');

// Check if we can access database environment variables
const DATABASE_URL = process.env.DATABASE_URL;
const PGHOST = process.env.PGHOST;
const PGPORT = process.env.PGPORT;
const PGUSER = process.env.PGUSER;
const PGPASSWORD = process.env.PGPASSWORD;
const PGDATABASE = process.env.PGDATABASE;

console.log('📊 Database Environment Variables:');
console.log(`DATABASE_URL: ${DATABASE_URL ? 'SET' : 'MISSING'}`);
console.log(`PGHOST: ${PGHOST || 'MISSING'}`);
console.log(`PGPORT: ${PGPORT || 'MISSING'}`);
console.log(`PGUSER: ${PGUSER || 'MISSING'}`);
console.log(`PGPASSWORD: ${PGPASSWORD ? 'SET' : 'MISSING'}`);
console.log(`PGDATABASE: ${PGDATABASE || 'MISSING'}`);

// Test with psql directly if available
if (DATABASE_URL) {
  console.log('\n🔧 Testing PostgreSQL connection with psql...');
  
  const psqlTest = spawn('psql', [DATABASE_URL, '-c', 'SELECT COUNT(*) FROM users;'], {
    stdio: 'pipe'
  });
  
  let psqlOutput = '';
  psqlTest.stdout.on('data', (data) => {
    psqlOutput += data.toString();
  });
  
  psqlTest.stderr.on('data', (data) => {
    console.error('PSQL Error:', data.toString());
  });
  
  psqlTest.on('close', (code) => {
    if (code === 0) {
      console.log('✅ PostgreSQL connection successful!');
      console.log('User count result:', psqlOutput.trim());
      
      // Test more queries
      console.log('\n📋 Testing additional queries...');
      
      const queries = [
        'SELECT COUNT(*) as post_count FROM posts;',
        'SELECT "subscriptionPlan", "subscriptionActive" FROM users WHERE id = 2;',
        'SELECT status, COUNT(*) FROM posts WHERE "userId" = 2 GROUP BY status;'
      ];
      
      queries.forEach((query, index) => {
        const queryTest = spawn('psql', [DATABASE_URL, '-c', query], {
          stdio: 'pipe'
        });
        
        let queryOutput = '';
        queryTest.stdout.on('data', (data) => {
          queryOutput += data.toString();
        });
        
        queryTest.on('close', (code) => {
          if (code === 0) {
            console.log(`✅ Query ${index + 1}: ${query}`);
            console.log(`   Result: ${queryOutput.trim()}`);
          } else {
            console.log(`❌ Query ${index + 1} failed: ${query}`);
          }
        });
      });
      
    } else {
      console.log('❌ PostgreSQL connection failed');
    }
  });
  
  psqlTest.on('error', (error) => {
    console.error('❌ PSQL command not available:', error.message);
    
    // Try alternative approach with node-postgres if available
    console.log('\n🔄 Attempting alternative connection method...');
    testAlternativeConnection();
  });
  
} else {
  console.log('❌ DATABASE_URL not available');
  testAlternativeConnection();
}

function testAlternativeConnection() {
  console.log('\n🔄 Testing alternative connection methods...');
  
  // Create a simple SQL test file
  const testQueries = `
-- Test User Status
SELECT id, email, "subscriptionPlan", "subscriptionActive", "subscriptionStart" 
FROM users WHERE id = 2;

-- Test Post Counts
SELECT status, COUNT(*) as count
FROM posts 
WHERE "userId" = 2 
GROUP BY status;

-- Test Total Posts
SELECT COUNT(*) as total_posts FROM posts WHERE "userId" = 2;

-- Test Subscription Period
SELECT 
  "subscriptionStart",
  "subscriptionStart" + INTERVAL '30 days' as subscription_end,
  NOW() < ("subscriptionStart" + INTERVAL '30 days') as is_active
FROM users 
WHERE id = 2;
`;
  
  writeFileSync('test-queries.sql', testQueries);
  console.log('📝 Created test-queries.sql file');
  
  // Try to execute with different methods
  if (PGHOST && PGPORT && PGUSER && PGDATABASE) {
    console.log('🔧 Trying connection with individual parameters...');
    
    const pgTest = spawn('psql', [
      '-h', PGHOST,
      '-p', PGPORT,
      '-U', PGUSER,
      '-d', PGDATABASE,
      '-f', 'test-queries.sql'
    ], {
      stdio: 'pipe',
      env: {
        ...process.env,
        PGPASSWORD: PGPASSWORD
      }
    });
    
    let pgOutput = '';
    pgTest.stdout.on('data', (data) => {
      pgOutput += data.toString();
    });
    
    pgTest.stderr.on('data', (data) => {
      console.error('PG Error:', data.toString());
    });
    
    pgTest.on('close', (code) => {
      if (code === 0) {
        console.log('✅ Alternative connection successful!');
        console.log('Query results:', pgOutput);
      } else {
        console.log('❌ Alternative connection failed');
      }
    });
    
    pgTest.on('error', (error) => {
      console.error('❌ Alternative connection error:', error.message);
    });
    
  } else {
    console.log('❌ Individual PostgreSQL parameters not available');
  }
}

// Summary
setTimeout(() => {
  console.log('\n📊 Database Connection Test Summary:');
  console.log('• Environment variables checked');
  console.log('• Direct psql connection attempted');
  console.log('• Alternative connection methods tested');
  console.log('• Test queries prepared');
  console.log('\nNext steps:');
  console.log('1. Verify DATABASE_URL is properly set');
  console.log('2. Test manual psql connection');
  console.log('3. Install pg package using system package manager');
  console.log('4. Create direct database connection server');
}, 5000);