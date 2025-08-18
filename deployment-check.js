#!/usr/bin/env node
/**
 * TheAgencyIQ Deployment Readiness Check
 * Verifies all deployment requirements are met
 */

const { Pool } = require('@neondatabase/serverless');
const fs = require('fs');
const path = require('path');

console.log('🚀 TheAgencyIQ Deployment Readiness Check');
console.log('==========================================');

// Check 1: Environment Variables
console.log('\n1. Environment Variables Check...');
const requiredEnvVars = [
  'DATABASE_URL',
  'PGDATABASE', 
  'PGHOST',
  'PGPASSWORD',
  'PGPORT',
  'PGUSER'
];

let envCheck = true;
requiredEnvVars.forEach(varName => {
  const exists = process.env[varName] ? '✅' : '❌';
  console.log(`   ${exists} ${varName}`);
  if (!process.env[varName]) envCheck = false;
});

// Check 2: Database Connection
console.log('\n2. Database Connection Check...');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function checkDatabase() {
  try {
    const client = await pool.connect();
    console.log('   ✅ Database connection successful');
    client.release();
    return true;
  } catch (err) {
    console.log('   ❌ Database connection failed:', err.message);
    return false;
  }
}

// Check 3: Build Files
console.log('\n3. Build Configuration Check...');
const buildFiles = [
  'package.json',
  'server/index.ts',
  'vite.config.ts',
  'tsconfig.json'
];

let buildCheck = true;
buildFiles.forEach(file => {
  const exists = fs.existsSync(file);
  const status = exists ? '✅' : '❌';
  console.log(`   ${status} ${file}`);
  if (!exists) buildCheck = false;
});

// Check 4: Privacy and Security
console.log('\n4. Privacy and Security Check...');
const gitignoreExists = fs.existsSync('.gitignore');
console.log(`   ${gitignoreExists ? '✅' : '❌'} .gitignore exists`);

if (gitignoreExists) {
  const gitignoreContent = fs.readFileSync('.gitignore', 'utf8');
  const hasEnvExclusion = gitignoreContent.includes('.env');
  const hasNodeModules = gitignoreContent.includes('node_modules');
  console.log(`   ${hasEnvExclusion ? '✅' : '❌'} .env files excluded`);
  console.log(`   ${hasNodeModules ? '✅' : '❌'} node_modules excluded`);
}

// Check 5: Port Configuration
console.log('\n5. Port Configuration Check...');
const replitConfig = fs.existsSync('.replit');
console.log(`   ${replitConfig ? '✅' : '❌'} .replit configuration exists`);

if (replitConfig) {
  const replitContent = fs.readFileSync('.replit', 'utf8');
  const hasDeploymentConfig = replitContent.includes('[deployment]');
  const hasBuildScript = replitContent.includes('build');
  console.log(`   ${hasDeploymentConfig ? '✅' : '❌'} Deployment configuration present`);
  console.log(`   ${hasBuildScript ? '✅' : '❌'} Build script configured`);
}

// Main check function
async function runAllChecks() {
  const dbCheck = await checkDatabase();
  
  console.log('\n📋 Deployment Readiness Summary:');
  console.log('================================');
  console.log(`Environment Variables: ${envCheck ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Database Connection: ${dbCheck ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Build Configuration: ${buildCheck ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Privacy & Security: ${gitignoreExists ? '✅ PASS' : '❌ FAIL'}`);
  console.log(`Port Configuration: ${replitConfig ? '✅ PASS' : '❌ FAIL'}`);
  
  const allChecks = envCheck && dbCheck && buildCheck && gitignoreExists && replitConfig;
  
  if (allChecks) {
    console.log('\n🎉 DEPLOYMENT READY! All checks passed.');
    console.log('Your TheAgencyIQ platform is ready for production deployment.');
  } else {
    console.log('\n⚠️  DEPLOYMENT ISSUES DETECTED');
    console.log('Please resolve the failed checks before deploying.');
  }
  
  process.exit(allChecks ? 0 : 1);
}

runAllChecks().catch(console.error);