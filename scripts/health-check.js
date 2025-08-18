#!/usr/bin/env node

import http from 'http';
const BASE_URL = 'http://localhost:5000';

function healthCheck() {
  return new Promise((resolve, reject) => {
    const req = http.get(`${BASE_URL}/api/health`, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        if (res.statusCode === 200) {
          resolve({
            status: 'healthy',
            statusCode: res.statusCode,
            response: data,
          });
        } else {
          reject({
            status: 'unhealthy',
            statusCode: res.statusCode,
            response: data,
          });
        }
      });
    });
    
    req.on('error', (error) => {
      reject({
        status: 'error',
        error: error.message,
      });
    });
    
    req.setTimeout(5000, () => {
      req.abort();
      reject({
        status: 'timeout',
        error: 'Health check timeout',
      });
    });
  });
}

async function runHealthCheck() {
  console.log('🏥 Running health check...');
  
  try {
    const result = await healthCheck();
    console.log('✅ Server is healthy');
    console.log(`Status: ${result.statusCode}`);
    console.log(`Response: ${result.response}`);
    process.exit(0);
  } catch (error) {
    console.log('❌ Server is unhealthy');
    console.log(`Status: ${error.status}`);
    console.log(`Error: ${error.error || error.response}`);
    process.exit(1);
  }
}

// Run health check if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  runHealthCheck();
}

export { healthCheck };