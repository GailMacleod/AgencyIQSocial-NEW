#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Files to check for cleanup
const filesToClean = [
  'attached_assets',
  'client/src',
  'server',
  'shared',
];

// Known unused files patterns
const unusedPatterns = [
  /Pasted-\d+/,
  /Screenshot.*\.png$/,
  /temp_.*\.tsx?$/,
  /\.backup$/,
  /\.original$/,
  /\.old$/,
];

function findUnusedFiles(dir) {
  const unusedFiles = [];
  
  function scan(currentDir) {
    const files = fs.readdirSync(currentDir);
    
    files.forEach(file => {
      const filePath = path.join(currentDir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory()) {
        scan(filePath);
      } else {
        // Check if file matches unused patterns
        if (unusedPatterns.some(pattern => pattern.test(file))) {
          unusedFiles.push(filePath);
        }
      }
    });
  }
  
  scan(dir);
  return unusedFiles;
}

function cleanupUnusedFiles() {
  console.log('🧹 Scanning for unused files...');
  
  filesToClean.forEach(dir => {
    if (fs.existsSync(dir)) {
      const unused = findUnusedFiles(dir);
      
      unused.forEach(file => {
        try {
          fs.unlinkSync(file);
          console.log(`✅ Deleted: ${file}`);
        } catch (error) {
          console.log(`❌ Failed to delete: ${file} - ${error.message}`);
        }
      });
    }
  });
  
  console.log('🎉 Cleanup complete!');
}

// Run cleanup if this is the main module
if (import.meta.url === `file://${process.argv[1]}`) {
  cleanupUnusedFiles();
}

export { cleanupUnusedFiles };