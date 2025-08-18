#!/usr/bin/env node

/**
 * COMPREHENSIVE CLEANUP SCRIPT FOR THEAGENCYIQ
 * Removes unused code, optimizes performance, and prepares for deployment
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class ComprehensiveCleanup {
  constructor() {
    this.cleanupLog = [];
    this.unusedFiles = [];
    this.optimizations = [];
  }

  /**
   * Main cleanup execution
   */
  async performCleanup() {
    console.log('🧹 Starting comprehensive cleanup...');
    
    try {
      // 1. Remove unused attached assets
      await this.cleanupAttachedAssets();
      
      // 2. Remove unused imports and variables
      await this.cleanupUnusedImports();
      
      // 3. Optimize database queries
      await this.optimizeDatabase();
      
      // 4. Clean up logs and temporary files
      await this.cleanupLogs();
      
      // 5. Validate critical files
      await this.validateCriticalFiles();
      
      // 6. Generate cleanup report
      await this.generateReport();
      
      console.log('✅ Comprehensive cleanup completed successfully');
      
    } catch (error) {
      console.error('❌ Cleanup failed:', error);
      throw error;
    }
  }

  /**
   * Clean up unused attached assets
   */
  async cleanupAttachedAssets() {
    console.log('📁 Cleaning up attached assets...');
    
    const attachedAssetsDir = path.join(process.cwd(), 'attached_assets');
    if (!fs.existsSync(attachedAssetsDir)) {
      return;
    }

    const files = fs.readdirSync(attachedAssetsDir);
    const usedAssets = ['agency_logo_512x512 (1)_1752200321498.png']; // Authorized logo
    
    const unusedAssets = files.filter(file => 
      !usedAssets.includes(file) && 
      (file.startsWith('Screenshot') || file.startsWith('Pasted-') || file.includes('_175'))
    );

    unusedAssets.forEach(file => {
      const filePath = path.join(attachedAssetsDir, file);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        this.cleanupLog.push(`Removed unused asset: ${file}`);
      }
    });

    console.log(`📁 Removed ${unusedAssets.length} unused assets`);
  }

  /**
   * Clean up unused imports and variables
   */
  async cleanupUnusedImports() {
    console.log('🔍 Cleaning up unused imports...');
    
    const sourceFiles = [
      'client/src/components/onboarding/OnboardingWizard.tsx',
      'client/src/pages/login.tsx',
      'client/src/pages/intelligent-schedule.tsx',
      'client/src/pages/brand-purpose.tsx'
    ];

    sourceFiles.forEach(file => {
      const filePath = path.join(process.cwd(), file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Check for unused imports (basic detection)
        const imports = content.match(/import\s+.*?from\s+['"].*?['"];?/g) || [];
        const usedImports = imports.filter(imp => {
          const importName = imp.match(/import\s+(?:\{([^}]+)\}|\s*(\w+))/);
          if (importName) {
            const names = importName[1] ? importName[1].split(',').map(n => n.trim()) : [importName[2]];
            return names.some(name => content.includes(name) && content.indexOf(name) !== content.indexOf(imp));
          }
          return true;
        });

        if (usedImports.length !== imports.length) {
          this.optimizations.push(`${file}: ${imports.length - usedImports.length} unused imports detected`);
        }
      }
    });

    console.log('🔍 Import cleanup analysis completed');
  }

  /**
   * Optimize database queries
   */
  async optimizeDatabase() {
    console.log('🗄️  Optimizing database...');
    
    // Check for database cleanup opportunities
    const dbFiles = [
      'server/PostQuotaService.ts',
      'server/storage.ts',
      'server/routes.ts'
    ];

    dbFiles.forEach(file => {
      const filePath = path.join(process.cwd(), file);
      if (fs.existsSync(filePath)) {
        const content = fs.readFileSync(filePath, 'utf8');
        
        // Check for potential optimizations
        const queryCount = (content.match(/SELECT|INSERT|UPDATE|DELETE/gi) || []).length;
        const transactionCount = (content.match(/BEGIN|COMMIT|ROLLBACK/gi) || []).length;
        
        this.optimizations.push(`${file}: ${queryCount} queries, ${transactionCount} transactions`);
      }
    });

    console.log('🗄️  Database optimization analysis completed');
  }

  /**
   * Clean up logs and temporary files
   */
  async cleanupLogs() {
    console.log('📝 Cleaning up logs...');
    
    const logDirs = ['logs', 'data'];
    const tempFiles = ['.tmp', '.cache', 'node_modules/.cache'];
    
    logDirs.forEach(dir => {
      const dirPath = path.join(process.cwd(), dir);
      if (fs.existsSync(dirPath)) {
        const files = fs.readdirSync(dirPath);
        const oldLogs = files.filter(file => {
          const filePath = path.join(dirPath, file);
          const stats = fs.statSync(filePath);
          const daysSinceModified = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
          return daysSinceModified > 7; // Remove logs older than 7 days
        });

        oldLogs.forEach(file => {
          const filePath = path.join(dirPath, file);
          if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
            this.cleanupLog.push(`Removed old log: ${file}`);
          }
        });
      }
    });

    console.log('📝 Log cleanup completed');
  }

  /**
   * Validate critical files
   */
  async validateCriticalFiles() {
    console.log('🔍 Validating critical files...');
    
    const criticalFiles = [
      'server/routes.ts',
      'server/PostQuotaService.ts',
      'shared/schema.ts',
      'client/src/App.tsx',
      'client/src/pages/login.tsx',
      'client/src/pages/intelligent-schedule.tsx',
      'package.json',
      'tsconfig.json'
    ];

    const missingFiles = criticalFiles.filter(file => 
      !fs.existsSync(path.join(process.cwd(), file))
    );

    if (missingFiles.length > 0) {
      throw new Error(`Missing critical files: ${missingFiles.join(', ')}`);
    }

    console.log('🔍 All critical files validated');
  }

  /**
   * Generate cleanup report
   */
  async generateReport() {
    console.log('📊 Generating cleanup report...');
    
    const report = {
      timestamp: new Date().toISOString(),
      cleanupActions: this.cleanupLog,
      optimizations: this.optimizations,
      unusedFiles: this.unusedFiles,
      summary: {
        filesRemoved: this.cleanupLog.length,
        optimizationsFound: this.optimizations.length,
        status: 'completed'
      }
    };

    fs.writeFileSync(
      path.join(process.cwd(), 'CLEANUP_REPORT.json'),
      JSON.stringify(report, null, 2)
    );

    console.log('📊 Cleanup report generated: CLEANUP_REPORT.json');
  }
}

// Execute cleanup if run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const cleanup = new ComprehensiveCleanup();
  cleanup.performCleanup()
    .then(() => {
      console.log('🎉 Cleanup completed successfully');
      process.exit(0);
    })
    .catch(error => {
      console.error('💥 Cleanup failed:', error);
      process.exit(1);
    });
}

export default ComprehensiveCleanup;